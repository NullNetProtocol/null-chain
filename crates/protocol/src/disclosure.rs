//! Selective disclosure, owner-controlled and off-chain.
//!
//! A [`PaymentDisclosure`] lets the sender of one output prove to anyone
//! what it paid, to whom and with which memo, by revealing the two keys
//! that decrypt exactly that output and nothing else. A [`Challenge`]
//! lets anyone check that a party controls an address: they encrypt a
//! message to it, and only a holder of the address's incoming viewing
//! key can read it back. Neither touches consensus.

use null_crypto::commitment::{ValueCommitTrapdoor, ValueCommitment};
use null_crypto::encryption::EphemeralSecretKey;
use null_crypto::keys::{DiversifiedTransmissionKey, IncomingViewingKey};
use rand_core::{CryptoRng, RngCore};

use crate::address::Address;
use crate::amount::Amount;
use crate::bytes::{Encodable, Reader, Writer};
use crate::memo::Memo;
use crate::note::{ExtractedNoteCommitment, Note, RandomSeed, Rho};
use crate::note_encryption::{
    decrypt_note_with_ivk, decrypt_note_with_keys, encrypt_note, EncryptedNote,
};
use crate::transaction::TxId;
use crate::Result;

/// The keys that open one output of one transaction.
#[derive(Clone, Debug)]
pub struct PaymentDisclosure {
    /// The transaction.
    pub txid: TxId,
    /// The action within it.
    pub index: u32,
    /// The recipient's transmission key.
    pub pk_d: DiversifiedTransmissionKey,
    /// The ephemeral secret the sender used.
    pub esk: EphemeralSecretKey,
}

impl PaymentDisclosure {
    /// Opens the output this disclosure is for, given the action's
    /// public data, and returns the note and memo it proves.
    ///
    /// # Errors
    /// Fails if the keys do not open the output or the plaintext does not
    /// match the action.
    pub fn open(
        &self,
        encrypted: &EncryptedNote,
        rho: Rho,
        cmx: &ExtractedNoteCommitment,
    ) -> Result<(Note, Memo)> {
        decrypt_note_with_keys(&self.pk_d, &self.esk, encrypted, rho, cmx)
    }
}

impl Encodable for PaymentDisclosure {
    fn write(&self, w: &mut Writer) {
        w.put(self.txid.as_bytes())
            .put(&self.index.to_le_bytes())
            .put(&self.pk_d.to_bytes())
            .put(&self.esk.to_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            txid: TxId::from_bytes(r.take_array()?),
            index: u32::from_le_bytes(r.take_array()?),
            pk_d: DiversifiedTransmissionKey::from_bytes(&r.take_array()?)?,
            esk: EphemeralSecretKey::from_bytes(&r.take_array()?)?,
        })
    }
}

/// A message encrypted to an address, readable only by its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The ciphertext, as an output would carry it.
    pub encrypted: EncryptedNote,
    /// The nullifier-derived randomness the note was built with.
    pub rho: Rho,
    /// The note's commitment, which the answer is checked against.
    pub cmx: ExtractedNoteCommitment,
}

impl Challenge {
    /// Encrypts `message` to `address` in a zero-value note.
    ///
    /// # Errors
    /// Fails if the message exceeds a memo or the address is invalid.
    pub fn create(
        address: &Address,
        message: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let note = Note::new(
            *address,
            Amount::ZERO,
            Rho::random(rng),
            RandomSeed::random(rng),
        );
        let memo = Memo::from_text(message)?;
        let cv = ValueCommitment::commit(0, &ValueCommitTrapdoor::zero());
        Ok(Self {
            encrypted: encrypt_note(&note, &memo, None, &cv, rng)?,
            rho: *note.rho(),
            cmx: note.cmx()?,
        })
    }

    /// Reads the message back as the address's owner.
    ///
    /// # Errors
    /// Fails if `ivk` does not own the address the challenge was made for.
    pub fn answer(&self, ivk: &IncomingViewingKey) -> Result<String> {
        let (_, memo) = decrypt_note_with_ivk(ivk, &self.encrypted, self.rho, &self.cmx)?;
        Ok(memo.to_text().unwrap_or_default().to_string())
    }
}

impl Encodable for Challenge {
    fn write(&self, w: &mut Writer) {
        self.encrypted.write(w);
        w.put(&self.rho.to_bytes());
        self.cmx.write(w);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            encrypted: EncryptedNote::read(r)?,
            rho: Rho::from_base(null_crypto::encoding::base_from_bytes(&r.take_array()?)?),
            cmx: ExtractedNoteCommitment::read(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use null_crypto::keys::{FullViewingKey, SpendingKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::note_encryption::recover_output_keys;

    fn keys(seed: u64) -> (FullViewingKey, Address) {
        let sk = SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(seed));
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let address = Address::from_index(&fvk, 0u64.into()).unwrap();
        (fvk, address)
    }

    #[test]
    fn a_disclosure_opens_exactly_the_output_it_was_made_for() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (sender, _) = keys(1);
        let (_, recipient) = keys(2);
        let note = Note::new(
            recipient,
            Amount::from_raw(1_000).unwrap(),
            Rho::random(&mut rng),
            RandomSeed::random(&mut rng),
        );
        let memo = Memo::from_text("invoice 7").unwrap();
        let cv = ValueCommitment::commit(1_000, &ValueCommitTrapdoor::random(&mut rng));
        let ovk = sender.outgoing_viewing_key();
        let encrypted = encrypt_note(&note, &memo, Some(&ovk), &cv, &mut rng).unwrap();
        let cmx = note.cmx().unwrap();

        let (pk_d, esk) = recover_output_keys(&ovk, &encrypted, &cv, &cmx).unwrap();
        let disclosure = PaymentDisclosure {
            txid: TxId::from_bytes([9; 32]),
            index: 1,
            pk_d,
            esk,
        };
        let again = PaymentDisclosure::from_slice(&disclosure.to_vec()).unwrap();
        let (opened, opened_memo) = again.open(&encrypted, *note.rho(), &cmx).unwrap();
        assert_eq!(opened.value().raw(), 1_000);
        assert_eq!(*opened.recipient(), recipient);
        assert_eq!(opened_memo.to_text(), Some("invoice 7"));

        // Another output's data does not verify against these keys.
        let other = Note::new(
            recipient,
            Amount::from_raw(5).unwrap(),
            Rho::random(&mut rng),
            RandomSeed::random(&mut rng),
        );
        assert!(again
            .open(&encrypted, *other.rho(), &other.cmx().unwrap())
            .is_err());
        let (stranger, _) = keys(3);
        assert!(
            recover_output_keys(&stranger.outgoing_viewing_key(), &encrypted, &cv, &cmx).is_err()
        );
        assert!(PaymentDisclosure::from_slice(&[0; 10]).is_err());
    }

    #[test]
    fn a_challenge_is_answered_only_by_the_address_owner() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let (owner, address) = keys(4);
        let (stranger, _) = keys(5);
        let challenge = Challenge::create(&address, "nonce 4242", &mut rng).unwrap();
        let again = Challenge::from_slice(&challenge.to_vec()).unwrap();
        assert_eq!(again, challenge);
        assert_eq!(
            again
                .answer(&owner.incoming_viewing_key().unwrap())
                .unwrap(),
            "nonce 4242"
        );
        assert!(again
            .answer(&stranger.incoming_viewing_key().unwrap())
            .is_err());
        assert!(Challenge::create(&address, &"x".repeat(600), &mut rng).is_err());
    }
}
