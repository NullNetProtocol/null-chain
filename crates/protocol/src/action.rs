//! An action: one spend and one output, the unit every transaction is
//! made of.
//!
//! The [`ActionBody`] is the part covered by the transaction id and the
//! signature message. The [`Action`] adds the spend authorization signature.

use null_circuit::action::PublicInputs;
use null_crypto::commitment::ValueCommitment;
use null_crypto::encoding::ENCODED_LEN;
use null_crypto::signature::{RandomizedVerificationKey, SpendAuthSignature, SIGNATURE_LEN};

use crate::bytes::{Encodable, Reader, Writer};
use crate::note::ExtractedNoteCommitment;
use crate::note_encryption::{EncryptedNote, ENCRYPTED_NOTE_LEN};
use crate::nullifier::Nullifier;
use crate::transaction::Anchor;
use crate::Result;

/// Byte length of an encoded [`ActionBody`].
pub const ACTION_BODY_LEN: usize = 4 * ENCODED_LEN + ENCRYPTED_NOTE_LEN;
/// Byte length of an encoded [`Action`].
pub const ACTION_LEN: usize = ACTION_BODY_LEN + SIGNATURE_LEN;

/// The unsigned content of an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionBody {
    nullifier: Nullifier,
    rk: RandomizedVerificationKey,
    cmx: ExtractedNoteCommitment,
    cv_net: ValueCommitment,
    encrypted_note: EncryptedNote,
}

impl ActionBody {
    /// Assembles a body from its parts.
    pub fn new(
        nullifier: Nullifier,
        rk: RandomizedVerificationKey,
        cmx: ExtractedNoteCommitment,
        cv_net: ValueCommitment,
        encrypted_note: EncryptedNote,
    ) -> Self {
        Self {
            nullifier,
            rk,
            cmx,
            cv_net,
            encrypted_note,
        }
    }

    /// Nullifier of the spent note.
    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }

    /// Randomized spend verification key.
    pub fn rk(&self) -> &RandomizedVerificationKey {
        &self.rk
    }

    /// Commitment of the created note.
    pub fn cmx(&self) -> &ExtractedNoteCommitment {
        &self.cmx
    }

    /// Commitment to `spent value - created value`.
    pub fn cv_net(&self) -> &ValueCommitment {
        &self.cv_net
    }

    /// The created note, encrypted.
    pub fn encrypted_note(&self) -> &EncryptedNote {
        &self.encrypted_note
    }

    /// Attaches a spend authorization signature.
    pub fn sign(self, spend_auth_sig: SpendAuthSignature) -> Action {
        Action {
            body: self,
            spend_auth_sig,
        }
    }

    /// The circuit public inputs this action commits to.
    ///
    /// # Errors
    /// Fails if `rk` is not a canonical point.
    pub fn public_inputs(&self, anchor: &Anchor) -> Result<PublicInputs> {
        Ok(PublicInputs {
            anchor: *anchor.inner(),
            nf_old: self.nullifier.to_base()?,
            rk: self.rk.to_point()?,
            cmx_new: *self.cmx.inner(),
            cv_net: *self.cv_net.as_point(),
        })
    }
}

impl Encodable for ActionBody {
    fn write(&self, w: &mut Writer) {
        self.nullifier.write(w);
        w.put(&self.rk.to_bytes());
        self.cmx.write(w);
        w.put(&self.cv_net.to_bytes());
        self.encrypted_note.write(w);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            nullifier: Nullifier::read(r)?,
            rk: RandomizedVerificationKey::from_bytes(&r.take_array()?)?,
            cmx: ExtractedNoteCommitment::read(r)?,
            cv_net: ValueCommitment::from_bytes(&r.take_array()?)?,
            encrypted_note: EncryptedNote::read(r)?,
        })
    }
}

/// A signed action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    body: ActionBody,
    spend_auth_sig: SpendAuthSignature,
}

impl Action {
    /// The unsigned content.
    pub fn body(&self) -> &ActionBody {
        &self.body
    }

    /// The spend authorization signature.
    pub fn spend_auth_sig(&self) -> &SpendAuthSignature {
        &self.spend_auth_sig
    }
}

impl Encodable for Action {
    fn write(&self, w: &mut Writer) {
        self.body.write(w);
        w.put(&self.spend_auth_sig.to_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let body = ActionBody::read(r)?;
        Ok(body.sign(SpendAuthSignature::from_bytes(r.take_array()?)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use null_crypto::commitment::ValueCommitTrapdoor;
    use null_crypto::keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey};
    use null_crypto::pallas;
    use null_crypto::signature::{RandomizedSigningKey, SpendAuthRandomizer};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::address::Address;
    use crate::amount::Amount;
    use crate::memo::Memo;
    use crate::note::{Note, RandomSeed, Rho};
    use crate::note_encryption::encrypt_note;

    /// A syntactically valid action whose signature is over `message`.
    pub(crate) fn sample_action(rng: &mut ChaCha20Rng, message: &[u8]) -> Action {
        let sk = SpendingKey::random(rng);
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let ivk = fvk.incoming_viewing_key().unwrap();
        let address = Address::derive(&ivk, null_crypto::keys::Diversifier::random(rng)).unwrap();
        let note = Note::new(
            address,
            Amount::from_raw(5).unwrap(),
            Rho::random(rng),
            RandomSeed::random(rng),
        );
        let nullifier = note.nullifier(fvk.nk()).unwrap();
        let cv = ValueCommitment::commit(0, &ValueCommitTrapdoor::random(rng));
        let encrypted = encrypt_note(&note, &Memo::empty(), None, &cv, rng).unwrap();
        let rsk = RandomizedSigningKey::new(
            &SpendAuthorizingKey::derive(&sk).unwrap(),
            &SpendAuthRandomizer::random(rng),
        )
        .unwrap();
        let body = ActionBody::new(
            nullifier,
            rsk.verification_key(),
            note.cmx().unwrap(),
            cv,
            encrypted,
        );
        let sig = rsk.sign(rng, message);
        body.sign(sig)
    }

    #[test]
    fn lengths_are_fixed() {
        assert_eq!(ACTION_BODY_LEN, 820);
        assert_eq!(ACTION_LEN, 884);
        let action = sample_action(&mut ChaCha20Rng::seed_from_u64(1), b"m");
        assert_eq!(action.body().to_vec().len(), ACTION_BODY_LEN);
        assert_eq!(action.to_vec().len(), ACTION_LEN);
    }

    #[test]
    fn action_roundtrips() {
        let action = sample_action(&mut ChaCha20Rng::seed_from_u64(2), b"m");
        assert_eq!(Action::from_slice(&action.to_vec()), Ok(action.clone()));
        assert_eq!(
            ActionBody::from_slice(&action.body().to_vec()),
            Ok(action.body().clone())
        );
    }

    #[test]
    fn truncated_and_garbage_actions_are_rejected() {
        let action = sample_action(&mut ChaCha20Rng::seed_from_u64(3), b"m");
        let bytes = action.to_vec();
        assert!(Action::from_slice(&bytes[..ACTION_LEN - 1]).is_err());
        let mut bad_nullifier = bytes.clone();
        bad_nullifier[..32].copy_from_slice(&[0xFF; 32]);
        assert!(Action::from_slice(&bad_nullifier).is_err());
        let _ = pallas::Base::from(0u64);
    }

    #[test]
    fn signature_verifies_against_rk() {
        let action = sample_action(&mut ChaCha20Rng::seed_from_u64(4), b"sighash");
        assert!(action
            .body()
            .rk()
            .verify(b"sighash", action.spend_auth_sig())
            .is_ok());
        assert!(action
            .body()
            .rk()
            .verify(b"other", action.spend_auth_sig())
            .is_err());
    }
}
