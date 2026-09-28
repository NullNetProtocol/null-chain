//! Note plaintext layout, encryption, and trial decryption.
//!
//! ```text
//! note plaintext  = version(1) || d(11) || value(8 LE) || rseed(32) || memo(512)
//! out plaintext   = pk_d(32) || esk(32)
//! ```
//!
//! The receiver decrypts with `ivk`. The sender, or a holder of its `ovk`,
//! decrypts the out ciphertext to recover `esk` and `pk_d` and then the note.
//! Both paths rebuild the note and check it against the public commitment
//! and ephemeral key, so a ciphertext can never claim a note it does not
//! match.

use null_crypto::commitment::ValueCommitment;
use null_crypto::encoding::ENCODED_LEN;
use null_crypto::encryption::{EphemeralPublicKey, EphemeralSecretKey, SymmetricKey, TAG_LEN};
use null_crypto::keys::{
    DiversifiedTransmissionKey, Diversifier, IncomingViewingKey, OutgoingViewingKey,
    DIVERSIFIER_LEN,
};
use rand_core::{CryptoRng, RngCore};

use crate::address::Address;
use crate::amount::Amount;
use crate::bytes::{Encodable, Reader, Writer};
use crate::memo::{Memo, MEMO_LEN};
use crate::note::{ExtractedNoteCommitment, Note, RandomSeed, Rho, RANDOM_SEED_LEN};
use crate::{Error, Result};

/// The only plaintext version currently defined.
const PLAINTEXT_VERSION: u8 = 0x02;

/// Byte length of a note plaintext.
pub const NOTE_PLAINTEXT_LEN: usize = 1 + DIVERSIFIER_LEN + 8 + RANDOM_SEED_LEN + MEMO_LEN;
/// Byte length of a note ciphertext.
pub const NOTE_CIPHERTEXT_LEN: usize = NOTE_PLAINTEXT_LEN + TAG_LEN;
/// Byte length of an outgoing plaintext.
pub const OUT_PLAINTEXT_LEN: usize = ENCODED_LEN + ENCODED_LEN;
/// Byte length of an outgoing ciphertext.
pub const OUT_CIPHERTEXT_LEN: usize = OUT_PLAINTEXT_LEN + TAG_LEN;
/// Byte length of an encoded [`EncryptedNote`].
pub const ENCRYPTED_NOTE_LEN: usize = ENCODED_LEN + NOTE_CIPHERTEXT_LEN + OUT_CIPHERTEXT_LEN;
/// Bytes of the note ciphertext a light client needs to detect and
/// rebuild a note: version, diversifier, value and seed, but not the memo.
pub const COMPACT_NOTE_LEAD: usize = 1 + DIVERSIFIER_LEN + 8 + RANDOM_SEED_LEN;

/// The encrypted form of a note as it appears in an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedNote {
    epk: EphemeralPublicKey,
    enc_ciphertext: [u8; NOTE_CIPHERTEXT_LEN],
    out_ciphertext: [u8; OUT_CIPHERTEXT_LEN],
}

impl EncryptedNote {
    /// The ephemeral public key.
    pub fn epk(&self) -> &EphemeralPublicKey {
        &self.epk
    }

    /// The note ciphertext.
    pub fn enc_ciphertext(&self) -> &[u8; NOTE_CIPHERTEXT_LEN] {
        &self.enc_ciphertext
    }

    /// The outgoing ciphertext.
    pub fn out_ciphertext(&self) -> &[u8; OUT_CIPHERTEXT_LEN] {
        &self.out_ciphertext
    }

    /// Builds from parts already validated elsewhere.
    pub fn from_parts(
        epk: EphemeralPublicKey,
        enc_ciphertext: [u8; NOTE_CIPHERTEXT_LEN],
        out_ciphertext: [u8; OUT_CIPHERTEXT_LEN],
    ) -> Self {
        Self {
            epk,
            enc_ciphertext,
            out_ciphertext,
        }
    }
}

impl Encodable for EncryptedNote {
    fn write(&self, w: &mut Writer) {
        w.put(&self.epk.to_bytes())
            .put(&self.enc_ciphertext)
            .put(&self.out_ciphertext);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let epk = EphemeralPublicKey::from_bytes(&r.take_array()?)?;
        Ok(Self::from_parts(epk, r.take_array()?, r.take_array()?))
    }
}

/// Encrypts `note` for its recipient and, if `ovk` is given, for the sender.
///
/// `cv` is the action's value commitment, bound into the outgoing key so a
/// sender can only recover outputs of the action it actually created.
///
/// # Errors
/// Fails if the note's recipient has an invalid diversifier.
pub fn encrypt_note(
    note: &Note,
    memo: &Memo,
    ovk: Option<&OutgoingViewingKey>,
    cv: &ValueCommitment,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<EncryptedNote> {
    let g_d = note.recipient().g_d()?;
    let pk_d = note.recipient().pk_d();
    let esk = note.esk();
    let epk = esk.public_key(&g_d);
    let key = esk.agree(pk_d).kdf(&epk);
    let enc_ciphertext = fixed(key.encrypt(&NotePlaintext::from_note(note, memo).encode()))?;

    let cmx = note.cmx()?.to_bytes();
    let (ock, out_plaintext) = match ovk {
        Some(ovk) => (
            SymmetricKey::outgoing(ovk, &cv.to_bytes(), &cmx, &epk.to_bytes()),
            out_plaintext(pk_d, &esk),
        ),
        None => (SymmetricKey::random(rng), random_out_plaintext(rng)),
    };
    let out_ciphertext = fixed(ock.encrypt(&out_plaintext))?;

    Ok(EncryptedNote {
        epk,
        enc_ciphertext,
        out_ciphertext,
    })
}

/// Trial-decrypts as the receiver.
///
/// `rho` and `cmx` come from the action carrying the ciphertext.
///
/// # Errors
/// Returns [`null_crypto::Error::DecryptionFailed`] when the note is not
/// for this key, or [`Error::NoteDecryption`] if it decrypts but does not
/// match the action.
pub fn decrypt_note_with_ivk(
    ivk: &IncomingViewingKey,
    encrypted: &EncryptedNote,
    rho: Rho,
    cmx: &ExtractedNoteCommitment,
) -> Result<(Note, Memo)> {
    let key = encrypted.epk.agree(ivk).kdf(&encrypted.epk);
    let plaintext = NotePlaintext::decode(&key.decrypt(&encrypted.enc_ciphertext)?)?;
    let pk_d = ivk.transmission_key(&plaintext.diversifier)?;
    finish_decryption(plaintext, pk_d, rho, encrypted, cmx)
}

/// Detects and rebuilds a note from the leading bytes of its ciphertext,
/// as a light client does over a compact block.
///
/// The lead is decrypted with the receiver's key but not authenticated,
/// so the note is accepted only once it matches the action's commitment.
/// The memo, which is past the lead, is not recovered.
///
/// # Errors
/// Returns [`null_crypto::Error::DecryptionFailed`] when the note is not
/// for this key, or [`Error::NoteDecryption`] if the lead decrypts but
/// does not match the commitment.
pub fn detect_note_with_ivk(
    ivk: &IncomingViewingKey,
    epk: &EphemeralPublicKey,
    enc_lead: &[u8; COMPACT_NOTE_LEAD],
    rho: Rho,
    cmx: &ExtractedNoteCommitment,
) -> Result<Note> {
    let key = epk.agree(ivk).kdf(epk);
    let lead = key.decrypt_lead(enc_lead);
    let plaintext = NoteLead::decode(&lead)?;
    let pk_d = ivk.transmission_key(&plaintext.diversifier)?;
    let recipient = Address::from_parts(plaintext.diversifier, pk_d);
    let note = Note::new(recipient, plaintext.value, rho, plaintext.rseed);
    if note.cmx()? != *cmx {
        return Err(Error::NoteDecryption("commitment mismatch"));
    }
    Ok(note)
}

/// The fields of a note plaintext before the memo.
struct NoteLead {
    diversifier: Diversifier,
    value: Amount,
    rseed: RandomSeed,
}

impl NoteLead {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take_u8()? != PLAINTEXT_VERSION {
            return Err(Error::NoteDecryption("unknown plaintext version"));
        }
        let diversifier = Diversifier::from_bytes(r.take_array()?);
        let value = Amount::from_raw(r.take_u64_le()?)?;
        let rseed = RandomSeed::from_bytes(r.take_array()?);
        r.finish()?;
        Ok(Self {
            diversifier,
            value,
            rseed,
        })
    }
}

/// Decrypts as the sender, using the outgoing viewing key.
///
/// # Errors
/// Returns [`null_crypto::Error::DecryptionFailed`] when this key did not
/// send the note, or [`Error::NoteDecryption`] on an inconsistent plaintext.
pub fn decrypt_note_with_ovk(
    ovk: &OutgoingViewingKey,
    encrypted: &EncryptedNote,
    cv: &ValueCommitment,
    rho: Rho,
    cmx: &ExtractedNoteCommitment,
) -> Result<(Note, Memo)> {
    let (pk_d, esk) = recover_output_keys(ovk, encrypted, cv, cmx)?;
    decrypt_note_with_keys(&pk_d, &esk, encrypted, rho, cmx)
}

/// Recovers, as the sender, the transmission key and ephemeral secret of
/// an output: the two values that let anyone decrypt exactly that note.
///
/// # Errors
/// Returns [`null_crypto::Error::DecryptionFailed`] when this key did not
/// send the note.
pub fn recover_output_keys(
    ovk: &OutgoingViewingKey,
    encrypted: &EncryptedNote,
    cv: &ValueCommitment,
    cmx: &ExtractedNoteCommitment,
) -> Result<(DiversifiedTransmissionKey, EphemeralSecretKey)> {
    let ock = SymmetricKey::outgoing(
        ovk,
        &cv.to_bytes(),
        &cmx.to_bytes(),
        &encrypted.epk.to_bytes(),
    );
    let out_plaintext = ock.decrypt(&encrypted.out_ciphertext)?;
    parse_out_plaintext(&out_plaintext)
}

/// Decrypts one output with its disclosed keys and checks it against the
/// action's public data, so a disclosure cannot claim a note the action
/// does not carry.
///
/// # Errors
/// Returns [`null_crypto::Error::DecryptionFailed`] if the keys do not
/// open the ciphertext, or [`Error::NoteDecryption`] if the plaintext
/// does not match the action.
pub fn decrypt_note_with_keys(
    pk_d: &DiversifiedTransmissionKey,
    esk: &EphemeralSecretKey,
    encrypted: &EncryptedNote,
    rho: Rho,
    cmx: &ExtractedNoteCommitment,
) -> Result<(Note, Memo)> {
    let key = esk.agree(pk_d).kdf(&encrypted.epk);
    let plaintext = NotePlaintext::decode(&key.decrypt(&encrypted.enc_ciphertext)?)?;
    finish_decryption(plaintext, *pk_d, rho, encrypted, cmx)
}

/// Rebuilds the note and checks it against the action's public data.
fn finish_decryption(
    plaintext: NotePlaintext,
    pk_d: DiversifiedTransmissionKey,
    rho: Rho,
    encrypted: &EncryptedNote,
    cmx: &ExtractedNoteCommitment,
) -> Result<(Note, Memo)> {
    let g_d = plaintext.diversifier.base()?;
    let recipient = Address::from_parts(plaintext.diversifier, pk_d);
    let note = Note::new(recipient, plaintext.value, rho, plaintext.rseed);

    if note.cmx()? != *cmx {
        return Err(Error::NoteDecryption("commitment mismatch"));
    }
    if note.esk().public_key(&g_d) != encrypted.epk {
        return Err(Error::NoteDecryption("ephemeral key mismatch"));
    }
    Ok((note, plaintext.memo))
}

/// The decrypted contents of a note ciphertext.
#[derive(Debug)]
struct NotePlaintext {
    diversifier: Diversifier,
    value: Amount,
    rseed: RandomSeed,
    memo: Memo,
}

impl NotePlaintext {
    fn from_note(note: &Note, memo: &Memo) -> Self {
        Self {
            diversifier: *note.recipient().diversifier(),
            value: note.value(),
            rseed: note.rseed().clone(),
            memo: memo.clone(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(NOTE_PLAINTEXT_LEN);
        w.put_u8(PLAINTEXT_VERSION)
            .put(self.diversifier.as_bytes())
            .put_u64_le(self.value.raw())
            .put(self.rseed.as_bytes())
            .put(self.memo.as_bytes());
        w.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take_u8()? != PLAINTEXT_VERSION {
            return Err(Error::NoteDecryption("unknown plaintext version"));
        }
        let diversifier = Diversifier::from_bytes(r.take_array()?);
        let value = Amount::from_raw(r.take_u64_le()?)?;
        let rseed = RandomSeed::from_bytes(r.take_array()?);
        let memo = Memo::from_bytes(r.take_array()?);
        r.finish()?;
        Ok(Self {
            diversifier,
            value,
            rseed,
            memo,
        })
    }
}

/// Converts a ciphertext into its fixed-size array.
fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| Error::Malformed("unexpected ciphertext length"))
}

fn out_plaintext(pk_d: &DiversifiedTransmissionKey, esk: &EphemeralSecretKey) -> Vec<u8> {
    let mut w = Writer::with_capacity(OUT_PLAINTEXT_LEN);
    w.put(&pk_d.to_bytes()).put(&esk.to_bytes());
    w.into_bytes()
}

fn random_out_plaintext(rng: &mut (impl RngCore + CryptoRng)) -> Vec<u8> {
    let mut bytes = vec![0u8; OUT_PLAINTEXT_LEN];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn parse_out_plaintext(bytes: &[u8]) -> Result<(DiversifiedTransmissionKey, EphemeralSecretKey)> {
    let mut r = Reader::new(bytes);
    let pk_d = DiversifiedTransmissionKey::from_bytes(&r.take_array::<ENCODED_LEN>()?)?;
    let esk = EphemeralSecretKey::from_bytes(&r.take_array::<ENCODED_LEN>()?)?;
    r.finish()?;
    Ok((pk_d, esk))
}

#[cfg(test)]
mod tests {
    use null_crypto::commitment::ValueCommitTrapdoor;
    use null_crypto::keys::{FullViewingKey, SpendingKey};
    use null_crypto::pallas;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    struct Party {
        ivk: IncomingViewingKey,
        ovk: OutgoingViewingKey,
        address: Address,
    }

    fn party(rng: &mut ChaCha20Rng) -> Party {
        let fvk = FullViewingKey::derive(&SpendingKey::random(rng)).unwrap();
        let ivk = fvk.incoming_viewing_key().unwrap();
        let address = Address::derive(&ivk, Diversifier::random(rng)).unwrap();
        Party {
            ivk,
            ovk: fvk.outgoing_viewing_key(),
            address,
        }
    }

    struct Scenario {
        rng: ChaCha20Rng,
        sender: Party,
        receiver: Party,
        note: Note,
        memo: Memo,
        cv: ValueCommitment,
        cmx: ExtractedNoteCommitment,
        encrypted: EncryptedNote,
    }

    fn scenario(seed: u64, with_ovk: bool) -> Scenario {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let sender = party(&mut rng);
        let receiver = party(&mut rng);
        let rho = Rho::from_base(pallas::Base::from(seed));
        let note = Note::new(
            receiver.address,
            Amount::from_raw(4_200).unwrap(),
            rho,
            RandomSeed::random(&mut rng),
        );
        let memo = Memo::from_text("grazie").unwrap();
        let cv = ValueCommitment::commit(-4_200, &ValueCommitTrapdoor::random(&mut rng));
        let cmx = note.cmx().unwrap();
        let ovk = with_ovk.then_some(&sender.ovk);
        let encrypted = encrypt_note(&note, &memo, ovk, &cv, &mut rng).unwrap();
        Scenario {
            rng,
            sender,
            receiver,
            note,
            memo,
            cv,
            cmx,
            encrypted,
        }
    }

    fn assert_same_note(a: &Note, b: &Note) {
        assert_eq!(a.recipient(), b.recipient());
        assert_eq!(a.value(), b.value());
        assert_eq!(a.rho(), b.rho());
        assert_eq!(a.rseed().as_bytes(), b.rseed().as_bytes());
    }

    #[test]
    fn sizes_are_fixed() {
        assert_eq!(NOTE_PLAINTEXT_LEN, 564);
        assert_eq!(NOTE_CIPHERTEXT_LEN, 580);
        assert_eq!(OUT_CIPHERTEXT_LEN, 80);
    }

    #[test]
    fn receiver_decrypts_with_ivk() {
        let s = scenario(1, true);
        let (note, memo) =
            decrypt_note_with_ivk(&s.receiver.ivk, &s.encrypted, *s.note.rho(), &s.cmx).unwrap();
        assert_same_note(&note, &s.note);
        assert_eq!(memo, s.memo);
    }

    #[test]
    fn sender_decrypts_with_ovk() {
        let s = scenario(2, true);
        let (note, memo) =
            decrypt_note_with_ovk(&s.sender.ovk, &s.encrypted, &s.cv, *s.note.rho(), &s.cmx)
                .unwrap();
        assert_same_note(&note, &s.note);
        assert_eq!(memo, s.memo);
    }

    #[test]
    fn wrong_keys_fail_to_decrypt() {
        let mut s = scenario(3, true);
        let stranger = party(&mut s.rng);
        let ivk_result = decrypt_note_with_ivk(&stranger.ivk, &s.encrypted, *s.note.rho(), &s.cmx);
        assert_eq!(
            ivk_result.unwrap_err(),
            Error::Crypto(null_crypto::Error::DecryptionFailed)
        );
        let ovk_result =
            decrypt_note_with_ovk(&stranger.ovk, &s.encrypted, &s.cv, *s.note.rho(), &s.cmx);
        assert_eq!(
            ovk_result.unwrap_err(),
            Error::Crypto(null_crypto::Error::DecryptionFailed)
        );
    }

    #[test]
    fn without_ovk_the_sender_cannot_recover_the_note() {
        let s = scenario(4, false);
        assert!(
            decrypt_note_with_ovk(&s.sender.ovk, &s.encrypted, &s.cv, *s.note.rho(), &s.cmx)
                .is_err()
        );
        // The receiver is unaffected.
        assert!(
            decrypt_note_with_ivk(&s.receiver.ivk, &s.encrypted, *s.note.rho(), &s.cmx).is_ok()
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let s = scenario(5, true);
        let mut enc = *s.encrypted.enc_ciphertext();
        enc[100] ^= 1;
        let tampered =
            EncryptedNote::from_parts(*s.encrypted.epk(), enc, *s.encrypted.out_ciphertext());
        assert!(decrypt_note_with_ivk(&s.receiver.ivk, &tampered, *s.note.rho(), &s.cmx).is_err());
    }

    #[test]
    fn mismatched_commitment_is_rejected() {
        let s = scenario(6, true);
        let wrong_cmx = ExtractedNoteCommitment::from_bytes(&[1; 32]).unwrap();
        let result =
            decrypt_note_with_ivk(&s.receiver.ivk, &s.encrypted, *s.note.rho(), &wrong_cmx);
        assert_eq!(
            result.unwrap_err(),
            Error::NoteDecryption("commitment mismatch")
        );
    }

    #[test]
    fn mismatched_rho_is_rejected() {
        // A different rho changes the commitment, so the cmx check catches it.
        let s = scenario(7, true);
        let other_rho = Rho::from_base(pallas::Base::from(999u64));
        assert!(decrypt_note_with_ivk(&s.receiver.ivk, &s.encrypted, other_rho, &s.cmx).is_err());
    }

    #[test]
    fn plaintext_roundtrips_and_rejects_bad_version_and_length() {
        let s = scenario(8, true);
        let encoded = NotePlaintext::from_note(&s.note, &s.memo).encode();
        assert_eq!(encoded.len(), NOTE_PLAINTEXT_LEN);
        let decoded = NotePlaintext::decode(&encoded).unwrap();
        assert_eq!(decoded.value, s.note.value());
        assert_eq!(decoded.memo, s.memo);

        let mut bad_version = encoded.clone();
        bad_version[0] = 0x01;
        assert_eq!(
            NotePlaintext::decode(&bad_version).unwrap_err(),
            Error::NoteDecryption("unknown plaintext version")
        );
        assert!(matches!(
            NotePlaintext::decode(&encoded[..10]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn plaintext_value_above_cap_is_rejected() {
        let s = scenario(9, true);
        let mut encoded = NotePlaintext::from_note(&s.note, &s.memo).encode();
        encoded[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            NotePlaintext::decode(&encoded).unwrap_err(),
            Error::AmountOutOfRange
        );
    }

    #[test]
    fn out_plaintext_roundtrips() {
        let s = scenario(10, true);
        let esk = s.note.esk();
        let bytes = out_plaintext(s.note.recipient().pk_d(), &esk);
        let (pk_d, parsed) = parse_out_plaintext(&bytes).unwrap();
        assert_eq!(&pk_d, s.note.recipient().pk_d());
        assert_eq!(parsed.to_bytes(), esk.to_bytes());
    }

    #[test]
    fn encrypted_note_roundtrips_and_rejects_identity_epk() {
        let s = scenario(11, true);
        let bytes = s.encrypted.to_vec();
        assert_eq!(bytes.len(), ENCRYPTED_NOTE_LEN);
        assert_eq!(EncryptedNote::from_slice(&bytes), Ok(s.encrypted.clone()));
        let mut bad = bytes;
        bad[..32].copy_from_slice(&[0; 32]);
        assert!(EncryptedNote::from_slice(&bad).is_err());
    }
}
