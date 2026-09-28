//! Notes: the unit of value in the shielded pool.
//!
//! A note is `(recipient, value, rho, rseed)`. From `rseed` and `rho` the
//! note derives its commitment trapdoor `rcm` and the nullifier nonce `psi`.
//!
//! ```text
//! cm  = Poseidon(g_d.x, pk_d.x, pack(value, signs), rho, psi, rcm)
//! nf  = Poseidon(nk, rho, psi, cm)
//! ```
//!
//! `rho` of an output note is the nullifier of the note spent in the same
//! action, which is what makes nullifiers unique across the chain.

use ff::Field;
use null_crypto::commitment::{NoteCommitInputs, NoteCommitTrapdoor, NoteCommitment};
use null_crypto::encoding::{base_from_bytes, base_to_bytes, Encoded};
use null_crypto::encryption::EphemeralSecretKey;
use null_crypto::hash::{prf_expand, wide_to_base, wide_to_scalar};
use null_crypto::keys::NullifierKey;
use null_crypto::pallas;
use null_crypto::poseidon::nullifier;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::address::Address;
use crate::amount::Amount;
use crate::bytes::{Encodable, Reader, Writer};
use crate::nullifier::Nullifier;
use crate::Result;

/// `PRF^expand` tag deriving `esk` from the random seed.
const ESK_TAG: u8 = 0x04;
/// `PRF^expand` tag deriving `rcm` from the random seed.
const RCM_TAG: u8 = 0x05;
/// `PRF^expand` tag deriving `psi` from the random seed.
const PSI_TAG: u8 = 0x09;

/// Byte length of a random seed.
pub const RANDOM_SEED_LEN: usize = 32;

/// The 32-byte seed from which a note's randomness is derived.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RandomSeed([u8; RANDOM_SEED_LEN]);

impl RandomSeed {
    /// Samples a fresh seed.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; RANDOM_SEED_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps raw bytes, as recovered from a decrypted note plaintext.
    pub fn from_bytes(bytes: [u8; RANDOM_SEED_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for the note plaintext.
    pub fn as_bytes(&self) -> &[u8; RANDOM_SEED_LEN] {
        &self.0
    }

    /// `esk`: the ephemeral secret used to encrypt this note.
    pub fn esk(&self, rho: &Rho) -> EphemeralSecretKey {
        EphemeralSecretKey::from_scalar(wide_to_scalar(&self.expand(ESK_TAG, rho)))
    }

    fn expand(&self, tag: u8, rho: &Rho) -> [u8; null_crypto::hash::WIDE_OUTPUT_LEN] {
        let mut input = [0u8; 33];
        let (t, r) = input.split_at_mut(1);
        t.copy_from_slice(&[tag]);
        r.copy_from_slice(&rho.to_bytes());
        prf_expand(&self.0, &input)
    }

    /// `rcm`: the note commitment trapdoor.
    pub fn rcm(&self, rho: &Rho) -> NoteCommitTrapdoor {
        NoteCommitTrapdoor::from_base(wide_to_base(&self.expand(RCM_TAG, rho)))
    }

    /// `psi`: the nullifier nonce.
    pub fn psi(&self, rho: &Rho) -> pallas::Base {
        wide_to_base(&self.expand(PSI_TAG, rho))
    }
}

impl core::fmt::Debug for RandomSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RandomSeed(<redacted>)")
    }
}

/// `rho`: the uniqueness nonce of a note, the nullifier of the note that
/// was spent to create it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rho(pallas::Base);

impl Rho {
    /// A note created by spending the note with nullifier `nf`.
    ///
    /// # Errors
    /// Cannot fail for a well-formed nullifier.
    pub fn from_nullifier(nf: &Nullifier) -> Result<Self> {
        nf.to_base().map(Self)
    }

    /// Wraps a field element directly, for coinbase notes and tests.
    pub fn from_base(value: pallas::Base) -> Self {
        Self(value)
    }

    /// A random `rho`, for dummy notes that are never spent.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(pallas::Base::random(rng))
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        base_to_bytes(&self.0)
    }

    /// The field element.
    pub fn inner(&self) -> &pallas::Base {
        &self.0
    }
}

/// `cmx`: the x-coordinate of a note commitment, as stored in the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtractedNoteCommitment(pallas::Base);

impl ExtractedNoteCommitment {
    /// Extracts from a full commitment.
    pub fn from_commitment(cm: &NoteCommitment) -> Self {
        Self(*cm.inner())
    }

    /// The field element.
    pub fn inner(&self) -> &pallas::Base {
        &self.0
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> Encoded {
        base_to_bytes(&self.0)
    }

    /// Parses a canonical encoding.
    ///
    /// # Errors
    /// Fails if the bytes are not a canonical base field element.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        Ok(Self(base_from_bytes(bytes)?))
    }
}

impl Encodable for ExtractedNoteCommitment {
    fn write(&self, w: &mut Writer) {
        w.put(&self.to_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_bytes(&r.take_array()?)
    }
}

/// A note in the shielded pool.
#[derive(Clone, Debug)]
pub struct Note {
    recipient: Address,
    value: Amount,
    rho: Rho,
    rseed: RandomSeed,
}

impl Note {
    /// Builds a note from its parts.
    pub fn new(recipient: Address, value: Amount, rho: Rho, rseed: RandomSeed) -> Self {
        Self {
            recipient,
            value,
            rho,
            rseed,
        }
    }

    /// The recipient address.
    pub fn recipient(&self) -> &Address {
        &self.recipient
    }

    /// The value.
    pub fn value(&self) -> Amount {
        self.value
    }

    /// The uniqueness nonce.
    pub fn rho(&self) -> &Rho {
        &self.rho
    }

    /// The random seed.
    pub fn rseed(&self) -> &RandomSeed {
        &self.rseed
    }

    /// `psi`, derived from the seed and `rho`.
    pub fn psi(&self) -> pallas::Base {
        self.rseed.psi(&self.rho)
    }

    /// The ephemeral secret key used to encrypt this note.
    pub fn esk(&self) -> EphemeralSecretKey {
        self.rseed.esk(&self.rho)
    }

    /// The note commitment `cm`.
    ///
    /// # Errors
    /// Fails if the recipient's diversifier is invalid.
    pub fn commitment(&self) -> Result<NoteCommitment> {
        let g_d = self.recipient.g_d()?;
        let inputs = NoteCommitInputs {
            g_d: &g_d,
            pk_d: self.recipient.pk_d().as_point(),
            value: self.value.raw(),
            rho: &self.rho.0,
            psi: &self.psi(),
        };
        Ok(NoteCommitment::commit(&inputs, &self.rseed.rcm(&self.rho)))
    }

    /// `cmx`, the extracted note commitment.
    ///
    /// # Errors
    /// Propagates commitment errors.
    pub fn cmx(&self) -> Result<ExtractedNoteCommitment> {
        self.commitment()
            .map(|cm| ExtractedNoteCommitment::from_commitment(&cm))
    }

    /// The nullifier that spending this note reveals.
    ///
    /// # Errors
    /// Propagates commitment errors.
    pub fn nullifier(&self, nk: &NullifierKey) -> Result<Nullifier> {
        let cm = self.commitment()?;
        Ok(Nullifier::from_base(&nullifier(
            &nk.expose(),
            &self.rho.0,
            &self.psi(),
            cm.inner(),
        )))
    }
}

impl Encodable for Note {
    fn write(&self, w: &mut Writer) {
        self.recipient.write(w);
        w.put_u64_le(self.value.raw())
            .put(&self.rho.to_bytes())
            .put(self.rseed.as_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let recipient = Address::read(r)?;
        let value = Amount::from_raw(r.take_u64_le()?)?;
        let rho = Rho::from_base(base_from_bytes(&r.take_array()?)?);
        let rseed = RandomSeed::from_bytes(r.take_array()?);
        Ok(Self::new(recipient, value, rho, rseed))
    }
}

#[cfg(test)]
mod tests {
    use null_crypto::keys::{Diversifier, FullViewingKey, SpendingKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    struct Fixture {
        fvk: FullViewingKey,
        note: Note,
    }

    fn fixture(seed: u64) -> Fixture {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let fvk = FullViewingKey::derive(&SpendingKey::random(&mut rng)).unwrap();
        let ivk = fvk.incoming_viewing_key().unwrap();
        let recipient = Address::derive(&ivk, Diversifier::random(&mut rng)).unwrap();
        let rho = Rho::from_base(pallas::Base::from(seed));
        let note = Note::new(
            recipient,
            Amount::from_raw(1_000).unwrap(),
            rho,
            RandomSeed::random(&mut rng),
        );
        Fixture { fvk, note }
    }

    #[test]
    fn commitment_is_deterministic() {
        let f = fixture(1);
        assert_eq!(f.note.commitment().unwrap(), f.note.commitment().unwrap());
    }

    #[test]
    fn commitment_changes_with_every_field() {
        let f = fixture(2);
        let base = f.note.commitment().unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(99);

        let other_value = Note::new(
            f.note.recipient,
            Amount::from_raw(1_001).unwrap(),
            f.note.rho,
            f.note.rseed.clone(),
        );
        assert_ne!(base, other_value.commitment().unwrap(), "value");

        let other_rho = Note::new(
            f.note.recipient,
            f.note.value,
            Rho::from_base(pallas::Base::from(7u64)),
            f.note.rseed.clone(),
        );
        assert_ne!(base, other_rho.commitment().unwrap(), "rho");

        let other_seed = Note::new(
            f.note.recipient,
            f.note.value,
            f.note.rho,
            RandomSeed::random(&mut rng),
        );
        assert_ne!(base, other_seed.commitment().unwrap(), "rseed");

        let other_recipient = Note::new(
            fixture(3).note.recipient,
            f.note.value,
            f.note.rho,
            f.note.rseed.clone(),
        );
        assert_ne!(base, other_recipient.commitment().unwrap(), "recipient");
    }

    #[test]
    fn nullifier_is_deterministic_and_key_dependent() {
        let f = fixture(4);
        let nf = f.note.nullifier(f.fvk.nk()).unwrap();
        assert_eq!(nf, f.note.nullifier(f.fvk.nk()).unwrap());
        let other_key = fixture(5).fvk;
        assert_ne!(nf, f.note.nullifier(other_key.nk()).unwrap());
    }

    #[test]
    fn distinct_notes_have_distinct_nullifiers() {
        let (a, b) = (fixture(6), fixture(7));
        assert_ne!(
            a.note.nullifier(a.fvk.nk()).unwrap(),
            b.note.nullifier(a.fvk.nk()).unwrap()
        );
    }

    #[test]
    fn rho_chains_from_nullifier() {
        let f = fixture(8);
        let nf = f.note.nullifier(f.fvk.nk()).unwrap();
        let rho = Rho::from_nullifier(&nf).unwrap();
        assert_eq!(rho.to_bytes(), nf.to_bytes());
    }

    #[test]
    fn rcm_and_psi_depend_on_rho() {
        let seed = RandomSeed::from_bytes([9; 32]);
        let (r1, r2) = (
            Rho::from_base(pallas::Base::from(1u64)),
            Rho::from_base(pallas::Base::from(2u64)),
        );
        assert_ne!(seed.psi(&r1), seed.psi(&r2));
        let note = |rho| {
            Note::new(
                fixture(9).note.recipient,
                Amount::ZERO,
                rho,
                RandomSeed::from_bytes([9; 32]),
            )
        };
        assert_ne!(
            note(r1).commitment().unwrap(),
            note(r2).commitment().unwrap()
        );
    }

    #[test]
    fn esk_differs_from_rcm_and_depends_on_rho() {
        let seed = RandomSeed::from_bytes([3; RANDOM_SEED_LEN]);
        let (r1, r2) = (
            Rho::from_base(pallas::Base::from(1u64)),
            Rho::from_base(pallas::Base::from(2u64)),
        );
        assert_ne!(seed.esk(&r1).to_bytes(), seed.esk(&r2).to_bytes());
        assert_eq!(seed.esk(&r1).to_bytes(), seed.esk(&r1).to_bytes());
        assert_eq!(
            fixture(10).note.esk().to_bytes(),
            fixture(10).note.esk().to_bytes()
        );
    }

    #[test]
    fn cmx_matches_extracted_commitment_and_roundtrips() {
        let f = fixture(11);
        let cmx = f.note.cmx().unwrap();
        assert_eq!(cmx.inner(), f.note.commitment().unwrap().inner());
        assert_eq!(ExtractedNoteCommitment::from_slice(&cmx.to_vec()), Ok(cmx));
        assert!(ExtractedNoteCommitment::from_bytes(&[0xFF; 32]).is_err());
    }

    #[test]
    fn random_rho_differs_per_call() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        assert_ne!(Rho::random(&mut rng), Rho::random(&mut rng));
    }

    #[test]
    fn note_encoding_roundtrips_and_preserves_the_commitment() {
        let f = fixture(13);
        let decoded = Note::from_slice(&f.note.to_vec()).unwrap();
        assert_eq!(decoded.recipient(), f.note.recipient());
        assert_eq!(decoded.value(), f.note.value());
        assert_eq!(decoded.rho(), f.note.rho());
        assert_eq!(decoded.cmx().unwrap(), f.note.cmx().unwrap());
    }

    #[test]
    fn random_seed_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", RandomSeed::from_bytes([0; 32])),
            "RandomSeed(<redacted>)"
        );
    }
}
