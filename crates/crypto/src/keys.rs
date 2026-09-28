//! The spending key hierarchy and diversified addresses.
//!
//! ```text
//! SpendingKey (32 random bytes)
//!   ├─ SpendAuthorizingKey  ask   scalar   PRF_expand(sk, [ASK_TAG])
//!   ├─ NullifierKey         nk    base     PRF_expand(sk, [NK_TAG])
//!   └─ CommitIvkRandomness  rivk  scalar   PRF_expand(sk, [RIVK_TAG])
//!
//! SpendValidatingKey ak = [ask] G_spend        (`RedPallas` basepoint)
//! FullViewingKey    = (ak, nk, rivk)
//! IncomingViewingKey ivk = H_ivk(ak, nk, rivk)
//! OutgoingViewingKey ovk = H_ovk(rivk, ak, nk)
//! DiversifiedTransmissionKey pk_d = [ivk] g_d,   g_d = HashToCurve(d)
//! ```
//!
//! Every type that is derived from the spending key is zeroized on drop.

use ff::{Field, PrimeField};
use pasta_curves::pallas;
use rand_core::{CryptoRng, RngCore};
use reddsa::orchard::SpendAuth;
use reddsa::{SigningKey, VerificationKey};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::curve::{base_to_scalar, diversified_base, extract_x, is_identity};
use crate::diversifier::DiversifierKey;
use crate::encoding::{
    base_from_bytes, base_to_bytes, point_from_bytes, point_to_bytes, Encoded, ENCODED_LEN,
};
use crate::hash::{blake2b_short, prf_expand, wide_to_base, wide_to_scalar, DK, OVK};
use crate::poseidon::ivk as poseidon_ivk;
use crate::secret::{SecretBase, SecretScalar};
use crate::{Error, Result};

/// Byte length of a spending key.
pub const SPENDING_KEY_LEN: usize = 32;
/// Byte length of a diversifier.
pub const DIVERSIFIER_LEN: usize = 11;

/// `PRF^expand` tag for the spend authorizing key.
const ASK_TAG: u8 = 0x06;
/// `PRF^expand` tag for the nullifier key.
const NK_TAG: u8 = 0x07;
/// `PRF^expand` tag for the ivk commitment randomness.
const RIVK_TAG: u8 = 0x08;
/// Byte length of an outgoing viewing key.
pub const OUTGOING_VIEWING_KEY_LEN: usize = 32;

/// The root secret. Everything else is derived from it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpendingKey([u8; SPENDING_KEY_LEN]);

impl SpendingKey {
    /// Samples a fresh spending key.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; SPENDING_KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps raw bytes as a spending key.
    pub fn from_bytes(bytes: [u8; SPENDING_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for encrypted storage.
    pub fn to_bytes(&self) -> [u8; SPENDING_KEY_LEN] {
        self.0
    }

    fn expand(&self, tag: u8) -> [u8; crate::hash::WIDE_OUTPUT_LEN] {
        prf_expand(&self.0, &[tag])
    }
}

impl ConstantTimeEq for SpendingKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl core::fmt::Debug for SpendingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SpendingKey(<redacted>)")
    }
}

/// `ask`: the scalar that authorizes spends. Never zero.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SpendAuthorizingKey(SecretScalar);

impl SpendAuthorizingKey {
    /// Derives `ask` from the spending key.
    ///
    /// # Errors
    /// Returns [`Error::DegenerateKey`] if the derived scalar is zero.
    pub fn derive(sk: &SpendingKey) -> Result<Self> {
        let ask = wide_to_scalar(&sk.expand(ASK_TAG));
        if bool::from(ask.is_zero()) {
            return Err(Error::DegenerateKey);
        }
        Ok(Self(SecretScalar::new(ask)))
    }

    /// The public validating key `ak = [ask] G_spend`.
    pub fn validating_key(&self) -> SpendValidatingKey {
        SpendValidatingKey(VerificationKey::from(&self.signing_key()))
    }

    /// The inner scalar, for randomization.
    pub(crate) fn expose(&self) -> pallas::Scalar {
        self.0.expose()
    }

    /// The `reddsa` signing key for `ask`.
    ///
    /// `ask` is non-zero and canonical by construction, so conversion
    /// cannot fail; the fallback is unreachable and covered by tests.
    fn signing_key(&self) -> SigningKey<SpendAuth> {
        signing_key_from_scalar(&self.expose()).unwrap_or_else(|_| SigningKey::new(ZeroRng))
    }
}

/// Builds a `reddsa` signing key from a scalar.
///
/// # Errors
/// Returns [`Error::DegenerateKey`] for the zero scalar.
pub(crate) fn signing_key_from_scalar(scalar: &pallas::Scalar) -> Result<SigningKey<SpendAuth>> {
    // `reddsa` accepts the zero scalar; we do not, since its key is the identity.
    if bool::from(scalar.is_zero()) {
        return Err(Error::DegenerateKey);
    }
    SigningKey::try_from(scalar.to_repr()).map_err(|_| Error::DegenerateKey)
}

/// An RNG that yields zeros, used only for an unreachable fallback.
struct ZeroRng;

impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        dest.fill(0);
        Ok(())
    }
}

impl CryptoRng for ZeroRng {}

/// `ak`: the public counterpart of `ask`, a `RedPallas` verification key.
#[derive(Clone, Debug, PartialEq)]
pub struct SpendValidatingKey(VerificationKey<SpendAuth>);

impl Eq for SpendValidatingKey {}

impl SpendValidatingKey {
    /// Compressed encoding.
    pub fn to_bytes(&self) -> Encoded {
        self.0.into()
    }

    /// Decodes a compressed point.
    ///
    /// # Errors
    /// Returns [`Error::InvalidPoint`] on a non-canonical encoding.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        VerificationKey::try_from(*bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPoint)
    }

    /// The inner verification key.
    pub(crate) fn inner(&self) -> &VerificationKey<SpendAuth> {
        &self.0
    }

    /// The point `ak`.
    ///
    /// # Errors
    /// Cannot fail for a key built by this type.
    pub fn to_point(&self) -> Result<pallas::Point> {
        point_from_bytes(&self.to_bytes())
    }

    /// The x-coordinate of `ak`, an input to the ivk derivation.
    ///
    /// # Errors
    /// Cannot fail for a key built by this type.
    pub fn x(&self) -> Result<pallas::Base> {
        self.to_point().map(|p| extract_x(&p))
    }
}

/// `nk`: the key that makes nullifiers unlinkable to note commitments.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct NullifierKey(SecretBase);

impl NullifierKey {
    /// Derives `nk` from the spending key.
    pub fn derive(sk: &SpendingKey) -> Self {
        Self(SecretBase::new(wide_to_base(&sk.expand(NK_TAG))))
    }

    /// The inner field element, for nullifier derivation.
    pub fn expose(&self) -> pallas::Base {
        self.0.expose()
    }

    /// The canonical field encoding.
    pub fn to_bytes(&self) -> Encoded {
        base_to_bytes(&self.0.expose())
    }

    /// Parses the canonical field encoding.
    ///
    /// # Errors
    /// Fails on a non-canonical encoding.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        Ok(Self(SecretBase::new(base_from_bytes(bytes)?)))
    }
}

/// `rivk`: randomness for the ivk commitment.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct CommitIvkRandomness(SecretBase);

impl CommitIvkRandomness {
    /// Derives `rivk` from the spending key.
    pub fn derive(sk: &SpendingKey) -> Self {
        Self(SecretBase::new(wide_to_base(&sk.expand(RIVK_TAG))))
    }

    /// The inner field element, for the circuit witness.
    pub fn expose(&self) -> pallas::Base {
        self.0.expose()
    }

    /// The canonical field encoding.
    pub fn to_bytes(&self) -> Encoded {
        base_to_bytes(&self.0.expose())
    }

    /// Parses the canonical field encoding.
    ///
    /// # Errors
    /// Fails on a non-canonical encoding.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        Ok(Self(SecretBase::new(base_from_bytes(bytes)?)))
    }
}

/// Byte length of a serialized full viewing key: `ak || nk || rivk`.
pub const FULL_VIEWING_KEY_LEN: usize = 3 * ENCODED_LEN;

/// The full viewing key: sees incoming and outgoing notes, cannot spend.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct FullViewingKey {
    #[zeroize(skip)]
    ak: SpendValidatingKey,
    nk: NullifierKey,
    rivk: CommitIvkRandomness,
}

impl FullViewingKey {
    /// Derives the full viewing key from the spending key.
    ///
    /// # Errors
    /// Propagates [`Error::DegenerateKey`] from `ask` derivation.
    pub fn derive(sk: &SpendingKey) -> Result<Self> {
        Ok(Self {
            ak: SpendAuthorizingKey::derive(sk)?.validating_key(),
            nk: NullifierKey::derive(sk),
            rivk: CommitIvkRandomness::derive(sk),
        })
    }

    /// Assembles a key from its parts, as parsed from an export.
    pub fn from_parts(ak: SpendValidatingKey, nk: NullifierKey, rivk: CommitIvkRandomness) -> Self {
        Self { ak, nk, rivk }
    }

    /// The canonical encoding `ak || nk || rivk`.
    pub fn to_bytes(&self) -> [u8; FULL_VIEWING_KEY_LEN] {
        let mut out = [0u8; FULL_VIEWING_KEY_LEN];
        let [rivk, ak, nk] = self.viewing_key_material();
        for (slot, part) in out.chunks_exact_mut(ENCODED_LEN).zip([ak, nk, rivk]) {
            slot.copy_from_slice(&part);
        }
        out
    }

    /// Parses the canonical encoding.
    ///
    /// # Errors
    /// Fails if any part is not a canonical key or field element.
    pub fn from_bytes(bytes: &[u8; FULL_VIEWING_KEY_LEN]) -> Result<Self> {
        let mut parts = bytes.chunks_exact(ENCODED_LEN).map(|chunk| {
            let mut part = [0u8; ENCODED_LEN];
            part.copy_from_slice(chunk);
            part
        });
        let (Some(ak), Some(nk), Some(rivk)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(Error::InvalidDerivation("full viewing key length"));
        };
        Ok(Self::from_parts(
            SpendValidatingKey::from_bytes(&ak)?,
            NullifierKey::from_bytes(&nk)?,
            CommitIvkRandomness::from_bytes(&rivk)?,
        ))
    }

    /// The spend validating key.
    pub fn ak(&self) -> &SpendValidatingKey {
        &self.ak
    }

    /// The nullifier key.
    pub fn nk(&self) -> &NullifierKey {
        &self.nk
    }

    /// The ivk commitment randomness.
    pub fn rivk(&self) -> &CommitIvkRandomness {
        &self.rivk
    }

    /// Derives the outgoing viewing key, which lets the holder decrypt the
    /// notes this key sent.
    pub fn outgoing_viewing_key(&self) -> OutgoingViewingKey {
        let [rivk, ak, nk] = self.viewing_key_material();
        OutgoingViewingKey(blake2b_short(OVK, &[&rivk, &ak, &nk]))
    }

    /// Derives the diversifier key, which maps indices to diversifiers.
    pub fn diversifier_key(&self) -> DiversifierKey {
        let [rivk, ak, nk] = self.viewing_key_material();
        DiversifierKey::from_bytes(blake2b_short(DK, &[&rivk, &ak, &nk]))
    }

    /// The inputs shared by every key derived from the full viewing key.
    fn viewing_key_material(&self) -> [Encoded; 3] {
        [self.rivk.to_bytes(), self.ak.to_bytes(), self.nk.to_bytes()]
    }

    /// Derives the incoming viewing key, `Poseidon(ak.x, nk, rivk) mod r`,
    /// exactly as the circuit recomputes it.
    ///
    /// # Errors
    /// Returns [`Error::DegenerateKey`] if the derived scalar is zero.
    pub fn incoming_viewing_key(&self) -> Result<IncomingViewingKey> {
        let ivk = base_to_scalar(&poseidon_ivk(
            &self.ak.x()?,
            &self.nk.expose(),
            &self.rivk.expose(),
        ));
        if bool::from(ivk.is_zero()) {
            return Err(Error::DegenerateKey);
        }
        Ok(IncomingViewingKey(SecretScalar::new(ivk)))
    }
}

/// `ivk`: detects and decrypts incoming notes. Never zero.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct IncomingViewingKey(SecretScalar);

impl IncomingViewingKey {
    /// The diversified transmission key `pk_d = [ivk] g_d`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDiversifier`] if `g_d` is the identity.
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn transmission_key(&self, d: &Diversifier) -> Result<DiversifiedTransmissionKey> {
        let g_d = d.base()?;
        Ok(DiversifiedTransmissionKey(g_d * self.0.expose()))
    }

    /// Constant-time equality, for wallets comparing keys.
    pub fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }

    /// The inner scalar, for key agreement.
    pub(crate) fn expose(&self) -> pallas::Scalar {
        self.0.expose()
    }
}

/// `ovk`: decrypts the outgoing ciphertext of notes this key sent.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OutgoingViewingKey([u8; OUTGOING_VIEWING_KEY_LEN]);

impl OutgoingViewingKey {
    /// Wraps raw bytes.
    pub fn from_bytes(bytes: [u8; OUTGOING_VIEWING_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for the outgoing cipher key derivation.
    pub fn as_bytes(&self) -> &[u8; OUTGOING_VIEWING_KEY_LEN] {
        &self.0
    }
}

impl ConstantTimeEq for OutgoingViewingKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl core::fmt::Debug for OutgoingViewingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OutgoingViewingKey(<redacted>)")
    }
}

/// An 11-byte diversifier selecting one of a key's many addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Diversifier([u8; DIVERSIFIER_LEN]);

impl Diversifier {
    /// Wraps raw bytes. Validity is checked by [`Self::base`].
    pub fn from_bytes(bytes: [u8; DIVERSIFIER_LEN]) -> Self {
        Self(bytes)
    }

    /// Samples a random diversifier.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; DIVERSIFIER_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; DIVERSIFIER_LEN] {
        &self.0
    }

    /// The diversified base `g_d`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDiversifier`] if the base is the identity.
    pub fn base(&self) -> Result<pallas::Point> {
        let g_d = diversified_base(&self.0);
        if is_identity(&g_d) {
            return Err(Error::InvalidDiversifier);
        }
        Ok(g_d)
    }
}

/// `pk_d`: the public key part of a payment address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiversifiedTransmissionKey(pallas::Point);

impl DiversifiedTransmissionKey {
    /// Compressed encoding.
    pub fn to_bytes(&self) -> Encoded {
        point_to_bytes(&self.0)
    }

    /// Decodes a compressed point.
    ///
    /// # Errors
    /// Returns [`Error::InvalidPoint`] on a non-canonical encoding and
    /// [`Error::DegenerateKey`] for the identity.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        let point = crate::encoding::point_from_bytes(bytes)?;
        if is_identity(&point) {
            return Err(Error::DegenerateKey);
        }
        Ok(Self(point))
    }

    /// The inner point.
    pub fn as_point(&self) -> &pallas::Point {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use group::Group;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn sk(seed: u64) -> SpendingKey {
        SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    #[test]
    fn spending_key_roundtrips_bytes() {
        let key = sk(1);
        assert!(bool::from(
            SpendingKey::from_bytes(key.to_bytes()).ct_eq(&key)
        ));
    }

    #[test]
    fn spending_key_debug_is_redacted() {
        assert_eq!(format!("{:?}", sk(1)), "SpendingKey(<redacted>)");
    }

    #[test]
    fn derivation_is_deterministic() {
        let (a, b) = (
            FullViewingKey::derive(&sk(2)).unwrap(),
            FullViewingKey::derive(&sk(2)).unwrap(),
        );
        assert_eq!(a.ak(), b.ak());
        assert!(bool::from(
            a.incoming_viewing_key()
                .unwrap()
                .ct_eq(&b.incoming_viewing_key().unwrap())
        ));
    }

    #[test]
    fn different_spending_keys_give_different_keys() {
        let (a, b) = (
            FullViewingKey::derive(&sk(3)).unwrap(),
            FullViewingKey::derive(&sk(4)).unwrap(),
        );
        assert_ne!(a.ak(), b.ak());
        assert_ne!(a.nk().expose(), b.nk().expose());
    }

    #[test]
    fn sub_keys_are_independent() {
        // ask, nk and rivk come from different PRF tags, so their bytes differ.
        let key = sk(5);
        let nk = NullifierKey::derive(&key).to_bytes();
        let rivk = CommitIvkRandomness::derive(&key).to_bytes();
        assert_ne!(nk, rivk);
    }

    #[test]
    fn transmission_keys_differ_per_diversifier() {
        let ivk = FullViewingKey::derive(&sk(6))
            .unwrap()
            .incoming_viewing_key()
            .unwrap();
        let d1 = Diversifier::from_bytes([1; DIVERSIFIER_LEN]);
        let d2 = Diversifier::from_bytes([2; DIVERSIFIER_LEN]);
        assert_ne!(
            ivk.transmission_key(&d1).unwrap(),
            ivk.transmission_key(&d2).unwrap()
        );
    }

    #[test]
    fn transmission_keys_differ_per_ivk() {
        let d = Diversifier::random(&mut ChaCha20Rng::seed_from_u64(7));
        let a = FullViewingKey::derive(&sk(8))
            .unwrap()
            .incoming_viewing_key()
            .unwrap();
        let b = FullViewingKey::derive(&sk(9))
            .unwrap()
            .incoming_viewing_key()
            .unwrap();
        assert_ne!(
            a.transmission_key(&d).unwrap(),
            b.transmission_key(&d).unwrap()
        );
    }

    #[test]
    fn transmission_key_roundtrips_bytes() {
        let ivk = FullViewingKey::derive(&sk(10))
            .unwrap()
            .incoming_viewing_key()
            .unwrap();
        let pk_d = ivk
            .transmission_key(&Diversifier::from_bytes([0; DIVERSIFIER_LEN]))
            .unwrap();
        assert_eq!(
            DiversifiedTransmissionKey::from_bytes(&pk_d.to_bytes()),
            Ok(pk_d)
        );
    }

    #[test]
    fn transmission_key_rejects_identity_and_garbage() {
        let identity = point_to_bytes(&pallas::Point::identity());
        assert_eq!(
            DiversifiedTransmissionKey::from_bytes(&identity),
            Err(Error::DegenerateKey)
        );
        assert_eq!(
            DiversifiedTransmissionKey::from_bytes(&[0xFF; 32]),
            Err(Error::InvalidPoint)
        );
    }

    #[test]
    fn diversifier_base_is_never_identity_for_samples() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        for _ in 0..16 {
            assert!(Diversifier::random(&mut rng).base().is_ok());
        }
    }

    #[test]
    fn validating_key_is_ask_times_spend_auth_base() {
        let ask = SpendAuthorizingKey::derive(&sk(12)).unwrap();
        let ak = ask.validating_key();
        assert_eq!(ak, FullViewingKey::derive(&sk(12)).unwrap().ak().clone());
        let expected = crate::curve::Generator::SpendAuth.point() * ask.expose();
        assert_eq!(ak.to_bytes(), point_to_bytes(&expected));
        assert_eq!(SpendValidatingKey::from_bytes(&ak.to_bytes()), Ok(ak));
    }

    #[test]
    fn validating_key_rejects_garbage() {
        assert_eq!(
            SpendValidatingKey::from_bytes(&[0xFF; 32]),
            Err(Error::InvalidPoint)
        );
    }

    #[test]
    fn signing_key_from_zero_scalar_is_rejected() {
        assert!(signing_key_from_scalar(&pallas::Scalar::ZERO).is_err());
        assert!(signing_key_from_scalar(&pallas::Scalar::ONE).is_ok());
    }

    #[test]
    fn diversifier_key_differs_from_outgoing_viewing_key() {
        let fvk = FullViewingKey::derive(&sk(15)).unwrap();
        assert_ne!(
            fvk.diversifier_key().as_bytes(),
            fvk.outgoing_viewing_key().as_bytes()
        );
    }

    #[test]
    fn outgoing_viewing_key_is_deterministic_and_key_dependent() {
        let a = FullViewingKey::derive(&sk(13))
            .unwrap()
            .outgoing_viewing_key();
        let b = FullViewingKey::derive(&sk(13))
            .unwrap()
            .outgoing_viewing_key();
        let c = FullViewingKey::derive(&sk(14))
            .unwrap()
            .outgoing_viewing_key();
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
        assert_eq!(format!("{a:?}"), "OutgoingViewingKey(<redacted>)");
        assert_eq!(
            OutgoingViewingKey::from_bytes(*a.as_bytes()).as_bytes(),
            a.as_bytes()
        );
    }

    #[test]
    fn full_viewing_keys_round_trip_and_reject_garbage() {
        let sk = SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(9));
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let bytes = fvk.to_bytes();
        let again = FullViewingKey::from_bytes(&bytes).unwrap();
        assert_eq!(again.to_bytes(), bytes);
        let ivk = fvk.incoming_viewing_key().unwrap();
        assert!(bool::from(
            again.incoming_viewing_key().unwrap().ct_eq(&ivk)
        ));
        assert_eq!(
            again.outgoing_viewing_key().as_bytes(),
            fvk.outgoing_viewing_key().as_bytes()
        );
        assert!(FullViewingKey::from_bytes(&[0xff; FULL_VIEWING_KEY_LEN]).is_err());
    }
}
