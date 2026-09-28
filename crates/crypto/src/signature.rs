//! `RedPallas` signatures, wrapping the audited `reddsa` crate.
//!
//! Two signature types exist:
//!
//! - **Spend authorization.** Each action is signed with a randomized
//!   version of `ask`. The verifier sees only the randomized key `rk`, which
//!   is unlinkable to `ak` without the randomizer.
//! - **Binding.** One per transaction, proving that the sum of value
//!   commitments equals a commitment to the public net value, so amounts
//!   balance without being revealed.
//!
//! Signatures are stored as raw 64-byte arrays so they can be encoded and
//! compared; they are converted to `reddsa` types only for verification.

use core::marker::PhantomData;

use ff::Field;
use pasta_curves::pallas;
use rand_core::{CryptoRng, RngCore};
use reddsa::batch;
use reddsa::orchard::{Binding, SpendAuth};
use reddsa::{SigType, Signature, SigningKey, VerificationKey, VerificationKeyBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::commitment::{ValueCommitTrapdoor, ValueCommitment};
use crate::encoding::Encoded;
use crate::keys::{signing_key_from_scalar, SpendAuthorizingKey, SpendValidatingKey};
use crate::secret::SecretScalar;
use crate::{Error, Result};

/// Byte length of a signature.
pub const SIGNATURE_LEN: usize = 64;

/// A signature of type `T`, kept as bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes<T: SigType> {
    bytes: [u8; SIGNATURE_LEN],
    kind: PhantomData<T>,
}

impl<T: SigType> SignatureBytes<T> {
    /// Wraps raw bytes. Validity is only known after verification.
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self {
            bytes,
            kind: PhantomData,
        }
    }

    /// The raw bytes.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.bytes
    }

    fn inner(&self) -> Signature<T> {
        Signature::from(self.bytes)
    }
}

impl<T: SigType> From<Signature<T>> for SignatureBytes<T> {
    fn from(signature: Signature<T>) -> Self {
        Self::from_bytes(signature.into())
    }
}

impl<T: SigType> core::fmt::Debug for SignatureBytes<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SignatureBytes").field(&self.bytes).finish()
    }
}

/// A spend authorization signature over one action.
pub type SpendAuthSignature = SignatureBytes<SpendAuth>;
/// A binding signature over one transaction.
pub type BindingSignature = SignatureBytes<Binding>;

/// `alpha`: the per-action randomizer that hides `ak` behind `rk`.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SpendAuthRandomizer(SecretScalar);

impl SpendAuthRandomizer {
    /// Samples a fresh randomizer.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::from_scalar(pallas::Scalar::random(rng))
    }

    /// Wraps a scalar, for provers that already hold the witness.
    pub fn from_scalar(scalar: pallas::Scalar) -> Self {
        Self(SecretScalar::new(scalar))
    }

    /// The inner scalar, for the circuit witness.
    pub fn expose(&self) -> pallas::Scalar {
        self.0.expose()
    }
}

/// `rsk = ask + alpha`: signs one action.
pub struct RandomizedSigningKey(SigningKey<SpendAuth>);

impl RandomizedSigningKey {
    /// Randomizes `ask` with `alpha`.
    ///
    /// # Errors
    /// Returns [`Error::DegenerateKey`] if `ask + alpha` is zero.
    #[allow(clippy::arithmetic_side_effects)] // field arithmetic is modular
    pub fn new(ask: &SpendAuthorizingKey, alpha: &SpendAuthRandomizer) -> Result<Self> {
        signing_key_from_scalar(&(ask.expose() + alpha.expose())).map(Self)
    }

    /// Signs `message`.
    pub fn sign(&self, rng: &mut (impl RngCore + CryptoRng), message: &[u8]) -> SpendAuthSignature {
        self.0.sign(rng, message).into()
    }

    /// The matching randomized verification key `rk`.
    pub fn verification_key(&self) -> RandomizedVerificationKey {
        RandomizedVerificationKey(VerificationKey::from(&self.0))
    }
}

impl core::fmt::Debug for RandomizedSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RandomizedSigningKey(<redacted>)")
    }
}

/// `rk = ak + [alpha] G_spend`: the public key that appears in an action.
#[derive(Clone, Debug, PartialEq)]
pub struct RandomizedVerificationKey(VerificationKey<SpendAuth>);

impl Eq for RandomizedVerificationKey {}

impl RandomizedVerificationKey {
    /// Randomizes `ak` with `alpha`. Matches [`RandomizedSigningKey::new`].
    pub fn new(ak: &SpendValidatingKey, alpha: &SpendAuthRandomizer) -> Self {
        Self(ak.inner().randomize(&alpha.expose()))
    }

    /// Verifies a single signature.
    ///
    /// # Errors
    /// Returns [`Error::InvalidSignature`] if the signature is wrong.
    pub fn verify(&self, message: &[u8], signature: &SpendAuthSignature) -> Result<()> {
        verify_single(&self.0, message, signature)
    }

    /// Compressed encoding.
    pub fn to_bytes(&self) -> Encoded {
        self.0.into()
    }

    /// Decodes a compressed point.
    ///
    /// # Errors
    /// Returns [`Error::InvalidPoint`] on a non-canonical encoding.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        verification_key_from_bytes(bytes).map(Self)
    }

    /// The point `rk`, a public input of the circuit.
    ///
    /// # Errors
    /// Cannot fail for a key built by this type.
    pub fn to_point(&self) -> Result<pallas::Point> {
        crate::encoding::point_from_bytes(&self.to_bytes())
    }
}

/// `bsk = sum(rcv)`: signs the binding signature of a transaction.
pub struct BindingSigningKey(SigningKey<Binding>);

impl BindingSigningKey {
    /// Sums the trapdoors of every value commitment in the transaction.
    ///
    /// # Errors
    /// Returns [`Error::DegenerateKey`] if the sum is zero.
    pub fn from_trapdoors<'a>(
        trapdoors: impl IntoIterator<Item = &'a ValueCommitTrapdoor>,
    ) -> Result<Self> {
        let sum = ValueCommitTrapdoor::sum(trapdoors).expose();
        if bool::from(sum.is_zero()) {
            return Err(Error::DegenerateKey);
        }
        SigningKey::try_from(sum.to_repr())
            .map(Self)
            .map_err(|_| Error::DegenerateKey)
    }

    /// Signs `message`, normally the transaction sighash.
    pub fn sign(&self, rng: &mut (impl RngCore + CryptoRng), message: &[u8]) -> BindingSignature {
        self.0.sign(rng, message).into()
    }

    /// The matching verification key, for tests and self-checks.
    pub fn verification_key(&self) -> BindingVerificationKey {
        BindingVerificationKey(VerificationKey::from(&self.0))
    }
}

impl core::fmt::Debug for BindingSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BindingSigningKey(<redacted>)")
    }
}

use ff::PrimeField;

/// `bvk = sum(cv) - ValueCommit_0(net_value)`: derived by the verifier from
/// public data, valid only if the hidden values really sum to `net_value`.
#[derive(Clone, Debug, PartialEq)]
pub struct BindingVerificationKey(VerificationKey<Binding>);

impl Eq for BindingVerificationKey {}

impl BindingVerificationKey {
    /// Derives `bvk` from the value commitments and the public net value,
    /// which for a normal transaction is the fee.
    ///
    /// # Errors
    /// Returns [`Error::DegenerateKey`] if the resulting point is not a
    /// valid verification key.
    pub fn from_commitments<'a>(
        commitments: impl IntoIterator<Item = &'a ValueCommitment>,
        net_value: i64,
    ) -> Result<Self> {
        let sum = ValueCommitment::sum(commitments);
        let public = ValueCommitment::commit(net_value, &ValueCommitTrapdoor::zero());
        let bvk = sum.minus(&public);
        verification_key_from_bytes(&bvk.to_bytes())
            .map(Self)
            .map_err(|_| Error::DegenerateKey)
    }

    /// Verifies a single binding signature.
    ///
    /// # Errors
    /// Returns [`Error::InvalidSignature`] if the signature is wrong.
    pub fn verify(&self, message: &[u8], signature: &BindingSignature) -> Result<()> {
        verify_single(&self.0, message, signature)
    }

    /// Compressed encoding.
    pub fn to_bytes(&self) -> Encoded {
        self.0.into()
    }
}

fn verification_key_from_bytes<T: SigType>(bytes: &Encoded) -> Result<VerificationKey<T>> {
    VerificationKey::try_from(*bytes).map_err(|_| Error::InvalidPoint)
}

fn verify_single<T: SigType>(
    key: &VerificationKey<T>,
    message: &[u8],
    signature: &SignatureBytes<T>,
) -> Result<()> {
    key.verify(message, &signature.inner())
        .map_err(|_| Error::InvalidSignature)
}

/// Verifies many spend authorization and binding signatures at once, which
/// is several times faster than one at a time. Use per block.
#[derive(Default)]
pub struct BatchVerifier {
    inner: batch::Verifier<SpendAuth, Binding>,
    count: usize,
}

impl BatchVerifier {
    /// An empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of queued signatures.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Queues a spend authorization signature.
    pub fn queue_spend_auth(
        &mut self,
        key: &RandomizedVerificationKey,
        signature: &SpendAuthSignature,
        message: &[u8],
    ) {
        let bytes = VerificationKeyBytes::from(key.to_bytes());
        self.inner.queue(batch::Item::from_spendauth(
            bytes,
            signature.inner(),
            &message,
        ));
        self.count = self.count.saturating_add(1);
    }

    /// Queues a binding signature.
    pub fn queue_binding(
        &mut self,
        key: &BindingVerificationKey,
        signature: &BindingSignature,
        message: &[u8],
    ) {
        let bytes = VerificationKeyBytes::from(key.to_bytes());
        self.inner.queue(batch::Item::from_binding(
            bytes,
            signature.inner(),
            &message,
        ));
        self.count = self.count.saturating_add(1);
    }

    /// Verifies everything queued.
    ///
    /// # Errors
    /// Returns [`Error::InvalidSignature`] if any queued signature is wrong.
    /// The batch does not say which one; fall back to single verification
    /// to find it.
    pub fn verify(self, rng: &mut (impl RngCore + CryptoRng)) -> Result<()> {
        self.inner.verify(rng).map_err(|_| Error::InvalidSignature)
    }
}

impl core::fmt::Debug for BatchVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BatchVerifier")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::keys::{FullViewingKey, SpendingKey};

    struct Signer {
        rng: ChaCha20Rng,
        ask: SpendAuthorizingKey,
        ak: SpendValidatingKey,
    }

    fn signer(seed: u64) -> Signer {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let sk = SpendingKey::random(&mut rng);
        let ask = SpendAuthorizingKey::derive(&sk).unwrap();
        let ak = FullViewingKey::derive(&sk).unwrap().ak().clone();
        Signer { rng, ask, ak }
    }

    #[test]
    fn randomized_keys_agree_between_signer_and_verifier() {
        let mut s = signer(1);
        let alpha = SpendAuthRandomizer::random(&mut s.rng);
        let rsk = RandomizedSigningKey::new(&s.ask, &alpha).unwrap();
        assert_eq!(
            rsk.verification_key(),
            RandomizedVerificationKey::new(&s.ak, &alpha)
        );
    }

    #[test]
    fn randomized_key_hides_ak() {
        let mut s = signer(2);
        let alpha = SpendAuthRandomizer::random(&mut s.rng);
        let rk = RandomizedVerificationKey::new(&s.ak, &alpha);
        assert_ne!(rk.to_bytes(), s.ak.to_bytes());
        assert_eq!(
            crate::encoding::point_to_bytes(&rk.to_point().unwrap()),
            rk.to_bytes()
        );
        assert_eq!(
            RandomizedVerificationKey::from_bytes(&rk.to_bytes()),
            Ok(rk)
        );
    }

    #[test]
    fn spend_auth_signature_verifies_and_rejects_tampering() {
        let mut s = signer(3);
        let alpha = SpendAuthRandomizer::random(&mut s.rng);
        let rsk = RandomizedSigningKey::new(&s.ask, &alpha).unwrap();
        let rk = rsk.verification_key();
        let sig = rsk.sign(&mut s.rng, b"sighash");
        assert_eq!(rk.verify(b"sighash", &sig), Ok(()));
        assert_eq!(rk.verify(b"other", &sig), Err(Error::InvalidSignature));

        let mut bytes = sig.to_bytes();
        bytes[0] ^= 1;
        let bad = SpendAuthSignature::from_bytes(bytes);
        assert_eq!(rk.verify(b"sighash", &bad), Err(Error::InvalidSignature));

        let other_rk = RandomizedVerificationKey::new(&signer(4).ak, &alpha);
        assert_eq!(
            other_rk.verify(b"sighash", &sig),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn binding_signature_verifies_only_for_the_true_net_value() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        // Two actions: spend 10 create 3, spend 0 create 6; fee is 1.
        let trapdoors: Vec<_> = (0..2)
            .map(|_| ValueCommitTrapdoor::random(&mut rng))
            .collect();
        let cvs = [
            ValueCommitment::commit(7, &trapdoors[0]),
            ValueCommitment::commit(-6, &trapdoors[1]),
        ];
        let bsk = BindingSigningKey::from_trapdoors(&trapdoors).unwrap();
        let sig = bsk.sign(&mut rng, b"sighash");

        let bvk = BindingVerificationKey::from_commitments(&cvs, 1).unwrap();
        assert_eq!(bvk, bsk.verification_key());
        assert_eq!(bvk.verify(b"sighash", &sig), Ok(()));

        let wrong_fee = BindingVerificationKey::from_commitments(&cvs, 2).unwrap();
        assert_eq!(
            wrong_fee.verify(b"sighash", &sig),
            Err(Error::InvalidSignature)
        );
        assert_eq!(bvk.verify(b"other", &sig), Err(Error::InvalidSignature));
    }

    #[test]
    fn batch_verifies_mixed_signatures_and_rejects_one_bad() {
        let mut s = signer(6);
        let alpha = SpendAuthRandomizer::random(&mut s.rng);
        let rsk = RandomizedSigningKey::new(&s.ask, &alpha).unwrap();
        let rk = rsk.verification_key();
        let spend_sig = rsk.sign(&mut s.rng, b"a");

        let rcv = ValueCommitTrapdoor::random(&mut s.rng);
        let cv = ValueCommitment::commit(0, &rcv);
        let bsk = BindingSigningKey::from_trapdoors([&rcv]).unwrap();
        let bvk = BindingVerificationKey::from_commitments([&cv], 0).unwrap();
        let bind_sig = bsk.sign(&mut s.rng, b"b");

        let mut good = BatchVerifier::new();
        assert!(good.is_empty());
        good.queue_spend_auth(&rk, &spend_sig, b"a");
        good.queue_binding(&bvk, &bind_sig, b"b");
        assert_eq!(good.len(), 2);
        assert_eq!(good.verify(&mut s.rng), Ok(()));

        let mut bad = BatchVerifier::new();
        bad.queue_spend_auth(&rk, &spend_sig, b"a");
        bad.queue_binding(&bvk, &bind_sig, b"tampered");
        assert_eq!(bad.verify(&mut s.rng), Err(Error::InvalidSignature));
    }

    #[test]
    fn binding_key_from_zero_trapdoor_sum_is_rejected() {
        let zero = ValueCommitTrapdoor::zero();
        assert!(BindingSigningKey::from_trapdoors([&zero]).is_err());
    }

    #[test]
    fn randomizer_roundtrips_its_scalar() {
        let alpha = SpendAuthRandomizer::from_scalar(pallas::Scalar::from(5u64));
        assert_eq!(alpha.expose(), pallas::Scalar::from(5u64));
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let sig = SpendAuthSignature::from_bytes([7; SIGNATURE_LEN]);
        assert_eq!(SpendAuthSignature::from_bytes(sig.to_bytes()), sig);
        assert!(format!("{sig:?}").starts_with("SignatureBytes"));
    }
}
