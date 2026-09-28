//! Value commitments and note commitments.
//!
//! Value commitments are Pedersen commitments over the generators in
//! [`crate::curve::Generator`]; they are additively homomorphic, which is
//! what lets a verifier check that inputs balance outputs without seeing
//! any amount. Note commitments are Poseidon hashes with a random trapdoor,
//! which the circuit can recompute cheaply.

use core::ops::{Add, Neg, Sub};

use ff::Field;
use group::Group;
use pasta_curves::pallas;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::curve::{pedersen, Generator};
use crate::encoding::{base_from_bytes, base_to_bytes, point_from_bytes, point_to_bytes, Encoded};
use crate::poseidon::note_commitment;
use crate::secret::{SecretBase, SecretScalar};
use crate::Result;

/// `rcv`: the blinding factor of a value commitment.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ValueCommitTrapdoor(SecretScalar);

impl ValueCommitTrapdoor {
    /// Samples a fresh trapdoor.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::from_scalar(pallas::Scalar::random(rng))
    }

    /// Wraps a scalar.
    pub fn from_scalar(scalar: pallas::Scalar) -> Self {
        Self(SecretScalar::new(scalar))
    }

    /// The zero trapdoor, which makes a commitment non-hiding.
    pub fn zero() -> Self {
        Self::from_scalar(pallas::Scalar::ZERO)
    }

    /// The inner scalar, for signing the binding signature.
    pub fn expose(&self) -> pallas::Scalar {
        self.0.expose()
    }

    /// Sums trapdoors, matching the sum of their commitments.
    #[allow(clippy::arithmetic_side_effects)] // field arithmetic is modular
    pub fn sum<'a>(trapdoors: impl IntoIterator<Item = &'a Self>) -> Self {
        Self::from_scalar(
            trapdoors
                .into_iter()
                .fold(pallas::Scalar::ZERO, |acc, t| acc + t.expose()),
        )
    }
}

/// `cv`: a hiding commitment to a signed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueCommitment(pallas::Point);

impl ValueCommitment {
    /// The identity, the neutral element for summing commitments.
    pub fn identity() -> Self {
        Self(pallas::Point::identity())
    }

    /// Commits to `value` with blinding `rcv`.
    ///
    /// Negative values are allowed because an action commits to the net
    /// value `v_in - v_out`.
    pub fn commit(value: i64, rcv: &ValueCommitTrapdoor) -> Self {
        Self(pedersen(
            &signed_to_scalar(value),
            &rcv.expose(),
            Generator::ValueCommitValue,
            Generator::ValueCommitRandom,
        ))
    }

    /// Sums commitments, matching [`ValueCommitTrapdoor::sum`].
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn sum<'a>(commitments: impl IntoIterator<Item = &'a Self>) -> Self {
        commitments
            .into_iter()
            .fold(Self::identity(), |acc, cv| acc + *cv)
    }

    /// `self - other`, by reference.
    #[must_use]
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn minus(&self, other: &Self) -> Self {
        *self - *other
    }

    /// Compressed encoding.
    pub fn to_bytes(&self) -> Encoded {
        point_to_bytes(&self.0)
    }

    /// Decodes a compressed point.
    ///
    /// # Errors
    /// Returns [`crate::Error::InvalidPoint`] on a non-canonical encoding.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        point_from_bytes(bytes).map(Self)
    }

    /// The inner point.
    pub fn as_point(&self) -> &pallas::Point {
        &self.0
    }
}

#[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
impl Add for ValueCommitment {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

#[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
impl Sub for ValueCommitment {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

#[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
impl Neg for ValueCommitment {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

/// Maps a signed 64-bit integer to a scalar, so that `-v` maps to `-[v]`.
#[allow(clippy::arithmetic_side_effects)] // field negation is modular
fn signed_to_scalar(value: i64) -> pallas::Scalar {
    let magnitude = pallas::Scalar::from(value.unsigned_abs());
    if value < 0 {
        -magnitude
    } else {
        magnitude
    }
}

/// `rcm`: the blinding factor of a note commitment.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct NoteCommitTrapdoor(SecretBase);

impl NoteCommitTrapdoor {
    /// Wraps a base field element.
    pub fn from_base(value: pallas::Base) -> Self {
        Self(SecretBase::new(value))
    }

    /// Samples a fresh trapdoor.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::from_base(pallas::Base::random(rng))
    }

    /// The inner field element, for the circuit witness.
    pub fn expose(&self) -> pallas::Base {
        self.0.expose()
    }
}

/// The public fields of a note, borrowed for commitment.
#[derive(Clone, Copy, Debug)]
pub struct NoteCommitInputs<'a> {
    /// The diversified base of the recipient.
    pub g_d: &'a pallas::Point,
    /// The transmission key of the recipient.
    pub pk_d: &'a pallas::Point,
    /// The value in smallest units.
    pub value: u64,
    /// The uniqueness nonce.
    pub rho: &'a pallas::Base,
    /// The nullifier nonce.
    pub psi: &'a pallas::Base,
}

/// `cm`: a hiding, binding Poseidon commitment to the contents of a note.
///
/// It is a base field element, so it is also directly the tree leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteCommitment(pallas::Base);

impl NoteCommitment {
    /// Commits to `inputs` with blinding `rcm`.
    pub fn commit(inputs: &NoteCommitInputs<'_>, rcm: &NoteCommitTrapdoor) -> Self {
        Self(note_commitment(
            inputs.g_d,
            inputs.pk_d,
            inputs.value,
            inputs.rho,
            inputs.psi,
            &rcm.expose(),
        ))
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
    /// Returns [`crate::Error::InvalidBase`] on a non-canonical encoding.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        base_from_bytes(bytes).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    #[test]
    fn value_commitments_are_additively_homomorphic() {
        let mut rng = rng(1);
        let (r1, r2) = (
            ValueCommitTrapdoor::random(&mut rng),
            ValueCommitTrapdoor::random(&mut rng),
        );
        let sum = ValueCommitment::commit(5, &r1) + ValueCommitment::commit(7, &r2);
        let r_sum = ValueCommitTrapdoor::sum([&r1, &r2]);
        assert_eq!(sum, ValueCommitment::commit(12, &r_sum));
    }

    #[test]
    fn value_commitments_balance_to_zero_trapdoor_commitment() {
        // cv(in) - cv(out) with equal values commits to zero under r_in - r_out.
        let mut rng = rng(2);
        let (r_in, r_out) = (
            ValueCommitTrapdoor::random(&mut rng),
            ValueCommitTrapdoor::random(&mut rng),
        );
        let net = ValueCommitment::commit(42, &r_in) - ValueCommitment::commit(42, &r_out);
        let expected_r = ValueCommitTrapdoor::from_scalar(r_in.expose() - r_out.expose());
        assert_eq!(net, ValueCommitment::commit(0, &expected_r));
    }

    #[test]
    fn negative_values_commit_to_negated_points() {
        let r = ValueCommitTrapdoor::zero();
        assert_eq!(
            ValueCommitment::commit(-3, &r),
            -ValueCommitment::commit(3, &r)
        );
    }

    #[test]
    fn signed_to_scalar_handles_extremes() {
        assert_eq!(signed_to_scalar(0), pallas::Scalar::ZERO);
        assert_eq!(
            signed_to_scalar(i64::MAX),
            pallas::Scalar::from(i64::MAX.unsigned_abs())
        );
        assert_eq!(
            signed_to_scalar(i64::MIN),
            -pallas::Scalar::from(i64::MIN.unsigned_abs())
        );
    }

    #[test]
    fn value_commitment_is_hiding() {
        let mut rng = rng(3);
        let (r1, r2) = (
            ValueCommitTrapdoor::random(&mut rng),
            ValueCommitTrapdoor::random(&mut rng),
        );
        assert_ne!(
            ValueCommitment::commit(1, &r1),
            ValueCommitment::commit(1, &r2)
        );
    }

    #[test]
    fn value_commitment_is_binding_to_value() {
        let r = ValueCommitTrapdoor::random(&mut rng(4));
        assert_ne!(
            ValueCommitment::commit(1, &r),
            ValueCommitment::commit(2, &r)
        );
    }

    #[test]
    fn value_commitment_roundtrips_bytes() {
        let cv = ValueCommitment::commit(9, &ValueCommitTrapdoor::random(&mut rng(5)));
        assert_eq!(ValueCommitment::from_bytes(&cv.to_bytes()), Ok(cv));
    }

    #[test]
    fn identity_is_neutral_for_addition() {
        let cv = ValueCommitment::commit(3, &ValueCommitTrapdoor::random(&mut rng(8)));
        assert_eq!(ValueCommitment::identity() + cv, cv);
        assert_eq!(ValueCommitment::sum([&cv, &cv]), cv + cv);
        assert_eq!(cv.minus(&cv), ValueCommitment::identity());
    }

    fn inputs<'a>(
        g: &'a pallas::Point,
        p: &'a pallas::Point,
        value: u64,
        rho: &'a pallas::Base,
    ) -> NoteCommitInputs<'a> {
        NoteCommitInputs {
            g_d: g,
            pk_d: p,
            value,
            rho,
            psi: rho,
        }
    }

    #[test]
    fn note_commitment_is_hiding_and_binding() {
        let mut rng = rng(6);
        let (g, p) = (
            pallas::Point::random(&mut rng),
            pallas::Point::random(&mut rng),
        );
        let rho = pallas::Base::random(&mut rng);
        let (r1, r2) = (
            NoteCommitTrapdoor::random(&mut rng),
            NoteCommitTrapdoor::random(&mut rng),
        );
        let base = NoteCommitment::commit(&inputs(&g, &p, 1, &rho), &r1);
        assert_eq!(base, NoteCommitment::commit(&inputs(&g, &p, 1, &rho), &r1));
        assert_ne!(
            base,
            NoteCommitment::commit(&inputs(&g, &p, 1, &rho), &r2),
            "same fields, other rcm"
        );
        assert_ne!(
            base,
            NoteCommitment::commit(&inputs(&g, &p, 2, &rho), &r1),
            "other value, same rcm"
        );
        assert_ne!(
            base,
            NoteCommitment::commit(&inputs(&p, &g, 1, &rho), &r1),
            "keys swapped"
        );
    }

    #[test]
    fn note_commitment_roundtrips_bytes() {
        let mut rng = rng(7);
        let (g, p) = (
            pallas::Point::random(&mut rng),
            pallas::Point::random(&mut rng),
        );
        let rho = pallas::Base::random(&mut rng);
        let cm = NoteCommitment::commit(
            &inputs(&g, &p, 3, &rho),
            &NoteCommitTrapdoor::random(&mut rng),
        );
        assert_eq!(NoteCommitment::from_bytes(&cm.to_bytes()), Ok(cm));
        assert!(NoteCommitment::from_bytes(&[0xFF; 32]).is_err());
        assert_eq!(
            NoteCommitTrapdoor::from_base(pallas::Base::ONE).expose(),
            pallas::Base::ONE
        );
    }
}
