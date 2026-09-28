//! Poseidon hashing over the Pallas base field, with one typed function
//! per use in the protocol.
//!
//! The constant-length domain of `halo2_poseidon` encodes the input length
//! in the capacity element, so uses with different lengths are domain
//! separated. Every use here has a distinct length; see `docs/circuit.md`.

use ff::Field;
use group::Curve;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;

/// Sponge width.
pub const WIDTH: usize = 3;
/// Sponge rate.
pub const RATE: usize = 2;

/// Input count of the Merkle node hash.
pub const MERKLE_INPUTS: usize = 2;
/// Input count of the incoming viewing key hash.
pub const IVK_INPUTS: usize = 3;
/// Input count of the nullifier hash.
pub const NULLIFIER_INPUTS: usize = 4;
/// Input count of the note commitment hash.
pub const NOTE_COMMIT_INPUTS: usize = 8;

/// Poseidon over `L` base field elements.
pub fn hash<const L: usize>(inputs: [pallas::Base; L]) -> pallas::Base {
    Hash::<pallas::Base, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init().hash(inputs)
}

/// A Merkle tree node from its children.
pub fn merkle_node(left: &pallas::Base, right: &pallas::Base) -> pallas::Base {
    hash([*left, *right])
}

/// The incoming viewing key as a base field element, before reduction
/// modulo the scalar field order.
pub fn ivk(ak_x: &pallas::Base, nk: &pallas::Base, rivk: &pallas::Base) -> pallas::Base {
    hash([*ak_x, *nk, *rivk])
}

/// The nullifier of a note.
pub fn nullifier(
    nk: &pallas::Base,
    rho: &pallas::Base,
    psi: &pallas::Base,
    cm: &pallas::Base,
) -> pallas::Base {
    hash([*nk, *rho, *psi, *cm])
}

/// The commitment to a note.
pub fn note_commitment(
    g_d: &pallas::Point,
    pk_d: &pallas::Point,
    value: u64,
    rho: &pallas::Base,
    psi: &pallas::Base,
    rcm: &pallas::Base,
) -> pallas::Base {
    let (g_d_x, g_d_y) = affine_coords(g_d);
    let (pk_d_x, pk_d_y) = affine_coords(pk_d);
    hash([
        g_d_x,
        g_d_y,
        pk_d_x,
        pk_d_y,
        pallas::Base::from(value),
        *rho,
        *psi,
        *rcm,
    ])
}

/// The affine coordinates of a point. The identity maps to `(0, 0)`, the
/// same representation the circuit's ECC chip uses.
pub fn affine_coords(point: &pallas::Point) -> (pallas::Base, pallas::Base) {
    Option::from(point.to_affine().coordinates()).map_or(
        (pallas::Base::ZERO, pallas::Base::ZERO),
        |c: pasta_curves::arithmetic::Coordinates<_>| (*c.x(), *c.y()),
    )
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use group::Group;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn f(v: u64) -> pallas::Base {
        pallas::Base::from(v)
    }

    #[test]
    fn input_lengths_are_distinct() {
        let mut lengths = [
            MERKLE_INPUTS,
            IVK_INPUTS,
            NULLIFIER_INPUTS,
            NOTE_COMMIT_INPUTS,
        ];
        lengths.sort_unstable();
        lengths.windows(2).for_each(|w| assert_ne!(w[0], w[1]));
    }

    #[test]
    fn hash_is_deterministic_and_length_separated() {
        assert_eq!(hash([f(1), f(2)]), hash([f(1), f(2)]));
        assert_ne!(hash([f(1), f(2)]), hash([f(2), f(1)]));
        // Same leading inputs, padded, must not collide with the shorter use.
        assert_ne!(hash([f(1), f(2)]), hash([f(1), f(2), f(0)]));
    }

    #[test]
    fn merkle_node_is_order_sensitive() {
        assert_ne!(merkle_node(&f(1), &f(2)), merkle_node(&f(2), &f(1)));
    }

    #[test]
    fn affine_coords_distinguish_a_point_from_its_negation() {
        let p = pallas::Point::random(ChaCha20Rng::seed_from_u64(1));
        let (x, y) = affine_coords(&p);
        let (nx, ny) = affine_coords(&-p);
        assert_eq!(x, nx);
        assert_ne!(y, ny);
        assert_eq!(
            affine_coords(&pallas::Point::identity()),
            (pallas::Base::ZERO, pallas::Base::ZERO)
        );
    }

    #[test]
    fn note_commitment_depends_on_every_input() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (g, p) = (
            pallas::Point::random(&mut rng),
            pallas::Point::random(&mut rng),
        );
        let (rho, psi, rcm) = (
            pallas::Base::random(&mut rng),
            pallas::Base::random(&mut rng),
            pallas::Base::random(&mut rng),
        );
        let base = note_commitment(&g, &p, 7, &rho, &psi, &rcm);
        assert_eq!(base, note_commitment(&g, &p, 7, &rho, &psi, &rcm));
        assert_ne!(
            base,
            note_commitment(&-g, &p, 7, &rho, &psi, &rcm),
            "g_d sign"
        );
        assert_ne!(
            base,
            note_commitment(&g, &-p, 7, &rho, &psi, &rcm),
            "pk_d sign"
        );
        assert_ne!(
            base,
            note_commitment(&p, &g, 7, &rho, &psi, &rcm),
            "points swapped"
        );
        assert_ne!(base, note_commitment(&g, &p, 8, &rho, &psi, &rcm), "value");
        assert_ne!(
            base,
            note_commitment(&g, &p, 7, &psi, &rho, &rcm),
            "rho/psi swapped"
        );
        assert_ne!(base, note_commitment(&g, &p, 7, &rho, &psi, &rho), "rcm");
    }

    #[test]
    fn nullifier_and_ivk_depend_on_every_input() {
        let base_nf = nullifier(&f(1), &f(2), &f(3), &f(4));
        assert_ne!(base_nf, nullifier(&f(9), &f(2), &f(3), &f(4)));
        assert_ne!(base_nf, nullifier(&f(1), &f(2), &f(4), &f(3)));
        let base_ivk = ivk(&f(1), &f(2), &f(3));
        assert_ne!(base_ivk, ivk(&f(1), &f(3), &f(2)));
        assert_ne!(base_ivk, ivk(&f(2), &f(2), &f(3)));
    }
}
