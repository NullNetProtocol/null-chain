//! Poseidon wiring: one configuration function and one hash function so
//! every use in the circuit goes through the same columns and parameters
//! as `null_crypto::poseidon` does outside it.

use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{AssignedCell, Layouter};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};

use crate::Fp;

/// Sponge width, matching `null_crypto::poseidon::WIDTH`.
pub const WIDTH: usize = null_crypto::poseidon::WIDTH;
/// Sponge rate, matching `null_crypto::poseidon::RATE`.
pub const RATE: usize = null_crypto::poseidon::RATE;

/// The Poseidon chip configuration used everywhere in the circuit.
pub type PoseidonConfig = Pow5Config<Fp, WIDTH, RATE>;

/// Configures the Poseidon chip on the given columns.
///
/// `state` columns must have equality enabled by the caller, so hash
/// outputs can be copied into other regions. `rc_b[0]` is enabled as the
/// constant column.
pub fn configure(
    meta: &mut ConstraintSystem<Fp>,
    state: [Column<Advice>; WIDTH],
    partial_sbox: Column<Advice>,
    rc_a: [Column<Fixed>; WIDTH],
    rc_b: [Column<Fixed>; WIDTH],
) -> PoseidonConfig {
    meta.enable_constant(rc_b[0]);
    Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b)
}

/// Hashes `message` in-circuit with the constant-length domain, matching
/// `null_crypto::poseidon::hash` for the same `L`.
///
/// # Errors
/// Propagates layouter errors.
pub fn hash<const L: usize>(
    config: &PoseidonConfig,
    mut layouter: impl Layouter<Fp>,
    message: [AssignedCell<Fp, Fp>; L],
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let chip = Pow5Chip::construct(config.clone());
    let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init(
        chip,
        layouter.namespace(|| "poseidon init"),
    )?;
    hasher.hash(layouter.namespace(|| "poseidon hash"), message)
}
