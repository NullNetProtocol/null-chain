//! Helpers for loading witnesses into advice cells.

use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, Error};

use crate::Fp;

/// An assigned base field cell.
pub type Cell = AssignedCell<Fp, Fp>;

/// Assigns `value` to a fresh cell in `column`.
///
/// # Errors
/// Propagates layouter errors.
pub fn load(
    mut layouter: impl Layouter<Fp>,
    column: Column<Advice>,
    name: &'static str,
    value: Value<Fp>,
) -> Result<Cell, Error> {
    layouter.assign_region(
        || name,
        |mut region| region.assign_advice(|| name, column, 0, || value),
    )
}

/// Assigns several values to fresh cells in `column`, one region each.
///
/// # Errors
/// Propagates layouter errors.
pub fn load_many<const N: usize>(
    mut layouter: impl Layouter<Fp>,
    column: Column<Advice>,
    name: &'static str,
    values: [Value<Fp>; N],
) -> Result<[Cell; N], Error> {
    let mut cells = Vec::with_capacity(N);
    for value in values {
        cells.push(load(layouter.namespace(|| name), column, name, value)?);
    }
    cells.try_into().map_err(|_| Error::Synthesis)
}

/// A boolean as a field element.
pub fn bool_to_fp(bit: bool) -> Fp {
    if bit {
        Fp::one()
    } else {
        Fp::zero()
    }
}
