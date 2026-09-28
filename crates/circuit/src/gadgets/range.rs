//! The 64-bit range check on note values, over the 10-bit lookup table.
//!
//! A value is decomposed into six 10-bit words by the running-sum gadget,
//! leaving a remainder `z_6 = value >> 60`, which is then checked to be
//! below `2^4`. Together that bounds the value below `2^64`.

use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheck;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;

use super::ecc::{Lookup, LOOKUP_BITS};
use super::witness::Cell;
use crate::Fp;

/// Bits every note value must fit in.
pub const VALUE_BITS: usize = 64;
/// Full lookup words in a value.
const FULL_WORDS: usize = VALUE_BITS / LOOKUP_BITS;
/// Bits left over after the full words. Must be a short check, so below
/// the lookup width; the const assertion enforces it at compile time.
const REMAINDER_BITS: usize = VALUE_BITS - FULL_WORDS * LOOKUP_BITS;
const _: () = assert!(REMAINDER_BITS < LOOKUP_BITS);

/// Constrains `value < 2^64`.
///
/// # Errors
/// Propagates layouter errors.
pub fn check_value(
    lookup: &Lookup,
    mut layouter: impl Layouter<Fp>,
    value: &Cell,
) -> Result<(), Error> {
    let running_sum = lookup.copy_check(
        layouter.namespace(|| "60-bit words"),
        value.clone(),
        FULL_WORDS,
        false,
    )?;
    let remainder = running_sum.get(FULL_WORDS).ok_or(Error::Synthesis)?;
    lookup.copy_short_check(
        layouter.namespace(|| "4-bit remainder"),
        remainder.clone(),
        REMAINDER_BITS,
    )
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use halo2_proofs::circuit::{SimpleFloorPlanner, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Fixed};

    use super::*;
    use crate::gadgets::ecc::{EccGadgetConfig, ECC_ADVICES, ECC_LAGRANGE};
    use crate::gadgets::witness::load;

    #[derive(Clone, Debug, Default)]
    struct RangeCircuit {
        value: Value<Fp>,
    }

    #[derive(Clone, Debug)]
    struct RangeConfig {
        ecc: EccGadgetConfig,
        witness: Column<Advice>,
    }

    impl Circuit<Fp> for RangeCircuit {
        type Config = RangeConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let constants = meta.fixed_column();
            meta.enable_constant(constants);
            let advices: [Column<Advice>; ECC_ADVICES] =
                core::array::from_fn(|_| meta.advice_column());
            let lagrange: [Column<Fixed>; ECC_LAGRANGE] =
                core::array::from_fn(|_| meta.fixed_column());
            let witness = meta.advice_column();
            meta.enable_equality(witness);
            RangeConfig {
                ecc: EccGadgetConfig::configure(meta, advices, lagrange),
                witness,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.ecc.load_table(&mut layouter)?;
            let cell = load(
                layouter.namespace(|| "value"),
                config.witness,
                "value",
                self.value,
            )?;
            check_value(config.ecc.lookup(), layouter.namespace(|| "range"), &cell)
        }
    }

    fn satisfied(value: Fp) -> bool {
        let circuit = RangeCircuit {
            value: Value::known(value),
        };
        MockProver::run(11, &circuit, vec![])
            .unwrap()
            .verify()
            .is_ok()
    }

    #[test]
    fn constants_cover_exactly_64_bits() {
        assert_eq!(FULL_WORDS * LOOKUP_BITS + REMAINDER_BITS, VALUE_BITS);
    }

    #[test]
    fn values_below_two_to_the_64_pass() {
        assert!(satisfied(Fp::zero()));
        assert!(satisfied(Fp::from(1)));
        assert!(satisfied(Fp::from(u64::MAX)));
    }

    #[test]
    fn values_at_or_above_two_to_the_64_fail() {
        assert!(!satisfied(Fp::from_u128(1u128 << 64)));
        assert!(!satisfied(Fp::from_u128((1u128 << 64) + 5)));
        assert!(!satisfied(-Fp::one()));
    }
}
