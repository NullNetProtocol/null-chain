//! Elliptic curve wiring over the `halo2_gadgets` ECC chip.
//!
//! Multiplications by the witnessed diversified base use the variable-base
//! gadget. The three fixed generators use precomputed window tables from
//! [`crate::constants`]: `G_spend` and `R` with full-width scalars, `V`
//! with a signed 64-bit scalar.

use group::Curve;
use halo2_gadgets::ecc::chip::{
    BaseFieldElem, CircuitVersion, EccChip, EccConfig, FixedPoint, FullScalar, ShortScalar, H,
};
use halo2_gadgets::ecc::{
    FixedPoint as FixedPointGadget, FixedPointShort, FixedPoints, NonIdentityPoint, Point,
    ScalarFixed, ScalarFixedShort, ScalarVar,
};
use halo2_gadgets::utilities::lookup_range_check::{
    LookupRangeCheck, PallasLookupRangeCheckConfig,
};
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, TableColumn};
use null_crypto::curve::Generator;
use pasta_curves::pallas;

use super::witness::Cell;
use crate::{constants, Fp};

/// Number of advice columns the ECC chip needs.
pub const ECC_ADVICES: usize = 10;
/// Number of fixed columns the ECC chip needs for Lagrange coefficients.
pub const ECC_LAGRANGE: usize = 8;
/// Bits per lookup word; the table has `2^LOOKUP_BITS` rows.
pub const LOOKUP_BITS: usize = 10;

/// The lookup configuration shared with the range layer.
pub type Lookup = PallasLookupRangeCheckConfig;

/// A fixed base multiplied by a full-width scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullBase {
    /// `G_spend`, the spend authorization base.
    SpendAuth,
    /// `R`, the value commitment randomness base.
    ValueCommitRandom,
}

impl FixedPoint<pallas::Affine> for FullBase {
    type FixedScalarKind = FullScalar;

    fn generator(&self) -> pallas::Affine {
        match self {
            Self::SpendAuth => Generator::SpendAuth,
            Self::ValueCommitRandom => Generator::ValueCommitRandom,
        }
        .point()
        .to_affine()
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        match self {
            Self::SpendAuth => constants::SPEND_AUTH_U.to_vec(),
            Self::ValueCommitRandom => constants::VALUE_COMMIT_R_U.to_vec(),
        }
    }

    fn z(&self) -> Vec<u64> {
        match self {
            Self::SpendAuth => constants::SPEND_AUTH_Z.to_vec(),
            Self::ValueCommitRandom => constants::VALUE_COMMIT_R_Z.to_vec(),
        }
    }
}

/// `V`, the value base, multiplied by a signed 64-bit scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueBase;

impl FixedPoint<pallas::Affine> for ValueBase {
    type FixedScalarKind = ShortScalar;

    fn generator(&self) -> pallas::Affine {
        Generator::ValueCommitValue.point().to_affine()
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        constants::VALUE_COMMIT_V_U.to_vec()
    }

    fn z(&self) -> Vec<u64> {
        constants::VALUE_COMMIT_V_Z.to_vec()
    }
}

/// No base is multiplied by a base field element; the chip requires the
/// type, so it is uninhabited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoBaseFieldBase {}

impl FixedPoint<pallas::Affine> for NoBaseFieldBase {
    type FixedScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        match *self {}
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        match *self {}
    }

    fn z(&self) -> Vec<u64> {
        match *self {}
    }
}

/// The circuit's fixed bases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedBases;

impl FixedPoints<pallas::Affine> for FixedBases {
    type FullScalar = FullBase;
    type ShortScalar = ValueBase;
    type Base = NoBaseFieldBase;
}

/// The concrete chip type.
pub type Chip = EccChip<FixedBases, Lookup>;
/// A point that may be the identity.
pub type AnyPoint = Point<pallas::Affine, Chip>;
/// A point constrained not to be the identity.
pub type NonIdPoint = NonIdentityPoint<pallas::Affine, Chip>;

/// ECC chip configuration plus the lookup table column it depends on.
#[derive(Clone, Debug)]
pub struct EccGadgetConfig {
    ecc: EccConfig<FixedBases, Lookup>,
    table_idx: TableColumn,
}

impl EccGadgetConfig {
    /// Configures the chip. The last advice column doubles as the running
    /// sum column of the lookup range check.
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advices: [Column<Advice>; ECC_ADVICES],
        lagrange_coeffs: [Column<Fixed>; ECC_LAGRANGE],
    ) -> Self {
        let table_idx = meta.lookup_table_column();
        let lookup = Lookup::configure(meta, advices[ECC_ADVICES - 1], table_idx);
        let ecc = EccChip::configure(meta, advices, lagrange_coeffs, lookup);
        Self { ecc, table_idx }
    }

    /// The lookup range check configuration, for the range layer.
    pub fn lookup(&self) -> &Lookup {
        &self.ecc.lookup_config
    }

    /// Fills the `2^LOOKUP_BITS` row table. Must be called once per proof.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn load_table(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_table(
            || "lookup range table",
            |mut table| {
                for index in 0..(1u64 << LOOKUP_BITS) {
                    let row = usize::try_from(index).map_err(|_| Error::Synthesis)?;
                    table.assign_cell(
                        || "index",
                        self.table_idx,
                        row,
                        || Value::known(Fp::from(index)),
                    )?;
                }
                Ok(())
            },
        )
    }

    /// A chip instance.
    pub fn chip(&self) -> Chip {
        EccChip::construct(self.ecc.clone(), CircuitVersion::AnchoredBase)
    }

    /// Witnesses a point constrained not to be the identity.
    ///
    /// # Errors
    /// Fails at proving time if the witness is the identity.
    pub fn witness_non_identity(
        &self,
        layouter: impl Layouter<Fp>,
        point: Value<pallas::Point>,
    ) -> Result<NonIdPoint, Error> {
        NonIdentityPoint::new(self.chip(), layouter, point.map(|p| p.to_affine()))
    }

    /// Witnesses a point that may be the identity.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn witness_point(
        &self,
        layouter: impl Layouter<Fp>,
        point: Value<pallas::Point>,
    ) -> Result<AnyPoint, Error> {
        Point::new(self.chip(), layouter, point.map(|p| p.to_affine()))
    }

    /// `[scalar] base` for a fixed base and a full-width scalar, witnessed
    /// by the chip in its window decomposition.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn mul_fixed(
        &self,
        mut layouter: impl Layouter<Fp>,
        base: FullBase,
        scalar: Value<pallas::Scalar>,
    ) -> Result<AnyPoint, Error> {
        let chip = self.chip();
        let scalar = ScalarFixed::new(chip.clone(), layouter.namespace(|| "scalar"), scalar)?;
        FixedPointGadget::from_inner(chip, base)
            .mul(layouter.namespace(|| "mul"), scalar)
            .map(|(point, _)| point)
    }

    /// `[sign * magnitude] V`. The chip constrains `magnitude < 2^64` and
    /// `sign` to be `1` or `-1`.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn mul_value(
        &self,
        mut layouter: impl Layouter<Fp>,
        magnitude: &Cell,
        sign: &Cell,
    ) -> Result<AnyPoint, Error> {
        let chip = self.chip();
        let scalar = ScalarFixedShort::new(
            chip.clone(),
            layouter.namespace(|| "signed value"),
            (magnitude.clone(), sign.clone()),
        )?;
        FixedPointShort::from_inner(chip, ValueBase)
            .mul(layouter.namespace(|| "mul"), scalar)
            .map(|(point, _)| point)
    }

    /// `[scalar] base`, where `scalar` is a base field cell interpreted as
    /// an integer, so the result is `[scalar mod r] base`.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn mul_by_base(
        &self,
        mut layouter: impl Layouter<Fp>,
        scalar: &Cell,
        base: &NonIdPoint,
    ) -> Result<AnyPoint, Error> {
        let scalar = ScalarVar::from_base(self.chip(), layouter.namespace(|| "scalar"), scalar)?;
        base.mul(layouter.namespace(|| "mul"), scalar)
            .map(|(point, _)| point)
    }
}

/// The coordinate cells of a non-identity point.
pub fn coords(point: &NonIdPoint) -> (Cell, Cell) {
    (point.inner().x(), point.inner().y())
}

/// The coordinate cells of any point; the identity is `(0, 0)`.
pub fn any_coords(point: &AnyPoint) -> (Cell, Cell) {
    (point.inner().x(), point.inner().y())
}

/// A point as `Value`s of its affine coordinates, for public inputs.
pub fn affine_values(point: &pallas::Point) -> (Fp, Fp) {
    null_crypto::poseidon::affine_coords(point)
}
