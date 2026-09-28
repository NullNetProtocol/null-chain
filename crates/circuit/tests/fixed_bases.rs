//! The committed window tables must match the generators.

use group::Curve;
use halo2_gadgets::ecc::chip::constants::{test_lagrange_coeffs, test_zs_and_us};
use halo2_gadgets::ecc::chip::{FixedPoint, FixedScalarKind, FullScalar, ShortScalar};
use null_crypto::curve::Generator;

use null_circuit::gadgets::ecc::{FullBase, ValueBase};

#[test]
fn spend_auth_tables_match_the_generator() {
    let base = Generator::SpendAuth.point().to_affine();
    assert_eq!(FullBase::SpendAuth.generator(), base);
    test_zs_and_us(
        base,
        &FullBase::SpendAuth.z(),
        &FullBase::SpendAuth.u(),
        FullScalar::NUM_WINDOWS,
    );
    test_lagrange_coeffs(base, FullScalar::NUM_WINDOWS);
}

#[test]
fn value_commit_r_tables_match_the_generator() {
    let base = Generator::ValueCommitRandom.point().to_affine();
    assert_eq!(FullBase::ValueCommitRandom.generator(), base);
    test_zs_and_us(
        base,
        &FullBase::ValueCommitRandom.z(),
        &FullBase::ValueCommitRandom.u(),
        FullScalar::NUM_WINDOWS,
    );
    test_lagrange_coeffs(base, FullScalar::NUM_WINDOWS);
}

#[test]
fn value_commit_v_tables_match_the_generator() {
    let base = Generator::ValueCommitValue.point().to_affine();
    assert_eq!(ValueBase.generator(), base);
    test_zs_and_us(
        base,
        &ValueBase.z(),
        &ValueBase.u(),
        ShortScalar::NUM_WINDOWS,
    );
    test_lagrange_coeffs(base, ShortScalar::NUM_WINDOWS);
}
