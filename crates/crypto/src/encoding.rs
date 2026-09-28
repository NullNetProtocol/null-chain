//! Canonical 32-byte encodings for Pallas field elements and points.
//!
//! Decoding rejects any non-canonical representation. There is exactly one
//! valid byte string for each value.

use ff::PrimeField;
use group::GroupEncoding;
use pasta_curves::pallas;
use subtle::CtOption;

use crate::{Error, Result};

/// Size in bytes of every encoding in this module.
pub const ENCODED_LEN: usize = 32;

/// A 32-byte canonical encoding.
pub type Encoded = [u8; ENCODED_LEN];

/// Converts a `CtOption` into a `Result`, attaching `error` on failure.
///
/// # Errors
/// Returns `error` when the option is `None`.
pub fn ct_option_to_result<T>(option: CtOption<T>, error: Error) -> Result<T> {
    Option::<T>::from(option).ok_or(error)
}

/// Decodes a canonical base field element.
///
/// # Errors
/// Returns [`Error::InvalidBase`] when the bytes are not a canonical element.
pub fn base_from_bytes(bytes: &Encoded) -> Result<pallas::Base> {
    ct_option_to_result(pallas::Base::from_repr(*bytes), Error::InvalidBase)
}

/// Decodes a canonical scalar field element.
///
/// # Errors
/// Returns [`Error::InvalidScalar`] when the bytes are not a canonical element.
pub fn scalar_from_bytes(bytes: &Encoded) -> Result<pallas::Scalar> {
    ct_option_to_result(pallas::Scalar::from_repr(*bytes), Error::InvalidScalar)
}

/// Decodes a canonical compressed point.
///
/// # Errors
/// Returns [`Error::InvalidPoint`] when the bytes are not a canonical point.
pub fn point_from_bytes(bytes: &Encoded) -> Result<pallas::Point> {
    ct_option_to_result(pallas::Point::from_bytes(bytes), Error::InvalidPoint)
}

/// Lowercase hexadecimal of any byte string.
pub fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut out, byte| {
            // Writing to a String cannot fail.
            let _ = write!(out, "{byte:02x}");
            out
        },
    )
}

/// Decodes lowercase or uppercase hexadecimal.
///
/// # Errors
/// Returns [`Error::InvalidBase`]'s sibling [`Error::InvalidHex`] on odd
/// length or a non-hex character.
pub fn from_hex(text: &str) -> Result<Vec<u8>> {
    let digits = text.as_bytes();
    if digits.len() % 2 != 0 {
        return Err(Error::InvalidHex);
    }
    digits
        .chunks(2)
        .map(|pair| {
            let hi = hex_digit(*pair.first().ok_or(Error::InvalidHex)?)?;
            let lo = hex_digit(*pair.get(1).ok_or(Error::InvalidHex)?)?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_digit(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(c.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Ok(c.saturating_sub(b'A').saturating_add(10)),
        _ => Err(Error::InvalidHex),
    }
}

/// Encodes a base field element.
pub fn base_to_bytes(value: &pallas::Base) -> Encoded {
    value.to_repr()
}

/// Encodes a scalar field element.
pub fn scalar_to_bytes(value: &pallas::Scalar) -> Encoded {
    value.to_repr()
}

/// Encodes a point in compressed form.
pub fn point_to_bytes(value: &pallas::Point) -> Encoded {
    value.to_bytes()
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use group::Group;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(1)
    }

    #[test]
    fn base_roundtrips() {
        let value = pallas::Base::random(rng());
        assert_eq!(base_from_bytes(&base_to_bytes(&value)), Ok(value));
    }

    #[test]
    fn scalar_roundtrips() {
        let value = pallas::Scalar::random(rng());
        assert_eq!(scalar_from_bytes(&scalar_to_bytes(&value)), Ok(value));
    }

    #[test]
    fn point_roundtrips() {
        let value = pallas::Point::random(rng());
        assert_eq!(point_from_bytes(&point_to_bytes(&value)), Ok(value));
    }

    #[test]
    fn non_canonical_field_encodings_are_rejected() {
        // All ones is larger than either modulus, so it is not canonical.
        let garbage = [0xFF; ENCODED_LEN];
        assert_eq!(base_from_bytes(&garbage), Err(Error::InvalidBase));
        assert_eq!(scalar_from_bytes(&garbage), Err(Error::InvalidScalar));
    }

    #[test]
    fn non_canonical_point_encodings_are_rejected() {
        let garbage = [0xFF; ENCODED_LEN];
        assert_eq!(point_from_bytes(&garbage), Err(Error::InvalidPoint));
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xab]), "000fab");
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn hex_decodes_both_cases_and_rejects_garbage() {
        assert_eq!(from_hex("000fAB"), Ok(vec![0x00, 0x0f, 0xab]));
        assert_eq!(from_hex(""), Ok(vec![]));
        assert_eq!(from_hex("abc"), Err(Error::InvalidHex));
        assert_eq!(from_hex("zz"), Err(Error::InvalidHex));
        let bytes = [7u8, 200, 33];
        assert_eq!(from_hex(&to_hex(&bytes)), Ok(bytes.to_vec()));
    }

    #[test]
    fn ct_option_maps_none_to_error() {
        let none = CtOption::new(0u8, 0.into());
        assert_eq!(
            ct_option_to_result(none, Error::InvalidBase),
            Err(Error::InvalidBase)
        );
        let some = CtOption::new(5u8, 1.into());
        assert_eq!(ct_option_to_result(some, Error::InvalidBase), Ok(5));
    }
}
