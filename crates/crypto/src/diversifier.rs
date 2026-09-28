//! Diversifier indices and their format-preserving encryption.
//!
//! A wallet numbers its addresses with an 88-bit index. The index is
//! encrypted under the diversifier key with FF1-AES256 to produce the
//! 11-byte diversifier that appears in the address, so addresses look
//! random and unrelated while the wallet can still recover the index from
//! any of its own diversifiers.

use aes::Aes256;
use fpe::ff1::{BinaryNumeralString, FF1};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::{Diversifier, DIVERSIFIER_LEN};
use crate::{Error, Result};

/// Byte length of a diversifier key.
pub const DIVERSIFIER_KEY_LEN: usize = 32;

/// FF1 radix: the index is treated as a binary numeral string.
const FF1_RADIX: u32 = 2;

/// An 88-bit little-endian address index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DiversifierIndex([u8; DIVERSIFIER_LEN]);

impl DiversifierIndex {
    /// Index zero, the wallet's default address.
    pub const ZERO: Self = Self([0u8; DIVERSIFIER_LEN]);

    /// Wraps raw little-endian bytes.
    pub fn from_bytes(bytes: [u8; DIVERSIFIER_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw little-endian bytes.
    pub fn as_bytes(&self) -> &[u8; DIVERSIFIER_LEN] {
        &self.0
    }

    /// The next index.
    ///
    /// # Errors
    /// Returns [`Error::DiversifierIndexOverflow`] at the end of the space.
    pub fn next(&self) -> Result<Self> {
        let mut bytes = self.0;
        for byte in &mut bytes {
            let (sum, carry) = byte.overflowing_add(1);
            *byte = sum;
            if !carry {
                return Ok(Self(bytes));
            }
        }
        Err(Error::DiversifierIndexOverflow)
    }
}

impl From<u64> for DiversifierIndex {
    fn from(value: u64) -> Self {
        let mut bytes = [0u8; DIVERSIFIER_LEN];
        let (head, _) = bytes.split_at_mut(8);
        head.copy_from_slice(&value.to_le_bytes());
        Self(bytes)
    }
}

/// `dk`: the key that encrypts indices into diversifiers.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DiversifierKey([u8; DIVERSIFIER_KEY_LEN]);

impl DiversifierKey {
    /// Wraps raw bytes.
    pub fn from_bytes(bytes: [u8; DIVERSIFIER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; DIVERSIFIER_KEY_LEN] {
        &self.0
    }

    fn cipher(&self) -> Result<FF1<Aes256>> {
        FF1::new(&self.0, FF1_RADIX).map_err(|_| Error::Internal("FF1 radix 2 rejected"))
    }

    /// The diversifier for `index`.
    ///
    /// # Errors
    /// Only on an internal failure of the cipher, which cannot happen for
    /// fixed-size input.
    pub fn diversifier(&self, index: DiversifierIndex) -> Result<Diversifier> {
        let plain = BinaryNumeralString::from_bytes_le(index.as_bytes());
        let cipher = self
            .cipher()?
            .encrypt(&[], &plain)
            .map_err(|_| Error::Internal("FF1 encrypt"))?;
        to_array(&cipher.to_bytes_le()).map(Diversifier::from_bytes)
    }

    /// Recovers the index of one of this key's diversifiers.
    ///
    /// Every 11-byte string decrypts to some index, so this does not prove
    /// ownership; the caller checks the resulting address.
    ///
    /// # Errors
    /// Only on an internal failure of the cipher.
    pub fn index(&self, diversifier: &Diversifier) -> Result<DiversifierIndex> {
        let cipher = BinaryNumeralString::from_bytes_le(diversifier.as_bytes());
        let plain = self
            .cipher()?
            .decrypt(&[], &cipher)
            .map_err(|_| Error::Internal("FF1 decrypt"))?;
        to_array(&plain.to_bytes_le()).map(DiversifierIndex::from_bytes)
    }
}

fn to_array(bytes: &[u8]) -> Result<[u8; DIVERSIFIER_LEN]> {
    bytes
        .try_into()
        .map_err(|_| Error::Internal("FF1 output length"))
}

impl ConstantTimeEq for DiversifierKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl core::fmt::Debug for DiversifierKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DiversifierKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dk(byte: u8) -> DiversifierKey {
        DiversifierKey::from_bytes([byte; DIVERSIFIER_KEY_LEN])
    }

    #[test]
    fn index_from_u64_is_little_endian() {
        let index = DiversifierIndex::from(0x0102u64);
        assert_eq!(index.as_bytes()[..2], [2, 1]);
        assert_eq!(index.as_bytes()[2..], [0; 9]);
    }

    #[test]
    fn next_increments_with_carry() {
        assert_eq!(
            DiversifierIndex::ZERO.next().unwrap(),
            DiversifierIndex::from(1)
        );
        assert_eq!(
            DiversifierIndex::from(0xFF).next().unwrap(),
            DiversifierIndex::from(0x100)
        );
        let last = DiversifierIndex::from_bytes([0xFF; DIVERSIFIER_LEN]);
        assert_eq!(last.next(), Err(Error::DiversifierIndexOverflow));
    }

    #[test]
    fn diversifier_roundtrips_through_index() {
        let key = dk(1);
        for i in [0u64, 1, 2, 1000, u64::MAX] {
            let index = DiversifierIndex::from(i);
            let d = key.diversifier(index).unwrap();
            assert_eq!(key.index(&d).unwrap(), index);
        }
    }

    #[test]
    fn diversifiers_are_deterministic_and_distinct() {
        let key = dk(2);
        let a = key.diversifier(DiversifierIndex::from(5)).unwrap();
        assert_eq!(a, key.diversifier(DiversifierIndex::from(5)).unwrap());
        assert_ne!(a, key.diversifier(DiversifierIndex::from(6)).unwrap());
        assert_ne!(a, dk(3).diversifier(DiversifierIndex::from(5)).unwrap());
    }

    #[test]
    fn diversifier_is_not_the_plain_index() {
        let index = DiversifierIndex::from(7);
        assert_ne!(
            dk(4).diversifier(index).unwrap().as_bytes(),
            index.as_bytes()
        );
    }

    #[test]
    fn key_is_redacted_and_compares_in_constant_time() {
        assert_eq!(format!("{:?}", dk(5)), "DiversifierKey(<redacted>)");
        assert!(bool::from(dk(5).ct_eq(&dk(5))));
        assert!(!bool::from(dk(5).ct_eq(&dk(6))));
    }
}
