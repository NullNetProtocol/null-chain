//! The nullifier newtype.
//!
//! A nullifier is revealed when a note is spent. It is unlinkable to the
//! note commitment without the nullifier key, and the chain rejects any
//! nullifier that has already appeared.

use null_crypto::encoding::{base_from_bytes, base_to_bytes, Encoded};
use null_crypto::pallas;

use crate::bytes::{Encodable, Reader, Writer};
use crate::Result;

/// A spent-note marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Nullifier(Encoded);

impl Nullifier {
    /// Wraps a base field element.
    pub fn from_base(value: &pallas::Base) -> Self {
        Self(base_to_bytes(value))
    }

    /// The canonical 32-byte encoding.
    pub fn to_bytes(&self) -> Encoded {
        self.0
    }

    /// Parses a canonical encoding.
    ///
    /// # Errors
    /// Fails if the bytes are not a canonical base field element.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        Ok(Self::from_base(&base_from_bytes(bytes)?))
    }

    /// The underlying field element.
    ///
    /// # Errors
    /// Cannot fail for a value built by this type; kept as `Result` so callers
    /// never unwrap.
    pub fn to_base(&self) -> Result<pallas::Base> {
        Ok(base_from_bytes(&self.0)?)
    }
}

impl Encodable for Nullifier {
    fn write(&self, w: &mut Writer) {
        w.put(&self.0);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_bytes(&r.take_array()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_bytes_and_base() {
        let nf = Nullifier::from_base(&pallas::Base::from(77u64));
        assert_eq!(Nullifier::from_bytes(&nf.to_bytes()), Ok(nf));
        assert_eq!(Nullifier::from_slice(&nf.to_vec()), Ok(nf));
        assert_eq!(nf.to_base(), Ok(pallas::Base::from(77u64)));
    }

    #[test]
    fn rejects_non_canonical_bytes() {
        assert!(Nullifier::from_bytes(&[0xFF; 32]).is_err());
    }

    #[test]
    fn ordering_is_byte_ordering() {
        let a = Nullifier::from_base(&pallas::Base::from(1u64));
        let b = Nullifier::from_base(&pallas::Base::from(2u64));
        assert!(a < b);
    }
}
