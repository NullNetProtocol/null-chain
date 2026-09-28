//! The fixed-size memo carried inside every note ciphertext.
//!
//! Memos are always present and always the same length, so their existence
//! and size reveal nothing. An unused memo is all zeros.

use crate::bytes::{Encodable, Reader, Writer};
use crate::{Error, Result};

/// Byte length of every memo.
pub const MEMO_LEN: usize = 512;

/// A 512-byte memo, usually UTF-8 text padded with zeros.
#[derive(Clone, PartialEq, Eq)]
pub struct Memo([u8; MEMO_LEN]);

impl Memo {
    /// The empty memo.
    pub fn empty() -> Self {
        Self([0u8; MEMO_LEN])
    }

    /// Wraps raw bytes.
    pub fn from_bytes(bytes: [u8; MEMO_LEN]) -> Self {
        Self(bytes)
    }

    /// Encodes text, zero padded.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] if the text exceeds [`MEMO_LEN`] bytes.
    pub fn from_text(text: &str) -> Result<Self> {
        let mut memo = Self::empty();
        let (head, _) = memo
            .0
            .split_at_mut_checked(text.len())
            .ok_or(Error::Malformed("memo too long"))?;
        head.copy_from_slice(text.as_bytes());
        Ok(memo)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; MEMO_LEN] {
        &self.0
    }

    /// The memo as text with trailing zeros removed, if it is valid UTF-8.
    pub fn to_text(&self) -> Option<&str> {
        let end = self
            .0
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |i| i.saturating_add(1));
        self.0
            .get(..end)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
    }

    /// Whether the memo is all zeros.
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Encodable for Memo {
    fn write(&self, w: &mut Writer) {
        w.put(&self.0);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(r.take_array()?))
    }
}

impl Default for Memo {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Debug for Memo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.to_text() {
            Some(text) => f.debug_tuple("Memo").field(&text).finish(),
            None => f.write_str("Memo(<binary>)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_memo_is_zeros() {
        assert!(Memo::empty().is_empty());
        assert_eq!(Memo::default(), Memo::empty());
        assert_eq!(Memo::empty().to_text(), Some(""));
    }

    #[test]
    fn text_roundtrips() {
        let memo = Memo::from_text("ciao").unwrap();
        assert_eq!(memo.to_text(), Some("ciao"));
        assert!(!memo.is_empty());
        assert_eq!(Memo::from_bytes(*memo.as_bytes()), memo);
        assert_eq!(format!("{memo:?}"), "Memo(\"ciao\")");
    }

    #[test]
    fn text_at_exact_capacity_is_accepted_and_one_more_is_rejected() {
        let exact = "a".repeat(MEMO_LEN);
        assert!(Memo::from_text(&exact).is_ok());
        let long = "a".repeat(MEMO_LEN + 1);
        assert!(matches!(Memo::from_text(&long), Err(Error::Malformed(_))));
    }

    #[test]
    fn encodable_roundtrips() {
        let memo = Memo::from_text("x").unwrap();
        assert_eq!(Memo::from_slice(&memo.to_vec()), Ok(memo));
    }

    #[test]
    fn binary_memo_has_no_text() {
        let mut bytes = [0u8; MEMO_LEN];
        bytes[0] = 0xFF;
        let memo = Memo::from_bytes(bytes);
        assert_eq!(memo.to_text(), None);
        assert_eq!(format!("{memo:?}"), "Memo(<binary>)");
    }
}
