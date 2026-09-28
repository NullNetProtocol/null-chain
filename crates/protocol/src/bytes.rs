//! Cursor helpers for canonical byte layouts.
//!
//! Every encoding in this crate is a fixed sequence of fixed-size fields.
//! [`Reader`] consumes such a layout without indexing, and [`Writer`]
//! produces it. Both fail loudly on length mismatches instead of panicking.

use crate::{Error, Result};

/// Reads fixed-size fields from a byte slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Starts reading at the beginning of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.data.len()
    }

    /// Consumes `len` bytes.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] if fewer than `len` bytes remain.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, tail) = self
            .data
            .split_at_checked(len)
            .ok_or(Error::Malformed("unexpected end of input"))?;
        self.data = tail;
        Ok(head)
    }

    /// Consumes exactly `N` bytes into an array.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] if fewer than `N` bytes remain.
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Consumes one byte.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] at end of input.
    pub fn take_u8(&mut self) -> Result<u8> {
        self.take_array::<1>().map(|[b]| b)
    }

    /// Consumes a little-endian `u64`.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] if fewer than eight bytes remain.
    pub fn take_u64_le(&mut self) -> Result<u64> {
        self.take_array::<8>().map(u64::from_le_bytes)
    }

    /// Asserts that every byte was consumed.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] if bytes remain.
    pub fn finish(self) -> Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes"))
        }
    }
}

/// A type with one canonical byte layout.
pub trait Encodable: Sized {
    /// Appends the canonical encoding.
    fn write(&self, w: &mut Writer);

    /// Parses the canonical encoding from the cursor.
    ///
    /// # Errors
    /// Fails on truncated or non-canonical input.
    fn read(r: &mut Reader<'_>) -> Result<Self>;

    /// The canonical encoding as a vector.
    fn to_vec(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.write(&mut w);
        w.into_bytes()
    }

    /// Parses a complete encoding, rejecting trailing bytes.
    ///
    /// # Errors
    /// Fails on truncated, non-canonical, or over-long input.
    fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let value = Self::read(&mut r)?;
        r.finish()?;
        Ok(value)
    }
}

/// Appends fixed-size fields to a buffer.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buffer: Vec<u8>,
}

impl Writer {
    /// An empty writer with room for `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Appends raw bytes.
    pub fn put(&mut self, bytes: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(bytes);
        self
    }

    /// Appends one byte.
    pub fn put_u8(&mut self, byte: u8) -> &mut Self {
        self.put(&[byte])
    }

    /// Appends a little-endian `u64`.
    pub fn put_u64_le(&mut self, value: u64) -> &mut Self {
        self.put(&value.to_le_bytes())
    }

    /// The written bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// The written bytes as a fixed array.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] if the length is not exactly `N`.
    pub fn into_array<const N: usize>(self) -> Result<[u8; N]> {
        self.buffer
            .try_into()
            .map_err(|_| Error::Malformed("unexpected length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_consumes_fields_in_order() {
        let data = [1u8, 2, 0, 0, 0, 0, 0, 0, 0, 9, 9];
        let mut r = Reader::new(&data);
        assert_eq!(r.take_u8(), Ok(1));
        assert_eq!(r.take_u64_le(), Ok(2));
        assert_eq!(r.take_array::<2>(), Ok([9, 9]));
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn reader_rejects_short_input_and_trailing_bytes() {
        let mut short = Reader::new(&[1u8]);
        assert!(matches!(short.take_u64_le(), Err(Error::Malformed(_))));
        let long = Reader::new(&[1u8]);
        assert!(matches!(long.finish(), Err(Error::Malformed(_))));
    }

    #[test]
    fn writer_and_reader_roundtrip() {
        let mut w = Writer::with_capacity(11);
        w.put_u8(7).put_u64_le(300).put(&[5, 6]);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.take_u8(), Ok(7));
        assert_eq!(r.take_u64_le(), Ok(300));
        assert_eq!(r.take(2), Ok(&[5u8, 6][..]));
        assert_eq!(r.finish(), Ok(()));
    }

    #[derive(Debug, PartialEq)]
    struct Pair(u8, u64);

    impl Encodable for Pair {
        fn write(&self, w: &mut Writer) {
            w.put_u8(self.0).put_u64_le(self.1);
        }
        fn read(r: &mut Reader<'_>) -> Result<Self> {
            Ok(Self(r.take_u8()?, r.take_u64_le()?))
        }
    }

    #[test]
    fn encodable_roundtrips_and_rejects_trailing_bytes() {
        let pair = Pair(1, 2);
        let bytes = pair.to_vec();
        assert_eq!(Pair::from_slice(&bytes), Ok(pair));
        let mut long = bytes.clone();
        long.push(0);
        assert!(matches!(Pair::from_slice(&long), Err(Error::Malformed(_))));
    }

    #[test]
    fn writer_into_array_checks_length() {
        let mut w = Writer::default();
        w.put(&[1, 2, 3]);
        assert_eq!(w.clone().into_array::<3>(), Ok([1, 2, 3]));
        assert!(matches!(w.into_array::<4>(), Err(Error::Malformed(_))));
    }
}
