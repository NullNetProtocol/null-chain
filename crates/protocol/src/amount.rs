//! Bounded monetary amounts.
//!
//! [`Amount`] is always in `0..=MAX_MONEY`. [`ValueSum`] is a signed running
//! total that can never overflow for any realistic number of terms, used
//! when checking that a transaction balances.

use core::ops::{Add, Sub};

use crate::{Error, Result};

/// Smallest unit. Provisional: eight decimal places.
pub const COIN: u64 = 100_000_000;

/// Hard cap on the total supply, in smallest units. Provisional.
pub const MAX_MONEY: u64 = 21_000_000 * COIN;

/// A non-negative amount no larger than [`MAX_MONEY`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    /// Zero.
    pub const ZERO: Self = Self(0);
    /// The maximum representable amount.
    pub const MAX: Self = Self(MAX_MONEY);

    /// Wraps a raw value.
    ///
    /// # Errors
    /// Returns [`Error::AmountOutOfRange`] above [`MAX_MONEY`].
    pub fn from_raw(raw: u64) -> Result<Self> {
        (raw <= MAX_MONEY)
            .then_some(Self(raw))
            .ok_or(Error::AmountOutOfRange)
    }

    /// The raw value in smallest units.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Little-endian encoding, used inside note commitments.
    pub fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Checked addition.
    ///
    /// # Errors
    /// Returns [`Error::AmountOutOfRange`] if the sum exceeds [`MAX_MONEY`].
    pub fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .ok_or(Error::AmountOutOfRange)
            .and_then(Self::from_raw)
    }

    /// Checked subtraction.
    ///
    /// # Errors
    /// Returns [`Error::AmountOutOfRange`] if the result would be negative.
    pub fn checked_sub(self, other: Self) -> Result<Self> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(Error::AmountOutOfRange)
    }
}

impl TryFrom<u64> for Amount {
    type Error = Error;
    fn try_from(raw: u64) -> Result<Self> {
        Self::from_raw(raw)
    }
}

impl From<Amount> for u64 {
    fn from(amount: Amount) -> Self {
        amount.raw()
    }
}

impl From<Amount> for i64 {
    fn from(amount: Amount) -> Self {
        // MAX_MONEY fits in i64 by construction; asserted in tests.
        #[allow(clippy::cast_possible_wrap)]
        let value = amount.raw() as Self;
        value
    }
}

/// A signed sum of amounts. `i128` cannot overflow with fewer than
/// `2^64` terms, so arithmetic here is unchecked by design.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValueSum(i128);

impl ValueSum {
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// Whether the sum is exactly zero, i.e. inputs equal outputs.
    pub fn is_balanced(self) -> bool {
        self.0 == 0
    }

    /// The raw signed value.
    pub fn raw(self) -> i128 {
        self.0
    }

    /// Sums amounts into a signed total. Cannot overflow, see the type doc.
    #[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
    pub fn sum(amounts: impl IntoIterator<Item = Amount>) -> Self {
        amounts
            .into_iter()
            .fold(Self::ZERO, |acc, amount| acc + amount)
    }

    /// `self - other`.
    #[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
    #[must_use]
    pub fn minus_sum(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }

    /// `self - amount`, by value.
    #[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
    #[must_use]
    pub fn minus(self, amount: Amount) -> Self {
        self - amount
    }

    /// `self + amount`, by value.
    #[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
    #[must_use]
    pub fn plus(self, amount: Amount) -> Self {
        self + amount
    }

    /// Converts to an `i64` for value commitments.
    ///
    /// # Errors
    /// Returns [`Error::AmountOutOfRange`] if the magnitude exceeds `i64`.
    pub fn to_i64(self) -> Result<i64> {
        i64::try_from(self.0).map_err(|_| Error::AmountOutOfRange)
    }
}

#[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
impl Add<Amount> for ValueSum {
    type Output = Self;
    fn add(self, rhs: Amount) -> Self {
        Self(self.0 + i128::from(rhs.0))
    }
}

#[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
impl Sub<Amount> for ValueSum {
    type Output = Self;
    fn sub(self, rhs: Amount) -> Self {
        Self(self.0 - i128::from(rhs.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amt(raw: u64) -> Amount {
        Amount::from_raw(raw).unwrap()
    }

    #[test]
    fn max_money_fits_in_i64() {
        assert!(i64::try_from(MAX_MONEY).is_ok());
        assert_eq!(i64::from(Amount::MAX), i64::try_from(MAX_MONEY).unwrap());
    }

    #[test]
    fn from_raw_enforces_cap() {
        assert_eq!(Amount::from_raw(MAX_MONEY), Ok(Amount::MAX));
        assert_eq!(
            Amount::from_raw(MAX_MONEY + 1),
            Err(Error::AmountOutOfRange)
        );
        assert_eq!(Amount::try_from(0), Ok(Amount::ZERO));
    }

    #[test]
    fn checked_add_respects_cap() {
        assert_eq!(amt(1).checked_add(amt(2)), Ok(amt(3)));
        assert_eq!(
            Amount::MAX.checked_add(amt(1)),
            Err(Error::AmountOutOfRange)
        );
    }

    #[test]
    fn checked_sub_rejects_negative() {
        assert_eq!(amt(3).checked_sub(amt(2)), Ok(amt(1)));
        assert_eq!(amt(2).checked_sub(amt(3)), Err(Error::AmountOutOfRange));
    }

    #[test]
    fn value_sum_balances_when_inputs_equal_outputs() {
        let sum = ValueSum::ZERO + amt(10) + amt(5) - amt(15);
        assert!(sum.is_balanced());
        assert_eq!(sum.to_i64(), Ok(0));
    }

    #[test]
    fn value_sum_helpers_match_operators() {
        let total = ValueSum::sum([amt(1), amt(2), amt(3)]);
        assert_eq!(total, ValueSum::ZERO + amt(1) + amt(2) + amt(3));
        assert_eq!(total.plus(amt(4)), total + amt(4));
        assert_eq!(total.minus_sum(ValueSum::sum([amt(6)])), ValueSum::ZERO);
        assert_eq!(total.minus(amt(6)), ValueSum::ZERO);
    }

    #[test]
    fn value_sum_can_go_negative() {
        let sum = ValueSum::ZERO - amt(7);
        assert!(!sum.is_balanced());
        assert_eq!(sum.raw(), -7);
        assert_eq!(sum.to_i64(), Ok(-7));
    }

    #[test]
    fn le_bytes_match_raw() {
        assert_eq!(amt(0x0102).to_le_bytes(), [2, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(u64::from(amt(9)), 9);
    }
}
