//! Consensus constants for transactions: action classes, the fee rule and
//! size limits. Everything here is a fingerprint if it varies, so nothing
//! here is configurable.

use crate::amount::Amount;
use crate::{Error, Result};

/// The only transaction version.
pub const TX_VERSION: u8 = 1;

/// The only block version.
pub const BLOCK_VERSION: u8 = 1;

/// Identifies one set of consensus rules. Every signature hash binds the
/// branch in force at the block's height, so a transaction signed under
/// one set of rules is invalid under any other: after a fork neither side
/// can replay the other's transactions, and a test network transaction
/// is never valid on the main network. The branch is not part of the
/// transaction bytes; validation supplies it from the chain parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BranchId(u32);

impl BranchId {
    /// Wraps a raw identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// The bytes hashed into a sighash.
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

/// Byte length of the proof-of-work solution in a block header: Equihash
/// `(144, 5)`, `2^5 * (144 / 6 + 1)` bits.
pub const POW_SOLUTION_LEN: usize = 100;

/// Most transactions a block may carry. Provisional.
pub const MAX_BLOCK_TRANSACTIONS: usize = 512;

/// The development fund paid by the genesis coinbase, in smallest units:
/// five percent of `MAX_MONEY`, carved out of the emission below so the
/// cap holds. Provisional. The genesis transaction that pays it is
/// embedded per network (`ChainParams::genesis_coinbase`); its binding
/// signature commits to exactly this value.
pub const PREMINE: u64 = 1_050_000 * crate::amount::COIN;

/// Block subsidy at height 1, in smallest units. Provisional: 9.5 coins,
/// so that the emission plus the premine sums to `MAX_MONEY`.
pub const INITIAL_SUBSIDY: u64 = 95 * crate::amount::COIN / 10;

/// Blocks between subsidy halvings. Provisional: about four years at
/// two-minute blocks.
pub const HALVING_INTERVAL: u32 = 1_050_000;

/// The block subsidy at `height`. Genesis pays nothing.
pub fn subsidy(height: u32) -> Amount {
    if height == 0 {
        return Amount::ZERO;
    }
    let halvings = height.saturating_sub(1) / HALVING_INTERVAL;
    let raw = INITIAL_SUBSIDY.checked_shr(halvings).unwrap_or(0);
    // INITIAL_SUBSIDY is below MAX_MONEY, so this cannot fail.
    Amount::from_raw(raw).unwrap_or(Amount::ZERO)
}

/// The height of the block after one at `height`.
///
/// # Errors
/// Returns [`Error::HeightExhausted`] at `u32::MAX`: the chain has no
/// defined continuation, so producing or importing a block there is
/// refused rather than letting a saturated height overwrite the index.
pub fn next_height(height: u32) -> Result<u32> {
    height.checked_add(1).ok_or(Error::HeightExhausted)
}

/// Allowed numbers of actions per transaction. A transaction is padded with
/// dummy actions up to the smallest class that fits.
pub const ACTION_CLASSES: [usize; 4] = [2, 4, 8, 16];

/// The largest action class.
pub const MAX_ACTIONS: usize = 16;

/// Fee per action in smallest units. Provisional.
pub const FEE_PER_ACTION: u64 = 10_000;

/// The exact proof length of a bundle with `actions` actions.
///
/// # Errors
/// Returns [`Error::InvalidTransaction`] if `actions` is not a class.
pub fn proof_len(actions: usize) -> Result<usize> {
    null_circuit::proof::proof_len(actions).ok_or(Error::InvalidTransaction(
        "action count is not an allowed class",
    ))
}

/// The smallest action class that fits `needed` actions.
///
/// # Errors
/// Returns [`Error::TooManyActions`] above [`MAX_ACTIONS`].
pub fn action_class_for(needed: usize) -> Result<usize> {
    ACTION_CLASSES
        .iter()
        .copied()
        .find(|class| *class >= needed)
        .ok_or(Error::TooManyActions)
}

/// Whether `count` is an allowed number of actions.
pub fn is_action_class(count: usize) -> bool {
    ACTION_CLASSES.contains(&count)
}

/// The fee of a transaction with `actions` actions.
///
/// # Errors
/// Returns [`Error::AmountOutOfRange`] on overflow, which cannot happen for
/// any valid action count.
pub fn fee_for_actions(actions: usize) -> Result<Amount> {
    let count = u64::try_from(actions).map_err(|_| Error::AmountOutOfRange)?;
    let raw = FEE_PER_ACTION
        .checked_mul(count)
        .ok_or(Error::AmountOutOfRange)?;
    Amount::from_raw(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_are_ascending_powers_of_two_up_to_max() {
        assert_eq!(ACTION_CLASSES.last(), Some(&MAX_ACTIONS));
        for window in ACTION_CLASSES.windows(2) {
            assert_eq!(window[0] * 2, window[1]);
        }
    }

    #[test]
    fn class_is_the_smallest_that_fits() {
        assert_eq!(action_class_for(0), Ok(2));
        assert_eq!(action_class_for(1), Ok(2));
        assert_eq!(action_class_for(2), Ok(2));
        assert_eq!(action_class_for(3), Ok(4));
        assert_eq!(action_class_for(9), Ok(16));
        assert_eq!(action_class_for(16), Ok(16));
        assert_eq!(action_class_for(17), Err(Error::TooManyActions));
    }

    #[test]
    fn branch_ids_encode_little_endian_and_compare_by_value() {
        assert_eq!(BranchId::new(0x0403_0201).to_bytes(), [1, 2, 3, 4]);
        assert_eq!(BranchId::new(7), BranchId::new(7));
        assert_ne!(BranchId::new(7), BranchId::new(8));
    }

    #[test]
    fn next_height_counts_up_and_refuses_exhaustion() {
        assert_eq!(next_height(0), Ok(1));
        assert_eq!(next_height(u32::MAX - 1), Ok(u32::MAX));
        assert_eq!(next_height(u32::MAX), Err(Error::HeightExhausted));
    }

    #[test]
    fn membership_matches_classes() {
        assert!(is_action_class(4));
        assert!(!is_action_class(3));
        assert!(!is_action_class(0));
    }

    #[test]
    fn proof_len_exists_exactly_for_classes() {
        for class in ACTION_CLASSES {
            assert!(proof_len(class).is_ok());
        }
        assert!(proof_len(3).is_err());
    }

    #[test]
    fn subsidy_halves_and_total_emission_stays_under_the_cap() {
        assert_eq!(subsidy(0), Amount::ZERO);
        assert_eq!(subsidy(1).raw(), INITIAL_SUBSIDY);
        assert_eq!(subsidy(HALVING_INTERVAL).raw(), INITIAL_SUBSIDY);
        assert_eq!(subsidy(HALVING_INTERVAL + 1).raw(), INITIAL_SUBSIDY / 2);
        let mut total: u128 = 0;
        let mut era = 0u32;
        loop {
            let per_block = subsidy(era.saturating_mul(HALVING_INTERVAL).saturating_add(1)).raw();
            if per_block == 0 {
                break;
            }
            total += u128::from(per_block) * u128::from(HALVING_INTERVAL);
            era += 1;
        }
        let total = total + u128::from(PREMINE);
        assert!(total <= u128::from(crate::amount::MAX_MONEY));
        assert!(
            total > u128::from(crate::amount::MAX_MONEY) * 99 / 100,
            "emission plus premine should approach the cap"
        );
        assert_eq!(
            u128::from(PREMINE) * 20,
            u128::from(crate::amount::MAX_MONEY),
            "the premine is five percent"
        );
    }

    #[test]
    fn fee_is_linear_in_actions() {
        assert_eq!(fee_for_actions(2).unwrap().raw(), 2 * FEE_PER_ACTION);
        assert_eq!(fee_for_actions(16).unwrap().raw(), 16 * FEE_PER_ACTION);
        assert_eq!(fee_for_actions(usize::MAX), Err(Error::AmountOutOfRange));
    }
}
