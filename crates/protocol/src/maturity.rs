//! Coinbase maturity: the order in which a block's note commitments enter
//! the commitment tree.
//!
//! A note can only be spent against a tree root that contains it. So
//! instead of a rule about spends, which would need the circuit to know a
//! note came from a coinbase, maturity delays the tree: the outputs of the
//! coinbase at height `h` enter the tree while block `h + M - 1` is
//! applied, before that block's own transactions, and are first spendable
//! in block `h + M`. Until then the reward cannot be spent, and a reorg
//! that orphans the block takes nothing downstream with it. Once in the
//! tree, a coinbase output is a note like any other.
//!
//! The genesis block is the exception: its outputs, the premine, enter at
//! once. With `M = 1` a block's own coinbase is the one maturing, which is
//! the plain block order.
//!
//! Everything that builds the tree (block validation, mining, wallets, and
//! compact blocks for light clients) goes through [`tree_transactions`] so
//! they cannot disagree.

use crate::block::Block;
use crate::transaction::Transaction;
use crate::{Error, Result};

/// The height whose coinbase outputs enter the tree while the block at
/// `height` is applied, for a maturity of `maturity` blocks (at least one):
/// `height - maturity + 1`. `None` for genesis and while no coinbase has
/// matured yet.
pub fn maturing_origin(height: u32, maturity: u32) -> Option<u32> {
    if height == 0 {
        return None;
    }
    let origin = height.checked_sub(maturity.saturating_sub(1))?;
    (origin >= 1).then_some(origin)
}

/// The transactions whose outputs `block` appends to the tree, in tree
/// order. For genesis, every transaction. Otherwise the coinbase maturing
/// at this height, then the block's transactions after its own coinbase.
///
/// `earlier` is the coinbase of the block at
/// [`maturing_origin`]`(height, maturity)` when that is below `height`; the
/// caller reads it from its chain. When the origin is `height` itself
/// (`maturity` of one), the block's own coinbase is used.
///
/// # Errors
/// Returns [`Error::InvalidBlock`] if a maturing coinbase is needed and
/// `earlier` is missing, or given when none matures.
pub fn tree_transactions<'a>(
    block: &'a Block,
    maturity: u32,
    earlier: Option<&'a Transaction>,
) -> Result<Vec<&'a Transaction>> {
    let height = block.header().height;
    let transactions = block.transactions();
    if height == 0 {
        return Ok(transactions.iter().collect());
    }
    let own = transactions.first();
    let maturing = match (maturing_origin(height, maturity), earlier) {
        (Some(origin), None) if origin == height => own,
        (Some(origin), Some(coinbase)) if origin < height => Some(coinbase),
        (None, None) => None,
        _ => return Err(Error::InvalidBlock("wrong maturing coinbase")),
    };
    Ok(maturing
        .into_iter()
        .chain(transactions.iter().skip(1))
        .collect())
}

/// Whether the caller must supply the coinbase of an earlier block to
/// [`tree_transactions`] for the block at `height`, and from which height.
pub fn earlier_origin(height: u32, maturity: u32) -> Option<u32> {
    maturing_origin(height, maturity).filter(|origin| *origin < height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{empty_header, BlockHash};
    use crate::transaction::tests::{sample_anchor, sample_transaction};
    use crate::transaction::TxId;

    #[test]
    fn a_coinbase_matures_maturity_minus_one_blocks_later() {
        assert_eq!(maturing_origin(0, 100), None, "genesis is exempt");
        assert_eq!(maturing_origin(1, 100), None);
        assert_eq!(maturing_origin(99, 100), None);
        assert_eq!(maturing_origin(100, 100), Some(1));
        assert_eq!(maturing_origin(250, 100), Some(151));
        for height in 1..10 {
            assert_eq!(
                maturing_origin(height, 1),
                Some(height),
                "M = 1 is block order"
            );
            assert_eq!(maturing_origin(height, 0), Some(height), "M = 0 means 1");
        }
        assert_eq!(maturing_origin(u32::MAX, 100), Some(u32::MAX - 99));
    }

    #[test]
    fn only_origins_below_the_block_are_fetched_from_the_chain() {
        assert_eq!(earlier_origin(100, 100), Some(1));
        assert_eq!(earlier_origin(5, 1), None, "its own coinbase");
        assert_eq!(earlier_origin(5, 100), None, "nothing matured yet");
    }

    fn block(height: u32, transactions: Vec<Transaction>) -> Block {
        Block::new(
            empty_header(height, BlockHash::ZERO, sample_anchor()),
            transactions,
        )
    }

    /// A block's coinbase and one ordinary transaction, told apart by seed.
    fn transactions(seed: u64) -> Vec<Transaction> {
        vec![
            sample_transaction(seed, 2),
            sample_transaction(seed.saturating_add(100), 2),
        ]
    }

    fn txids(transactions: &[&Transaction]) -> Vec<TxId> {
        transactions.iter().map(|tx| tx.txid()).collect()
    }

    #[test]
    fn genesis_appends_everything_at_once() {
        let genesis = block(0, transactions(1));
        let order = tree_transactions(&genesis, 100, None).unwrap();
        assert_eq!(
            txids(&order),
            txids(&genesis.transactions().iter().collect::<Vec<_>>())
        );
    }

    #[test]
    fn a_young_block_holds_back_its_coinbase() {
        let young = block(5, transactions(1));
        let order = tree_transactions(&young, 100, None).unwrap();
        assert_eq!(txids(&order), [young.transactions()[1].txid()]);
    }

    #[test]
    fn the_matured_coinbase_goes_first_and_the_own_one_waits() {
        let origin = block(1, transactions(1));
        let current = block(100, transactions(2));
        let matured = &origin.transactions()[0];
        let order = tree_transactions(&current, 100, Some(matured)).unwrap();
        assert_eq!(
            txids(&order),
            [matured.txid(), current.transactions()[1].txid()]
        );
    }

    #[test]
    fn maturity_one_is_plain_block_order() {
        let current = block(7, transactions(3));
        let order = tree_transactions(&current, 1, None).unwrap();
        assert_eq!(
            txids(&order),
            txids(&current.transactions().iter().collect::<Vec<_>>())
        );
    }

    #[test]
    fn a_missing_or_unexpected_maturing_coinbase_is_refused() {
        let spare = sample_transaction(9, 2);
        let due = block(100, transactions(1));
        assert!(
            tree_transactions(&due, 100, None).is_err(),
            "one matures here"
        );
        let young = block(5, transactions(1));
        assert!(
            tree_transactions(&young, 100, Some(&spare)).is_err(),
            "none matures"
        );
        assert!(
            tree_transactions(&young, 1, Some(&spare)).is_err(),
            "its own matures"
        );
    }
}
