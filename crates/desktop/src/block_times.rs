//! When received notes arrived, for the activity list.
//!
//! The wallet records only the height of the block that added a note to
//! the tree. The backend looks each height up once and keeps the answer:
//! a block deeper than the network's maximum reorganization depth can never
//! be replaced, and shallower ones are checked again only when the tip moves.
//!
//! A mined reward enters the tree when it matures, blocks after the block
//! that paid it, so its note is dated by the paying block instead.

use std::collections::HashMap;

use null_protocol::block::{Block, BlockHash};
use null_protocol::maturity::maturing_origin;
use serde_json::Value;

/// Most uncached blocks read in one refresh, so a wallet with many notes
/// fills in its dates over a few refreshes instead of stalling the backend.
pub const LOOKUPS_PER_REFRESH: usize = 64;

/// What the activity list needs from one main-chain block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFacts {
    /// The block's hash, to notice when a reorganization replaced it.
    pub hash: BlockHash,
    /// The header timestamp, in seconds since the Unix epoch.
    pub time: u64,
    /// The id of the block's own coinbase transaction.
    pub coinbase: Option<String>,
}

impl From<&Block> for BlockFacts {
    fn from(block: &Block) -> Self {
        Self {
            hash: block.hash(),
            time: block.header().timestamp,
            coinbase: block.transactions().first().map(|tx| tx.txid().to_string()),
        }
    }
}

/// Facts about the blocks holding the wallet's notes, by height.
#[derive(Default)]
pub struct BlockTimes {
    tip: Option<BlockHash>,
    blocks: HashMap<u32, BlockFacts>,
}

impl BlockTimes {
    /// Records the current tip and returns the cached heights a
    /// reorganization onto it could have replaced; none if the tip is the
    /// one already seen.
    pub fn follow_tip(
        &mut self,
        tip: BlockHash,
        tip_height: u32,
        max_reorg_depth: u32,
    ) -> Vec<u32> {
        if self.tip.replace(tip) == Some(tip) {
            return Vec::new();
        }
        let final_below = tip_height.saturating_sub(max_reorg_depth);
        let mut heights: Vec<u32> = self
            .blocks
            .keys()
            .copied()
            .filter(|h| *h >= final_below)
            .collect();
        heights.sort_unstable();
        heights
    }

    /// The cached block at `height`.
    pub fn get(&self, height: u32) -> Option<&BlockFacts> {
        self.blocks.get(&height)
    }

    /// Caches the block at `height`.
    pub fn insert(&mut self, height: u32, facts: BlockFacts) {
        self.blocks.insert(height, facts);
    }

    /// Drops the block at `height`, which is no longer on the main chain.
    pub fn remove(&mut self, height: u32) {
        self.blocks.remove(&height);
    }

    /// Forgets everything, for when the wallet locks.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Uncached heights the `notes` need, lowest first, at most `limit`.
    pub fn missing(&self, notes: &Value, maturity: u32, limit: usize) -> Vec<u32> {
        let mut heights: Vec<u32> = items(notes)
            .iter()
            .filter_map(note_height)
            .flat_map(|h| [Some(h), maturing_origin(h, maturity)])
            .flatten()
            .filter(|h| !self.blocks.contains_key(h))
            .collect();
        heights.sort_unstable();
        heights.dedup();
        heights.truncate(limit);
        heights
    }

    /// Adds `time` and `mined` to every note whose blocks are cached.
    pub fn annotate(&self, notes: &mut Value, maturity: u32) {
        if let Some(notes) = notes.as_array_mut() {
            for note in notes {
                self.annotate_note(note, maturity);
            }
        }
    }

    fn annotate_note(&self, note: &mut Value, maturity: u32) {
        let Some(height) = note_height(note) else {
            return;
        };
        let txid = note.get("txid").and_then(Value::as_str);
        let reward = maturing_origin(height, maturity)
            .and_then(|origin| self.get(origin))
            .filter(|origin| origin.coinbase.is_some() && origin.coinbase.as_deref() == txid);
        let time = reward.or_else(|| self.get(height)).map(|b| b.time);
        if let Some(object) = note.as_object_mut() {
            object.insert("time".into(), time.into());
            object.insert("mined".into(), reward.is_some().into());
        }
    }
}

fn items(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

fn note_height(note: &Value) -> Option<u32> {
    note.get("height")
        .and_then(Value::as_u64)
        .and_then(|h| u32::try_from(h).ok())
}

#[cfg(test)]
mod tests {
    use null_chain::genesis::genesis;
    use null_node::config::Network;
    use serde_json::json;

    use super::*;

    fn facts(byte: u8, time: u64, coinbase: &str) -> BlockFacts {
        BlockFacts {
            hash: BlockHash::from_bytes([byte; 32]),
            time,
            coinbase: Some(coinbase.into()),
        }
    }

    #[test]
    fn facts_come_from_the_header_and_the_first_transaction() {
        let block = genesis(&Network::Test.params());
        let facts = BlockFacts::from(&block);
        assert_eq!(facts.hash, block.hash());
        assert_eq!(facts.time, block.header().timestamp);
        assert_eq!(
            facts.coinbase,
            block.transactions().first().map(|tx| tx.txid().to_string())
        );
    }

    #[test]
    fn only_heights_a_reorganization_can_reach_are_rechecked_and_only_on_a_new_tip() {
        let mut times = BlockTimes::default();
        for height in [10, 300, 350, 400] {
            times.insert(height, facts(1, 0, "c"));
        }
        let tip = BlockHash::from_bytes([9; 32]);
        assert_eq!(times.follow_tip(tip, 500, 200), vec![300, 350, 400]);
        assert_eq!(times.follow_tip(tip, 500, 200), Vec::<u32>::new());
        let next = BlockHash::from_bytes([8; 32]);
        assert_eq!(times.follow_tip(next, 100, 200), vec![10, 300, 350, 400]);
    }

    #[test]
    fn missing_heights_include_reward_origins_once_lowest_first_and_capped() {
        let mut times = BlockTimes::default();
        times.insert(20, facts(1, 0, "c"));
        let notes = json!([{ "height": 30 }, { "height": 29 }, { "height": 30 }, { "x": 1 }]);
        assert_eq!(times.missing(&notes, 10, 10), vec![21, 29, 30]);
        assert_eq!(times.missing(&notes, 10, 2), vec![21, 29]);
        assert_eq!(times.missing(&json!(null), 10, 10), Vec::<u32>::new());
    }

    #[test]
    fn a_reward_is_dated_by_the_block_that_paid_it_and_others_by_their_own() {
        let mut times = BlockTimes::default();
        times.insert(21, facts(1, 1_000, "reward"));
        times.insert(30, facts(2, 2_000, "other"));
        let mut notes = json!([
            { "height": 30, "txid": "reward" },
            { "height": 30, "txid": "payment" },
            { "height": 30 },
            { "height": 31, "txid": "reward" },
        ]);
        times.annotate(&mut notes, 10);
        let got: Vec<(Value, Value)> = notes
            .as_array()
            .unwrap()
            .iter()
            .map(|n| (n["time"].clone(), n["mined"].clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                (json!(1_000), json!(true)),
                (json!(2_000), json!(false)),
                (json!(2_000), json!(false)),
                (json!(null), json!(false)),
            ]
        );
    }

    #[test]
    fn removing_and_clearing_forget_blocks() {
        let mut times = BlockTimes::default();
        times.insert(5, facts(1, 0, "c"));
        times.insert(6, facts(1, 0, "c"));
        times.remove(5);
        assert_eq!(times.get(5), None);
        assert!(times.get(6).is_some());
        times.clear();
        assert_eq!(times.get(6), None);
        assert_eq!(times.follow_tip(BlockHash::ZERO, 0, 200), Vec::<u32>::new());
    }
}
