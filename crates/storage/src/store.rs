//! The chain database.
//!
//! Tables:
//!
//! | table | key | value |
//! |---|---|---|
//! | `blocks` | block hash | block bytes |
//! | `heights` | height | block hash |
//! | `nullifiers` | nullifier | height it was spent at |
//! | `frontiers` | height | commitment tree after that block |
//! | `meta` | name | tip hash |
//!
//! [`Store::apply`] and [`Store::revert`] each run in one write
//! transaction, so the tables never disagree after a crash.

use std::path::Path;

use null_protocol::block::{Block, BlockHash};
use null_protocol::bytes::Encodable;
use null_protocol::consensus::next_height;
use null_protocol::nullifier::Nullifier;
use null_protocol::transaction::{Transaction, TxId};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::tree::CommitmentTree;
use crate::{Error, Result};

const BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("blocks");
const HEIGHTS: TableDefinition<u32, &[u8; 32]> = TableDefinition::new("heights");
const NULLIFIERS: TableDefinition<&[u8; 32], u32> = TableDefinition::new("nullifiers");
const FRONTIERS: TableDefinition<u32, &[u8]> = TableDefinition::new("frontiers");
const META: TableDefinition<&str, &[u8; 32]> = TableDefinition::new("meta");
/// Transaction id to its location, `LE32(height) || LE32(index)`.
const TXIDS: TableDefinition<&[u8; 32], &[u8; 8]> = TableDefinition::new("txids");

/// Meta key of the tip hash.
const TIP: &str = "tip";
/// Meta key of the consensus rules digest the store was built under.
const RULES: &str = "rules";
/// Meta key of the on-disk layout version.
const SCHEMA: &str = "schema";
/// The on-disk layout this code writes and reads. Bumped whenever a table
/// is added or changed; an older store is refused rather than served with
/// tables it never filled.
pub const SCHEMA_VERSION: u32 = 2;

/// The chain tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    /// Height of the tip block.
    pub height: u32,
    /// Hash of the tip block.
    pub hash: BlockHash,
}

/// The chain database.
#[derive(Debug)]
pub struct Store {
    db: Database,
}

impl Store {
    /// Opens or creates the database at `path`.
    ///
    /// # Errors
    /// Fails if the file cannot be opened or its tables created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::init(Database::create(path)?)
    }

    /// A database that lives only in memory, for tests and tools.
    ///
    /// # Errors
    /// Fails if the backend cannot be created.
    pub fn in_memory() -> Result<Self> {
        Self::init(Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?)
    }

    fn init(db: Database) -> Result<Self> {
        let tx = db.begin_write()?;
        tx.open_table(BLOCKS)?;
        tx.open_table(HEIGHTS)?;
        tx.open_table(NULLIFIERS)?;
        tx.open_table(FRONTIERS)?;
        tx.open_table(TXIDS)?;
        {
            let mut meta = tx.open_table(META)?;
            let recorded = meta.get(SCHEMA)?.map(|v| *v.value());
            let fresh = meta.get(TIP)?.is_none();
            match recorded {
                Some(v) if v == schema_bytes(SCHEMA_VERSION) => {}
                None if fresh => {
                    meta.insert(SCHEMA, &schema_bytes(SCHEMA_VERSION))?;
                }
                _ => {
                    return Err(Error::Corrupt(
                        "store layout outdated; delete it and resync",
                    ))
                }
            }
        }
        tx.commit()?;
        Ok(Self { db })
    }

    /// The current tip, or `None` before genesis.
    ///
    /// # Errors
    /// Fails on a read error or a corrupt height index.
    pub fn tip(&self) -> Result<Option<Tip>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        let Some(hash) = meta.get(TIP)? else {
            return Ok(None);
        };
        let hash = BlockHash::from_bytes(*hash.value());
        let block = self
            .block(&hash)?
            .ok_or(Error::Corrupt("tip block missing"))?;
        Ok(Some(Tip {
            height: block.header().height,
            hash,
        }))
    }

    /// Where a transaction is in the main chain: `(height, index)`.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn transaction_location(&self, txid: &TxId) -> Result<Option<(u32, u32)>> {
        let tx = self.db.begin_read()?;
        let txids = tx.open_table(TXIDS)?;
        Ok(txids
            .get(txid.as_bytes())?
            .map(|v| decode_location(*v.value())))
    }

    /// A main-chain transaction with its height and index in the block.
    ///
    /// # Errors
    /// Fails on a read error or an index pointing at a missing block.
    pub fn transaction(&self, txid: &TxId) -> Result<Option<(Transaction, u32, u32)>> {
        let Some((height, index)) = self.transaction_location(txid)? else {
            return Ok(None);
        };
        let hash = self
            .hash_at(height)?
            .ok_or(Error::Corrupt("indexed height missing"))?;
        let block = self
            .block(&hash)?
            .ok_or(Error::Corrupt("indexed block missing"))?;
        let tx = block
            .transactions()
            .get(usize::try_from(index).map_err(|_| Error::Corrupt("index"))?)
            .cloned()
            .ok_or(Error::Corrupt("indexed transaction missing"))?;
        Ok(Some((tx, height, index)))
    }

    /// The digest of the consensus rules this store was built under, if
    /// one was recorded.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn rules_digest(&self) -> Result<Option<[u8; 32]>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        Ok(meta.get(RULES)?.map(|v| *v.value()))
    }

    /// Records the digest of the consensus rules this store is built
    /// under.
    ///
    /// # Errors
    /// Fails on a write error.
    pub fn set_rules_digest(&self, digest: &[u8; 32]) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut meta = tx.open_table(META)?;
            meta.insert(RULES, digest)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The block with the given hash.
    ///
    /// # Errors
    /// Fails on a read error or undecodable bytes.
    pub fn block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        let tx = self.db.begin_read()?;
        let blocks = tx.open_table(BLOCKS)?;
        blocks
            .get(hash.as_bytes())?
            .map(|bytes| Ok(Block::from_slice(bytes.value())?))
            .transpose()
    }

    /// The hash of the block at `height` on the current chain.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn hash_at(&self, height: u32) -> Result<Option<BlockHash>> {
        let tx = self.db.begin_read()?;
        let heights = tx.open_table(HEIGHTS)?;
        Ok(heights
            .get(height)?
            .map(|h| BlockHash::from_bytes(*h.value())))
    }

    /// Whether `nullifier` has been spent.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn contains_nullifier(&self, nullifier: &Nullifier) -> Result<bool> {
        let tx = self.db.begin_read()?;
        let nullifiers = tx.open_table(NULLIFIERS)?;
        Ok(nullifiers.get(&nullifier.to_bytes())?.is_some())
    }

    /// The commitment tree after the tip, or the empty tree before genesis.
    ///
    /// # Errors
    /// Fails on a read error or undecodable bytes.
    pub fn tree(&self) -> Result<CommitmentTree> {
        match self.tip()? {
            None => Ok(CommitmentTree::empty()),
            Some(tip) => self
                .tree_at(tip.height)?
                .ok_or(Error::Corrupt("tip frontier missing")),
        }
    }

    /// The commitment tree after the block at `height`.
    ///
    /// # Errors
    /// Fails on a read error or undecodable bytes.
    pub fn tree_at(&self, height: u32) -> Result<Option<CommitmentTree>> {
        let tx = self.db.begin_read()?;
        let frontiers = tx.open_table(FRONTIERS)?;
        frontiers
            .get(height)?
            .map(|bytes| Ok(CommitmentTree::from_slice(bytes.value())?))
            .transpose()
    }

    /// Whether an anchor equals the tree root at some height on the chain.
    ///
    /// Scans back from the tip up to `max_depth` blocks; anchors older than
    /// that are refused so transactions cannot spend against ancient roots.
    ///
    /// # Errors
    /// Fails on a read error.
    pub fn anchor_height(
        &self,
        anchor: &null_protocol::transaction::Anchor,
        max_depth: u32,
    ) -> Result<Option<u32>> {
        let Some(tip) = self.tip()? else {
            return Ok(None);
        };
        let floor = tip.height.saturating_sub(max_depth);
        for height in (floor..=tip.height).rev() {
            if self.tree_at(height)?.is_some_and(|t| t.root() == *anchor) {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    /// Deletes frontiers of heights below `height`, which limits how far
    /// back a revert can go. The caller keeps enough for its reorg policy.
    ///
    /// # Errors
    /// Fails on a write error.
    pub fn prune_frontiers_below(&self, height: u32) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut frontiers = tx.open_table(FRONTIERS)?;
            frontiers.retain(|h, _| h >= height)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Stores a block's bytes without applying it, for side-chain blocks
    /// that may become the best chain later.
    ///
    /// # Errors
    /// Fails on a write error.
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut blocks = tx.open_table(BLOCKS)?;
            blocks.insert(block.hash().as_bytes(), block.to_vec().as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Appends `block` to the tip, spending its nullifiers and recording
    /// `tree`, the commitment tree after the block. All or nothing.
    ///
    /// The caller has validated the block; this only checks that it
    /// extends the tip.
    ///
    /// # Errors
    /// Returns [`Error::NotOnTip`] if the block's previous hash or height
    /// does not match the tip, or a write error.
    pub fn apply(&self, block: &Block, tree: &CommitmentTree) -> Result<()> {
        let header = block.header();
        let expected_prev = match self.tip()? {
            Some(t) => (t.hash, next_height(t.height)?),
            None => (BlockHash::ZERO, 0),
        };
        if (header.prev_hash, header.height) != expected_prev {
            return Err(Error::NotOnTip);
        }
        let hash = block.hash();
        let tx = self.db.begin_write()?;
        {
            let mut blocks = tx.open_table(BLOCKS)?;
            blocks.insert(hash.as_bytes(), block.to_vec().as_slice())?;
            let mut heights = tx.open_table(HEIGHTS)?;
            heights.insert(header.height, hash.as_bytes())?;
            let mut nullifiers = tx.open_table(NULLIFIERS)?;
            for nf in block
                .transactions()
                .iter()
                .flat_map(null_protocol::transaction::Transaction::nullifiers)
            {
                if nullifiers.insert(&nf.to_bytes(), header.height)?.is_some() {
                    return Err(Error::Corrupt("nullifier already spent"));
                }
            }
            let mut frontiers = tx.open_table(FRONTIERS)?;
            frontiers.insert(header.height, tree.to_vec().as_slice())?;
            let mut txids = tx.open_table(TXIDS)?;
            for (index, transaction) in block.transactions().iter().enumerate() {
                let index = u32::try_from(index).map_err(|_| Error::Corrupt("index"))?;
                txids.insert(
                    transaction.txid().as_bytes(),
                    &encode_location(header.height, index),
                )?;
            }
            let mut meta = tx.open_table(META)?;
            meta.insert(TIP, hash.as_bytes())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Removes the tip block, unspending its nullifiers. The block bytes
    /// stay in the block table so a reorg can be inspected.
    ///
    /// # Errors
    /// Returns [`Error::Corrupt`] before genesis, or a write error.
    pub fn revert(&self) -> Result<Block> {
        let tip = self.tip()?.ok_or(Error::Corrupt("nothing to revert"))?;
        let block = self
            .block(&tip.hash)?
            .ok_or(Error::Corrupt("tip block missing"))?;
        let tx = self.db.begin_write()?;
        {
            let mut heights = tx.open_table(HEIGHTS)?;
            heights.remove(tip.height)?;
            let mut nullifiers = tx.open_table(NULLIFIERS)?;
            for nf in block
                .transactions()
                .iter()
                .flat_map(null_protocol::transaction::Transaction::nullifiers)
            {
                nullifiers.remove(&nf.to_bytes())?;
            }
            let mut frontiers = tx.open_table(FRONTIERS)?;
            frontiers.remove(tip.height)?;
            let mut txids = tx.open_table(TXIDS)?;
            for transaction in block.transactions() {
                txids.remove(transaction.txid().as_bytes())?;
            }
            let mut meta = tx.open_table(META)?;
            if tip.height == 0 {
                meta.remove(TIP)?;
            } else {
                meta.insert(TIP, block.header().prev_hash.as_bytes())?;
            }
        }
        tx.commit()?;
        Ok(block)
    }
}

fn encode_location(height: u32, index: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&height.to_le_bytes());
    out[4..].copy_from_slice(&index.to_le_bytes());
    out
}

fn decode_location(bytes: [u8; 8]) -> (u32, u32) {
    let (height, index) = bytes.split_at(4);
    (
        u32::from_le_bytes(height.try_into().unwrap_or([0; 4])),
        u32::from_le_bytes(index.try_into().unwrap_or([0; 4])),
    )
}

fn schema_bytes(version: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&version.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use null_crypto::pallas;
    use null_protocol::block::{empty_header, BlockHeader};
    use null_protocol::transaction::Anchor;

    use super::*;

    #[test]
    fn locations_round_trip() {
        assert_eq!(decode_location(encode_location(7, 3)), (7, 3));
        assert_eq!(decode_location(encode_location(u32::MAX, 0)), (u32::MAX, 0));
    }

    #[test]
    fn a_store_with_an_older_layout_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.redb");
        {
            // A store written by code that recorded no layout version but
            // had already applied genesis.
            let db = Database::create(&path).unwrap();
            let tx = db.begin_write().unwrap();
            {
                let mut meta = tx.open_table(META).unwrap();
                meta.insert(TIP, &[0u8; 32]).unwrap();
            }
            tx.commit().unwrap();
        }
        assert!(matches!(
            Store::open(&path),
            Err(Error::Corrupt(
                "store layout outdated; delete it and resync"
            ))
        ));
        let fresh = dir.path().join("fresh.redb");
        assert!(Store::open(&fresh).is_ok());
        assert!(Store::open(&fresh).is_ok(), "reopening keeps the version");
    }

    fn anchor(v: u64) -> Anchor {
        Anchor::from_base(pallas::Base::from(v))
    }

    fn cmx(v: u64) -> null_protocol::note::ExtractedNoteCommitment {
        null_protocol::note::ExtractedNoteCommitment::from_bytes(
            &null_crypto::encoding::base_to_bytes(&pallas::Base::from(v)),
        )
        .unwrap()
    }

    /// An empty block at `height` on top of `prev`.
    fn block(height: u32, prev: BlockHash) -> Block {
        let mut header: BlockHeader = empty_header(height, prev, anchor(u64::from(height)));
        header.timestamp = u64::from(height);
        Block::new(header, Vec::new())
    }

    #[test]
    fn fresh_store_has_no_tip_and_an_empty_tree() {
        let store = Store::in_memory().unwrap();
        assert_eq!(store.tip().unwrap(), None);
        assert_eq!(store.tree().unwrap(), CommitmentTree::empty());
        assert_eq!(store.hash_at(0).unwrap(), None);
    }

    #[test]
    fn apply_advances_the_tip_and_indexes_by_height() {
        let store = Store::in_memory().unwrap();
        let genesis = block(0, BlockHash::ZERO);
        store.apply(&genesis, &CommitmentTree::empty()).unwrap();
        let tip = store.tip().unwrap().unwrap();
        assert_eq!(
            tip,
            Tip {
                height: 0,
                hash: genesis.hash()
            }
        );
        assert_eq!(store.hash_at(0).unwrap(), Some(genesis.hash()));
        assert_eq!(store.block(&genesis.hash()).unwrap(), Some(genesis.clone()));

        let next = block(1, genesis.hash());
        store.apply(&next, &CommitmentTree::empty()).unwrap();
        assert_eq!(store.tip().unwrap().unwrap().height, 1);
    }

    #[test]
    fn blocks_that_do_not_extend_the_tip_are_refused() {
        let store = Store::in_memory().unwrap();
        assert!(matches!(
            store.apply(&block(1, BlockHash::ZERO), &CommitmentTree::empty()),
            Err(Error::NotOnTip)
        ));
        let genesis = block(0, BlockHash::ZERO);
        store.apply(&genesis, &CommitmentTree::empty()).unwrap();
        assert!(matches!(
            store.apply(&block(1, BlockHash::ZERO), &CommitmentTree::empty()),
            Err(Error::NotOnTip)
        ));
        assert!(matches!(
            store.apply(&block(2, genesis.hash()), &CommitmentTree::empty()),
            Err(Error::NotOnTip)
        ));
    }

    #[test]
    fn revert_restores_the_previous_tip_and_tree() {
        let store = Store::in_memory().unwrap();
        let genesis = block(0, BlockHash::ZERO);
        store.apply(&genesis, &CommitmentTree::empty()).unwrap();
        let mut tree = CommitmentTree::empty();
        tree.append(&cmx(1)).unwrap();
        let next = block(1, genesis.hash());
        store.apply(&next, &tree).unwrap();
        assert_eq!(store.tree().unwrap(), tree);

        let reverted = store.revert().unwrap();
        assert_eq!(reverted, next);
        assert_eq!(store.tip().unwrap().unwrap().height, 0);
        assert_eq!(store.tree().unwrap(), CommitmentTree::empty());
        assert_eq!(store.hash_at(1).unwrap(), None);
        assert!(
            store.block(&next.hash()).unwrap().is_some(),
            "block bytes are kept"
        );

        store.revert().unwrap();
        assert_eq!(store.tip().unwrap(), None);
        assert!(store.revert().is_err());
    }

    #[test]
    fn anchor_lookup_finds_recent_roots_only() {
        let store = Store::in_memory().unwrap();
        let mut prev = BlockHash::ZERO;
        let mut roots = Vec::new();
        for height in 0..5u32 {
            let mut tree = CommitmentTree::empty();
            for leaf in 0..=height {
                tree.append(&cmx(u64::from(leaf) + 1)).unwrap();
            }
            roots.push(tree.root());
            let b = block(height, prev);
            prev = b.hash();
            store.apply(&b, &tree).unwrap();
        }
        assert_eq!(store.anchor_height(&roots[4], 10).unwrap(), Some(4));
        assert_eq!(store.anchor_height(&roots[1], 10).unwrap(), Some(1));
        assert_eq!(store.anchor_height(&roots[1], 2).unwrap(), None, "too old");
        assert_eq!(store.anchor_height(&anchor(999), 10).unwrap(), None);
    }

    #[test]
    fn pruned_frontiers_are_gone_and_recent_ones_stay() {
        let store = Store::in_memory().unwrap();
        let mut prev = BlockHash::ZERO;
        for height in 0..4u32 {
            let b = block(height, prev);
            prev = b.hash();
            store.apply(&b, &CommitmentTree::empty()).unwrap();
        }
        store.prune_frontiers_below(2).unwrap();
        assert!(store.tree_at(1).unwrap().is_none());
        assert!(store.tree_at(2).unwrap().is_some());
        assert!(store.tree().is_ok(), "the tip frontier is kept");
    }

    /// Measures nullifier inserts and lookups at scale. Run with
    /// `cargo test --release -p null-storage nullifier_lookup_cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn nullifier_lookup_cost() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("bench.redb")).unwrap();
        let count = 1_000_000u64;
        let key_of = |i: u64| {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&i.to_le_bytes());
            key
        };
        let started = std::time::Instant::now();
        let tx = store.db.begin_write().unwrap();
        {
            let mut table = tx.open_table(NULLIFIERS).unwrap();
            for i in 0..count {
                table.insert(&key_of(i), 1u32).unwrap();
            }
        }
        tx.commit().unwrap();
        let inserted = started.elapsed();
        let started = std::time::Instant::now();
        let mut hits = 0;
        for i in 0..100_000u64 {
            let nf = Nullifier::from_bytes(&key_of(i * 7)).unwrap();
            if store.contains_nullifier(&nf).unwrap() {
                hits += 1;
            }
        }
        let looked_up = started.elapsed();
        eprintln!("insert {count}: {inserted:?}; 100000 lookups: {looked_up:?} ({hits} hits)");
    }

    #[test]
    fn put_block_stores_bytes_without_moving_the_tip() {
        let store = Store::in_memory().unwrap();
        let side = block(5, BlockHash::from_bytes([9; 32]));
        store.put_block(&side).unwrap();
        assert_eq!(store.block(&side.hash()).unwrap(), Some(side));
        assert_eq!(store.tip().unwrap(), None);
    }

    #[test]
    fn store_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        let genesis = block(0, BlockHash::ZERO);
        {
            let store = Store::open(&path).unwrap();
            store.apply(&genesis, &CommitmentTree::empty()).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.tip().unwrap().unwrap().hash, genesis.hash());
    }
}
