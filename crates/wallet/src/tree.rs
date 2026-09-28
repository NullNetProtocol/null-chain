//! The witness tree: the note commitment tree pruned to what the wallet
//! needs, stored in shards inside the wallet database.
//!
//! The tree is a [`shardtree::ShardTree`] of depth 48 with shards of
//! height 16. Leaves the wallet owns are marked and kept; everything else
//! is pruned to subtree roots as soon as it is complete, so the file grows
//! with the number of owned notes, not with the chain. One checkpoint is
//! taken per scanned block, which is what rollback and witnesses use.
//!
//! Tables:
//!
//! | table | key | value |
//! |---|---|---|
//! | `shards` | shard index | encoded pruned subtree |
//! | `cap` | `()` | encoded pruned tree above the shards |
//! | `checkpoints` | height | tree state, marks removed at that height |
//!
//! The store is generic over the redb table handle, so a read transaction
//! can compute witnesses and a write transaction can append; writes through
//! a read-only handle fail with [`Error::ReadOnly`].

use std::collections::BTreeSet;
use std::sync::Arc;

use incrementalmerkletree::{Address, Level, Position, Retention};
use null_crypto::encoding::{base_from_bytes, base_to_bytes};
use null_crypto::merkle::{MerklePath, Node, MERKLE_DEPTH};
use null_protocol::bytes::{Reader, Writer};
use null_protocol::transaction::Anchor;
use redb::{Key, ReadOnlyTable, ReadableTable, Table, TableDefinition};
use shardtree::error::ShardTreeError;
use shardtree::store::{Checkpoint, ShardStore, TreeState};
use shardtree::{
    LocatedPrunableTree, LocatedTree, Node as TreeNode, PrunableTree, RetentionFlags, ShardTree,
    Tree,
};

use crate::{Error, Result};

/// Shard subtrees by index.
pub const SHARDS: TableDefinition<u64, &[u8]> = TableDefinition::new("shards");
/// The pruned tree above the shards, a single row.
pub const CAP: TableDefinition<(), &[u8]> = TableDefinition::new("cap");
/// Checkpoints by height.
pub const CHECKPOINTS: TableDefinition<u32, &[u8]> = TableDefinition::new("checkpoints");

/// Tree depth as the shard tree wants it.
pub const DEPTH: u8 = 48;
const _: () = assert!(DEPTH as usize == MERKLE_DEPTH);
/// Height of one shard: `2^16` leaves each.
pub const SHARD_HEIGHT: u8 = 16;
/// Checkpoints retained, one per scanned block. Rolling back further than
/// this fails, so it must exceed the chain's maximum reorganization depth.
pub const MAX_CHECKPOINTS: usize = 256;

const TAG_NIL: u8 = 0;
const TAG_LEAF: u8 = 1;
const TAG_PARENT: u8 = 2;
const TAG_EMPTY: u8 = 0;
const TAG_AT_POSITION: u8 = 1;

/// A redb table handle with the writes the store needs. Read-only handles
/// refuse them.
pub trait Slot<K: Key + 'static>: ReadableTable<K, &'static [u8]> {
    /// Inserts or replaces a row.
    ///
    /// # Errors
    /// Fails on a database error, or [`Error::ReadOnly`].
    fn put(&mut self, key: K::SelfType<'_>, value: &[u8]) -> Result<()>;
    /// Removes a row if present.
    ///
    /// # Errors
    /// Fails on a database error, or [`Error::ReadOnly`].
    fn delete(&mut self, key: K::SelfType<'_>) -> Result<()>;
    /// Keeps only the rows whose key satisfies `keep`.
    ///
    /// # Errors
    /// Fails on a database error, or [`Error::ReadOnly`].
    fn keep(&mut self, keep: impl for<'f> FnMut(K::SelfType<'f>) -> bool) -> Result<()>;
}

impl<K: Key + 'static> Slot<K> for Table<'_, K, &'static [u8]> {
    fn put(&mut self, key: K::SelfType<'_>, value: &[u8]) -> Result<()> {
        self.insert(key, value)?;
        Ok(())
    }

    fn delete(&mut self, key: K::SelfType<'_>) -> Result<()> {
        self.remove(key)?;
        Ok(())
    }

    fn keep(&mut self, mut keep: impl for<'f> FnMut(K::SelfType<'f>) -> bool) -> Result<()> {
        self.retain(|k, _| keep(k))?;
        Ok(())
    }
}

impl<K: Key + 'static> Slot<K> for ReadOnlyTable<K, &'static [u8]> {
    fn put(&mut self, _: K::SelfType<'_>, _: &[u8]) -> Result<()> {
        Err(Error::ReadOnly)
    }

    fn delete(&mut self, _: K::SelfType<'_>) -> Result<()> {
        Err(Error::ReadOnly)
    }

    fn keep(&mut self, _: impl for<'f> FnMut(K::SelfType<'f>) -> bool) -> Result<()> {
        Err(Error::ReadOnly)
    }
}

/// The shard store over three table handles.
pub struct Store<S, P, C> {
    shards: S,
    cap: P,
    checkpoints: C,
}

impl<S, P, C> Store<S, P, C> {
    /// Wraps the table handles.
    pub fn new(shards: S, cap: P, checkpoints: C) -> Self {
        Self {
            shards,
            cap,
            checkpoints,
        }
    }
}

/// The witness tree over a store.
pub type WitnessTree<S, P, C> = ShardTree<Store<S, P, C>, DEPTH, SHARD_HEIGHT>;

/// Builds the tree over the table handles.
pub fn witness_tree<S, P, C>(shards: S, cap: P, checkpoints: C) -> WitnessTree<S, P, C>
where
    S: Slot<u64>,
    P: Slot<()>,
    C: Slot<u32>,
{
    ShardTree::new(Store::new(shards, cap, checkpoints), MAX_CHECKPOINTS)
}

/// The address of the shard with the given index.
fn shard_address(index: u64) -> Address {
    Address::from_parts(Level::from(SHARD_HEIGHT), index)
}

impl From<ShardTreeError<Error>> for Error {
    fn from(e: ShardTreeError<Error>) -> Self {
        match e {
            ShardTreeError::Storage(inner) => inner,
            ShardTreeError::Query(q) => Self::Tree(format!("{q:?}")),
            ShardTreeError::Insert(i) => Self::Tree(format!("{i:?}")),
        }
    }
}

impl<S, P, C> Store<S, P, C>
where
    S: Slot<u64>,
    P: Slot<()>,
    C: Slot<u32>,
{
    fn checkpoints_from_tip<F>(&self, limit: usize, mut callback: F) -> Result<()>
    where
        F: FnMut(&u32, &Checkpoint) -> Result<()>,
    {
        // Checkpoint ids are heights, so key order is history order and
        // the callback sees the oldest retained checkpoints first.
        for row in self.checkpoints.iter()?.take(limit) {
            let (id, value) = row?;
            callback(&id.value(), &decode_checkpoint(value.value())?)?;
        }
        Ok(())
    }
}

impl<S, P, C> ShardStore for Store<S, P, C>
where
    S: Slot<u64>,
    P: Slot<()>,
    C: Slot<u32>,
{
    type H = Node;
    type CheckpointId = u32;
    type Error = Error;

    fn get_shard(&self, shard_root: Address) -> Result<Option<LocatedPrunableTree<Node>>> {
        self.shards
            .get(shard_root.index())?
            .map(|row| decode_shard(shard_root, row.value()))
            .transpose()
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Node>>> {
        self.shards
            .last()?
            .map(|(index, row)| decode_shard(shard_address(index.value()), row.value()))
            .transpose()
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Node>) -> Result<()> {
        let index = subtree.root_addr().index();
        self.shards.put(index, &encode_tree(subtree.root()))
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>> {
        self.shards
            .iter()?
            .map(|row| Ok(shard_address(row?.0.value())))
            .collect()
    }

    fn truncate_shards(&mut self, shard_index: u64) -> Result<()> {
        self.shards.keep(|index| index < shard_index)
    }

    fn get_cap(&self) -> Result<PrunableTree<Node>> {
        self.cap
            .get(())?
            .map_or_else(|| Ok(Tree::empty()), |row| decode_tree(row.value()))
    }

    fn put_cap(&mut self, cap: PrunableTree<Node>) -> Result<()> {
        self.cap.put((), &encode_tree(&cap))
    }

    fn min_checkpoint_id(&self) -> Result<Option<u32>> {
        Ok(self.checkpoints.first()?.map(|(k, _)| k.value()))
    }

    fn max_checkpoint_id(&self) -> Result<Option<u32>> {
        Ok(self.checkpoints.last()?.map(|(k, _)| k.value()))
    }

    fn add_checkpoint(&mut self, checkpoint_id: u32, checkpoint: Checkpoint) -> Result<()> {
        self.checkpoints
            .put(checkpoint_id, &encode_checkpoint(&checkpoint))
    }

    fn checkpoint_count(&self) -> Result<usize> {
        Ok(usize::try_from(self.checkpoints.len()?).unwrap_or(usize::MAX))
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(u32, Checkpoint)>> {
        self.checkpoints
            .iter()?
            .rev()
            .nth(checkpoint_depth)
            .map(|row| {
                let (id, value) = row?;
                Ok((id.value(), decode_checkpoint(value.value())?))
            })
            .transpose()
    }

    fn get_checkpoint(&self, checkpoint_id: &u32) -> Result<Option<Checkpoint>> {
        self.checkpoints
            .get(*checkpoint_id)?
            .map(|row| decode_checkpoint(row.value()))
            .transpose()
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<()>
    where
        F: FnMut(&u32, &Checkpoint) -> Result<()>,
    {
        self.checkpoints_from_tip(limit, callback)
    }

    fn for_each_checkpoint<F>(&self, limit: usize, callback: F) -> Result<()>
    where
        F: FnMut(&u32, &Checkpoint) -> Result<()>,
    {
        self.checkpoints_from_tip(limit, callback)
    }

    fn update_checkpoint_with<F>(&mut self, checkpoint_id: &u32, update: F) -> Result<bool>
    where
        F: Fn(&mut Checkpoint) -> Result<()>,
    {
        let Some(mut checkpoint) = self.get_checkpoint(checkpoint_id)? else {
            return Ok(false);
        };
        update(&mut checkpoint)?;
        self.add_checkpoint(*checkpoint_id, checkpoint)?;
        Ok(true)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &u32) -> Result<()> {
        self.checkpoints.delete(*checkpoint_id)
    }

    fn truncate_checkpoints_retaining(&mut self, checkpoint_id: &u32) -> Result<()> {
        self.checkpoints.keep(|id| id <= *checkpoint_id)?;
        if let Some(checkpoint) = self.get_checkpoint(checkpoint_id)? {
            let cleared = Checkpoint::from_parts(checkpoint.tree_state(), BTreeSet::new());
            self.add_checkpoint(*checkpoint_id, cleared)?;
        }
        Ok(())
    }
}

fn decode_shard(addr: Address, bytes: &[u8]) -> Result<LocatedPrunableTree<Node>> {
    LocatedTree::from_parts(addr, decode_tree(bytes)?).map_err(|_| Error::Corrupt("shard address"))
}

fn put_node(w: &mut Writer, node: &Node) {
    w.put(&base_to_bytes(node.inner()));
}

fn take_node(r: &mut Reader<'_>) -> Result<Node> {
    Ok(Node::new(base_from_bytes(&r.take_array()?)?))
}

fn write_tree(w: &mut Writer, tree: &PrunableTree<Node>) {
    match &**tree {
        TreeNode::Nil => {
            w.put_u8(TAG_NIL);
        }
        TreeNode::Leaf {
            value: (node, flags),
        } => {
            w.put_u8(TAG_LEAF);
            put_node(w, node);
            w.put_u8(flags.bits());
        }
        TreeNode::Parent { ann, left, right } => {
            w.put_u8(TAG_PARENT);
            match ann {
                Some(node) => {
                    w.put_u8(1);
                    put_node(w, node);
                }
                None => {
                    w.put_u8(0);
                }
            }
            write_tree(w, left);
            write_tree(w, right);
        }
    }
}

/// Serializes a pruned tree: a pre-order walk with one tag byte per node.
#[must_use]
pub fn encode_tree(tree: &PrunableTree<Node>) -> Vec<u8> {
    let mut w = Writer::with_capacity(64);
    write_tree(&mut w, tree);
    w.into_bytes()
}

fn read_tree(r: &mut Reader<'_>, depth: u8) -> Result<PrunableTree<Node>> {
    if depth > DEPTH {
        return Err(Error::Corrupt("tree deeper than the commitment tree"));
    }
    match r.take_u8()? {
        TAG_NIL => Ok(Tree::empty()),
        TAG_LEAF => {
            let node = take_node(r)?;
            let flags =
                RetentionFlags::from_bits(r.take_u8()?).ok_or(Error::Corrupt("retention flags"))?;
            Ok(Tree::leaf((node, flags)))
        }
        TAG_PARENT => {
            let ann = match r.take_u8()? {
                0 => None,
                1 => Some(Arc::new(take_node(r)?)),
                _ => return Err(Error::Corrupt("annotation tag")),
            };
            let below = depth.saturating_add(1);
            let left = read_tree(r, below)?;
            let right = read_tree(r, below)?;
            Ok(Tree::parent(ann, left, right))
        }
        _ => Err(Error::Corrupt("tree node tag")),
    }
}

/// Parses a tree written by [`encode_tree`].
///
/// # Errors
/// Returns [`Error::Corrupt`] on a malformed encoding.
pub fn decode_tree(bytes: &[u8]) -> Result<PrunableTree<Node>> {
    let mut r = Reader::new(bytes);
    let tree = read_tree(&mut r, 0)?;
    r.finish()?;
    Ok(tree)
}

/// Serializes a checkpoint: the tree state and the positions whose marks
/// were removed at it.
#[must_use]
pub fn encode_checkpoint(checkpoint: &Checkpoint) -> Vec<u8> {
    let mut w = Writer::with_capacity(16);
    match checkpoint.tree_state() {
        TreeState::Empty => {
            w.put_u8(TAG_EMPTY);
        }
        TreeState::AtPosition(position) => {
            w.put_u8(TAG_AT_POSITION).put_u64_le(u64::from(position));
        }
    }
    let removed = checkpoint.marks_removed();
    w.put_u64_le(u64::try_from(removed.len()).unwrap_or(u64::MAX));
    for position in removed {
        w.put_u64_le(u64::from(*position));
    }
    w.into_bytes()
}

/// Parses a checkpoint written by [`encode_checkpoint`].
///
/// # Errors
/// Returns [`Error::Corrupt`] on a malformed encoding.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<Checkpoint> {
    let mut r = Reader::new(bytes);
    let state = match r.take_u8()? {
        TAG_EMPTY => TreeState::Empty,
        TAG_AT_POSITION => TreeState::AtPosition(Position::from(r.take_u64_le()?)),
        _ => return Err(Error::Corrupt("checkpoint tag")),
    };
    let count = r.take_u64_le()?;
    if count > u64::try_from(r.remaining()).unwrap_or(u64::MAX) {
        return Err(Error::Corrupt("checkpoint length"));
    }
    let removed = (0..count)
        .map(|_| Ok(Position::from(r.take_u64_le()?)))
        .collect::<Result<BTreeSet<_>>>()?;
    r.finish()?;
    Ok(Checkpoint::from_parts(state, removed))
}

/// Retention for a leaf the wallet appends: marked if it owns the note.
#[must_use]
pub fn retention(owned: bool) -> Retention<u32> {
    if owned {
        Retention::Marked
    } else {
        Retention::Ephemeral
    }
}

/// Converts a witness from the shard tree to the protocol's path type.
///
/// # Errors
/// Returns [`Error::Corrupt`] if the path does not have `MERKLE_DEPTH`
/// siblings.
pub fn to_merkle_path(path: &incrementalmerkletree::MerklePath<Node, DEPTH>) -> Result<MerklePath> {
    let mut siblings = [null_crypto::merkle::EMPTY_LEAF; MERKLE_DEPTH];
    if path.path_elems().len() != MERKLE_DEPTH {
        return Err(Error::Corrupt("witness length"));
    }
    for (slot, node) in siblings.iter_mut().zip(path.path_elems()) {
        *slot = *node.inner();
    }
    Ok(MerklePath::new(u64::from(path.position()), siblings))
}

/// The anchor for a tree root node.
#[must_use]
pub fn anchor_of(root: &Node) -> Anchor {
    Anchor::from_base(*root.inner())
}

#[cfg(test)]
mod tests {
    use null_crypto::merkle::MerkleTree;
    use null_crypto::pallas;
    use redb::{Database, ReadableDatabase};

    use super::*;

    fn leaf(i: u64) -> Node {
        Node::new(pallas::Base::from(i.saturating_add(1)))
    }

    fn db() -> Database {
        Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .unwrap()
    }

    #[test]
    fn tree_and_checkpoint_encodings_round_trip() {
        let tree: PrunableTree<Node> = Tree::parent(
            Some(Arc::new(leaf(9))),
            Tree::leaf((leaf(1), RetentionFlags::MARKED | RetentionFlags::CHECKPOINT)),
            Tree::parent(
                None,
                Tree::empty(),
                Tree::leaf((leaf(2), RetentionFlags::EPHEMERAL)),
            ),
        );
        let bytes = encode_tree(&tree);
        assert_eq!(decode_tree(&bytes).unwrap(), tree);
        assert!(decode_tree(&[7]).is_err(), "unknown tag");
        assert!(decode_tree(&[TAG_LEAF]).is_err(), "truncated");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_tree(&trailing).is_err(), "trailing byte");
        let too_deep = [TAG_PARENT, 0].repeat(MERKLE_DEPTH + 8);
        assert!(matches!(
            decode_tree(&too_deep),
            Err(Error::Corrupt("tree deeper than the commitment tree"))
        ));

        let checkpoint = Checkpoint::from_parts(
            TreeState::AtPosition(Position::from(5)),
            [Position::from(1), Position::from(3)].into_iter().collect(),
        );
        let decoded = decode_checkpoint(&encode_checkpoint(&checkpoint)).unwrap();
        assert_eq!(decoded.tree_state(), checkpoint.tree_state());
        assert_eq!(decoded.marks_removed(), checkpoint.marks_removed());
        let empty = decode_checkpoint(&encode_checkpoint(&Checkpoint::tree_empty())).unwrap();
        assert_eq!(empty.tree_state(), TreeState::Empty);
        assert!(decode_checkpoint(&[TAG_EMPTY, 9, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn witnesses_match_the_naive_tree_and_survive_rollback() {
        let db = db();
        let mut naive = MerkleTree::new();
        // Three blocks of leaves; leaf 3 and leaf 6 are owned.
        let blocks: [&[u64]; 3] = [&[0, 1, 2, 3], &[4, 5, 6], &[7, 8]];
        let owned = [3u64, 6];
        for (height, leaves) in (0u32..).zip(blocks) {
            let tx = db.begin_write().unwrap();
            {
                let mut tree = witness_tree(
                    tx.open_table(SHARDS).unwrap(),
                    tx.open_table(CAP).unwrap(),
                    tx.open_table(CHECKPOINTS).unwrap(),
                );
                let start = Position::from(leaves[0]);
                tree.batch_insert(
                    start,
                    leaves
                        .iter()
                        .map(|&i| (leaf(i), retention(owned.contains(&i)))),
                )
                .unwrap();
                assert!(tree.checkpoint(height).unwrap());
            }
            tx.commit().unwrap();
            for &i in leaves {
                naive.append(*leaf(i).inner()).unwrap();
            }
        }

        let read = db.begin_read().unwrap();
        let mut tree = witness_tree(
            read.open_table(SHARDS).unwrap(),
            read.open_table(CAP).unwrap(),
            read.open_table(CHECKPOINTS).unwrap(),
        );
        let root = tree.root_at_checkpoint_id(&2).unwrap().unwrap();
        assert_eq!(anchor_of(&root), Anchor::from_base(naive.root()));
        for &i in &owned {
            let path = tree
                .witness_at_checkpoint_id(Position::from(i), &2)
                .unwrap()
                .unwrap();
            let path = to_merkle_path(&path).unwrap();
            assert_eq!(path, naive.path(i).unwrap());
        }
        assert!(
            tree.witness_at_checkpoint_id(Position::from(1), &2)
                .is_err(),
            "unmarked leaves have no witness"
        );
        assert!(matches!(
            tree.checkpoint(3),
            Err(ShardTreeError::Storage(Error::ReadOnly))
        ));
        drop(tree);
        drop(read);

        // Roll back to height 0: leaf 6 disappears, leaf 3 keeps its witness.
        let tx = db.begin_write().unwrap();
        {
            let mut tree = witness_tree(
                tx.open_table(SHARDS).unwrap(),
                tx.open_table(CAP).unwrap(),
                tx.open_table(CHECKPOINTS).unwrap(),
            );
            assert!(tree.truncate_to_checkpoint(&0).unwrap());
            assert!(!tree.truncate_to_checkpoint(&7).unwrap());
            assert_eq!(
                tree.max_leaf_position(None).unwrap(),
                Some(Position::from(3))
            );
            let mut short = MerkleTree::new();
            for i in 0..4 {
                short.append(*leaf(i).inner()).unwrap();
            }
            let path = tree
                .witness_at_checkpoint_id(Position::from(3), &0)
                .unwrap()
                .unwrap();
            assert_eq!(to_merkle_path(&path).unwrap(), short.path(3).unwrap());
            assert!(tree
                .witness_at_checkpoint_id(Position::from(6), &0)
                .is_err());
        }
        tx.commit().unwrap();
    }

    #[test]
    fn old_checkpoints_are_pruned_and_marks_removed_at_a_checkpoint_return_on_rollback() {
        let db = db();
        let tx = db.begin_write().unwrap();
        {
            let mut tree = witness_tree(
                tx.open_table(SHARDS).unwrap(),
                tx.open_table(CAP).unwrap(),
                tx.open_table(CHECKPOINTS).unwrap(),
            );
            tree.append(leaf(0), Retention::Marked).unwrap();
            let total = u32::try_from(MAX_CHECKPOINTS).unwrap() + 10;
            for height in 0..total {
                tree.append(leaf(u64::from(height) + 1), Retention::Ephemeral)
                    .unwrap();
                assert!(tree.checkpoint(height).unwrap());
            }
            assert_eq!(tree.store().checkpoint_count().unwrap(), MAX_CHECKPOINTS);
            assert_eq!(tree.store().min_checkpoint_id().unwrap(), Some(10));
            assert_eq!(tree.store().max_checkpoint_id().unwrap(), Some(total - 1));
            assert!(!tree.truncate_to_checkpoint(&5).unwrap(), "pruned");

            // Spending at the tip removes the mark as of that checkpoint.
            assert!(tree
                .remove_mark(Position::from(0), Some(&(total - 1)))
                .unwrap());
            assert!(tree
                .witness_at_checkpoint_id(Position::from(0), &(total - 1))
                .unwrap()
                .is_some());
            assert!(tree.truncate_to_checkpoint(&(total - 2)).unwrap());
            assert!(tree
                .witness_at_checkpoint_id(Position::from(0), &(total - 2))
                .unwrap()
                .is_some());
            assert!(tree.checkpoint(total - 1).unwrap());
            assert!(tree
                .remove_mark(Position::from(0), Some(&(total - 1)))
                .unwrap());
            assert_eq!(tree.store().get_shard_roots().unwrap().len(), 1);
        }
        tx.commit().unwrap();
    }
}
