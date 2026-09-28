//! The note commitment tree: a depth-48 Merkle tree over Poseidon.
//!
//! This module holds the primitives shared by the circuit, the chain and
//! wallets: authentication paths, root computation and empty subtree roots.
//! [`MerkleTree`] is a naive full tree for tests and small sets; the
//! storage layer keeps a frontier instead.

use std::sync::LazyLock;

use ff::Field;
use incrementalmerkletree::{Hashable, Level};
use pasta_curves::pallas;

use crate::poseidon::merkle_node;
use crate::{Error, Result};

/// Depth of the tree, and so the length of every authentication path.
/// `2^48` leaves is over 100,000 years at the maximum block load; the
/// circuit pays for the extra levels with one row doubling over depth 32
/// (`docs/decisions.md`, 2026-09-13).
pub const MERKLE_DEPTH: usize = 48;

/// The value of an empty leaf.
pub const EMPTY_LEAF: pallas::Base = pallas::Base::ZERO;

/// Roots of empty subtrees, indexed by height above the leaves.
static EMPTY_ROOTS: LazyLock<[pallas::Base; MERKLE_DEPTH + 1]> = LazyLock::new(|| {
    let mut roots = [EMPTY_LEAF; MERKLE_DEPTH + 1];
    for level in 1..=MERKLE_DEPTH {
        // `level - 1` is in range because the loop starts at 1.
        #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        let below = roots[level - 1];
        #[allow(clippy::indexing_slicing)]
        {
            roots[level] = merkle_node(&below, &below);
        }
    }
    roots
});

/// The root of an empty subtree of the given height (0 is a leaf).
///
/// # Errors
/// Returns [`Error::InvalidDerivation`] above [`MERKLE_DEPTH`].
pub fn empty_root(height: usize) -> Result<pallas::Base> {
    EMPTY_ROOTS
        .get(height)
        .copied()
        .ok_or(Error::InvalidDerivation("height exceeds tree depth"))
}

/// A tree node for the incremental tree crates: a base field element
/// with the Poseidon combiner. Shared by the chain's frontier and the
/// wallet's witness tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node(pallas::Base);

impl Node {
    /// Wraps a field element.
    pub fn new(value: pallas::Base) -> Self {
        Self(value)
    }

    /// The wrapped element.
    pub fn inner(&self) -> &pallas::Base {
        &self.0
    }
}

impl Hashable for Node {
    fn empty_leaf() -> Self {
        Self(EMPTY_LEAF)
    }

    fn combine(_level: Level, a: &Self, b: &Self) -> Self {
        Self(merkle_node(&a.0, &b.0))
    }
}

/// An authentication path from a leaf to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    position: u64,
    siblings: [pallas::Base; MERKLE_DEPTH],
}

impl MerklePath {
    /// A path for the leaf at `position`, with siblings ordered from the
    /// leaf level upwards.
    pub fn new(position: u64, siblings: [pallas::Base; MERKLE_DEPTH]) -> Self {
        Self { position, siblings }
    }

    /// The leaf position.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Siblings from the leaf level upwards.
    pub fn siblings(&self) -> &[pallas::Base; MERKLE_DEPTH] {
        &self.siblings
    }

    /// The root this path leads to from `leaf`.
    pub fn root(&self, leaf: &pallas::Base) -> pallas::Base {
        self.siblings
            .iter()
            .enumerate()
            .fold(*leaf, |node, (level, sibling)| {
                if bit(self.position, level) {
                    merkle_node(sibling, &node)
                } else {
                    merkle_node(&node, sibling)
                }
            })
    }
}

/// Bit `index` of `position`, where bit 0 selects left or right at the leaf.
fn bit(position: u64, index: usize) -> bool {
    u32::try_from(index).is_ok_and(|shift| shift < 64 && (position >> shift) & 1 == 1)
}

/// A naive append-only tree that keeps every leaf and recomputes on demand.
#[derive(Clone, Debug, Default)]
pub struct MerkleTree {
    leaves: Vec<pallas::Base>,
}

impl MerkleTree {
    /// An empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Appends a leaf and returns its position.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDerivation`] when the tree is full.
    pub fn append(&mut self, leaf: pallas::Base) -> Result<u64> {
        let position = u64::try_from(self.leaves.len())
            .ok()
            .filter(|p| *p < 1u64 << MERKLE_DEPTH)
            .ok_or(Error::InvalidDerivation("tree is full"))?;
        self.leaves.push(leaf);
        Ok(position)
    }

    /// The current root.
    pub fn root(&self) -> pallas::Base {
        let empty = empty_root(MERKLE_DEPTH).unwrap_or(EMPTY_LEAF);
        self.level_nodes(MERKLE_DEPTH)
            .first()
            .copied()
            .unwrap_or(empty)
    }

    /// The authentication path of the leaf at `position`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDerivation`] for a position past the end.
    pub fn path(&self, position: u64) -> Result<MerklePath> {
        let index = usize::try_from(position).map_err(|_| Error::InvalidDerivation("position"))?;
        if index >= self.leaves.len() {
            return Err(Error::InvalidDerivation("no leaf at position"));
        }
        let mut siblings = [EMPTY_LEAF; MERKLE_DEPTH];
        let mut node_index = index;
        for (level, slot) in siblings.iter_mut().enumerate() {
            let nodes = self.level_nodes(level);
            let sibling_index = node_index ^ 1;
            *slot = nodes
                .get(sibling_index)
                .copied()
                .unwrap_or(empty_root(level)?);
            node_index >>= 1;
        }
        Ok(MerklePath::new(position, siblings))
    }

    /// Every non-empty node at `level`, left to right.
    fn level_nodes(&self, level: usize) -> Vec<pallas::Base> {
        let mut nodes = self.leaves.clone();
        for height in 0..level {
            let filler = empty_root(height).unwrap_or(EMPTY_LEAF);
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    merkle_node(
                        pair.first().unwrap_or(&filler),
                        pair.get(1).unwrap_or(&filler),
                    )
                })
                .collect();
        }
        nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(v: u64) -> pallas::Base {
        pallas::Base::from(v)
    }

    #[test]
    fn empty_roots_chain_upwards() {
        assert_eq!(empty_root(0), Ok(EMPTY_LEAF));
        let one = merkle_node(&EMPTY_LEAF, &EMPTY_LEAF);
        assert_eq!(empty_root(1), Ok(one));
        assert_eq!(empty_root(2), Ok(merkle_node(&one, &one)));
        assert!(empty_root(MERKLE_DEPTH + 1).is_err());
    }

    #[test]
    fn empty_tree_root_is_the_top_empty_root() {
        assert_eq!(MerkleTree::new().root(), empty_root(MERKLE_DEPTH).unwrap());
        assert!(MerkleTree::new().is_empty());
    }

    #[test]
    fn path_reproduces_root_for_every_leaf() {
        let mut tree = MerkleTree::new();
        for v in 0..5u64 {
            assert_eq!(tree.append(f(v + 1)).unwrap(), v);
        }
        assert_eq!(tree.len(), 5);
        let root = tree.root();
        for i in 0..5u64 {
            let path = tree.path(i).unwrap();
            assert_eq!(path.position(), i);
            assert_eq!(path.root(&f(i + 1)), root, "leaf {i}");
        }
    }

    #[test]
    fn root_matches_manual_two_leaf_computation() {
        let mut tree = MerkleTree::new();
        tree.append(f(1)).unwrap();
        tree.append(f(2)).unwrap();
        let mut node = merkle_node(&f(1), &f(2));
        for level in 1..MERKLE_DEPTH {
            node = merkle_node(&node, &empty_root(level).unwrap());
        }
        assert_eq!(tree.root(), node);
    }

    #[test]
    fn wrong_leaf_or_sibling_changes_the_root() {
        let mut tree = MerkleTree::new();
        tree.append(f(1)).unwrap();
        tree.append(f(2)).unwrap();
        let path = tree.path(1).unwrap();
        assert_ne!(path.root(&f(3)), tree.root());
        let mut siblings = *path.siblings();
        siblings[0] = f(9);
        assert_ne!(MerklePath::new(1, siblings).root(&f(2)), tree.root());
        assert_ne!(
            MerklePath::new(0, *path.siblings()).root(&f(2)),
            tree.root(),
            "wrong position"
        );
    }

    #[test]
    fn appending_changes_the_root_and_missing_paths_fail() {
        let mut tree = MerkleTree::new();
        tree.append(f(1)).unwrap();
        let before = tree.root();
        tree.append(f(2)).unwrap();
        assert_ne!(before, tree.root());
        assert!(tree.path(2).is_err());
    }

    #[test]
    fn bit_selects_from_the_least_significant_end() {
        assert!(bit(1, 0));
        assert!(!bit(1, 1));
        assert!(bit(0b100, 2));
        assert!(bit(u64::from(u32::MAX), 31));
        assert!(!bit(u64::from(u32::MAX), 40));
        assert!(bit(1 << 47, 47));
        assert!(!bit(u64::MAX, 64));
    }
}
