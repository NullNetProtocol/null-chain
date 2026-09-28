//! The note commitment tree as a frontier: only the rightmost path is
//! kept, which is all a node needs to append and compute roots. Wallets
//! that need witnesses keep their own structure.

use incrementalmerkletree::frontier::Frontier;
use incrementalmerkletree::Position;
use null_crypto::merkle::{Node, MERKLE_DEPTH};
use null_protocol::bytes::{Encodable, Reader, Writer};
use null_protocol::note::ExtractedNoteCommitment;
use null_protocol::transaction::Anchor;

use crate::{Error, Result};

/// Tree depth as the frontier type wants it.
const DEPTH: u8 = 48;
const _: () = assert!(DEPTH as usize == MERKLE_DEPTH);

/// The frontier of the note commitment tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentTree {
    frontier: Frontier<Node, DEPTH>,
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::empty()
    }
}

impl CommitmentTree {
    /// The empty tree.
    pub fn empty() -> Self {
        Self {
            frontier: Frontier::empty(),
        }
    }

    /// Appends a commitment and returns its position.
    ///
    /// # Errors
    /// Returns [`Error::TreeFull`] once `2^MERKLE_DEPTH` leaves are stored.
    pub fn append(&mut self, cmx: &ExtractedNoteCommitment) -> Result<u64> {
        let position = self.size();
        if self.frontier.append(Node::new(*cmx.inner())) {
            Ok(position)
        } else {
            Err(Error::TreeFull)
        }
    }

    /// Number of leaves.
    pub fn size(&self) -> u64 {
        self.frontier
            .value()
            .map_or(0, |f| u64::from(f.position()).saturating_add(1))
    }

    /// The current root, which later transactions may use as an anchor.
    pub fn root(&self) -> Anchor {
        Anchor::from_base(*self.frontier.root().inner())
    }
}

impl Encodable for CommitmentTree {
    fn write(&self, w: &mut Writer) {
        match self.frontier.value() {
            None => {
                w.put_u8(0);
            }
            Some(f) => {
                w.put_u8(1).put_u64_le(u64::from(f.position()));
                w.put(&null_crypto::encoding::base_to_bytes(f.leaf().inner()));
                // At most MERKLE_DEPTH ommers, so the count fits a byte.
                w.put_u8(u8::try_from(f.ommers().len()).unwrap_or(u8::MAX));
                for ommer in f.ommers() {
                    w.put(&null_crypto::encoding::base_to_bytes(ommer.inner()));
                }
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> null_protocol::Result<Self> {
        match r.take_u8()? {
            0 => Ok(Self::empty()),
            1 => {
                let position = Position::from(r.take_u64_le()?);
                let leaf = Node::new(null_crypto::encoding::base_from_bytes(&r.take_array()?)?);
                let count = usize::from(r.take_u8()?);
                let ommers = (0..count)
                    .map(|_| {
                        Ok(Node::new(null_crypto::encoding::base_from_bytes(
                            &r.take_array()?,
                        )?))
                    })
                    .collect::<null_protocol::Result<Vec<_>>>()?;
                let frontier = Frontier::from_parts(position, leaf, ommers)
                    .map_err(|_| null_protocol::Error::Malformed("inconsistent frontier"))?;
                Ok(Self { frontier })
            }
            _ => Err(null_protocol::Error::Malformed("unknown frontier tag")),
        }
    }
}

/// Conversion helper so callers can name the error without importing `redb`.
impl From<incrementalmerkletree::frontier::FrontierError> for Error {
    fn from(_: incrementalmerkletree::frontier::FrontierError) -> Self {
        Self::Corrupt("frontier")
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use null_crypto::merkle::MerkleTree;
    use null_crypto::pallas;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn cmx(v: u64) -> ExtractedNoteCommitment {
        ExtractedNoteCommitment::from_bytes(&null_crypto::encoding::base_to_bytes(
            &pallas::Base::from(v),
        ))
        .unwrap()
    }

    #[test]
    fn empty_frontier_matches_the_naive_empty_tree() {
        assert_eq!(
            CommitmentTree::empty().root().inner(),
            &MerkleTree::new().root()
        );
        assert_eq!(CommitmentTree::empty().size(), 0);
    }

    #[test]
    fn frontier_root_matches_the_naive_tree_after_every_append() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut frontier = CommitmentTree::empty();
        let mut naive = MerkleTree::new();
        for i in 0..9u64 {
            let leaf = pallas::Base::random(&mut rng);
            let c =
                ExtractedNoteCommitment::from_bytes(&null_crypto::encoding::base_to_bytes(&leaf))
                    .unwrap();
            assert_eq!(frontier.append(&c).unwrap(), i);
            naive.append(leaf).unwrap();
            assert_eq!(
                frontier.root().inner(),
                &naive.root(),
                "after {} leaves",
                i + 1
            );
            assert_eq!(frontier.size(), i + 1);
        }
    }

    #[test]
    fn encoding_roundtrips_empty_and_non_empty() {
        let empty = CommitmentTree::empty();
        assert_eq!(CommitmentTree::from_slice(&empty.to_vec()).unwrap(), empty);
        let mut tree = CommitmentTree::empty();
        for v in 1..=5 {
            tree.append(&cmx(v)).unwrap();
        }
        let decoded = CommitmentTree::from_slice(&tree.to_vec()).unwrap();
        assert_eq!(decoded, tree);
        assert_eq!(decoded.root(), tree.root());
    }

    #[test]
    fn garbage_encodings_are_rejected() {
        assert!(CommitmentTree::from_slice(&[2]).is_err());
        assert!(CommitmentTree::from_slice(&[1, 0]).is_err());
    }
}
