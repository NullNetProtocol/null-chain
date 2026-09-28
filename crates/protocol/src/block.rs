//! Blocks: a fixed-size header over a list of transactions.
//!
//! ```text
//! header = version || prev_hash || height || timestamp || commitment_root
//!          || tx_root || target || nonce || solution
//! hash   = BLAKE2b-256_{BLOCK_HASH}(header)
//! tx_root = BLAKE2b-256_{TX_ROOT}(txid_1 || txid_2 || ...)
//! ```
//!
//! `commitment_root` is the note commitment tree root *after* applying
//! the block, so it doubles as the anchor later transactions may use.
//! Proof-of-work semantics of `target`, `nonce` and `solution` live in the
//! chain crate; the protocol only fixes their layout.

use null_crypto::encoding::{to_hex, Encoded};
use null_crypto::hash::{blake2b_short, BLOCK_HASH, SHORT_OUTPUT_LEN, TX_ROOT};

use crate::bytes::{Encodable, Reader, Writer};
use crate::consensus::{BLOCK_VERSION, MAX_BLOCK_TRANSACTIONS, POW_SOLUTION_LEN};
use crate::transaction::{Anchor, Transaction, TxId};
use crate::{Error, Result};

/// A block identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct BlockHash([u8; SHORT_OUTPUT_LEN]);

impl BlockHash {
    /// The all-zero hash, used as the previous hash of the genesis block.
    pub const ZERO: Self = Self([0; SHORT_OUTPUT_LEN]);

    /// Wraps raw bytes.
    pub fn from_bytes(bytes: [u8; SHORT_OUTPUT_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; SHORT_OUTPUT_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BlockHash({self})")
    }
}

impl core::fmt::Display for BlockHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&to_hex(&self.0))
    }
}

/// The proof-of-work solution bytes, fixed length.
#[derive(Clone, PartialEq, Eq)]
pub struct PowSolution([u8; POW_SOLUTION_LEN]);

impl PowSolution {
    /// Wraps solution bytes.
    pub fn from_bytes(bytes: [u8; POW_SOLUTION_LEN]) -> Self {
        Self(bytes)
    }

    /// An all-zero solution, for tests and for headers under construction.
    pub fn empty() -> Self {
        Self([0; POW_SOLUTION_LEN])
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; POW_SOLUTION_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for PowSolution {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PowSolution({POW_SOLUTION_LEN} bytes)")
    }
}

/// The block header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Format version.
    pub version: u8,
    /// Hash of the previous block, zero for genesis.
    pub prev_hash: BlockHash,
    /// Height, zero for genesis.
    pub height: u32,
    /// Seconds since the Unix epoch.
    pub timestamp: u64,
    /// Note commitment tree root after this block.
    pub commitment_root: Anchor,
    /// Commitment to the transactions.
    pub tx_root: [u8; SHORT_OUTPUT_LEN],
    /// Compact difficulty target.
    pub target: u32,
    /// Proof-of-work nonce.
    pub nonce: Encoded,
    /// Proof-of-work solution.
    pub solution: PowSolution,
}

/// Byte length of an encoded header.
pub const HEADER_LEN: usize = 1 + 32 + 4 + 8 + 32 + 32 + 4 + 32 + POW_SOLUTION_LEN;

impl BlockHeader {
    /// The block hash.
    pub fn hash(&self) -> BlockHash {
        BlockHash(blake2b_short(BLOCK_HASH, &[&self.to_vec()]))
    }

    /// The header without the proof-of-work fields, the input the solver
    /// commits to.
    pub fn pow_input(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(HEADER_LEN);
        self.write_pow_input(&mut w);
        w.into_bytes()
    }

    fn write_pow_input(&self, w: &mut Writer) {
        w.put_u8(self.version)
            .put(self.prev_hash.as_bytes())
            .put(&self.height.to_le_bytes())
            .put_u64_le(self.timestamp)
            .put(&self.commitment_root.to_bytes())
            .put(&self.tx_root)
            .put(&self.target.to_le_bytes());
    }
}

impl Encodable for BlockHeader {
    fn write(&self, w: &mut Writer) {
        self.write_pow_input(w);
        w.put(&self.nonce).put(self.solution.as_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            version: r.take_u8()?,
            prev_hash: BlockHash::from_bytes(r.take_array()?),
            height: u32::from_le_bytes(r.take_array()?),
            timestamp: r.take_u64_le()?,
            commitment_root: Anchor::read(r)?,
            tx_root: r.take_array()?,
            target: u32::from_le_bytes(r.take_array()?),
            nonce: r.take_array()?,
            solution: PowSolution::from_bytes(r.take_array()?),
        })
    }
}

/// A block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

impl Block {
    /// Assembles a block. Consistency of `header.tx_root` with the
    /// transactions is checked by [`Block::check_tx_root`].
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    /// The header.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// The transactions.
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    /// The block hash.
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// The commitment to this block's transactions.
    pub fn tx_root(&self) -> [u8; SHORT_OUTPUT_LEN] {
        tx_root(self.transactions.iter().map(Transaction::txid))
    }

    /// Whether the header commits to exactly these transactions.
    ///
    /// # Errors
    /// Returns [`Error::InvalidBlock`] on a mismatch.
    pub fn check_tx_root(&self) -> Result<()> {
        if self.tx_root() == self.header.tx_root {
            Ok(())
        } else {
            Err(Error::InvalidBlock("transaction root mismatch"))
        }
    }
}

/// The transaction root over a list of transaction ids.
pub fn tx_root(txids: impl IntoIterator<Item = TxId>) -> [u8; SHORT_OUTPUT_LEN] {
    let mut w = Writer::default();
    for txid in txids {
        w.put(txid.as_bytes());
    }
    blake2b_short(TX_ROOT, &[&w.into_bytes()])
}

impl Encodable for Block {
    fn write(&self, w: &mut Writer) {
        self.header.write(w);
        // Bounded by MAX_BLOCK_TRANSACTIONS in valid blocks.
        let count = u32::try_from(self.transactions.len()).unwrap_or(u32::MAX);
        w.put(&count.to_le_bytes());
        for tx in &self.transactions {
            tx.write(w);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let header = BlockHeader::read(r)?;
        let count = usize::try_from(u32::from_le_bytes(r.take_array()?))
            .map_err(|_| Error::Malformed("transaction count"))?;
        if count > MAX_BLOCK_TRANSACTIONS {
            return Err(Error::InvalidBlock("too many transactions"));
        }
        let transactions = (0..count)
            .map(|_| Transaction::read(r))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            header,
            transactions,
        })
    }
}

/// A header with every field zero except the given ones, for tests and
/// for the genesis block.
pub fn empty_header(height: u32, prev_hash: BlockHash, commitment_root: Anchor) -> BlockHeader {
    BlockHeader {
        version: BLOCK_VERSION,
        prev_hash,
        height,
        timestamp: 0,
        commitment_root,
        tx_root: tx_root([]),
        target: 0,
        nonce: [0; 32],
        solution: PowSolution::empty(),
    }
}

#[cfg(test)]
mod tests {
    use null_crypto::pallas;

    use super::*;

    fn anchor(v: u64) -> Anchor {
        Anchor::from_base(pallas::Base::from(v))
    }

    #[test]
    fn header_encodes_to_the_documented_length_and_roundtrips() {
        let header = empty_header(3, BlockHash::from_bytes([1; 32]), anchor(9));
        let bytes = header.to_vec();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(BlockHeader::from_slice(&bytes), Ok(header));
    }

    #[test]
    fn hash_changes_with_every_field_and_pow_input_excludes_nonce() {
        let base = empty_header(1, BlockHash::ZERO, anchor(1));
        let mut other = base.clone();
        other.nonce[0] = 1;
        assert_ne!(base.hash(), other.hash());
        assert_eq!(base.pow_input(), other.pow_input());
        other.timestamp = 5;
        assert_ne!(base.pow_input(), other.pow_input());
        assert_eq!(base.pow_input().len(), HEADER_LEN - 32 - POW_SOLUTION_LEN);
    }

    #[test]
    fn empty_block_roundtrips_and_has_a_consistent_tx_root() {
        let block = Block::new(empty_header(0, BlockHash::ZERO, anchor(0)), Vec::new());
        assert_eq!(block.check_tx_root(), Ok(()));
        assert_eq!(Block::from_slice(&block.to_vec()), Ok(block.clone()));
        assert_eq!(block.hash(), block.header().hash());
        assert!(block.transactions().is_empty());
    }

    #[test]
    fn tx_root_mismatch_is_detected() {
        let mut header = empty_header(0, BlockHash::ZERO, anchor(0));
        header.tx_root = [7; 32];
        let block = Block::new(header, Vec::new());
        assert_eq!(
            block.check_tx_root(),
            Err(Error::InvalidBlock("transaction root mismatch"))
        );
    }

    #[test]
    fn oversized_transaction_count_is_rejected() {
        let mut bytes = empty_header(0, BlockHash::ZERO, anchor(0)).to_vec();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Block::from_slice(&bytes),
            Err(Error::InvalidBlock("too many transactions"))
        ));
    }

    #[test]
    fn block_hash_displays_as_hex() {
        let hash = BlockHash::from_bytes([0xab; 32]);
        assert_eq!(hash.to_string(), "ab".repeat(32));
        assert_eq!(
            format!("{hash:?}"),
            format!("BlockHash({})", "ab".repeat(32))
        );
        assert_eq!(
            format!("{:?}", PowSolution::empty()),
            format!("PowSolution({POW_SOLUTION_LEN} bytes)")
        );
    }
}
