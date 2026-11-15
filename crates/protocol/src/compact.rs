//! Compact blocks: the minimum a light client needs to find its notes and
//! maintain the commitment tree without downloading full transactions.
//!
//! Per action it carries the nullifier, the note commitment, the ephemeral
//! key and the leading [`COMPACT_NOTE_LEAD`] bytes of the note ciphertext.
//! A light client trial-decrypts the lead against its incoming viewing key
//! and confirms a hit against the commitment; every commitment lets it
//! append to its witness tree, and every nullifier lets it detect spends.
//! The block hash and height let it track its scan position and reorgs.
//!
//! A coinbase's actions wait for its maturity before they enter the tree,
//! so they appear in the block they mature in. Its spends, though, take
//! effect in its own block: consensus cannot tell a real spend from a
//! dummy one, so a coinbase may spend a note. [`CompactBlock::coinbase_spends`]
//! carries those nullifiers at the block's own height.
//!
//! Two encodings exist. Format 1 ends after the actions and has no
//! coinbase spends; it is what clients from before format 2 can read.
//! Format 2 appends `LE32(n) || n * nullifier`. [`Encodable`] writes
//! format 2 and reads either.

use null_crypto::encryption::EphemeralPublicKey;

use crate::block::{Block, BlockHash};
use crate::bytes::{Encodable, Reader, Writer};
use crate::maturity::tree_transactions;
use crate::note::ExtractedNoteCommitment;
use crate::note_encryption::COMPACT_NOTE_LEAD;
use crate::nullifier::Nullifier;
use crate::transaction::Transaction;
use crate::{Error, Result};

/// One action, stripped to what a light client reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactAction {
    /// The nullifier the action reveals.
    pub nullifier: Nullifier,
    /// The new note's commitment.
    pub cmx: ExtractedNoteCommitment,
    /// The ephemeral public key.
    pub epk: EphemeralPublicKey,
    /// The leading bytes of the note ciphertext.
    pub enc_lead: [u8; COMPACT_NOTE_LEAD],
}

impl Encodable for CompactAction {
    fn write(&self, w: &mut Writer) {
        w.put(&self.nullifier.to_bytes())
            .put(&self.cmx.to_bytes())
            .put(&self.epk.to_bytes())
            .put(&self.enc_lead);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let nullifier = Nullifier::from_bytes(&r.take_array()?)?;
        let cmx = ExtractedNoteCommitment::from_bytes(&r.take_array()?)?;
        let epk = EphemeralPublicKey::from_bytes(&r.take_array()?)?;
        let enc_lead = r.take_array()?;
        Ok(Self {
            nullifier,
            cmx,
            epk,
            enc_lead,
        })
    }
}

/// A block reduced to its compact actions, in tree order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactBlock {
    /// The block height.
    pub height: u32,
    /// The block hash, so a light client can track reorgs.
    pub hash: BlockHash,
    /// The actions whose commitments the block appends, in tree order: a
    /// maturing coinbase from an earlier block first, then the block's own
    /// transactions after its coinbase (see [`crate::maturity`]).
    pub actions: Vec<CompactAction>,
    /// The nullifiers of the block's own coinbase that `actions` does not
    /// carry, because its actions enter the tree only when it matures.
    pub coinbase_spends: Vec<Nullifier>,
}

/// The newest compact-block encoding, see the module documentation.
pub const COMPACT_FORMAT: u32 = 2;

impl CompactBlock {
    /// Reduces a full block to its compact form on a network whose coinbase
    /// matures after `maturity` blocks. `earlier` is the maturing coinbase
    /// from an earlier block, as [`tree_transactions`] requires.
    ///
    /// # Errors
    /// Returns [`Error::InvalidBlock`] if `earlier` does not fit the rule.
    pub fn from_block(block: &Block, maturity: u32, earlier: Option<&Transaction>) -> Result<Self> {
        let tree = tree_transactions(block, maturity, earlier)?;
        let mut actions = Vec::new();
        for tx in tree {
            for action in tx.actions() {
                let body = action.body();
                let mut enc_lead = [0u8; COMPACT_NOTE_LEAD];
                enc_lead
                    .copy_from_slice(&body.encrypted_note().enc_ciphertext()[..COMPACT_NOTE_LEAD]);
                actions.push(CompactAction {
                    nullifier: *body.nullifier(),
                    cmx: *body.cmx(),
                    epk: *body.encrypted_note().epk(),
                    enc_lead,
                });
            }
        }
        let coinbase_spends = block
            .transactions()
            .first()
            .map(|coinbase| {
                coinbase
                    .nullifiers()
                    .filter(|nf| !actions.iter().any(|a| a.nullifier == **nf))
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            height: block.header().height,
            hash: block.hash(),
            actions,
            coinbase_spends,
        })
    }

    /// Format 1 bytes, for clients from before [`COMPACT_FORMAT`] 2: the
    /// same without [`Self::coinbase_spends`].
    pub fn to_format_1(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.write_format_1(&mut w);
        w.into_bytes()
    }

    /// The bytes of `format` (1 or [`COMPACT_FORMAT`]).
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for an unknown format.
    pub fn encode(&self, format: u32) -> Result<Vec<u8>> {
        match format {
            1 => Ok(self.to_format_1()),
            COMPACT_FORMAT => Ok(self.to_vec()),
            _ => Err(Error::Malformed("unknown compact block format")),
        }
    }

    fn write_format_1(&self, w: &mut Writer) {
        w.put(&self.height.to_le_bytes()).put(self.hash.as_bytes());
        // A block holds at most MAX_BLOCK_TRANSACTIONS * 16 actions, which
        // fits a u32 with room to spare.
        w.put(
            &u32::try_from(self.actions.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for action in &self.actions {
            action.write(w);
        }
    }
}

impl Encodable for CompactBlock {
    fn write(&self, w: &mut Writer) {
        self.write_format_1(w);
        // At most MAX_ACTIONS, the most spends one transaction has.
        w.put(
            &u32::try_from(self.coinbase_spends.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for nf in &self.coinbase_spends {
            w.put(&nf.to_bytes());
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let height = u32::from_le_bytes(r.take_array()?);
        let hash = BlockHash::from_bytes(r.take_array()?);
        let count = u32::from_le_bytes(r.take_array()?);
        let max = crate::consensus::MAX_BLOCK_TRANSACTIONS
            .saturating_mul(*crate::consensus::ACTION_CLASSES.last().unwrap_or(&16));
        if count as usize > max {
            return Err(Error::Malformed("too many compact actions"));
        }
        let actions = (0..count)
            .map(|_| CompactAction::read(r))
            .collect::<Result<Vec<_>>>()?;
        // Format 1 ends here.
        let mut coinbase_spends = Vec::new();
        if r.remaining() > 0 {
            let count = u32::from_le_bytes(r.take_array()?);
            if count as usize > crate::consensus::MAX_ACTIONS {
                return Err(Error::Malformed("too many coinbase spends"));
            }
            for _ in 0..count {
                coinbase_spends.push(Nullifier::from_bytes(&r.take_array()?)?);
            }
        }
        Ok(Self {
            height,
            hash,
            actions,
            coinbase_spends,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compact_block_round_trips_through_bytes() {
        let action = CompactAction {
            nullifier: Nullifier::from_base(&null_crypto::pallas::Base::from(7u64)),
            cmx: ExtractedNoteCommitment::from_bytes(&[0; 32]).unwrap(),
            epk: EphemeralPublicKey::from_bytes(&null_crypto::encoding::point_to_bytes(
                &null_crypto::curve::Generator::SpendAuth.point(),
            ))
            .unwrap(),
            enc_lead: [9u8; COMPACT_NOTE_LEAD],
        };
        let block = CompactBlock {
            height: 5,
            hash: BlockHash::from_bytes([3; 32]),
            actions: vec![action.clone(), action],
            coinbase_spends: vec![Nullifier::from_base(&null_crypto::pallas::Base::from(8u64))],
        };
        let mut w = Writer::with_capacity(256);
        block.write(&mut w);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let decoded = CompactBlock::read(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(decoded, block);
        assert_eq!(block.encode(COMPACT_FORMAT).unwrap(), bytes);

        // Format 1 is format 2 without the tail, and still decodes.
        let old = block.encode(1).unwrap();
        assert_eq!(old.len(), bytes.len() - 4 - 32);
        assert_eq!(&bytes[..old.len()], old.as_slice());
        let decoded = CompactBlock::from_slice(&old).unwrap();
        assert_eq!(decoded.coinbase_spends, []);
        assert_eq!(decoded.actions, block.actions);
        assert!(block.encode(3).is_err());
    }

    #[test]
    fn decoding_rejects_a_bad_coinbase_spend_tail() {
        let block = CompactBlock {
            height: 1,
            hash: BlockHash::ZERO,
            actions: vec![],
            coinbase_spends: vec![],
        };
        let mut bytes = block.to_format_1();
        bytes.extend_from_slice(&17u32.to_le_bytes());
        assert!(
            CompactBlock::from_slice(&bytes).is_err(),
            "more than MAX_ACTIONS"
        );
        let mut short = block.to_format_1();
        short.extend_from_slice(&1u32.to_le_bytes());
        assert!(CompactBlock::from_slice(&short).is_err(), "truncated");
        let mut stray = block.to_format_1();
        stray.push(0);
        assert!(CompactBlock::from_slice(&stray).is_err(), "a partial count");
    }

    #[test]
    fn decoding_rejects_an_absurd_action_count() {
        let mut w = Writer::with_capacity(40);
        w.put(&1u32.to_le_bytes())
            .put(BlockHash::ZERO.as_bytes())
            .put(&u32::MAX.to_le_bytes());
        let bytes = w.into_bytes();
        assert!(CompactBlock::read(&mut Reader::new(&bytes)).is_err());
    }
}
