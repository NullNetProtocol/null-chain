//! Compact blocks: the minimum a light client needs to find its notes and
//! maintain the commitment tree without downloading full transactions.
//!
//! Per action it carries the nullifier, the note commitment, the ephemeral
//! key and the leading [`COMPACT_NOTE_LEAD`] bytes of the note ciphertext.
//! A light client trial-decrypts the lead against its incoming viewing key
//! and confirms a hit against the commitment; every commitment lets it
//! append to its witness tree, and every nullifier lets it detect spends.
//! The block hash and height let it track its scan position and reorgs.

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
}

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
        Ok(Self {
            height: block.header().height,
            hash: block.hash(),
            actions,
        })
    }
}

impl Encodable for CompactBlock {
    fn write(&self, w: &mut Writer) {
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
        Ok(Self {
            height,
            hash,
            actions,
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
        };
        let mut w = Writer::with_capacity(256);
        block.write(&mut w);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let decoded = CompactBlock::read(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(decoded, block);
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
