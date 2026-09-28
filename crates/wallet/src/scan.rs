//! Trial decryption of one block into owned notes.

use null_protocol::amount::Amount;
use null_protocol::block::Block;
use null_protocol::bytes::{Encodable, Reader, Writer};
use null_protocol::compact::CompactBlock;
use null_protocol::memo::Memo;
use null_protocol::note::{Note, RandomSeed, Rho};
use null_protocol::note_encryption::{decrypt_note_with_ivk, detect_note_with_ivk};
use null_protocol::nullifier::Nullifier;
use null_protocol::transaction::TxId;

use crate::keys::WalletKeys;
use crate::Result;

/// A note the wallet owns.
#[derive(Clone, Debug)]
pub struct OwnedNote {
    /// The note.
    pub note: Note,
    /// Its memo.
    pub memo: Memo,
    /// Its position in the commitment tree.
    pub position: u64,
    /// The nullifier spending it reveals.
    pub nullifier: Nullifier,
    /// Height of the block that created it.
    pub height: u32,
    /// Height of the block that spent it, once seen.
    pub spent_at: Option<u32>,
    /// The transaction that created it; unknown after a compact scan.
    pub txid: Option<TxId>,
    /// The transaction that spent it, once seen in a full scan.
    pub spent_by: Option<TxId>,
}

impl Encodable for OwnedNote {
    fn write(&self, w: &mut Writer) {
        self.note.write(w);
        self.memo.write(w);
        w.put_u64_le(self.position);
        self.nullifier.write(w);
        w.put(&self.height.to_le_bytes());
        match self.spent_at {
            Some(h) => {
                w.put_u8(1).put(&h.to_le_bytes());
            }
            None => {
                w.put_u8(0);
            }
        }
        write_txid(w, self.txid);
        write_txid(w, self.spent_by);
    }

    fn read(r: &mut Reader<'_>) -> null_protocol::Result<Self> {
        let note = Note::read(r)?;
        let memo = Memo::read(r)?;
        let position = r.take_u64_le()?;
        let nullifier = Nullifier::read(r)?;
        let height = u32::from_le_bytes(r.take_array()?);
        let spent_at = match r.take_u8()? {
            0 => None,
            1 => Some(u32::from_le_bytes(r.take_array()?)),
            _ => return Err(null_protocol::Error::Malformed("spent flag")),
        };
        let txid = read_txid(r)?;
        let spent_by = read_txid(r)?;
        Ok(Self {
            note,
            memo,
            position,
            nullifier,
            height,
            spent_at,
            txid,
            spent_by,
        })
    }
}

/// An optional transaction id: a presence byte, then the id.
fn write_txid(w: &mut Writer, txid: Option<TxId>) {
    match txid {
        Some(id) => {
            w.put_u8(1).put(id.as_bytes());
        }
        None => {
            w.put_u8(0);
        }
    }
}

fn read_txid(r: &mut Reader<'_>) -> null_protocol::Result<Option<TxId>> {
    match r.take_u8()? {
        0 => Ok(None),
        1 => Ok(Some(TxId::from_bytes(r.take_array()?))),
        _ => Err(null_protocol::Error::Malformed("txid flag")),
    }
}

/// What scanning one block found.
#[derive(Debug, Default)]
pub struct BlockScan {
    /// Every commitment in the block, in tree order.
    pub leaves: Vec<null_crypto::pallas::Base>,
    /// Notes the wallet owns, with positions relative to `first_position`.
    pub found: Vec<OwnedNote>,
    /// Every nullifier the block spent, with the spending transaction
    /// when the scan knew it.
    pub spent: Vec<(Nullifier, Option<TxId>)>,
}

/// The work a successful decryption does after the cipher check, so it
/// can be repeated on a stand-in note when the check fails.
///
/// Trial decryption stops at the authentication tag for a note that is
/// not ours; for ours it goes on to derive the transmission key, the
/// diversified base, the ephemeral key, the commitment and the
/// nullifier. Doing the same on a stand-in note for every other action
/// makes the cost per action the same either way, so timing does not
/// tell which actions were ours. It equalizes work, not branches: a
/// found note still costs a vector push.
struct StandIn {
    note: Note,
}

impl StandIn {
    fn new(keys: &WalletKeys) -> Result<Self> {
        Ok(Self {
            note: Note::new(
                keys.default_address()?,
                Amount::ZERO,
                Rho::from_nullifier(&Nullifier::from_bytes(&[0; 32])?)?,
                RandomSeed::from_bytes([0; 32]),
            ),
        })
    }

    /// Performs the success path's work and discards it.
    fn work(&self, keys: &WalletKeys) -> Result<()> {
        let diversifier = self.note.recipient().diversifier();
        let _pk_d = keys.incoming_viewing_key().transmission_key(diversifier)?;
        let g_d = diversifier.base()?;
        let _epk = self.note.esk().public_key(&g_d);
        let _cmx = self.note.cmx()?;
        let _nf = self.note.nullifier(keys.full_viewing_key().nk())?;
        Ok(())
    }

    /// The compact detection success path's work, for a non-match.
    fn detect(&self, keys: &WalletKeys) -> Result<()> {
        let diversifier = self.note.recipient().diversifier();
        let _pk_d = keys.incoming_viewing_key().transmission_key(diversifier)?;
        let _cmx = self.note.cmx()?;
        Ok(())
    }
}

/// Decrypts every action of `block` with `keys`. Positions start at
/// `first_position`, the tree size before the block. Every action costs
/// the same work whether or not it is ours; see the internal `StandIn` helper.
///
/// # Errors
/// Fails if a decrypted note cannot derive its nullifier.
pub fn scan_block(keys: &WalletKeys, block: &Block, first_position: u64) -> Result<BlockScan> {
    let mut scan = BlockScan::default();
    let stand_in = StandIn::new(keys)?;
    for tx in block.transactions() {
        let txid = tx.txid();
        for action in tx.actions() {
            let body = action.body();
            let position =
                first_position.saturating_add(u64::try_from(scan.leaves.len()).unwrap_or(u64::MAX));
            scan.leaves.push(*body.cmx().inner());
            scan.spent.push((*body.nullifier(), Some(txid)));
            let rho = Rho::from_nullifier(body.nullifier())?;
            let decrypted = decrypt_note_with_ivk(
                keys.incoming_viewing_key(),
                body.encrypted_note(),
                rho,
                body.cmx(),
            );
            let Ok((note, memo)) = decrypted else {
                stand_in.work(keys)?;
                continue;
            };
            let nullifier = note.nullifier(keys.full_viewing_key().nk())?;
            if note.value().raw() == 0 {
                continue;
            }
            scan.found.push(OwnedNote {
                note,
                memo,
                position,
                nullifier,
                height: block.header().height,
                spent_at: None,
                txid: Some(txid),
                spent_by: None,
            });
        }
    }
    Ok(scan)
}

/// Detects owned notes in one compact block. Produces the same leaves
/// and spent nullifiers as [`scan_block`], and the same owned notes
/// except that their memos are empty, since a compact block omits them.
///
/// # Errors
/// Fails if a detected note cannot derive its nullifier.
pub fn scan_compact_block(
    keys: &WalletKeys,
    block: &CompactBlock,
    first_position: u64,
) -> Result<BlockScan> {
    let mut scan = BlockScan::default();
    let stand_in = StandIn::new(keys)?;
    for action in &block.actions {
        let position =
            first_position.saturating_add(u64::try_from(scan.leaves.len()).unwrap_or(u64::MAX));
        scan.leaves.push(*action.cmx.inner());
        scan.spent.push((action.nullifier, None));
        let rho = Rho::from_nullifier(&action.nullifier)?;
        let detected = detect_note_with_ivk(
            keys.incoming_viewing_key(),
            &action.epk,
            &action.enc_lead,
            rho,
            &action.cmx,
        );
        let Ok(note) = detected else {
            stand_in.detect(keys)?;
            continue;
        };
        let nullifier = note.nullifier(keys.full_viewing_key().nk())?;
        if note.value().raw() == 0 {
            continue;
        }
        scan.found.push(OwnedNote {
            note,
            memo: Memo::empty(),
            position,
            nullifier,
            height: block.height,
            spent_at: None,
            txid: None,
            spent_by: None,
        });
    }
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use null_crypto::keys::SpendingKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn the_stand_in_does_the_success_path_work_without_failing() {
        let keys =
            WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(1)))
                .unwrap();
        let stand_in = StandIn::new(&keys).unwrap();
        stand_in.work(&keys).unwrap();
        assert_eq!(stand_in.note.value().raw(), 0);
    }
}
