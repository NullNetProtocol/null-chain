//! The persistent, encrypted wallet.
//!
//! Tables:
//!
//! | table | key | value |
//! |---|---|---|
//! | `meta` | name | salt, encrypted spending key, fingerprint, genesis |
//! | `notes` | tree position | encrypted owned note |
//! | `heights` | height | block hash, tree size before the block |
//! | `shards`, `cap`, `checkpoints` | see [`crate::tree`] | the witness tree |
//!
//! A file key is derived from the passphrase with Argon2id and a random
//! salt. The spending key and every note record are encrypted under it
//! with ChaCha20-Poly1305; the witness tree and heights are public chain
//! data and stay in the clear. Scanning a block is one write transaction
//! that appends the block's commitments to the witness tree and takes a
//! checkpoint at its height; a reorganization is handled by rolling back
//! to the last matching height, which truncates the tree to that
//! checkpoint.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use incrementalmerkletree::Position;
use null_crypto::diversifier::DiversifierIndex;
use null_crypto::hash::{blake2b_short, PIN};
use null_crypto::keys::{FullViewingKey, SpendingKey, FULL_VIEWING_KEY_LEN};
use null_crypto::merkle::{MerklePath, Node};
use null_protocol::address::Address;
use null_protocol::block::{Block, BlockHash};
use null_protocol::bytes::Encodable;
use null_protocol::compact::CompactBlock;
use null_protocol::maturity::tree_transactions;
use null_protocol::transaction::{Anchor, Transaction};
use rand_core::{CryptoRng, OsRng, RngCore};
use redb::{
    Database, ReadOnlyTable, ReadTransaction, ReadableDatabase, ReadableTable, Table,
    TableDefinition, WriteTransaction,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::WalletKeys;
use crate::operations::{Operation, OperationStatus};
use crate::scan::{scan_block, scan_compact_block, BlockScan, OwnedNote};
use crate::spend::Payment;
use crate::tree::{
    anchor_of, retention, to_merkle_path, witness_tree, WitnessTree, CAP, CHECKPOINTS, SHARDS,
};
use crate::{Error, Result};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const NOTES: TableDefinition<u64, &[u8]> = TableDefinition::new("notes");
const HEIGHTS: TableDefinition<u32, &[u8]> = TableDefinition::new("heights");
/// Diversifier index to the sealed label of an address handed out.
const ADDRESSES: TableDefinition<u64, &[u8]> = TableDefinition::new("addresses");
/// Operation id to the sealed operation.
const OPERATIONS: TableDefinition<u64, &[u8]> = TableDefinition::new("operations");

const SALT: &str = "salt";
const SPENDING_KEY: &str = "spending_key";
/// The sealed full viewing key of a watch-only wallet.
const FULL_VIEWING_KEY: &str = "full_viewing_key";
const FINGERPRINT: &str = "fingerprint";
const GENESIS: &str = "genesis";
/// The next diversifier index to hand out; index zero is the default
/// address, used for change.
const NEXT_ADDRESS: &str = "next_address";
const NEXT_OPERATION: &str = "next_operation";

/// Argon2id memory in KiB.
const KDF_MEMORY_KIB: u32 = 64 * 1024;
/// Argon2id passes.
const KDF_PASSES: u32 = 3;
/// Argon2id lanes.
const KDF_LANES: u32 = 1;
/// Salt length in bytes.
const SALT_LEN: usize = 16;

/// Record tag of the spending key, authenticated with its ciphertext.
const TAG_SPENDING_KEY: u8 = 0;
/// Record tag of a note, authenticated with its ciphertext.
const TAG_NOTE: u8 = 1;
/// Record tag of an address label.
const TAG_LABEL: u8 = 2;
/// Record tag of an operation.
const TAG_OPERATION: u8 = 3;
/// Record tag of the full viewing key of a watch-only wallet.
const TAG_VIEWING_KEY: u8 = 4;
/// Length of the random nonce stored ahead of every ciphertext.
const NONCE_LEN: usize = 12;
/// Version of the sealed record layout, authenticated with every record.
const RECORD_VERSION: u8 = 1;
/// Length of the associated data: version, tag and position.
const AAD_LEN: usize = 10;

/// The symmetric key that protects the file's secrets.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct FileKey([u8; 32]);

impl FileKey {
    fn derive(passphrase: &[u8], salt: &[u8]) -> Result<Self> {
        let params = Params::new(KDF_MEMORY_KIB, KDF_PASSES, KDF_LANES, Some(32))
            .map_err(|_| Error::Corrupt("kdf parameters"))?;
        let mut out = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|_| Error::Corrupt("kdf"))?;
        Ok(Self(out))
    }

    fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut out = [0u8; 32];
        rng.fill_bytes(&mut out);
        Self(out)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.0))
    }

    /// A fresh random nonce for one encryption. A note record is
    /// re-encrypted in place when it is spent and when that spend is
    /// rolled back, and a position can hold a different note after a
    /// reorganization, so a nonce derived from the position would repeat
    /// under the same key; a random one never does.
    fn fresh_nonce() -> Result<[u8; NONCE_LEN]> {
        let mut out = [0u8; NONCE_LEN];
        OsRng.try_fill_bytes(&mut out).map_err(|_| Error::Entropy)?;
        Ok(out)
    }

    /// Associated data binding a record to the layout version, its kind
    /// and its position, so a ciphertext cannot be moved to another slot.
    fn associated_data(tag: u8, position: u64) -> [u8; AAD_LEN] {
        let mut out = [0u8; AAD_LEN];
        out[0] = RECORD_VERSION;
        out[1] = tag;
        out[2..].copy_from_slice(&position.to_le_bytes());
        out
    }

    /// Encrypts `plaintext` as `nonce || ciphertext || tag`.
    fn seal(&self, tag: u8, position: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::fresh_nonce()?;
        let payload = Payload {
            msg: plaintext,
            aad: &Self::associated_data(tag, position),
        };
        let ciphertext = self
            .cipher()
            .encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| Error::Corrupt("encrypt"))?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn open(&self, tag: u8, position: u64, sealed: &[u8]) -> Result<Vec<u8>> {
        let (nonce, ciphertext) = sealed
            .split_at_checked(NONCE_LEN)
            .ok_or(Error::WrongPassphrase)?;
        let payload = Payload {
            msg: ciphertext,
            aad: &Self::associated_data(tag, position),
        };
        self.cipher()
            .decrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| Error::WrongPassphrase)
    }
}

/// A wallet database with its keys unlocked.
pub struct Wallet {
    db: Database,
    keys: WalletKeys,
    file_key: FileKey,
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Wallet(<unlocked>)")
    }
}

/// What one scanned block changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Notes found for the wallet.
    pub found: usize,
    /// Wallet notes the block spent.
    pub spent: usize,
}

/// The witness tree over a read transaction.
type ReadTree = WitnessTree<
    ReadOnlyTable<u64, &'static [u8]>,
    ReadOnlyTable<(), &'static [u8]>,
    ReadOnlyTable<u32, &'static [u8]>,
>;

/// The witness tree over a write transaction.
type WriteTree<'txn> = WitnessTree<
    Table<'txn, u64, &'static [u8]>,
    Table<'txn, (), &'static [u8]>,
    Table<'txn, u32, &'static [u8]>,
>;

fn read_tree(tx: &ReadTransaction) -> Result<ReadTree> {
    Ok(witness_tree(
        tx.open_table(SHARDS)?,
        tx.open_table(CAP)?,
        tx.open_table(CHECKPOINTS)?,
    ))
}

fn write_tree(tx: &WriteTransaction) -> Result<WriteTree<'_>> {
    Ok(witness_tree(
        tx.open_table(SHARDS)?,
        tx.open_table(CAP)?,
        tx.open_table(CHECKPOINTS)?,
    ))
}

/// Number of leaves in a tree: the greatest position plus one.
fn size_of<S, P, C>(tree: &WitnessTree<S, P, C>) -> Result<u64>
where
    S: crate::tree::Slot<u64>,
    P: crate::tree::Slot<()>,
    C: crate::tree::Slot<u32>,
{
    Ok(tree
        .max_leaf_position(None)?
        .map_or(0, |p| u64::from(p).saturating_add(1)))
}

/// A fingerprint of the viewing key, so a file cannot be used with other
/// keys by mistake.
fn fingerprint(keys: &WalletKeys) -> [u8; 32] {
    blake2b_short(
        PIN,
        &[
            &keys.full_viewing_key().ak().to_bytes(),
            keys.outgoing_viewing_key().as_bytes(),
        ],
    )
}

impl Wallet {
    /// Creates a new wallet file for `sk` under `passphrase`. Fails if the
    /// file already holds a wallet.
    ///
    /// # Errors
    /// Returns [`Error::WrongWallet`] if the file is already initialized,
    /// or a key derivation or database error.
    pub fn create(
        path: impl AsRef<Path>,
        sk: &SpendingKey,
        genesis: BlockHash,
        passphrase: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let keys = WalletKeys::from_spending_key(sk.clone())?;
        Self::create_with(path, keys, genesis, passphrase, rng)
    }

    /// Creates a watch-only wallet file from a full viewing key: it finds
    /// notes and their spends but cannot sign.
    ///
    /// # Errors
    /// As [`Self::create`].
    pub fn create_watch_only(
        path: impl AsRef<Path>,
        fvk: FullViewingKey,
        genesis: BlockHash,
        passphrase: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let keys = WalletKeys::from_full_viewing_key(fvk)?;
        Self::create_with(path, keys, genesis, passphrase, rng)
    }

    fn create_with(
        path: impl AsRef<Path>,
        keys: WalletKeys,
        genesis: BlockHash,
        passphrase: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let db = Database::create(path)?;
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let file_key = FileKey::derive(passphrase, &salt)?;
        Self::init(db, keys, genesis, file_key, Some(&salt))
    }

    /// Opens a wallet file, deriving the file key from `passphrase`.
    ///
    /// # Errors
    /// Returns [`Error::WrongPassphrase`] if the passphrase does not
    /// unlock the file, [`Error::WrongWallet`] if the file is for another
    /// network, or a database error.
    pub fn open(path: impl AsRef<Path>, genesis: BlockHash, passphrase: &[u8]) -> Result<Self> {
        let db = Database::create(path)?;
        let (salt, sealed_sk, sealed_fvk, stored_genesis) = {
            let tx = db.begin_read()?;
            let meta = tx.open_table(META)?;
            let salt = meta
                .get(SALT)?
                .map(|v| v.value().to_vec())
                .ok_or(Error::WrongWallet)?;
            let sealed_sk = meta.get(SPENDING_KEY)?.map(|v| v.value().to_vec());
            let sealed_fvk = meta.get(FULL_VIEWING_KEY)?.map(|v| v.value().to_vec());
            let stored = meta
                .get(GENESIS)?
                .map(|v| v.value().to_vec())
                .ok_or(Error::WrongWallet)?;
            (salt, sealed_sk, sealed_fvk, stored)
        };
        if stored_genesis != genesis.as_bytes() {
            return Err(Error::WrongWallet);
        }
        let file_key = FileKey::derive(passphrase, &salt)?;
        let keys = match (sealed_sk, sealed_fvk) {
            (Some(sealed), _) => {
                let mut sk_bytes: [u8; 32] = file_key
                    .open(TAG_SPENDING_KEY, 0, &sealed)?
                    .try_into()
                    .map_err(|_| Error::Corrupt("spending key"))?;
                let keys = WalletKeys::from_spending_key(SpendingKey::from_bytes(sk_bytes))?;
                sk_bytes.zeroize();
                keys
            }
            (None, Some(sealed)) => {
                let bytes: [u8; FULL_VIEWING_KEY_LEN] = file_key
                    .open(TAG_VIEWING_KEY, 0, &sealed)?
                    .try_into()
                    .map_err(|_| Error::Corrupt("viewing key"))?;
                WalletKeys::from_full_viewing_key(FullViewingKey::from_bytes(&bytes)?)?
            }
            (None, None) => return Err(Error::WrongWallet),
        };
        Ok(Self { db, keys, file_key })
    }

    /// A wallet that lives only in memory, under a random key.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn in_memory(
        sk: &SpendingKey,
        genesis: BlockHash,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let db = Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        let keys = WalletKeys::from_spending_key(sk.clone())?;
        Self::init(db, keys, genesis, FileKey::random(rng), None)
    }

    /// A watch-only wallet that lives only in memory.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn in_memory_watch_only(
        fvk: FullViewingKey,
        genesis: BlockHash,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let db = Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        let keys = WalletKeys::from_full_viewing_key(fvk)?;
        Self::init(db, keys, genesis, FileKey::random(rng), None)
    }

    fn init(
        db: Database,
        keys: WalletKeys,
        genesis: BlockHash,
        file_key: FileKey,
        salt: Option<&[u8]>,
    ) -> Result<Self> {
        let sealed_key = match keys.spending_key() {
            Ok(sk) => (
                SPENDING_KEY,
                file_key.seal(TAG_SPENDING_KEY, 0, &sk.to_bytes())?,
            ),
            Err(_) => (
                FULL_VIEWING_KEY,
                file_key.seal(TAG_VIEWING_KEY, 0, &keys.full_viewing_key().to_bytes())?,
            ),
        };
        let tx = db.begin_write()?;
        {
            let mut meta = tx.open_table(META)?;
            tx.open_table(NOTES)?;
            tx.open_table(HEIGHTS)?;
            tx.open_table(SHARDS)?;
            tx.open_table(CAP)?;
            tx.open_table(CHECKPOINTS)?;
            tx.open_table(ADDRESSES)?;
            tx.open_table(OPERATIONS)?;
            if meta.get(GENESIS)?.is_some() {
                return Err(Error::WrongWallet);
            }
            meta.insert(SALT, salt.unwrap_or(&[]))?;
            meta.insert(sealed_key.0, sealed_key.1.as_slice())?;
            meta.insert(FINGERPRINT, fingerprint(&keys).as_slice())?;
            meta.insert(GENESIS, genesis.as_bytes().as_slice())?;
        }
        tx.commit()?;
        Ok(Self { db, keys, file_key })
    }

    /// The unlocked keys.
    pub fn keys(&self) -> &WalletKeys {
        &self.keys
    }

    /// Height of the next block to scan.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn next_height(&self) -> Result<u32> {
        let tx = self.db.begin_read()?;
        let heights = tx.open_table(HEIGHTS)?;
        let next = heights
            .last()?
            .map_or(0, |(k, _)| k.value().saturating_add(1));
        Ok(next)
    }

    /// Number of leaves in the witness tree.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn tree_size(&self) -> Result<u64> {
        let tx = self.db.begin_read()?;
        size_of(&read_tree(&tx)?)
    }

    /// The hash of the block scanned at `height`, if any.
    ///
    /// # Errors
    /// Fails on a database error or corrupt row.
    pub fn scanned_hash(&self, height: u32) -> Result<Option<BlockHash>> {
        let tx = self.db.begin_read()?;
        let heights = tx.open_table(HEIGHTS)?;
        let hash = heights
            .get(height)?
            .map(|row| decode_height(row.value()).map(|(hash, _)| hash))
            .transpose();
        hash
    }

    /// Scans the next full block: appends its commitments to the witness
    /// tree, marking the ones it owns, takes a checkpoint at the block's
    /// height, records owned notes with their memos and marks notes it
    /// spent. All or nothing.
    ///
    /// Commitments enter in tree order on a network whose coinbase matures
    /// after `maturity` blocks: `earlier` is the coinbase maturing at this
    /// height when it comes from an earlier block (see
    /// [`null_protocol::maturity`]). A reward the wallet mined is found when
    /// it matures, since only then can it be spent.
    ///
    /// # Errors
    /// Returns [`Error::OutOfOrder`] if `block` is not the next height, or a
    /// protocol error if `earlier` does not fit the maturity rule.
    pub fn scan(
        &self,
        block: &Block,
        maturity: u32,
        earlier: Option<&Transaction>,
    ) -> Result<ScanReport> {
        let height = block.header().height;
        let tree = tree_transactions(block, maturity, earlier)?;
        self.apply(height, block.hash(), |first_position| {
            scan_block(&self.keys, block, &tree, first_position)
        })
    }

    /// Scans the next block from its compact form, as a light client does.
    /// It maintains the same witness tree and finds the same notes, but
    /// their memos are not recovered.
    ///
    /// # Errors
    /// Returns [`Error::OutOfOrder`] if `block` is not the next height.
    pub fn scan_compact(&self, block: &CompactBlock) -> Result<ScanReport> {
        self.apply(block.height, block.hash, |first_position| {
            scan_compact_block(&self.keys, block, first_position)
        })
    }

    /// Applies one scanned block in a single write transaction: appends
    /// leaves, checkpoints, records found notes and marks spends. Shared
    /// by the full and compact scanners.
    fn apply(
        &self,
        height: u32,
        hash: BlockHash,
        build: impl FnOnce(u64) -> Result<BlockScan>,
    ) -> Result<ScanReport> {
        let expected = self.next_height()?;
        if height != expected {
            return Err(Error::OutOfOrder {
                expected,
                got: height,
            });
        }
        let tx = self.db.begin_write()?;
        let mut report = ScanReport::default();
        {
            let mut tree = write_tree(&tx)?;
            let first_position = size_of(&tree)?;
            let scan = build(first_position)?;
            report.found = scan.found.len();
            let owned: Vec<u64> = scan.found.iter().map(|n| n.position).collect();
            let leaves = scan.leaves.iter().enumerate().map(|(i, leaf)| {
                let position = first_position.saturating_add(u64::try_from(i).unwrap_or(u64::MAX));
                (Node::new(*leaf), retention(owned.contains(&position)))
            });
            tree.batch_insert(Position::from(first_position), leaves)?;
            if !tree.checkpoint(height)? {
                return Err(Error::Corrupt("checkpoint out of order"));
            }
            let mut notes = tx.open_table(NOTES)?;
            for note in &scan.found {
                notes.insert(note.position, self.seal_note(note)?.as_slice())?;
            }
            for mut note in self.decrypt_all(&notes)? {
                let spent = scan.spent.iter().find(|(nf, _)| *nf == note.nullifier);
                if let (None, Some((_, by))) = (note.spent_at, spent) {
                    note.spent_at = Some(height);
                    note.spent_by = *by;
                    notes.insert(note.position, self.seal_note(&note)?.as_slice())?;
                    // The mark is removed as of this checkpoint, so a
                    // rollback below it restores the witness.
                    tree.remove_mark(Position::from(note.position), Some(&height))?;
                    report.spent = report.spent.saturating_add(1);
                }
            }
            let mut heights = tx.open_table(HEIGHTS)?;
            heights.insert(height, encode_height(hash, first_position).as_slice())?;
        }
        tx.commit()?;
        Ok(report)
    }

    /// Forgets every block above `height`: tree leaves, notes created
    /// after it, and spends recorded after it. Reopens removed confirmations
    /// and reserves their inputs in the same database transaction.
    ///
    /// # Errors
    /// Returns [`Error::RollbackTooDeep`] if the checkpoint at `height`
    /// was pruned, or a database error.
    pub fn rollback_to(&self, height: u32) -> Result<()> {
        if self.next_height()? <= height.saturating_add(1) {
            return Ok(());
        }
        let tx = self.db.begin_write()?;
        {
            let mut tree = write_tree(&tx)?;
            if !tree.truncate_to_checkpoint(&height)? {
                return Err(Error::RollbackTooDeep(height));
            }
            let mut heights = tx.open_table(HEIGHTS)?;
            heights.retain(|h, _| h <= height)?;
            let mut notes = tx.open_table(NOTES)?;
            let owned = self.decrypt_all(&notes)?;
            for mut note in owned {
                if note.height > height {
                    notes.remove(note.position)?;
                } else if note.spent_at.is_some_and(|h| h > height) {
                    note.spent_at = None;
                    note.spent_by = None;
                    notes.insert(note.position, self.seal_note(&note)?.as_slice())?;
                }
            }
            let mut operations = tx.open_table(OPERATIONS)?;
            for mut op in self.decrypt_operations(&operations)? {
                if let OperationStatus::Confirmed { txid, height: at } = op.status {
                    if at > height {
                        // The build height was no later than the confirmation.
                        // Using this upper bound delays expiry conservatively.
                        op.status = OperationStatus::Submitted { txid, built_at: at };
                        operations.insert(op.id, self.seal_operation(&op)?.as_slice())?;
                    }
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn seal_note(&self, note: &OwnedNote) -> Result<Vec<u8>> {
        self.file_key.seal(TAG_NOTE, note.position, &note.to_vec())
    }

    fn decrypt_all(
        &self,
        notes: &impl ReadableTable<u64, &'static [u8]>,
    ) -> Result<Vec<OwnedNote>> {
        notes
            .iter()?
            .map(|row| {
                let (position, value) = row?;
                let plain = self
                    .file_key
                    .open(TAG_NOTE, position.value(), value.value())?;
                Ok(OwnedNote::from_slice(&plain)?)
            })
            .collect()
    }

    /// Every owned note, spent or not, by position.
    ///
    /// # Errors
    /// Fails on a database error or corrupt row.
    pub fn notes(&self) -> Result<Vec<OwnedNote>> {
        let tx = self.db.begin_read()?;
        let notes = tx.open_table(NOTES)?;
        self.decrypt_all(&notes)
    }

    /// Notes not yet seen spent on chain.
    ///
    /// # Errors
    /// See [`Self::notes`].
    pub fn unspent(&self) -> Result<Vec<OwnedNote>> {
        Ok(self
            .notes()?
            .into_iter()
            .filter(|n| n.spent_at.is_none())
            .collect())
    }

    /// Unspent value.
    ///
    /// # Errors
    /// See [`Self::notes`].
    pub fn balance(&self) -> Result<u64> {
        Ok(self.unspent()?.iter().map(|n| n.note.value().raw()).sum())
    }

    /// The height of the last scanned block, which is the checkpoint
    /// witnesses are taken at.
    fn tip_height(&self) -> Result<u32> {
        self.next_height()?
            .checked_sub(1)
            .ok_or(Error::Corrupt("no block scanned"))
    }

    /// The tree root after the last scanned block.
    ///
    /// # Errors
    /// Fails before any block is scanned or on a database error.
    pub fn anchor(&self) -> Result<Anchor> {
        let tip = self.tip_height()?;
        let tx = self.db.begin_read()?;
        let root = read_tree(&tx)?
            .root_at_checkpoint_id(&tip)?
            .ok_or(Error::Corrupt("missing tip checkpoint"))?;
        Ok(anchor_of(&root))
    }

    /// Witnesses for owned note positions, all against the anchor after
    /// the last scanned block, in the order given.
    ///
    /// # Errors
    /// Returns [`Error::NoWitness`] for a position that is not an unspent
    /// owned note.
    pub fn witnesses(&self, positions: &[u64]) -> Result<(Vec<MerklePath>, Anchor)> {
        let tip = self.tip_height()?;
        let tx = self.db.begin_read()?;
        let tree = read_tree(&tx)?;
        let root = tree
            .root_at_checkpoint_id(&tip)?
            .ok_or(Error::Corrupt("missing tip checkpoint"))?;
        let paths = positions
            .iter()
            .map(|&position| {
                let path = tree
                    .witness_at_checkpoint_id(Position::from(position), &tip)
                    .ok()
                    .flatten()
                    .ok_or(Error::NoWitness(position))?;
                to_merkle_path(&path)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((paths, anchor_of(&root)))
    }

    /// The witness for one note position and the anchor it is valid for.
    ///
    /// # Errors
    /// See [`Self::witnesses`].
    pub fn witness(&self, position: u64) -> Result<(MerklePath, Anchor)> {
        let (mut paths, anchor) = self.witnesses(&[position])?;
        let path = paths.pop().ok_or(Error::NoWitness(position))?;
        Ok((path, anchor))
    }

    /// The height of the last scanned block, or `None` before any.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn scanned_height(&self) -> Result<Option<u32>> {
        Ok(self.next_height()?.checked_sub(1))
    }

    /// Hands out the next diversified address under `label` and records
    /// it, so a received note can be traced back to the label.
    ///
    /// # Errors
    /// Fails on a database error or an exhausted index space.
    pub fn new_address(&self, label: &str) -> Result<(u64, Address)> {
        let tx = self.db.begin_write()?;
        let index = {
            let mut meta = tx.open_table(META)?;
            let index = meta
                .get(NEXT_ADDRESS)?
                .map(|v| decode_u64(v.value()))
                .transpose()?
                .unwrap_or(1);
            let next = index
                .checked_add(1)
                .ok_or(Error::Corrupt("address index exhausted"))?;
            meta.insert(NEXT_ADDRESS, next.to_le_bytes().as_slice())?;
            let mut addresses = tx.open_table(ADDRESSES)?;
            let sealed = self.file_key.seal(TAG_LABEL, index, label.as_bytes())?;
            addresses.insert(index, sealed.as_slice())?;
            index
        };
        tx.commit()?;
        Ok((index, self.keys.address(DiversifierIndex::from(index))?))
    }

    /// Every address handed out, with its index and label, plus the
    /// default address at index zero.
    ///
    /// # Errors
    /// Fails on a database error or a label that does not decrypt.
    pub fn addresses(&self) -> Result<Vec<(u64, Address, String)>> {
        let tx = self.db.begin_read()?;
        let addresses = tx.open_table(ADDRESSES)?;
        let mut out = vec![(0, self.keys.default_address()?, String::new())];
        for row in addresses.iter()? {
            let (index, sealed) = row?;
            let index = index.value();
            let label = self.file_key.open(TAG_LABEL, index, sealed.value())?;
            out.push((
                index,
                self.keys.address(DiversifierIndex::from(index))?,
                String::from_utf8(label).map_err(|_| Error::Corrupt("label"))?,
            ));
        }
        Ok(out)
    }

    /// The index of one of our addresses, if it is ours and fits the
    /// wallet's `u64` index space.
    pub fn address_index_of(&self, address: &Address) -> Option<u64> {
        let index = self.keys.index_of(address)?;
        let bytes = index.as_bytes();
        let (low, high) = bytes.split_at(8);
        high.iter()
            .all(|b| *b == 0)
            .then(|| u64::from_le_bytes(low.try_into().unwrap_or([0; 8])))
    }

    /// Records a new queued operation and returns it with its id.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn add_operation(
        &self,
        recipients: Vec<Payment>,
        min_confirmations: u32,
        created_at: u64,
    ) -> Result<Operation> {
        let tx = self.db.begin_write()?;
        let operation = {
            let mut meta = tx.open_table(META)?;
            let id = meta
                .get(NEXT_OPERATION)?
                .map(|v| decode_u64(v.value()))
                .transpose()?
                .unwrap_or(1);
            let next = id
                .checked_add(1)
                .ok_or(Error::Corrupt("operation id exhausted"))?;
            meta.insert(NEXT_OPERATION, next.to_le_bytes().as_slice())?;
            let operation = Operation::new(id, created_at, recipients, min_confirmations);
            let mut operations = tx.open_table(OPERATIONS)?;
            operations.insert(id, self.seal_operation(&operation)?.as_slice())?;
            operation
        };
        tx.commit()?;
        Ok(operation)
    }

    /// Stores the current state of an operation.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn put_operation(&self, operation: &Operation) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut operations = tx.open_table(OPERATIONS)?;
            operations.insert(operation.id, self.seal_operation(operation)?.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Replaces an operation only if its persisted state still equals `previous`.
    /// Returns false if another writer changed it, so a cancellation or rollback
    /// cannot be overwritten by a worker holding an older snapshot.
    ///
    /// # Errors
    /// Fails on a database/decoding error or if the ids differ.
    pub fn compare_and_swap_operation(
        &self,
        previous: &Operation,
        operation: &Operation,
    ) -> Result<bool> {
        if previous.id != operation.id {
            return Err(Error::Corrupt("operation ids differ"));
        }
        let tx = self.db.begin_write()?;
        {
            let mut operations = tx.open_table(OPERATIONS)?;
            let Some(sealed) = operations.get(previous.id)? else {
                return Ok(false);
            };
            let current = self.open_operation(previous.id, sealed.value())?;
            if current != *previous {
                return Ok(false);
            }
            drop(sealed);
            operations.insert(operation.id, self.seal_operation(operation)?.as_slice())?;
        }
        tx.commit()?;
        Ok(true)
    }

    fn open_operation(&self, id: u64, sealed: &[u8]) -> Result<Operation> {
        let plain = self.file_key.open(TAG_OPERATION, id, sealed)?;
        Ok(Operation::from_slice(&plain)?)
    }

    fn decrypt_operations(
        &self,
        operations: &impl ReadableTable<u64, &'static [u8]>,
    ) -> Result<Vec<Operation>> {
        operations
            .iter()?
            .map(|row| {
                let (id, sealed) = row?;
                self.open_operation(id.value(), sealed.value())
            })
            .collect()
    }

    /// Every operation, oldest first.
    ///
    /// # Errors
    /// Fails on a database error or a record that does not decrypt.
    pub fn operations(&self) -> Result<Vec<Operation>> {
        let tx = self.db.begin_read()?;
        let operations = tx.open_table(OPERATIONS)?;
        self.decrypt_operations(&operations)
    }

    /// One operation by id.
    ///
    /// # Errors
    /// Returns [`Error::NoOperation`] if there is none.
    pub fn operation(&self, id: u64) -> Result<Operation> {
        self.operations()?
            .into_iter()
            .find(|op| op.id == id)
            .ok_or(Error::NoOperation(id))
    }

    /// Positions of notes set aside by pending operations, which a new
    /// send must not touch.
    ///
    /// # Errors
    /// See [`Self::operations`].
    pub fn locked_positions(&self) -> Result<Vec<u64>> {
        Ok(self
            .operations()?
            .iter()
            .filter(|op| op.status.is_pending())
            .flat_map(|op| op.locked.iter().copied())
            .collect())
    }

    fn seal_operation(&self, operation: &Operation) -> Result<Vec<u8>> {
        self.file_key
            .seal(TAG_OPERATION, operation.id, &operation.to_vec())
    }
}

/// A little-endian `u64` meta value.
fn decode_u64(bytes: &[u8]) -> Result<u64> {
    bytes
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| Error::Corrupt("u64 meta value"))
}

/// A height row: `hash || first position`.
fn encode_height(hash: BlockHash, first_position: u64) -> Vec<u8> {
    let mut out = hash.as_bytes().to_vec();
    out.extend_from_slice(&first_position.to_le_bytes());
    out
}

fn decode_height(bytes: &[u8]) -> Result<(BlockHash, u64)> {
    let hash: [u8; 32] = bytes
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Corrupt("height row"))?;
    let first: [u8; 8] = bytes
        .get(32..40)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Corrupt("height row"))?;
    Ok((BlockHash::from_bytes(hash), u64::from_le_bytes(first)))
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use null_circuit::proof::ProvingKey;
    use null_crypto::pallas;
    use null_protocol::amount::Amount;
    use null_protocol::block::{empty_header, BlockHeader};
    use null_protocol::builder::{Builder, OutputInfo, SpendInfo};
    use null_protocol::consensus::BranchId;
    use null_protocol::memo::Memo;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    static PK: OnceLock<ProvingKey> = OnceLock::new();

    /// The branch every test transaction is signed for.
    const BRANCH: BranchId = BranchId::new(1);

    fn pk() -> &'static ProvingKey {
        PK.get_or_init(|| ProvingKey::build().unwrap())
    }

    fn sk(seed: u64) -> SpendingKey {
        SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    /// The stored, still encrypted note record at `position`.
    fn raw_note(wallet: &Wallet, position: u64) -> Vec<u8> {
        let tx = wallet.db.begin_read().unwrap();
        let notes = tx.open_table(NOTES).unwrap();
        notes.get(position).unwrap().unwrap().value().to_vec()
    }

    #[test]
    fn sealing_the_same_record_twice_uses_distinct_nonces_and_both_open() {
        let key = FileKey::random(&mut ChaCha20Rng::seed_from_u64(1));
        let a = key.seal(TAG_NOTE, 7, b"note").unwrap();
        let b = key.seal(TAG_NOTE, 7, b"note").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN], "fresh nonce");
        assert_ne!(a[NONCE_LEN..], b[NONCE_LEN..], "fresh keystream");
        assert_eq!(key.open(TAG_NOTE, 7, &a).unwrap(), b"note");
        assert_eq!(key.open(TAG_NOTE, 7, &b).unwrap(), b"note");
    }

    #[test]
    fn a_sealed_record_opens_only_under_its_key_tag_and_position() {
        let key = FileKey::random(&mut ChaCha20Rng::seed_from_u64(2));
        let other = FileKey::random(&mut ChaCha20Rng::seed_from_u64(3));
        let sealed = key.seal(TAG_NOTE, 7, b"note").unwrap();
        assert!(matches!(
            key.open(TAG_NOTE, 8, &sealed),
            Err(Error::WrongPassphrase)
        ));
        assert!(key.open(TAG_SPENDING_KEY, 7, &sealed).is_err());
        assert!(other.open(TAG_NOTE, 7, &sealed).is_err());
        let mut flipped = sealed.clone();
        flipped[NONCE_LEN] ^= 1;
        assert!(key.open(TAG_NOTE, 7, &flipped).is_err());
        assert!(key.open(TAG_NOTE, 7, &sealed[..NONCE_LEN - 1]).is_err());
        assert!(key.open(TAG_NOTE, 7, &[]).is_err());
    }

    /// A block at `height` paying `value` to `keys` through a coinbase.
    fn coinbase_block(
        rng: &mut ChaCha20Rng,
        keys: &WalletKeys,
        prev: BlockHash,
        height: u32,
        value: u64,
    ) -> Block {
        let mut b = Builder::new(Anchor::from_base(pallas::Base::from(0u64)));
        let credit = Amount::from_raw(value).unwrap();
        b.add_output(OutputInfo::new(
            keys.default_address().unwrap(),
            credit,
            Memo::from_text("cb").unwrap(),
            None,
        ))
        .unwrap();
        let tx = b.build_coinbase(pk(), credit, BRANCH, rng).unwrap();
        let mut header: BlockHeader = empty_header(
            height,
            prev,
            Anchor::from_base(pallas::Base::from(u64::from(height))),
        );
        header.tx_root = null_protocol::block::tx_root([tx.txid()]);
        Block::new(header, vec![tx])
    }

    #[test]
    fn wallet_files_open_only_with_their_passphrase_and_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.redb");
        let genesis = BlockHash::from_bytes([1; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let created = Wallet::create(&path, &sk(1), genesis, b"secret", &mut rng).unwrap();
        let address = created.keys().default_address().unwrap();
        drop(created);
        assert!(matches!(
            Wallet::open(&path, genesis, b"wrong"),
            Err(Error::WrongPassphrase)
        ));
        assert!(matches!(
            Wallet::open(&path, BlockHash::ZERO, b"secret"),
            Err(Error::WrongWallet)
        ));
        let opened = Wallet::open(&path, genesis, b"secret").unwrap();
        assert_eq!(opened.keys().default_address().unwrap(), address);
        let debug = format!("{opened:?}");
        drop(opened);
        assert!(
            matches!(
                Wallet::create(&path, &sk(2), genesis, b"x", &mut rng),
                Err(Error::WrongWallet)
            ),
            "no overwrite"
        );
        assert_eq!(debug, "Wallet(<unlocked>)");
    }

    #[test]
    // One persisted chain exercises scanning, spending, rollback, and reopening.
    #[allow(clippy::too_many_lines)]
    fn scanning_finds_notes_persists_encrypted_and_detects_spends() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let other_keys = WalletKeys::from_spending_key(sk(4)).unwrap();
        let genesis = BlockHash::from_bytes([2; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.redb");

        let owner = WalletKeys::from_spending_key(sk(3)).unwrap();
        let b0 = coinbase_block(&mut rng, &other_keys, BlockHash::ZERO, 0, 5);
        let b1 = coinbase_block(&mut rng, &owner, b0.hash(), 1, 1_000_000_000);
        {
            let wallet = Wallet::create(&path, &sk(3), genesis, b"pw", &mut rng).unwrap();
            assert_eq!(
                wallet.scan(&b0, 1, None).unwrap(),
                ScanReport { found: 0, spent: 0 }
            );
            assert!(matches!(
                wallet.scan(&b0, 1, None),
                Err(Error::OutOfOrder {
                    expected: 1,
                    got: 0
                })
            ));
            assert_eq!(
                wallet.scan(&b1, 1, None).unwrap(),
                ScanReport { found: 1, spent: 0 }
            );
            assert_eq!(wallet.balance().unwrap(), 1_000_000_000);
            assert_eq!(wallet.tree_size().unwrap(), 4);
        }
        // The note is not readable from the file without the key.
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(2).any(|w| w == b"cb"),
            "memo text must not appear in the clear"
        );

        let wallet = Wallet::open(&path, genesis, b"pw").unwrap();
        assert_eq!(wallet.next_height().unwrap(), 2);
        assert_eq!(wallet.scanned_hash(1).unwrap(), Some(b1.hash()));
        let note = &wallet.unspent().unwrap()[0];
        assert_eq!(note.memo.to_text(), Some("cb"));

        let (path_to_note, anchor) = wallet.witness(note.position).unwrap();
        let mut b = Builder::new(anchor);
        b.add_spend(SpendInfo::new(sk(3), note.note.clone(), path_to_note))
            .unwrap();
        b.add_output(OutputInfo::new(
            other_keys.default_address().unwrap(),
            Amount::from_raw(1_000).unwrap(),
            Memo::empty(),
            None,
        ))
        .unwrap();
        let change = 1_000_000_000 - 1_000 - 2 * null_protocol::consensus::FEE_PER_ACTION;
        b.add_output(OutputInfo::new(
            owner.default_address().unwrap(),
            Amount::from_raw(change).unwrap(),
            Memo::empty(),
            None,
        ))
        .unwrap();
        let spend = b.build(pk(), BRANCH, &mut rng).unwrap();
        let mut operation = wallet.add_operation(Vec::new(), 1, 0).unwrap();
        operation.status = OperationStatus::Confirmed {
            txid: spend.txid(),
            height: 2,
        };
        operation.locked = vec![note.position];
        operation.transaction = Some(spend.to_vec());
        wallet.put_operation(&operation).unwrap();
        let mut retained = wallet.add_operation(Vec::new(), 1, 0).unwrap();
        retained.status = OperationStatus::Confirmed {
            txid: b1.transactions()[0].txid(),
            height: 1,
        };
        wallet.put_operation(&retained).unwrap();
        let mut header = empty_header(2, b1.hash(), anchor);
        header.tx_root = null_protocol::block::tx_root([spend.txid()]);
        let b2 = Block::new(header, vec![spend]);
        let position = note.position;
        let unspent_record = raw_note(&wallet, position);
        assert_eq!(
            wallet.scan(&b2, 1, None).unwrap(),
            ScanReport { found: 1, spent: 1 }
        );
        assert_eq!(wallet.balance().unwrap(), change);
        assert_eq!(wallet.notes().unwrap().len(), 2);
        let spent_record = raw_note(&wallet, position);

        wallet.rollback_to(1).unwrap();
        let pending = wallet.operation(operation.id).unwrap();
        assert_eq!(
            pending.status,
            OperationStatus::Submitted {
                txid: operation.status.txid().unwrap(),
                built_at: 2,
            }
        );
        assert_eq!(pending.transaction, operation.transaction);
        assert_eq!(wallet.locked_positions().unwrap(), vec![position]);
        assert_eq!(wallet.operation(retained.id).unwrap(), retained);
        let restored_record = raw_note(&wallet, position);
        // Every rewrite of the record used a nonce of its own.
        let nonces = [&unspent_record, &spent_record, &restored_record]
            .map(|record| record[..NONCE_LEN].to_vec());
        assert_ne!(nonces[0], nonces[1]);
        assert_ne!(nonces[1], nonces[2]);
        assert_ne!(nonces[0], nonces[2]);
        assert_eq!(wallet.balance().unwrap(), 1_000_000_000);
        assert_eq!(wallet.tree_size().unwrap(), 4);
        assert_eq!(wallet.notes().unwrap().len(), 1);
        wallet.rollback_to(5).unwrap();
        assert_eq!(
            wallet.next_height().unwrap(),
            2,
            "rollback above the tip is a no-op"
        );
        drop(wallet);
        let reopened = Wallet::open(&path, genesis, b"pw").unwrap();
        assert_eq!(reopened.operation(operation.id).unwrap(), pending);
        assert_eq!(reopened.locked_positions().unwrap(), vec![position]);
    }

    #[test]
    fn compact_scanning_finds_the_same_notes_and_tree_as_full_scanning() {
        use null_protocol::compact::CompactBlock;

        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let owner = WalletKeys::from_spending_key(sk(11)).unwrap();
        let other = WalletKeys::from_spending_key(sk(12)).unwrap();
        let b0 = coinbase_block(&mut rng, &other, BlockHash::ZERO, 0, 5);
        let b1 = coinbase_block(&mut rng, &owner, b0.hash(), 1, 1_000_000_000);

        let full = Wallet::in_memory(&sk(11), BlockHash::ZERO, &mut rng).unwrap();
        full.scan(&b0, 1, None).unwrap();
        full.scan(&b1, 1, None).unwrap();

        let light = Wallet::in_memory(&sk(11), BlockHash::ZERO, &mut rng).unwrap();
        assert_eq!(
            light
                .scan_compact(&CompactBlock::from_block(&b0, 1, None).unwrap())
                .unwrap(),
            ScanReport { found: 0, spent: 0 }
        );
        assert_eq!(
            light
                .scan_compact(&CompactBlock::from_block(&b1, 1, None).unwrap())
                .unwrap(),
            ScanReport { found: 1, spent: 0 }
        );

        assert_eq!(light.balance().unwrap(), full.balance().unwrap());
        assert_eq!(light.tree_size().unwrap(), full.tree_size().unwrap());
        let (lp, la) = light.witness(light.unspent().unwrap()[0].position).unwrap();
        let (fp, fa) = full.witness(full.unspent().unwrap()[0].position).unwrap();
        assert_eq!(la, fa, "same anchor");
        assert_eq!(lp, fp, "same witness");
        // The memo is the one difference: compact blocks omit it.
        assert_eq!(light.unspent().unwrap()[0].memo.to_text(), Some(""));
        assert_eq!(full.unspent().unwrap()[0].memo.to_text(), Some("cb"));

        light
            .scan_compact(&CompactBlock::from_block(&b1, 1, None).unwrap())
            .unwrap_err();
    }

    #[test]
    fn in_memory_wallet_works_and_witnesses_match_the_naive_tree() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let wallet = Wallet::in_memory(&sk(5), BlockHash::ZERO, &mut rng).unwrap();
        let owner = WalletKeys::from_spending_key(sk(5)).unwrap();
        let other = WalletKeys::from_spending_key(sk(6)).unwrap();
        assert!(matches!(wallet.anchor(), Err(Error::Corrupt(_))));
        let b0 = coinbase_block(&mut rng, &owner, BlockHash::ZERO, 0, 7);
        let b1 = coinbase_block(&mut rng, &other, b0.hash(), 1, 8);
        let b2 = coinbase_block(&mut rng, &owner, b1.hash(), 2, 9);
        let mut naive = null_crypto::merkle::MerkleTree::new();
        for block in [&b0, &b1, &b2] {
            wallet.scan(block, 1, None).unwrap();
            for leaf in scan_block(
                &owner,
                block,
                &tree_transactions(block, 1, None).unwrap(),
                0,
            )
            .unwrap()
            .leaves
            {
                naive.append(leaf).unwrap();
            }
        }
        let notes = wallet.unspent().unwrap();
        assert_eq!(notes.len(), 2);
        let positions: Vec<u64> = notes.iter().map(|n| n.position).collect();
        let (paths, anchor) = wallet.witnesses(&positions).unwrap();
        assert_eq!(anchor, Anchor::from_base(naive.root()));
        assert_eq!(anchor, wallet.anchor().unwrap());
        for (note, path) in notes.iter().zip(&paths) {
            assert_eq!(path.root(note.note.cmx().unwrap().inner()), naive.root());
            assert_eq!(*path, naive.path(note.position).unwrap());
        }
        assert!(matches!(wallet.witness(99), Err(Error::NoWitness(99))));
        assert_eq!(wallet.tree_size().unwrap(), 6);

        // Rolling back keeps the older witness valid against the older root.
        wallet.rollback_to(0).unwrap();
        let mut short = null_crypto::merkle::MerkleTree::new();
        for leaf in scan_block(&owner, &b0, &tree_transactions(&b0, 1, None).unwrap(), 0)
            .unwrap()
            .leaves
        {
            short.append(leaf).unwrap();
        }
        let (path, anchor) = wallet.witness(positions[0]).unwrap();
        assert_eq!(anchor, Anchor::from_base(short.root()));
        assert_eq!(path, short.path(positions[0]).unwrap());
        assert_eq!(wallet.tree_size().unwrap(), 2);
    }

    #[test]
    fn addresses_are_handed_out_with_labels_and_map_back() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let wallet = Wallet::in_memory(&sk(11), BlockHash::ZERO, &mut rng).unwrap();
        let (first, a) = wallet.new_address("alice").unwrap();
        let (second, b) = wallet.new_address("bob").unwrap();
        assert_eq!((first, second), (1, 2));
        assert_ne!(a, b);
        let listed = wallet.addresses().unwrap();
        assert_eq!(listed.len(), 3, "default plus two");
        assert_eq!(listed[0].0, 0);
        assert_eq!(listed[1], (1, a, "alice".to_string()));
        assert_eq!(listed[2], (2, b, "bob".to_string()));
        assert_eq!(wallet.address_index_of(&b), Some(2));
        assert_eq!(
            wallet.address_index_of(&wallet.keys().default_address().unwrap()),
            Some(0)
        );
        let other = WalletKeys::from_spending_key(sk(12)).unwrap();
        assert_eq!(
            wallet.address_index_of(&other.default_address().unwrap()),
            None
        );
    }

    #[test]
    fn operations_persist_and_lock_notes_while_pending() {
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let wallet = Wallet::in_memory(&sk(13), BlockHash::ZERO, &mut rng).unwrap();
        let payment = Payment {
            recipient: wallet.keys().default_address().unwrap(),
            amount: Amount::from_raw(5).unwrap(),
            memo: Memo::empty(),
        };
        let mut op = wallet
            .add_operation(vec![payment.clone()], 3, 1_000)
            .unwrap();
        assert_eq!(op.id, 1);
        assert_eq!(wallet.add_operation(vec![payment], 3, 1_001).unwrap().id, 2);
        op.locked = vec![4, 9];
        op.status = crate::operations::OperationStatus::Proving;
        wallet.put_operation(&op).unwrap();
        assert_eq!(wallet.operation(1).unwrap(), op);
        assert_eq!(wallet.operations().unwrap().len(), 2);
        assert_eq!(wallet.locked_positions().unwrap(), vec![4, 9]);
        op.status = crate::operations::OperationStatus::Cancelled;
        wallet.put_operation(&op).unwrap();
        assert!(wallet.locked_positions().unwrap().is_empty());
        assert!(matches!(wallet.operation(7), Err(Error::NoOperation(7))));
    }

    #[test]
    fn operation_updates_cannot_overwrite_a_cancellation_or_a_prover_claim() {
        let mut rng = ChaCha20Rng::seed_from_u64(16);
        let wallet = Wallet::in_memory(&sk(16), BlockHash::ZERO, &mut rng).unwrap();
        let queued = wallet.add_operation(Vec::new(), 1, 0).unwrap();
        let mut cancelled = queued.clone();
        cancelled.status = OperationStatus::Cancelled;
        let mut building = queued.clone();
        building.status = OperationStatus::Building;
        assert!(wallet
            .compare_and_swap_operation(&queued, &cancelled)
            .unwrap());
        assert!(!wallet
            .compare_and_swap_operation(&queued, &building)
            .unwrap());
        assert_eq!(wallet.operation(queued.id).unwrap(), cancelled);

        wallet.put_operation(&queued).unwrap();
        assert!(wallet
            .compare_and_swap_operation(&queued, &building)
            .unwrap());
        assert!(!wallet
            .compare_and_swap_operation(&queued, &cancelled)
            .unwrap());
        assert_eq!(wallet.operation(queued.id).unwrap(), building);
        cancelled.id = 999;
        assert!(wallet
            .compare_and_swap_operation(&building, &cancelled)
            .is_err());
        assert!(!wallet
            .compare_and_swap_operation(&cancelled, &cancelled)
            .unwrap());
    }

    #[test]
    fn a_watch_only_wallet_file_opens_and_sees_notes_but_cannot_spend() {
        let mut rng = ChaCha20Rng::seed_from_u64(14);
        let genesis = BlockHash::from_bytes([4; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch.redb");
        let owner = WalletKeys::from_spending_key(sk(14)).unwrap();
        let b0 = coinbase_block(&mut rng, &owner, BlockHash::ZERO, 0, 700);
        {
            let watch = Wallet::create_watch_only(
                &path,
                owner.full_viewing_key().clone(),
                genesis,
                b"pw",
                &mut rng,
            )
            .unwrap();
            assert!(watch.keys().is_watch_only());
            assert_eq!(watch.scan(&b0, 1, None).unwrap().found, 1);
        }
        let watch = Wallet::open(&path, genesis, b"pw").unwrap();
        assert!(watch.keys().is_watch_only());
        assert_eq!(watch.balance().unwrap(), 700);
        let note = &watch.unspent().unwrap()[0];
        assert_eq!(note.txid, Some(b0.transactions()[0].txid()));
        assert!(matches!(
            crate::spend::build_payment(
                &watch,
                Payment {
                    recipient: owner.default_address().unwrap(),
                    amount: Amount::from_raw(1).unwrap(),
                    memo: Memo::empty(),
                },
                pk(),
                BRANCH,
                &mut rng,
            ),
            Err(Error::WatchOnly)
        ));
        assert!(Wallet::open(&path, genesis, b"nope").is_err());
    }

    #[test]
    fn a_mined_reward_is_found_when_it_matures_not_when_mined() {
        let mut rng = ChaCha20Rng::seed_from_u64(61);
        let owner = WalletKeys::from_spending_key(sk(61)).unwrap();
        let wallet = Wallet::in_memory(&sk(61), BlockHash::ZERO, &mut rng).unwrap();
        let b0 = coinbase_block(&mut rng, &owner, BlockHash::ZERO, 0, 7);
        let b1 = coinbase_block(&mut rng, &owner, b0.hash(), 1, 8);
        let b2 = coinbase_block(&mut rng, &owner, b1.hash(), 2, 9);
        // Maturity two: block 1's reward enters the tree with block 2.
        wallet.scan(&b0, 2, None).unwrap();
        wallet.scan(&b1, 2, None).unwrap();
        assert_eq!(
            wallet.balance().unwrap(),
            7,
            "genesis is exempt, block 1 waits"
        );
        let size_before = wallet.tree_size().unwrap();

        let matured = &b1.transactions()[0];
        assert!(
            wallet.scan(&b2, 2, None).is_err(),
            "the maturing coinbase is required"
        );
        wallet.scan(&b2, 2, Some(matured)).unwrap();
        assert_eq!(
            wallet.balance().unwrap(),
            7 + 8,
            "block 2's own reward waits"
        );
        let reward = wallet
            .unspent()
            .unwrap()
            .into_iter()
            .find(|n| n.note.value().raw() == 8)
            .unwrap();
        let leaves = size_before..size_before + matured.actions().len() as u64;
        assert!(
            leaves.contains(&reward.position),
            "one of the leaves it just added"
        );
        assert_eq!((reward.height, reward.txid), (2, Some(matured.txid())));

        wallet.rollback_to(1).unwrap();
        assert_eq!(wallet.balance().unwrap(), 7, "a rollback unmatures it");
    }
}
