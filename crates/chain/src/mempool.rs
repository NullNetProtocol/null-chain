//! The transaction pool: an arrival-order queue of transactions that are
//! valid against the current tip.
//!
//! There is no fee market, so there is no ordering by fee and no
//! replacement: transactions are mined in the order they arrived, the
//! pool refuses new transactions when full, and a transaction leaves when
//! it is mined, when a block spends one of its nullifiers, or when its
//! anchor becomes too old to include.

use std::collections::{BTreeMap, HashMap, HashSet};

use null_circuit::proof::VerifyingKey;
use null_protocol::block::Block;
use null_protocol::consensus::{next_height, BranchId};
use null_protocol::nullifier::Nullifier;
use null_protocol::transaction::{Transaction, TxId};
use null_protocol::validate as tx_validate;
use null_storage::store::Store;
use rand_core::{CryptoRng, RngCore};

use crate::params::ChainParams;
use crate::{Error, Result};

/// Why a transaction was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The pool already holds it.
    AlreadyKnown,
    /// The pool is full.
    Full,
    /// Its anchor is unknown or too old.
    StaleAnchor,
    /// A nullifier is already spent on chain.
    SpentNullifier,
    /// A nullifier conflicts with a pooled transaction.
    Conflict,
}

impl core::fmt::Display for Rejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::AlreadyKnown => "already in the pool",
            Self::Full => "pool is full",
            Self::StaleAnchor => "anchor unknown or too old",
            Self::SpentNullifier => "nullifier already spent",
            Self::Conflict => "nullifier conflicts with a pooled transaction",
        })
    }
}

/// The pool.
#[derive(Debug)]
pub struct Mempool {
    /// Arrival sequence to transaction, oldest first.
    queue: BTreeMap<u64, Transaction>,
    /// Transaction id to arrival sequence.
    by_id: HashMap<TxId, u64>,
    /// Nullifier to the transaction that would spend it.
    nullifiers: HashMap<Nullifier, TxId>,
    next_seq: u64,
    capacity: usize,
    /// The consensus branch every pooled signature was verified for. The
    /// pool empties whenever the next block's branch differs, whichever
    /// way the tip moved.
    verified_for: Option<BranchId>,
}

impl Mempool {
    /// An empty pool holding at most `capacity` transactions.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: BTreeMap::new(),
            by_id: HashMap::new(),
            nullifiers: HashMap::new(),
            next_seq: 0,
            capacity,
            verified_for: None,
        }
    }

    /// The branch the next block is validated under, emptying the pool
    /// first if it differs from the one the pool was verified for.
    fn sync_branch(&mut self, store: &Store, params: &ChainParams) -> Result<BranchId> {
        let branch = next_branch(store, params)?;
        if self.verified_for != Some(branch) {
            self.clear();
            self.verified_for = Some(branch);
        }
        Ok(branch)
    }

    /// Number of pooled transactions.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Whether the pool holds `txid`.
    pub fn contains(&self, txid: &TxId) -> bool {
        self.by_id.contains_key(txid)
    }

    /// Pooled transactions, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &Transaction> {
        self.queue.values()
    }

    /// A pooled transaction by id.
    pub fn get(&self, txid: &TxId) -> Option<&Transaction> {
        self.by_id.get(txid).and_then(|seq| self.queue.get(seq))
    }

    /// Admits `tx` after full stateless verification and the stateful
    /// checks against `store`.
    ///
    /// # Errors
    /// Returns [`Error::Rejected`] with the reason, or a validation or
    /// storage error.
    pub fn insert(
        &mut self,
        tx: Transaction,
        store: &Store,
        params: &ChainParams,
        vk: &VerifyingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<TxId> {
        let branch = self.sync_branch(store, params)?;
        let txid = tx.txid();
        if self.contains(&txid) {
            return Err(Error::Rejected(Rejection::AlreadyKnown));
        }
        if self.len() >= self.capacity {
            return Err(Error::Rejected(Rejection::Full));
        }
        tx_validate::check_structure(&tx)?;
        self.check_state(&tx, store, params)?;
        tx_validate::verify(&tx, branch, vk, rng)?;
        self.admit(txid, tx);
        Ok(txid)
    }

    /// Re-admits the non-coinbase transactions of reverted blocks without
    /// re-verifying their signatures and proofs, which were valid when
    /// mined. Blocks from another consensus branch than the next block's
    /// are skipped: their signatures would not verify again.
    ///
    /// # Errors
    /// Fails on a storage error. Transactions that no longer fit the state
    /// are dropped silently.
    pub fn readmit(
        &mut self,
        reverted: &[Block],
        store: &Store,
        params: &ChainParams,
    ) -> Result<()> {
        let branch = self.sync_branch(store, params)?;
        let txs = reverted
            .iter()
            .filter(|b| params.branch_at(b.header().height) == branch)
            .flat_map(|b| b.transactions().iter().skip(1));
        for tx in txs {
            let txid = tx.txid();
            if self.contains(&txid) || self.len() >= self.capacity {
                continue;
            }
            if self.check_state(tx, store, params).is_ok() {
                self.admit(txid, tx.clone());
            }
        }
        Ok(())
    }

    /// Anchor recency and nullifier freshness against the store and the
    /// pool.
    fn check_state(&self, tx: &Transaction, store: &Store, params: &ChainParams) -> Result<()> {
        if store
            .anchor_height(tx.anchor(), params.anchor_max_age)?
            .is_none()
        {
            return Err(Error::Rejected(Rejection::StaleAnchor));
        }
        for nf in tx.nullifiers() {
            if store.contains_nullifier(nf)? {
                return Err(Error::Rejected(Rejection::SpentNullifier));
            }
            if self.nullifiers.contains_key(nf) {
                return Err(Error::Rejected(Rejection::Conflict));
            }
        }
        Ok(())
    }

    fn admit(&mut self, txid: TxId, tx: Transaction) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        for nf in tx.nullifiers() {
            self.nullifiers.insert(*nf, txid);
        }
        self.by_id.insert(txid, seq);
        self.queue.insert(seq, tx);
    }

    fn clear(&mut self) {
        self.queue.clear();
        self.by_id.clear();
        self.nullifiers.clear();
    }

    fn remove(&mut self, txid: &TxId) -> Option<Transaction> {
        let seq = self.by_id.remove(txid)?;
        let tx = self.queue.remove(&seq)?;
        for nf in tx.nullifiers() {
            self.nullifiers.remove(nf);
        }
        Some(tx)
    }

    /// The oldest transactions still valid against `store`, at most
    /// `max`, for the next block. Transactions whose anchor has aged out
    /// are dropped from the pool on the way.
    ///
    /// # Errors
    /// Fails on a storage error.
    pub fn select(
        &mut self,
        store: &Store,
        params: &ChainParams,
        max: usize,
    ) -> Result<Vec<Transaction>> {
        self.sync_branch(store, params)?;
        let mut stale = Vec::new();
        let mut chosen = Vec::new();
        for tx in self.queue.values() {
            if chosen.len() >= max {
                break;
            }
            if store
                .anchor_height(tx.anchor(), params.anchor_max_age)?
                .is_none()
            {
                stale.push(tx.txid());
            } else {
                chosen.push(tx.clone());
            }
        }
        for txid in &stale {
            self.remove(txid);
        }
        Ok(chosen)
    }

    /// Drops the transactions `block` mined and any that spend a nullifier
    /// the block spent. If the next block is under another consensus
    /// branch than the pool was verified for, drops everything.
    ///
    /// # Errors
    /// Fails on a storage error.
    pub fn on_block_applied(
        &mut self,
        block: &Block,
        store: &Store,
        params: &ChainParams,
    ) -> Result<()> {
        self.sync_branch(store, params)?;
        let spent: HashSet<Nullifier> = block
            .transactions()
            .iter()
            .flat_map(Transaction::nullifiers)
            .copied()
            .collect();
        let conflicting: Vec<TxId> = self
            .nullifiers
            .iter()
            .filter(|(nf, _)| spent.contains(nf))
            .map(|(_, txid)| *txid)
            .collect();
        for txid in conflicting {
            self.remove(&txid);
        }
        for tx in block.transactions() {
            self.remove(&tx.txid());
        }
        Ok(())
    }
}

/// The consensus branch the next block will be validated under.
fn next_branch(store: &Store, params: &ChainParams) -> Result<BranchId> {
    let tip = store.tip()?.ok_or(Error::InvalidBlock("no genesis"))?;
    Ok(params.branch_at(next_height(tip.height)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejections_display_a_reason() {
        for r in [
            Rejection::AlreadyKnown,
            Rejection::Full,
            Rejection::StaleAnchor,
            Rejection::SpentNullifier,
            Rejection::Conflict,
        ] {
            assert!(!r.to_string().is_empty());
        }
        let empty = Mempool::new(4);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.iter().count(), 0);
    }
}
