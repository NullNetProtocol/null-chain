//! Block validation.
//!
//! [`Validator::validate_and_apply`] is the stateful path, in order,
//! cheapest first: header shape, timestamps, target, proof of work,
//! transaction root, per-transaction structure and anchors, nullifier
//! freshness, then one batch of signatures and one batch of proofs, and
//! finally the commitment root after appending every new note.
//!
//! [`Validator::check_authorization`] is the stateless subset: transaction
//! count, structure, balances, signatures and proofs. Side-chain blocks
//! pass it before they are stored. The txid and the transaction root
//! exclude proofs and signatures, so without this check a peer could
//! store an unverifiable body under a valid header hash and the node would
//! then refuse the real body as already known.

use std::collections::BTreeSet;

use null_circuit::proof::{ProofBatch, VerifyingKey};
use null_crypto::signature::BatchVerifier;
use null_protocol::amount::Amount;
use null_protocol::block::{Block, BlockHeader};
use null_protocol::consensus::{
    next_height, subsidy, BranchId, BLOCK_VERSION, MAX_BLOCK_TRANSACTIONS,
};
use null_protocol::maturity::{earlier_origin, tree_transactions};
use null_protocol::nullifier::Nullifier;
use null_protocol::transaction::Transaction;
use null_protocol::validate as tx_validate;
use null_storage::store::Store;
use null_storage::tree::CommitmentTree;
use rand_core::{CryptoRng, RngCore};

use crate::difficulty::{next_target, Sample};
use crate::params::ChainParams;
use crate::pow::EquihashPow;
use crate::target::Target;
use crate::{Error, Result};

/// Headers whose timestamps form the median a new block must exceed.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// How many headers before a block the header rules look at: the
/// difficulty rule needs `difficulty_window + 1` to form its solve-time
/// pairs, the timestamp rule [`MEDIAN_TIME_SPAN`]. Validation and block
/// templates must use the same count or a miner disagrees with its own
/// validator once the chain is long enough to retarget.
pub fn header_lookback(params: &ChainParams) -> usize {
    params
        .difficulty_window
        .saturating_add(1)
        .max(MEDIAN_TIME_SPAN)
}

/// What the validator needs besides the block.
pub struct Validator<'a> {
    /// Network parameters.
    pub params: &'a ChainParams,
    /// Proof of work for those parameters.
    pub pow: &'a EquihashPow,
    /// The circuit verifying key.
    pub vk: &'a VerifyingKey,
    /// Local wall-clock time in seconds, for the future-timestamp rule.
    pub now: u64,
}

impl Validator<'_> {
    /// Validates `block` against the tip of `store` and, if valid, applies
    /// it. Returns the commitment tree after the block.
    ///
    /// # Errors
    /// Returns the first rule violated, or a storage error.
    pub fn validate_and_apply(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<CommitmentTree> {
        let tip = store.tip()?.ok_or(Error::InvalidBlock("no genesis"))?;
        let header = block.header();
        if header.prev_hash != tip.hash || header.height != next_height(tip.height)? {
            return Err(Error::InvalidHeader("does not extend the tip"));
        }
        self.check_checkpoint(block)?;
        let recent = recent_headers(store, tip.height, self.window())?;
        self.check_header(header, &recent)?;
        block.check_tx_root()?;

        let tree = self.check_transactions(store, block, rng)?;
        if tree.root() != header.commitment_root {
            return Err(Error::InvalidHeader("commitment root mismatch"));
        }
        store.apply(block, &tree)?;
        if let Some(prune_below) = header.height.checked_sub(self.params.max_reorg_depth) {
            store.prune_frontiers_below(prune_below)?;
        }
        Ok(tree)
    }

    /// Checks a side-chain block before it is stored: its header against
    /// its own ancestry (height, timestamp, target, proof of work), the
    /// checkpoint at its height, the transaction root, and everything
    /// stateless about its transactions. Nothing here needs the tip.
    ///
    /// # Errors
    /// Returns [`Error::Orphan`] if the parent is unknown, or the first
    /// rule violated.
    pub fn check_side_chain_block(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<()> {
        let header = block.header();
        let parent = store.block(&header.prev_hash)?.ok_or(Error::Orphan)?;
        if header.height != next_height(parent.header().height)? {
            return Err(Error::InvalidHeader("height does not follow the parent"));
        }
        self.check_checkpoint(block)?;
        let recent = branch_headers(store, parent.header(), self.window())?;
        self.check_header(header, &recent)?;
        block.check_tx_root()?;
        self.check_authorization(block, rng)
    }

    /// Headers the timestamp and difficulty rules look back over.
    fn window(&self) -> usize {
        header_lookback(self.params)
    }

    fn check_checkpoint(&self, block: &Block) -> Result<()> {
        if self
            .params
            .checkpoint_at(block.header().height)
            .is_some_and(|c| c.hash != block.hash())
        {
            return Err(Error::InvalidHeader("conflicts with a checkpoint"));
        }
        Ok(())
    }

    /// The header rules that depend only on the headers before it:
    /// version, timestamp, target and proof of work, cheapest first.
    fn check_header(&self, header: &BlockHeader, recent: &[BlockHeader]) -> Result<()> {
        if header.version != BLOCK_VERSION {
            return Err(Error::InvalidHeader("unknown version"));
        }
        self.check_timestamp(header, recent)?;
        self.check_target(header, recent)?;
        self.pow.check(header)
    }

    fn check_timestamp(&self, header: &BlockHeader, recent: &[BlockHeader]) -> Result<()> {
        let mut times: Vec<u64> = recent
            .iter()
            .rev()
            .take(MEDIAN_TIME_SPAN)
            .map(|h| h.timestamp)
            .collect();
        times.sort_unstable();
        let median = times.get(times.len() / 2).copied().unwrap_or(0);
        if header.timestamp <= median {
            return Err(Error::InvalidHeader("timestamp not after median"));
        }
        if header.timestamp > self.now.saturating_add(self.params.max_future_seconds) {
            return Err(Error::InvalidHeader("timestamp too far in the future"));
        }
        Ok(())
    }

    fn check_target(&self, header: &BlockHeader, recent: &[BlockHeader]) -> Result<()> {
        let samples = recent
            .iter()
            .map(|h| {
                Ok(Sample {
                    timestamp: h.timestamp,
                    target: Target::from_compact(h.target)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let expected = next_target(self.params, &samples);
        if Target::from_compact(header.target)? == expected {
            Ok(())
        } else {
            Err(Error::InvalidHeader(
                "target does not match the difficulty rule",
            ))
        }
    }

    /// Checks everything about the transactions that needs no chain
    /// state: count, structure, balances, signatures and proofs.
    ///
    /// # Errors
    /// Returns the first rule violated.
    pub fn check_authorization(
        &self,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<()> {
        let branch = self.params.branch_at(block.header().height);
        let mut batch = AuthorizationBatch::default();
        for (tx, balance) in balances(block)? {
            batch.queue(tx, balance, branch)?;
        }
        batch.verify(self.vk, rng)
    }

    /// Checks every transaction and returns the tree after the outputs the
    /// block appends, in tree order: the coinbase maturing at this height,
    /// then the block's transactions after its own coinbase, which waits
    /// for its own maturity.
    fn check_transactions(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<CommitmentTree> {
        let branch = self.params.branch_at(block.header().height);
        let mut batch = AuthorizationBatch::default();
        for (tx, balance) in balances(block)? {
            batch.queue(tx, balance, branch)?;
            self.check_chain_state(store, tx)?;
        }
        batch.verify(self.vk, rng)?;
        let earlier = earlier_coinbase(store, self.params, block.header().height)?;
        let mut tree = store.tree()?;
        for tx in tree_transactions(block, self.params.coinbase_maturity, earlier.as_ref())? {
            for action in tx.actions() {
                tree.append(action.body().cmx())?;
            }
        }
        Ok(tree)
    }

    /// The checks that need the store: anchor age and nullifier freshness
    /// against the chain.
    fn check_chain_state(&self, store: &Store, tx: &Transaction) -> Result<()> {
        if store
            .anchor_height(tx.anchor(), self.params.anchor_max_age)?
            .is_none()
        {
            return Err(Error::InvalidBlock("unknown or stale anchor"));
        }
        for nf in tx.nullifiers() {
            if store.contains_nullifier(nf)? {
                return Err(Error::InvalidBlock("nullifier already spent"));
            }
        }
        Ok(())
    }
}

/// The coinbase of an earlier main-chain block that matures at `height`,
/// if one does. Blocks are applied in order, so during a reorganization the
/// store's main chain already holds the new branch below `height`.
///
/// # Errors
/// Returns a storage error, or [`Error::InvalidBlock`] if the store lacks
/// the block or it has no coinbase.
pub fn earlier_coinbase(
    store: &Store,
    params: &ChainParams,
    height: u32,
) -> Result<Option<Transaction>> {
    let Some(origin) = earlier_origin(height, params.coinbase_maturity) else {
        return Ok(None);
    };
    let block = store
        .hash_at(origin)?
        .and_then(|hash| store.block(&hash).transpose())
        .transpose()?
        .ok_or(Error::InvalidBlock("maturing block missing"))?;
    let coinbase = block
        .transactions()
        .first()
        .ok_or(Error::InvalidBlock("maturing block has no coinbase"))?;
    Ok(Some(coinbase.clone()))
}

/// Every transaction of `block` with the public balance it must prove:
/// the coinbase gets the negative block credit, every other transaction
/// its fee.
///
/// # Errors
/// Fails if the count is out of range or the fees overflow.
fn balances(block: &Block) -> Result<Vec<(&Transaction, i64)>> {
    let txs = block.transactions();
    if txs.is_empty() || txs.len() > MAX_BLOCK_TRANSACTIONS {
        return Err(Error::InvalidBlock("transaction count out of range"));
    }
    let fees = txs
        .iter()
        .skip(1)
        .try_fold(Amount::ZERO, |acc, tx| acc.checked_add(tx.fee()?))?;
    let credit = subsidy(block.header().height).checked_add(fees)?;
    txs.iter()
        .enumerate()
        .map(|(index, tx)| {
            let balance = if index == 0 {
                tx_validate::coinbase_balance(credit)?
            } else {
                tx_validate::regular_balance(tx)?
            };
            Ok((tx, balance))
        })
        .collect()
}

/// One block's signatures and proofs, verified together at the end, and
/// the nullifiers seen so far, so a nullifier spent twice within the
/// block is caught before any expensive verification.
#[derive(Default)]
struct AuthorizationBatch {
    signatures: BatchVerifier,
    proofs: ProofBatch,
    seen: BTreeSet<Nullifier>,
}

impl AuthorizationBatch {
    /// Checks `tx`'s structure and block-wide nullifier uniqueness and
    /// queues its signatures, made for `branch`, and its proof.
    fn queue(&mut self, tx: &Transaction, balance: i64, branch: BranchId) -> Result<()> {
        tx_validate::check_structure(tx)?;
        for nf in tx.nullifiers() {
            if !self.seen.insert(*nf) {
                return Err(Error::InvalidBlock("nullifier already spent"));
            }
        }
        tx_validate::queue_signatures(tx, balance, branch, &mut self.signatures)?;
        tx_validate::queue_proof(tx, &mut self.proofs)?;
        Ok(())
    }

    fn verify(self, vk: &VerifyingKey, rng: &mut (impl RngCore + CryptoRng)) -> Result<()> {
        self.signatures.verify(rng)?;
        self.proofs.verify(vk)?;
        Ok(())
    }
}

/// The last `count` headers ending at `parent`, oldest first, found by
/// following previous-hash links, so it works for any stored branch.
///
/// # Errors
/// Fails on a storage error or a missing ancestor.
pub fn branch_headers(
    store: &Store,
    parent: &BlockHeader,
    count: usize,
) -> Result<Vec<BlockHeader>> {
    let mut headers = vec![parent.clone()];
    while headers.len() < count {
        let Some(last) = headers.last() else { break };
        if last.height == 0 {
            break;
        }
        let ancestor = store
            .block(&last.prev_hash)?
            .ok_or(Error::InvalidBlock("ancestor missing"))?;
        headers.push(ancestor.header().clone());
    }
    headers.reverse();
    Ok(headers)
}

/// The last `count` headers ending at `tip_height`, oldest first.
///
/// # Errors
/// Fails on a storage error or a gap in the height index.
pub fn recent_headers(store: &Store, tip_height: u32, count: usize) -> Result<Vec<BlockHeader>> {
    let count = u32::try_from(count).unwrap_or(u32::MAX);
    let start = tip_height.saturating_sub(count.saturating_sub(1));
    (start..=tip_height)
        .map(|height| {
            let hash = store
                .hash_at(height)?
                .ok_or(Error::InvalidBlock("height index gap"))?;
            let block = store
                .block(&hash)?
                .ok_or(Error::InvalidBlock("block missing"))?;
            Ok(block.header().clone())
        })
        .collect()
}
