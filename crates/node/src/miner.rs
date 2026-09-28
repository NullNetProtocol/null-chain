//! Block templates and the mining task.

use null_chain::difficulty::{next_target, Sample};
use null_chain::params::ChainParams;
use null_chain::pow::EquihashPow;
use null_chain::target::Target;
use null_circuit::proof::ProvingKey;
use null_protocol::address::Address;
use null_protocol::amount::Amount;
use null_protocol::block::{tx_root, Block, BlockHeader, PowSolution};
use null_protocol::builder::{Builder, OutputInfo};
use null_protocol::consensus::{next_height, subsidy, BLOCK_VERSION};
use null_protocol::memo::Memo;
use null_protocol::transaction::Transaction;
use std::sync::Arc;

use null_storage::tree::CommitmentTree;
use rand_core::{CryptoRng, RngCore};
use tokio::sync::{mpsc, oneshot};

use crate::node::Event;
use crate::{Error, Result};

/// Nonces tried per template before asking for a fresh one.
const NONCES_PER_TEMPLATE: u32 = 32;

/// What a miner needs to build the next block.
#[derive(Clone, Debug)]
pub struct Template {
    /// The tip header.
    pub parent: BlockHeader,
    /// Recent headers for the difficulty rule, oldest first.
    pub recent: Vec<BlockHeader>,
    /// The tree after the parent.
    pub tree: CommitmentTree,
    /// Transactions to include after the coinbase.
    pub transactions: Vec<Transaction>,
    /// Network parameters.
    pub params: ChainParams,
    /// Wall-clock time.
    pub now: u64,
}

impl Template {
    /// Builds the coinbase paying `miner` and assembles the header over
    /// it and the template's transactions, with the nonce and solution
    /// still empty. This is the block a pool grinds.
    ///
    /// # Errors
    /// Fails on a building or proving error.
    pub fn assemble(
        &self,
        miner: &Address,
        pk: &ProvingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(BlockHeader, Vec<Transaction>)> {
        let height = next_height(self.parent.height)?;
        let credit = self.credit()?;
        let mut coinbase = Builder::new(self.parent.commitment_root);
        coinbase.add_output(OutputInfo::new(*miner, credit, Memo::empty(), None))?;
        let coinbase = coinbase.build_coinbase(pk, credit, self.params.branch_at(height), rng)?;

        let mut transactions = vec![coinbase];
        transactions.extend(self.transactions.iter().cloned());
        let mut tree = self.tree.clone();
        for tx in &transactions {
            for action in tx.actions() {
                tree.append(action.body().cmx())?;
            }
        }
        let header = BlockHeader {
            version: BLOCK_VERSION,
            prev_hash: self.parent.hash(),
            height,
            timestamp: self.now.max(self.parent.timestamp.saturating_add(1)),
            commitment_root: tree.root(),
            tx_root: tx_root(transactions.iter().map(Transaction::txid)),
            target: self.next_target()?.to_compact(),
            nonce: [0; 32],
            solution: PowSolution::empty(),
        };
        Ok((header, transactions))
    }

    /// The subsidy plus the fees of the template's transactions.
    ///
    /// # Errors
    /// Fails if the sum overflows.
    pub fn credit(&self) -> Result<Amount> {
        let height = next_height(self.parent.height)?;
        let fees = self
            .transactions
            .iter()
            .try_fold(Amount::ZERO, |acc, tx| acc.checked_add(tx.fee()?))?;
        Ok(subsidy(height).checked_add(fees)?)
    }

    /// The target the next block must meet.
    ///
    /// # Errors
    /// Fails on a malformed target in the recent headers.
    pub fn next_target(&self) -> Result<Target> {
        let samples = self
            .recent
            .iter()
            .map(|h| {
                Ok(Sample {
                    timestamp: h.timestamp,
                    target: Target::from_compact(h.target)?,
                })
            })
            .collect::<core::result::Result<Vec<_>, null_chain::Error>>()?;
        Ok(next_target(&self.params, &samples))
    }

    /// Assembles the block and mines it, trying a bounded number of
    /// nonces.
    ///
    /// # Errors
    /// Fails on a building or proving error.
    pub fn mine(
        &self,
        miner: &Address,
        pk: &ProvingKey,
        pow: &EquihashPow,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Option<Block>> {
        let (mut header, transactions) = self.assemble(miner, pk, rng)?;
        if pow.mine(&mut header, NONCES_PER_TEMPLATE, rng)? {
            Ok(Some(Block::new(header, transactions)))
        } else {
            Ok(None)
        }
    }
}

/// Mines on `threads` cores: builds the proving key once, then runs that
/// many independent workers. Each worker fetches its own template and
/// mines from a random nonce, so they explore disjoint nonce ranges with
/// overwhelming probability and their throughput adds up.
///
/// # Errors
/// Returns [`Error::Stopped`] when the node loop is gone, or a proving
/// or building error.
pub async fn run(
    miner: Address,
    params: ChainParams,
    threads: usize,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    let pk = Arc::new(
        tokio::task::spawn_blocking(ProvingKey::build)
            .await
            .map_err(|_| Error::Stopped)??,
    );
    let pow = EquihashPow::new(params.equihash);
    let workers: Vec<_> = (0..threads.max(1))
        .map(|_| tokio::spawn(mine_loop(miner, pow, Arc::clone(&pk), events.clone())))
        .collect();
    // Every worker runs until the node loop is gone, when they all stop.
    for worker in workers {
        worker.await.map_err(|_| Error::Stopped)??;
    }
    Ok(())
}

/// One worker: fetch a template, mine it on the blocking pool, submit any
/// block found, repeat.
async fn mine_loop(
    miner: Address,
    pow: EquihashPow,
    pk: Arc<ProvingKey>,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    loop {
        let (reply, response) = oneshot::channel();
        events
            .send(Event::TemplateRequest(reply))
            .await
            .map_err(|_| Error::Stopped)?;
        let Ok(template) = response.await else {
            return Err(Error::Stopped);
        };
        let pk = Arc::clone(&pk);
        // Proving and solving are CPU-bound; run them on the blocking pool
        // so many workers use many cores without starving the runtime.
        let found = tokio::task::spawn_blocking(move || {
            let mut rng = rand::rngs::OsRng;
            template.mine(&miner, pk.as_ref(), &pow, &mut rng)
        })
        .await
        .map_err(|_| Error::Stopped)??;
        if let Some(block) = found {
            events
                .send(Event::Mined(Box::new(block)))
                .await
                .map_err(|_| Error::Stopped)?;
        }
        tokio::task::yield_now().await;
    }
}
