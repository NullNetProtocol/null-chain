//! Shared mining harness for the chain integration tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::OnceLock;

use null_chain::chain::{Chain, Import};
use null_chain::difficulty::{next_target, Sample};
use null_chain::params::ChainParams;
use null_chain::target::Target;
use null_chain::validate::{header_lookback, recent_headers};
use null_chain::Error;
use null_circuit::proof::ProvingKey;
use null_crypto::keys::{Diversifier, FullViewingKey, SpendingKey};
use null_crypto::merkle::MerkleTree;
use null_protocol::address::Address;
use null_protocol::amount::Amount;
use null_protocol::block::{Block, BlockHeader, PowSolution};
use null_protocol::builder::{Builder, OutputInfo, SpendInfo};
use null_protocol::consensus::{subsidy, BranchId, BLOCK_VERSION, FEE_PER_ACTION};
use null_protocol::memo::Memo;
use null_protocol::note::{Note, Rho};
use null_protocol::note_encryption::decrypt_note_with_ivk;
use null_protocol::transaction::Transaction;
use null_storage::store::Store;
use null_storage::tree::CommitmentTree;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

static PK: OnceLock<ProvingKey> = OnceLock::new();

pub fn proving_key() -> &'static ProvingKey {
    PK.get_or_init(|| ProvingKey::build().unwrap())
}

pub struct Wallet {
    pub sk: SpendingKey,
    pub fvk: FullViewingKey,
    pub address: Address,
    /// Every commitment on the chain, in tree order, for witnesses.
    pub tree: MerkleTree,
    /// Notes this wallet owns, with their tree positions.
    pub notes: Vec<(Note, u64)>,
}

impl Wallet {
    pub fn new(rng: &mut ChaCha20Rng) -> Self {
        let sk = SpendingKey::random(rng);
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let address = Address::derive(
            &fvk.incoming_viewing_key().unwrap(),
            Diversifier::random(rng),
        )
        .unwrap();
        Self {
            sk,
            fvk,
            address,
            tree: MerkleTree::new(),
            notes: Vec::new(),
        }
    }

    /// Scans a block the way a wallet would, tracking the tree.
    pub fn scan(&mut self, block: &Block) {
        let ivk = self.fvk.incoming_viewing_key().unwrap();
        for tx in block.transactions() {
            for action in tx.actions() {
                let body = action.body();
                let position = self.tree.append(*body.cmx().inner()).unwrap();
                let rho = Rho::from_nullifier(body.nullifier()).unwrap();
                if let Ok((note, _)) =
                    decrypt_note_with_ivk(&ivk, body.encrypted_note(), rho, body.cmx())
                {
                    if note.value().raw() > 0 {
                        self.notes.push((note, position));
                    }
                }
            }
        }
    }

    /// A copy whose first note is note `index`, for spending helpers.
    pub fn clone_for_test(&self, index: usize) -> Self {
        let mut notes = self.notes.clone();
        notes.swap(0, index);
        Self {
            sk: self.sk.clone(),
            fvk: FullViewingKey::derive(&self.sk).unwrap(),
            address: self.address,
            tree: self.tree.clone(),
            notes,
        }
    }

    pub fn balance(&self) -> u64 {
        self.notes.iter().map(|(n, _)| n.value().raw()).sum()
    }
}

pub struct Harness {
    pub chain: Chain,
    pub rng: ChaCha20Rng,
    pub miner: Wallet,
    /// Seconds between the blocks this harness mines; the network's
    /// block interval unless a test wants faster or slower blocks.
    pub spacing: u64,
}

impl Harness {
    pub fn new(seed: u64) -> Self {
        Self::with_params(seed, ChainParams::test())
    }

    /// A harness on a chain with explicit parameters, for upgrade tests.
    pub fn with_params(seed: u64, params: ChainParams) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let chain = Chain::new(
            Store::in_memory().unwrap(),
            params,
            proving_key().verifying_key(),
        )
        .unwrap();
        let mut miner = Wallet::new(&mut rng);
        // Genesis carries the premine coinbase, whose leaves every later
        // witness is computed over.
        let genesis_hash = chain.store().hash_at(0).unwrap().unwrap();
        miner.scan(&chain.store().block(&genesis_hash).unwrap().unwrap());
        Self {
            spacing: params.block_interval,
            chain,
            rng,
            miner,
        }
    }

    /// Builds and mines a block on top of a main-chain `parent`.
    pub fn make_block(&mut self, parent: &BlockHeader, txs: Vec<Transaction>) -> Block {
        let parent_tree = self.chain.store().tree_at(parent.height).unwrap().unwrap();
        self.make_block_on(parent, &parent_tree, txs).0
    }

    /// Builds and mines a block on top of any `parent` whose tree after
    /// application is `parent_tree`. Returns the block and its tree.
    pub fn make_block_on(
        &mut self,
        parent: &BlockHeader,
        parent_tree: &CommitmentTree,
        txs: Vec<Transaction>,
    ) -> (Block, CommitmentTree) {
        let height = parent.height + 1;
        let fees: u64 = txs.iter().map(|t| t.fee().unwrap().raw()).sum();
        let credit = subsidy(height)
            .checked_add(null_protocol::amount::Amount::from_raw(fees).unwrap())
            .unwrap();
        let anchor = parent.commitment_root;
        let mut b = Builder::new(anchor);
        b.add_output(OutputInfo::new(
            self.miner.address,
            credit,
            Memo::empty(),
            None,
        ))
        .unwrap();
        let branch = self.chain.params().branch_at(height);
        let coinbase = b
            .build_coinbase(proving_key(), credit, branch, &mut self.rng)
            .unwrap();
        let mut transactions = vec![coinbase];
        transactions.extend(txs);

        // The tree after this block: the store's tree at the parent plus
        // every commitment in block order.
        let mut tree = parent_tree.clone();
        for tx in &transactions {
            for action in tx.actions() {
                tree.append(action.body().cmx()).unwrap();
            }
        }

        let params = *self.chain.params();
        let recent =
            recent_headers(self.chain.store(), parent.height, header_lookback(&params)).unwrap();
        let samples: Vec<Sample> = recent
            .iter()
            .map(|h| Sample {
                timestamp: h.timestamp,
                target: Target::from_compact(h.target).unwrap(),
            })
            .collect();
        let mut header = BlockHeader {
            version: BLOCK_VERSION,
            prev_hash: parent.hash(),
            height,
            timestamp: parent.timestamp + self.spacing,
            commitment_root: tree.root(),
            tx_root: null_protocol::block::tx_root(transactions.iter().map(Transaction::txid)),
            target: next_target(&params, &samples).to_compact(),
            nonce: [0; 32],
            solution: PowSolution::empty(),
        };
        assert!(
            self.chain
                .pow()
                .mine(&mut header, 256, &mut self.rng)
                .unwrap(),
            "mining failed"
        );
        (Block::new(header, transactions), tree)
    }

    pub fn tip_header(&self) -> BlockHeader {
        let tip = self.chain.tip().unwrap();
        self.chain
            .store()
            .block(&tip.hash)
            .unwrap()
            .unwrap()
            .header()
            .clone()
    }

    pub fn import(&mut self, block: &Block) -> Result<Import, Error> {
        let now = block.header().timestamp;
        self.chain.import(block, now, &mut self.rng)
    }

    /// Mines and imports one block on the tip.
    pub fn extend(&mut self, txs: Vec<Transaction>) -> Block {
        let parent = self.tip_header();
        let block = self.make_block(&parent, txs);
        assert_eq!(self.import(&block).unwrap(), Import::Extended);
        self.miner.scan(&block);
        block
    }
}

/// A regular transaction paying `pay` from the wallet's first note to
/// `recipient`, built against the current tip and signed for the branch
/// of the next block.
pub fn spend_first_note(
    h: &mut Harness,
    wallet: &Wallet,
    recipient: &Address,
    pay: u64,
) -> Transaction {
    let branch = h.chain.params().branch_at(h.tip_header().height + 1);
    spend_first_note_for(h, wallet, recipient, pay, branch)
}

/// As [`spend_first_note`], signed for an explicit `branch`.
pub fn spend_first_note_for(
    h: &mut Harness,
    wallet: &Wallet,
    recipient: &Address,
    pay: u64,
    branch: BranchId,
) -> Transaction {
    let (note, position) = wallet.notes[0].clone();
    let path = wallet.tree.path(position).unwrap();
    let parent = h.tip_header();
    let fee = 2 * FEE_PER_ACTION;
    let change = note.value().raw() - pay - fee;
    let mut b = Builder::new(parent.commitment_root);
    b.add_spend(SpendInfo::new(wallet.sk.clone(), note, path))
        .unwrap();
    b.add_output(OutputInfo::new(
        *recipient,
        Amount::from_raw(pay).unwrap(),
        Memo::empty(),
        None,
    ))
    .unwrap();
    if change > 0 {
        b.add_output(OutputInfo::new(
            wallet.address,
            Amount::from_raw(change).unwrap(),
            Memo::empty(),
            None,
        ))
        .unwrap();
    }
    b.build(proving_key(), branch, &mut h.rng).unwrap()
}
