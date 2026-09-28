//! The genesis block: the premine coinbase if the network has one, the
//! commitment tree root after it, the limit target, no proof of work. It
//! is identified by hash, not validated; the tests here verify the
//! embedded coinbase once, so every node agrees on it by construction.

use null_circuit::proof::ProvingKey;
use null_protocol::address::Address;
use null_protocol::amount::Amount;
use null_protocol::block::{empty_header, tx_root, Block, BlockHash};
use null_protocol::builder::{Builder, OutputInfo};
use null_protocol::bytes::Encodable;
use null_protocol::consensus::PREMINE;
use null_protocol::memo::Memo;
use null_protocol::transaction::Transaction;
use null_storage::tree::CommitmentTree;
use rand_core::{CryptoRng, RngCore};

use crate::params::ChainParams;
use crate::Result;

/// The genesis block of a network.
pub fn genesis(params: &ChainParams) -> Block {
    genesis_with_tree(params).0
}

/// The genesis block and the commitment tree after it, which holds the
/// premine's note commitments.
pub fn genesis_with_tree(params: &ChainParams) -> (Block, CommitmentTree) {
    // The bytes are a compiled-in constant checked by the tests below; a
    // network whose constant does not parse would fail those tests, not
    // a node at runtime.
    let transactions: Vec<Transaction> = params
        .genesis_coinbase
        .and_then(|bytes| Transaction::from_slice(bytes).ok())
        .into_iter()
        .collect();
    let mut tree = CommitmentTree::empty();
    for action in transactions.iter().flat_map(Transaction::actions) {
        // Genesis holds at most one transaction's outputs; the tree
        // cannot be full.
        let _ = tree.append(action.body().cmx());
    }
    let mut header = empty_header(0, BlockHash::ZERO, tree.root());
    header.timestamp = params.genesis_timestamp;
    header.target = params.pow_limit.to_compact();
    header.tx_root = tx_root(transactions.iter().map(Transaction::txid));
    (Block::new(header, transactions), tree)
}

/// Builds the coinbase that pays the premine to `dev` on `params`'s
/// network: no spends, one output of [`PREMINE`], signed for the genesis
/// branch and proved against the empty tree. Its bytes go into
/// `ChainParams::genesis_coinbase`; because proofs are randomized, every
/// run yields a different transaction and so a different genesis hash.
///
/// # Errors
/// Fails on a building or proving error.
pub fn build_genesis_coinbase(
    params: &ChainParams,
    dev: &Address,
    pk: &ProvingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Transaction> {
    let credit = Amount::from_raw(PREMINE)?;
    let mut builder = Builder::new(CommitmentTree::empty().root());
    builder.add_output(OutputInfo::new(*dev, credit, Memo::empty(), None))?;
    Ok(builder.build_coinbase(pk, credit, params.genesis_branch, rng)?)
}

#[cfg(test)]
mod tests {
    use null_circuit::proof::VerifyingKey;
    use null_protocol::validate::{coinbase_balance, verify_with_balance};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn genesis_is_deterministic_and_pinned_for_mainnet() {
        let a = genesis(&ChainParams::mainnet());
        assert_eq!(a, genesis(&ChainParams::mainnet()));
        assert_eq!(a.header().height, 0);
        assert_eq!(a.check_tx_root(), Ok(()));
        assert_eq!(
            a.hash().to_string(),
            "6c49fc018f0f7d2ee744e55c28df974b96c8daa68a7b5f3ee52b60cba31d14d6",
            "genesis changed; update deliberately"
        );
    }

    #[test]
    fn networks_have_different_genesis_blocks() {
        assert_ne!(
            genesis(&ChainParams::mainnet()).hash(),
            genesis(&ChainParams::test()).hash()
        );
    }

    /// The embedded coinbase of every network is a valid coinbase paying
    /// exactly the premine, and the genesis root commits to its outputs.
    #[test]
    fn embedded_premines_verify_and_pay_exactly_the_premine() {
        let vk = VerifyingKey::build().unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for params in [ChainParams::mainnet(), ChainParams::test()] {
            let (block, tree) = genesis_with_tree(&params);
            assert_eq!(block.header().commitment_root, tree.root());
            let Some(bytes) = params.genesis_coinbase else {
                assert!(block.transactions().is_empty());
                continue;
            };
            let tx = Transaction::from_slice(bytes).expect("embedded coinbase parses");
            assert_eq!(block.transactions(), std::slice::from_ref(&tx));
            let balance = coinbase_balance(Amount::from_raw(PREMINE).unwrap()).unwrap();
            verify_with_balance(&tx, balance, params.genesis_branch, &vk, &mut rng)
                .expect("embedded coinbase verifies for exactly the premine");
            assert!(
                verify_with_balance(&tx, balance + 1, params.genesis_branch, &vk, &mut rng)
                    .is_err(),
                "any other balance fails the binding signature"
            );
            assert_eq!(tree.size(), u64::try_from(tx.actions().len()).unwrap());
        }
    }
}
