//! Findings of the 2026-11 monetary review, kept as regression tests: a
//! failed deep reorganization restores the old chain, and a node accepts a
//! valid deep branch whose anchors are older than the reorganization depth.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{proving_key, Harness};
use null_chain::chain::Import;
use null_chain::params::ChainParams;
use null_protocol::block::{Block, BlockHeader, PowSolution};
use null_protocol::builder::{Builder, OutputInfo};
use null_protocol::consensus::subsidy;
use null_protocol::maturity::tree_transactions;
use null_protocol::memo::Memo;
use null_protocol::transaction::{Anchor, Transaction};

fn coinbase_at(h: &mut Harness, height: u32, anchor: Anchor) -> Transaction {
    let credit = subsidy(height);
    let mut builder = Builder::new(anchor);
    builder
        .add_output(OutputInfo::new(
            h.miner.address,
            credit,
            Memo::empty(),
            None,
        ))
        .unwrap();
    builder
        .build_coinbase(
            proving_key(),
            credit,
            h.chain.params().branch_at(height),
            &mut h.rng,
        )
        .unwrap()
}

fn replace_coinbase(h: &mut Harness, template: &Block, coinbase: Transaction) -> Block {
    let params = *h.chain.params();
    let height = template.header().height;
    let mut tree = h.chain.store().tree_at(height - 1).unwrap().unwrap();
    let earlier = null_chain::validate::earlier_coinbase(h.chain.store(), &params, height).unwrap();
    let shell = Block::new(template.header().clone(), vec![coinbase]);
    for tx in tree_transactions(&shell, params.coinbase_maturity, earlier.as_ref()).unwrap() {
        for action in tx.actions() {
            tree.append(action.body().cmx()).unwrap();
        }
    }
    let mut header = shell.header().clone();
    header.commitment_root = tree.root();
    header.tx_root =
        null_protocol::block::tx_root(shell.transactions().iter().map(Transaction::txid));
    remine(h, header, shell.transactions().to_vec())
}

fn remine(h: &mut Harness, mut header: BlockHeader, txs: Vec<Transaction>) -> Block {
    header.solution = PowSolution::empty();
    assert!(h.chain.pow().mine(&mut header, 256, &mut h.rng).unwrap());
    Block::new(header, txs)
}

#[test]
fn a_failed_deep_reorganization_restores_the_old_chain() {
    let params = ChainParams {
        max_reorg_depth: 2,
        anchor_max_age: 2,
        coinbase_maturity: 1,
        ..ChainParams::test()
    };
    let mut h = Harness::with_params(8101, params);
    let genesis = h.tip_header();
    let first = h.extend(vec![]);
    let template = h.make_block(first.header(), vec![]);
    // This anchor is valid when height two is first applied.
    let old_coinbase = coinbase_at(&mut h, 2, genesis.commitment_root);
    let second = replace_coinbase(&mut h, &template, old_coinbase);
    assert_eq!(h.import(&second).unwrap(), Import::Extended);
    h.extend(vec![]);
    let original_tip = h.chain.tip().unwrap();
    let original_root = h.chain.store().tree().unwrap().root();
    assert_eq!(original_tip.height, 3);

    let fork_tree = h.chain.store().tree_at(1).unwrap().unwrap();
    let (side2, tree2) = h.make_block_on(first.header(), &fork_tree, vec![]);
    assert_eq!(h.import(&side2).unwrap(), Import::SideChain);
    let (side3, tree3) = h.make_block_on(side2.header(), &tree2, vec![]);
    assert_eq!(h.import(&side3).unwrap(), Import::SideChain);
    let (side4, _) = h.make_block_on(side3.header(), &tree3, vec![]);
    let mut bad_header = side4.header().clone();
    bad_header.commitment_root = genesis.commitment_root;
    let bad = remine(&mut h, bad_header, side4.transactions().to_vec());
    let error = h.import(&bad).unwrap_err();
    assert!(
        error.to_string().contains("commitment root mismatch"),
        "{error}"
    );
    // The roots the old blocks' anchors need are kept, and the old chain is
    // back, as import promises.
    assert!(h.chain.store().tree_at(0).unwrap().is_some());
    assert_eq!(h.chain.tip().unwrap(), original_tip);
    assert_eq!(h.chain.store().tree().unwrap().root(), original_root);
    assert_eq!(h.import(&second).unwrap(), Import::AlreadyKnown);
}

#[test]
fn a_valid_deep_branch_with_an_old_anchor_is_followed() {
    // Maturity 1: every coinbase enters the tree in its own block, so each
    // height has its own root.
    let params = ChainParams {
        max_reorg_depth: 2,
        anchor_max_age: 2,
        coinbase_maturity: 1,
        ..ChainParams::test()
    };
    let mut h = Harness::with_params(8103, params);
    let genesis = h.tip_header();
    let first = h.extend(vec![]);
    h.extend(vec![]);
    h.extend(vec![]);
    assert_eq!(h.chain.tip().unwrap().height, 3);

    // A branch from height one whose first block's coinbase is anchored at
    // genesis: two blocks old there, as the rule allows, but more than the
    // reorganization depth below the old tip.
    let template = h.make_block(first.header(), vec![]);
    let coinbase = coinbase_at(&mut h, 2, genesis.commitment_root);
    let side2 = replace_coinbase(&mut h, &template, coinbase);
    let mut tree2 = h.chain.store().tree_at(1).unwrap().unwrap();
    for tx in tree_transactions(&side2, 1, None).unwrap() {
        for action in tx.actions() {
            tree2.append(action.body().cmx()).unwrap();
        }
    }
    assert_eq!(tree2.root(), side2.header().commitment_root);
    assert_eq!(h.import(&side2).unwrap(), Import::SideChain);
    let (side3, tree3) = h.make_block_on(side2.header(), &tree2, vec![]);
    assert_eq!(h.import(&side3).unwrap(), Import::SideChain);
    let (side4, _) = h.make_block_on(side3.header(), &tree3, vec![]);
    assert!(matches!(
        h.import(&side4).unwrap(),
        Import::Reorganized { applied: 3, .. }
    ));
    assert_eq!(h.chain.tip().unwrap().hash, side4.hash());
}
