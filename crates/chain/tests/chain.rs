//! End to end: mine blocks with coinbases, spend a coinbase output, reject
//! double spends and bad blocks, and reorganize to a longer side chain.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{proving_key, spend_first_note_for, Harness, Wallet};
use null_chain::chain::{Chain, Import};
use null_chain::genesis::genesis;
use null_chain::params::{ChainParams, Upgrade};
use null_chain::target::Target;
use null_chain::Error;
use null_circuit::proof::Proof;
use null_protocol::block::{empty_header, Block, PowSolution};
use null_protocol::builder::{Builder, OutputInfo, SpendInfo};
use null_protocol::consensus::{subsidy, BranchId, FEE_PER_ACTION};
use null_protocol::memo::Memo;
use null_protocol::transaction::Transaction;
use null_storage::store::Store;
use null_storage::tree::CommitmentTree;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn mining_extends_the_chain_and_pays_the_miner() {
    let mut h = Harness::new(1);
    assert_eq!(h.miner.tree.len(), 2, "the premine coinbase's two leaves");
    for height in 1..=3u32 {
        let block = h.extend(Vec::new());
        assert_eq!(block.header().height, height);
        assert_eq!(h.chain.tip().unwrap().height, height);
    }
    assert_eq!(h.miner.balance(), 3 * subsidy(1).raw());
    let again = h
        .chain
        .store()
        .block(&h.chain.tip().unwrap().hash)
        .unwrap()
        .unwrap();
    assert_eq!(h.import(&again).unwrap(), Import::AlreadyKnown);
}

#[test]
fn a_coinbase_output_can_be_spent_once() {
    let mut h = Harness::new(2);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let (note, position) = h.miner.notes[0].clone();
    let path = h.miner.tree.path(position).unwrap();
    let parent = h.tip_header();

    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let recipient = Wallet::new(&mut rng);
    let fee = 2 * FEE_PER_ACTION;
    let pay = note.value().raw() - fee;
    let mut b = Builder::new(parent.commitment_root);
    b.add_spend(SpendInfo::new(h.miner.sk.clone(), note, path))
        .unwrap();
    b.add_output(OutputInfo::new(
        recipient.address,
        null_protocol::amount::Amount::from_raw(pay).unwrap(),
        Memo::empty(),
        None,
    ))
    .unwrap();
    let tx = b
        .build(
            proving_key(),
            h.chain.params().branch_at(parent.height + 1),
            &mut h.rng,
        )
        .unwrap();
    let nullifier = *tx.actions()[0].body().nullifier();

    let block = h.make_block(&parent, vec![tx.clone()]);
    assert_eq!(h.import(&block).unwrap(), Import::Extended);
    h.miner.scan(&block);
    assert!(
        h.chain.store().contains_nullifier(&nullifier).unwrap()
            || h.chain
                .store()
                .contains_nullifier(tx.actions()[1].body().nullifier())
                .unwrap()
    );

    // The same transaction in the next block is a double spend.
    let parent = h.tip_header();
    let double = h.make_block(&parent, vec![tx]);
    assert!(matches!(
        h.import(&double),
        Err(Error::InvalidBlock("nullifier already spent"))
    ));
}

#[test]
fn bad_blocks_are_rejected() {
    let mut h = Harness::new(3);
    h.extend(Vec::new());
    let parent = h.tip_header();

    let mut orphan = h.make_block(&parent, Vec::new());
    let mut header = orphan.header().clone();
    header.prev_hash = null_protocol::block::BlockHash::from_bytes([9; 32]);
    orphan = Block::new(header, orphan.transactions().to_vec());
    assert!(matches!(h.import(&orphan), Err(Error::Orphan)));

    let good = h.make_block(&parent, Vec::new());
    let mut wrong_root = good.header().clone();
    wrong_root.commitment_root = parent.commitment_root;
    assert!(h
        .chain
        .pow()
        .mine(&mut wrong_root, 256, &mut h.rng)
        .unwrap());
    let bad = Block::new(wrong_root, good.transactions().to_vec());
    assert!(matches!(
        h.import(&bad),
        Err(Error::InvalidHeader("commitment root mismatch"))
    ));

    let mut no_pow = good.header().clone();
    no_pow.solution = PowSolution::empty();
    assert!(h
        .import(&Block::new(no_pow, good.transactions().to_vec()))
        .is_err());

    let mut future = good.header().clone();
    future.timestamp += 10 * 60 * 60;
    assert!(h.chain.pow().mine(&mut future, 256, &mut h.rng).unwrap());
    let block = Block::new(future, good.transactions().to_vec());
    let now = parent.timestamp;
    assert!(matches!(
        h.chain.import(&block, now, &mut h.rng),
        Err(Error::InvalidHeader("timestamp too far in the future"))
    ));

    assert_eq!(h.import(&good).unwrap(), Import::Extended);
}

#[test]
fn side_chain_blocks_without_proof_of_work_are_not_stored() {
    let mut h = Harness::new(5);
    h.extend(Vec::new());
    let fork = h.tip_header();
    h.extend(Vec::new());
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side, _) = h.make_block_on(&fork, &fork_tree, Vec::new());
    let mut header = side.header().clone();
    header.solution = PowSolution::empty();
    let unmined = Block::new(header, side.transactions().to_vec());
    assert!(h.import(&unmined).is_err());
    assert!(
        h.chain.store().block(&unmined.hash()).unwrap().is_none(),
        "nothing stored"
    );
}

/// The same block with one byte of its coinbase proof flipped: same txid,
/// same transaction root, same header hash, invalid authorization.
fn with_corrupted_proof(block: &Block) -> Block {
    let tx = &block.transactions()[0];
    let mut bytes = tx.proof().as_bytes().to_vec();
    bytes[0] ^= 1;
    let bad = Transaction::new(
        *tx.anchor(),
        tx.actions().to_vec(),
        Proof::from_bytes(bytes),
        *tx.binding_signature(),
    );
    assert_eq!(bad.txid(), tx.txid(), "the txid excludes the proof");
    let mut txs = block.transactions().to_vec();
    txs[0] = bad;
    Block::new(block.header().clone(), txs)
}

#[test]
fn a_side_chain_block_with_a_bad_proof_is_not_stored_and_cannot_shadow_the_real_one() {
    let mut h = Harness::new(9);
    h.extend(Vec::new());
    let fork = h.tip_header();
    let main_2 = h.extend(Vec::new());
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side_2, side_2_tree) = h.make_block_on(&fork, &fork_tree, Vec::new());
    let poisoned = with_corrupted_proof(&side_2);
    assert_eq!(
        poisoned.hash(),
        side_2.hash(),
        "the header hash is unchanged"
    );

    assert!(h.import(&poisoned).is_err());
    assert!(
        h.chain.store().block(&side_2.hash()).unwrap().is_none(),
        "nothing stored under the valid hash"
    );
    assert_eq!(h.chain.tip().unwrap().hash, main_2.hash());

    // The authentic body is still accepted, and its branch can still win.
    assert_eq!(h.import(&side_2).unwrap(), Import::SideChain);
    let (side_3, _) = h.make_block_on(side_2.header(), &side_2_tree, Vec::new());
    assert!(matches!(
        h.import(&side_3).unwrap(),
        Import::Reorganized { .. }
    ));
    assert_eq!(h.chain.tip().unwrap().hash, side_3.hash());
}

#[test]
fn a_longer_side_chain_triggers_a_reorganization() {
    let mut h = Harness::new(4);
    h.extend(Vec::new());
    let fork = h.tip_header();
    let main_3 = h.extend(Vec::new());
    assert_eq!(h.chain.tip().unwrap().height, 2);

    // A competing branch from the fork point, one block longer. Coinbase
    // randomness makes it differ from the main-chain block at height 2.
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side_2, side_2_tree) = h.make_block_on(&fork, &fork_tree, Vec::new());
    assert_ne!(side_2.hash(), main_3.hash());
    assert_eq!(h.import(&side_2).unwrap(), Import::SideChain);
    assert_eq!(h.chain.tip().unwrap().hash, main_3.hash());

    let (side_3, _) = h.make_block_on(side_2.header(), &side_2_tree, Vec::new());
    assert_eq!(
        h.import(&side_3).unwrap(),
        Import::Reorganized {
            reverted: vec![main_3.clone()],
            applied: 2
        }
    );
    assert_eq!(h.chain.tip().unwrap().hash, side_3.hash());
    assert_eq!(h.chain.store().hash_at(2).unwrap(), Some(side_2.hash()));
    assert_eq!(h.chain.store().hash_at(3).unwrap(), Some(side_3.hash()));
    assert!(
        h.chain.store().block(&main_3.hash()).unwrap().is_some(),
        "old block kept"
    );
}

/// One upgrade at height 3 on the test network.
static UPGRADE_AT_3: [Upgrade; 1] = [Upgrade {
    height: 3,
    branch: BranchId::new(0x0000_0002),
}];

fn params_with_upgrade() -> ChainParams {
    ChainParams {
        upgrades: &UPGRADE_AT_3,
        ..ChainParams::test()
    }
}

#[test]
fn an_upgrade_changes_which_signatures_a_block_accepts() {
    let mut h = Harness::with_params(10, params_with_upgrade());
    let old = h.chain.params().genesis_branch;
    let new = UPGRADE_AT_3[0].branch;
    h.extend(Vec::new());
    h.extend(Vec::new());
    assert_eq!(
        h.chain.tip().unwrap().height,
        2,
        "last block under the old rules"
    );
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(10_000));
    let wallet = h.miner.clone_for_test(0);

    // A transaction signed for the old branch is refused at height 3.
    let parent = h.tip_header();
    let stale = spend_first_note_for(&mut h, &wallet, &other.address, 1_000, old);
    let coinbase = coinbase_for(&mut h, &parent, old);
    let block = block_over(&mut h, &parent, vec![coinbase, stale]);
    assert!(matches!(
        h.import(&block),
        Err(Error::Crypto(null_crypto::Error::InvalidSignature))
    ));
    assert_eq!(h.chain.tip().unwrap().height, 2);

    // The same payment signed for the new branch is accepted.
    let fresh = spend_first_note_for(&mut h, &wallet, &other.address, 1_000, new);
    let block = h.make_block(&parent, vec![fresh]);
    assert_eq!(h.import(&block).unwrap(), Import::Extended);
    assert_eq!(h.chain.params().branch_at(3), new);
}

/// A coinbase for the block after `parent`, signed for `branch`.
fn coinbase_for(
    h: &mut Harness,
    parent: &null_protocol::block::BlockHeader,
    branch: BranchId,
) -> null_protocol::transaction::Transaction {
    let credit = subsidy(parent.height + 1);
    let mut b = Builder::new(parent.commitment_root);
    b.add_output(OutputInfo::new(
        h.miner.address,
        credit,
        Memo::empty(),
        None,
    ))
    .unwrap();
    b.build_coinbase(proving_key(), credit, branch, &mut h.rng)
        .unwrap()
}

/// Assembles and mines a block over explicit transactions, computing the
/// tree root itself, so tests can put invalid transaction sets in valid
/// looking blocks.
fn block_over(
    h: &mut Harness,
    parent: &null_protocol::block::BlockHeader,
    transactions: Vec<null_protocol::transaction::Transaction>,
) -> Block {
    use null_chain::difficulty::{next_target, Sample};
    use null_chain::target::Target;
    use null_chain::validate::{header_lookback, recent_headers};
    let params = *h.chain.params();
    let mut tree = h.chain.store().tree_at(parent.height).unwrap().unwrap();
    for tx in &transactions {
        for action in tx.actions() {
            tree.append(action.body().cmx()).unwrap();
        }
    }
    let recent = recent_headers(h.chain.store(), parent.height, header_lookback(&params)).unwrap();
    let samples: Vec<Sample> = recent
        .iter()
        .map(|hd| Sample {
            timestamp: hd.timestamp,
            target: Target::from_compact(hd.target).unwrap(),
        })
        .collect();
    let mut header = null_protocol::block::BlockHeader {
        version: null_protocol::consensus::BLOCK_VERSION,
        prev_hash: parent.hash(),
        height: parent.height + 1,
        timestamp: parent.timestamp + params.block_interval,
        commitment_root: tree.root(),
        tx_root: null_protocol::block::tx_root(
            transactions
                .iter()
                .map(null_protocol::transaction::Transaction::txid),
        ),
        target: next_target(&params, &samples).to_compact(),
        nonce: [0; 32],
        solution: PowSolution::empty(),
    };
    assert!(h.chain.pow().mine(&mut header, 256, &mut h.rng).unwrap());
    Block::new(header, transactions)
}

#[test]
fn a_coinbase_claiming_the_wrong_credit_is_rejected() {
    let mut h = Harness::new(6);
    h.extend(Vec::new());
    let parent = h.tip_header();
    let height = parent.height + 1;
    for wrong in [subsidy(height).raw() + 1, subsidy(height).raw() - 1] {
        let credit = null_protocol::amount::Amount::from_raw(wrong).unwrap();
        let mut b = Builder::new(parent.commitment_root);
        b.add_output(OutputInfo::new(
            h.miner.address,
            credit,
            Memo::empty(),
            None,
        ))
        .unwrap();
        let coinbase = b
            .build_coinbase(
                proving_key(),
                credit,
                h.chain.params().branch_at(parent.height + 1),
                &mut h.rng,
            )
            .unwrap();
        let block = block_over(&mut h, &parent, vec![coinbase]);
        assert!(
            matches!(
                h.import(&block),
                Err(Error::Crypto(null_crypto::Error::InvalidSignature))
            ),
            "{wrong}"
        );
    }
}

#[test]
fn only_the_first_transaction_may_create_value() {
    let mut h = Harness::new(7);
    h.extend(Vec::new());
    let parent = h.tip_header();
    let credit = subsidy(parent.height + 1);
    let mut first = Builder::new(parent.commitment_root);
    first
        .add_output(OutputInfo::new(
            h.miner.address,
            credit,
            Memo::empty(),
            None,
        ))
        .unwrap();
    let coinbase = first
        .build_coinbase(
            proving_key(),
            credit,
            h.chain.params().branch_at(parent.height + 1),
            &mut h.rng,
        )
        .unwrap();
    let mut second = Builder::new(parent.commitment_root);
    second
        .add_output(OutputInfo::new(
            h.miner.address,
            credit,
            Memo::empty(),
            None,
        ))
        .unwrap();
    let extra = second
        .build_coinbase(
            proving_key(),
            credit,
            h.chain.params().branch_at(parent.height + 1),
            &mut h.rng,
        )
        .unwrap();
    let block = block_over(&mut h, &parent, vec![coinbase, extra]);
    assert!(matches!(
        h.import(&block),
        Err(Error::Crypto(null_crypto::Error::InvalidSignature))
    ));
}

#[test]
fn a_failed_apply_leaves_no_partial_state() {
    let mut h = Harness::new(8);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(80));
    // Two transactions spending the same note: the store's own duplicate
    // check fails mid-transaction, and nothing of the block persists.
    let wallet = h.miner.clone_for_test(0);
    let a = common::spend_first_note(&mut h, &wallet, &other.address, 1_000);
    let b = common::spend_first_note(&mut h, &wallet, &other.address, 2_000);
    let parent = h.tip_header();
    let block = block_over(&mut h, &parent, vec![a.clone(), b]);
    let tree = h.chain.store().tree().unwrap();
    let tip_before = h.chain.tip().unwrap();
    assert!(h.chain.store().apply(&block, &tree).is_err());
    assert_eq!(h.chain.tip().unwrap(), tip_before);
    assert!(h.chain.store().block(&block.hash()).unwrap().is_none());
    assert!(!h
        .chain
        .store()
        .contains_nullifier(a.actions()[0].body().nullifier())
        .unwrap());
    assert_eq!(
        h.chain.store().hash_at(tip_before.height + 1).unwrap(),
        None
    );
}

#[test]
fn a_side_chain_block_with_the_wrong_target_is_not_stored() {
    let mut h = Harness::new(11);
    h.extend(Vec::new());
    let fork = h.tip_header();
    h.extend(Vec::new());
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side, _) = h.make_block_on(&fork, &fork_tree, Vec::new());
    // A target easier than the limit: free to meet, and never what the
    // difficulty rule expects.
    let mut header = side.header().clone();
    let easy = Target::from_compact(0x2100_ffff).unwrap();
    assert!(easy > h.chain.params().pow_limit);
    header.target = easy.to_compact();
    assert!(h.chain.pow().mine(&mut header, 256, &mut h.rng).unwrap());
    let cheap = Block::new(header, side.transactions().to_vec());
    assert!(matches!(
        h.import(&cheap),
        Err(Error::InvalidHeader(
            "target does not match the difficulty rule"
        ))
    ));
    assert!(h.chain.store().block(&cheap.hash()).unwrap().is_none());
}

#[test]
fn a_side_chain_block_repeating_a_transaction_is_not_stored() {
    let mut h = Harness::new(12);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let fork = h.tip_header();
    h.extend(Vec::new());
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(12_000));
    let wallet = h.miner.clone_for_test(0);
    let tx = common::spend_first_note(&mut h, &wallet, &other.address, 1_000);
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side, _) = h.make_block_on(&fork, &fork_tree, vec![tx.clone(), tx]);
    assert!(matches!(
        h.import(&side),
        Err(Error::InvalidBlock("nullifier already spent"))
    ));
    assert!(h.chain.store().block(&side.hash()).unwrap().is_none());
}

#[test]
fn a_store_built_under_other_rules_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.redb");
    let vk = || proving_key().verifying_key();
    drop(Chain::new(Store::open(&path).unwrap(), ChainParams::test(), vk()).unwrap());
    assert!(matches!(
        Chain::new(Store::open(&path).unwrap(), params_with_upgrade(), vk()),
        Err(Error::RulesMismatch)
    ));
    assert!(Chain::new(Store::open(&path).unwrap(), ChainParams::test(), vk()).is_ok());
}

/// A block after `parent` declaring the easiest target, mined and
/// otherwise identical to what the harness would build.
fn at_easiest_target(h: &mut Harness, parent: &null_protocol::block::BlockHeader) -> Block {
    let parent_tree = h.chain.store().tree_at(parent.height).unwrap().unwrap();
    let (block, _) = h.make_block_on(parent, &parent_tree, Vec::new());
    let mut header = block.header().clone();
    header.target = h.chain.params().pow_limit.to_compact();
    assert!(h.chain.pow().mine(&mut header, 256, &mut h.rng).unwrap());
    Block::new(header, block.transactions().to_vec())
}

#[test]
fn a_mainnet_sized_difficulty_window_retargets_and_is_enforced() {
    // A window at least as long as the median span, like mainnet's 60, so
    // the lookback is decided by the difficulty rule and not the median.
    let params = ChainParams {
        difficulty_window: 12,
        ..ChainParams::test()
    };
    let mut h = Harness::with_params(13, params);
    h.spacing = 1;
    // Blocks arrive five times faster than the interval; once the window
    // is full the target drops below the limit and the harness, which
    // computes targets the way the node's miner does, must still be
    // accepted by the validator.
    for _ in 0..14 {
        h.extend(Vec::new());
    }
    let tip = h.tip_header();
    assert!(Target::from_compact(tip.target).unwrap() < params.pow_limit);

    // The easiest target is no longer acceptable, on the main chain...
    let easy = at_easiest_target(&mut h, &tip);
    assert!(matches!(
        h.import(&easy),
        Err(Error::InvalidHeader(
            "target does not match the difficulty rule"
        ))
    ));
    // ...nor on a side chain.
    let fork = h.chain.store().block(&tip.prev_hash).unwrap().unwrap();
    let easy_side = at_easiest_target(&mut h, fork.header());
    assert!(matches!(
        h.import(&easy_side),
        Err(Error::InvalidHeader(
            "target does not match the difficulty rule"
        ))
    ));
    assert!(h.chain.store().block(&easy_side.hash()).unwrap().is_none());
}

#[test]
fn a_store_with_history_but_no_rules_digest_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let vk = || proving_key().verifying_key();
    let params = ChainParams::test();
    let first = genesis(&params);

    // Genesis alone, from a binary that recorded no digest: stamped on open.
    let only_genesis = dir.path().join("genesis.redb");
    Store::open(&only_genesis)
        .unwrap()
        .apply(&first, &CommitmentTree::empty())
        .unwrap();
    assert!(Chain::new(Store::open(&only_genesis).unwrap(), params, vk()).is_ok());
    assert!(Store::open(&only_genesis)
        .unwrap()
        .rules_digest()
        .unwrap()
        .is_some());

    // History validated under unknown rules: refused.
    let with_history = dir.path().join("history.redb");
    {
        let store = Store::open(&with_history).unwrap();
        store.apply(&first, &CommitmentTree::empty()).unwrap();
        let header = empty_header(1, first.hash(), CommitmentTree::empty().root());
        store
            .apply(&Block::new(header, Vec::new()), &CommitmentTree::empty())
            .unwrap();
    }
    assert!(matches!(
        Chain::new(Store::open(&with_history).unwrap(), params, vk()),
        Err(Error::RulesMismatch)
    ));
}

#[test]
fn transactions_are_indexed_by_id_while_in_the_main_chain() {
    let mut h = Harness::new(14);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(14_000));
    let wallet = h.miner.clone_for_test(0);
    let tx = common::spend_first_note(&mut h, &wallet, &other.address, 1_000);
    let txid = tx.txid();
    assert_eq!(h.chain.store().transaction_location(&txid).unwrap(), None);
    let block = h.extend(vec![tx.clone()]);
    let height = block.header().height;
    let store = h.chain.store();
    assert_eq!(
        store.transaction_location(&txid).unwrap(),
        Some((height, 1))
    );
    let coinbase = block.transactions()[0].txid();
    assert_eq!(
        store.transaction_location(&coinbase).unwrap(),
        Some((height, 0))
    );
    let (found, at, index) = store.transaction(&txid).unwrap().unwrap();
    assert_eq!((found, at, index), (tx, height, 1));
    store.revert().unwrap();
    assert_eq!(store.transaction_location(&txid).unwrap(), None);
    assert_eq!(store.transaction(&coinbase).unwrap(), None);
}
