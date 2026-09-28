//! The mempool against a live chain: admission, conflicts, spent
//! nullifiers, stale anchors, capacity, selection and block updates.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{proving_key, spend_first_note, spend_first_note_for, Harness, Wallet};
use null_chain::mempool::{Mempool, Rejection};
use null_chain::params::{ChainParams, Upgrade};
use null_chain::Error;
use null_protocol::consensus::BranchId;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn funded(seed: u64) -> (Harness, Wallet) {
    let mut h = Harness::new(seed);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(seed + 1000));
    (h, other)
}

fn insert(
    pool: &mut Mempool,
    h: &mut Harness,
    tx: null_protocol::transaction::Transaction,
) -> Result<null_protocol::transaction::TxId, Error> {
    let params = *h.chain.params();
    pool.insert(
        tx,
        h.chain.store(),
        &params,
        &proving_key().verifying_key(),
        &mut h.rng,
    )
}

#[test]
fn valid_transactions_are_admitted_in_arrival_order_and_mined() {
    let (mut h, other) = funded(1);
    let mut pool = Mempool::new(8);
    let w = h.miner.clone_for_test(0);

    let tx1 = spend_first_note(&mut h, &w, &other.address, 1_000);
    let w = h.miner.clone_for_test(1);

    let tx2 = spend_first_note(&mut h, &w, &other.address, 2_000);
    let id1 = insert(&mut pool, &mut h, tx1.clone()).unwrap();
    let id2 = insert(&mut pool, &mut h, tx2.clone()).unwrap();
    assert_eq!(pool.len(), 2);
    assert!(pool.contains(&id1) && pool.contains(&id2));
    assert!(matches!(
        insert(&mut pool, &mut h, tx1.clone()),
        Err(Error::Rejected(Rejection::AlreadyKnown))
    ));

    let params = *h.chain.params();
    let selected = pool.select(h.chain.store(), &params, 10).unwrap();
    assert_eq!(
        selected
            .iter()
            .map(null_protocol::transaction::Transaction::txid)
            .collect::<Vec<_>>(),
        vec![id1, id2]
    );

    let block = h.extend(selected);
    pool.on_block_applied(&block, h.chain.store(), h.chain.params())
        .unwrap();
    assert!(pool.is_empty());
    assert!(matches!(
        insert(&mut pool, &mut h, tx1),
        Err(Error::Rejected(Rejection::SpentNullifier))
    ));
}

#[test]
fn conflicting_spends_are_refused() {
    let (mut h, other) = funded(2);
    let mut pool = Mempool::new(8);
    let w = h.miner.clone_for_test(0);

    let a = spend_first_note(&mut h, &w, &other.address, 1_000);
    let w = h.miner.clone_for_test(0);

    let b = spend_first_note(&mut h, &w, &other.address, 1_500);
    insert(&mut pool, &mut h, a).unwrap();
    assert!(matches!(
        insert(&mut pool, &mut h, b),
        Err(Error::Rejected(Rejection::Conflict))
    ));
}

#[test]
fn a_block_spending_a_pooled_nullifier_evicts_the_conflict() {
    let (mut h, other) = funded(3);
    let mut pool = Mempool::new(8);
    let w = h.miner.clone_for_test(0);

    let pooled = spend_first_note(&mut h, &w, &other.address, 1_000);
    let w = h.miner.clone_for_test(0);

    let mined = spend_first_note(&mut h, &w, &other.address, 1_500);
    insert(&mut pool, &mut h, pooled).unwrap();
    let block = h.extend(vec![mined]);
    pool.on_block_applied(&block, h.chain.store(), h.chain.params())
        .unwrap();
    assert!(
        pool.is_empty(),
        "the conflicting pooled transaction is gone"
    );
}

#[test]
fn capacity_and_stale_anchors_are_enforced() {
    let (mut h, other) = funded(4);
    let mut pool = Mempool::new(1);
    let wallet = h.miner.clone_for_test(0);

    let first = spend_first_note(&mut h, &wallet, &other.address, 1_000);
    let wallet = h.miner.clone_for_test(1);

    let second = spend_first_note(&mut h, &wallet, &other.address, 1_000);
    insert(&mut pool, &mut h, first).unwrap();
    assert!(matches!(
        insert(&mut pool, &mut h, second),
        Err(Error::Rejected(Rejection::Full))
    ));

    // A transaction against an anchor that never existed.
    let mut stale = Mempool::new(4);
    let mut params = *h.chain.params();
    params.anchor_max_age = 0;
    let wallet = h.miner.clone_for_test(1);

    let third = spend_first_note(&mut h, &wallet, &other.address, 1_000);
    h.extend(Vec::new());
    let vk = proving_key().verifying_key();
    assert!(matches!(
        stale.insert(third, h.chain.store(), &params, &vk, &mut h.rng),
        Err(Error::Rejected(Rejection::StaleAnchor))
    ));
}

#[test]
fn readmit_restores_reverted_transactions_that_still_fit() {
    let (mut h, other) = funded(5);
    let mut pool = Mempool::new(8);
    let w = h.miner.clone_for_test(0);

    let tx = spend_first_note(&mut h, &w, &other.address, 1_000);
    let block = h.extend(vec![tx.clone()]);
    pool.on_block_applied(&block, h.chain.store(), h.chain.params())
        .unwrap();
    let params = *h.chain.params();
    // Pretend the block was reverted: its nullifiers are spent on chain,
    // so the transaction no longer fits and is dropped.
    pool.readmit(std::slice::from_ref(&block), h.chain.store(), &params)
        .unwrap();
    assert!(pool.is_empty());
    // After a real revert it fits again.
    h.chain.store().revert().unwrap();
    pool.readmit(&[block], h.chain.store(), &params).unwrap();
    assert!(pool.contains(&tx.txid()));
}

/// One upgrade at height 3 on the test network.
static UPGRADE_AT_3: [Upgrade; 1] = [Upgrade {
    height: 3,
    branch: BranchId::new(0x0000_0002),
}];

#[test]
fn the_pool_empties_at_an_upgrade_and_admits_only_the_new_branch_after() {
    let params = ChainParams {
        upgrades: &UPGRADE_AT_3,
        ..ChainParams::test()
    };
    let mut h = Harness::with_params(6, params);
    let old = params.genesis_branch;
    let new = UPGRADE_AT_3[0].branch;
    h.extend(Vec::new());
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(6_000));
    let mut pool = Mempool::new(8);

    // Tip 1: the next block is under the old branch.
    let w = h.miner.clone_for_test(0);
    let signed_old = spend_first_note_for(&mut h, &w, &other.address, 1_000, old);
    insert(&mut pool, &mut h, signed_old).unwrap();
    assert_eq!(pool.len(), 1);

    // Block 2 is the last under the old branch; applying it empties the
    // pool because block 3 will not accept old signatures.
    h.extend(Vec::new());
    let block_2 = h
        .chain
        .store()
        .block(&h.chain.tip().unwrap().hash)
        .unwrap()
        .unwrap();
    pool.on_block_applied(&block_2, h.chain.store(), h.chain.params())
        .unwrap();
    assert!(pool.is_empty());

    let w = h.miner.clone_for_test(0);
    let stale = spend_first_note_for(&mut h, &w, &other.address, 1_000, old);
    assert!(matches!(
        insert(&mut pool, &mut h, stale),
        Err(Error::Protocol(null_protocol::Error::Crypto(
            null_crypto::Error::InvalidSignature
        )))
    ));
    let fresh = spend_first_note_for(&mut h, &w, &other.address, 1_000, new);
    insert(&mut pool, &mut h, fresh).unwrap();
    assert_eq!(pool.len(), 1);
}

#[test]
fn a_reorganization_below_an_activation_empties_the_pool_too() {
    let params = ChainParams {
        upgrades: &UPGRADE_AT_3,
        ..ChainParams::test()
    };
    let mut h = Harness::with_params(7, params);
    let old = params.genesis_branch;
    let new = UPGRADE_AT_3[0].branch;
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(7_000));
    h.extend(Vec::new());
    let at_tip_1 = h.miner.clone_for_test(0);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let at_tip_3 = h.miner.clone_for_test(0);
    let mut pool = Mempool::new(8);

    // Tip 3: the pool is verified for the new branch.
    let signed_new = spend_first_note_for(&mut h, &at_tip_3, &other.address, 1_000, new);
    insert(&mut pool, &mut h, signed_new).unwrap();
    assert_eq!(pool.len(), 1);

    // A reorganization that ends below the activation: the next block is
    // under the old branch again, so the pooled signatures are worthless.
    h.chain.store().revert().unwrap();
    h.chain.store().revert().unwrap();
    assert_eq!(h.chain.tip().unwrap().height, 1);
    let params = *h.chain.params();
    assert!(pool.select(h.chain.store(), &params, 8).unwrap().is_empty());
    assert!(pool.is_empty());

    let signed_old = spend_first_note_for(&mut h, &at_tip_1, &other.address, 1_000, old);
    insert(&mut pool, &mut h, signed_old).unwrap();
    assert_eq!(pool.len(), 1);
}
