//! Findings of the 2026-11 monetary review, kept as regression tests: a
//! failed deep reorganization restores the old chain, a node accepts a
//! valid deep branch whose anchors are older than the reorganization depth,
//! and a compact block carries the spends of its own coinbase.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{proving_key, Harness};
use null_chain::chain::Import;
use null_chain::params::ChainParams;
use null_circuit::action::{ActionWitness, NoteWitness, SpendWitness};
use null_crypto::commitment::{ValueCommitTrapdoor, ValueCommitment};
use null_crypto::keys::SpendAuthorizingKey;
use null_crypto::merkle::{MerklePath, EMPTY_LEAF, MERKLE_DEPTH};
use null_crypto::signature::{BindingSigningKey, RandomizedSigningKey, SpendAuthRandomizer};
use null_protocol::action::ActionBody;
use null_protocol::amount::Amount;
use null_protocol::block::{Block, BlockHeader, PowSolution};
use null_protocol::builder::{Builder, OutputInfo};
use null_protocol::bytes::Encodable;
use null_protocol::compact::CompactBlock;
use null_protocol::consensus::subsidy;
use null_protocol::maturity::tree_transactions;
use null_protocol::memo::Memo;
use null_protocol::note::{Note, RandomSeed, Rho};
use null_protocol::note_encryption::encrypt_note;
use null_protocol::transaction::{sighash_of, Anchor, Proof, Transaction};

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

fn witness(note: &Note) -> NoteWitness {
    NoteWitness {
        g_d: note.recipient().g_d().unwrap(),
        pk_d: *note.recipient().pk_d().as_point(),
        value: note.value().raw(),
        rho: *note.rho().inner(),
        psi: note.psi(),
        rcm: note.rseed().rcm(note.rho()).expose(),
    }
}

// Construct a valid coinbase directly, bypassing the honest builder's local
// prohibition on adding spends. The verifier must enforce its own rules.
fn spending_coinbase(h: &mut Harness) -> Transaction {
    let anchor = h.tip_header().commitment_root;
    let height = h.tip_header().height + 1;
    let (old, position) = h.miner.notes[0].clone();
    let dummy = Note::new(
        h.miner.address,
        Amount::ZERO,
        Rho::random(&mut h.rng),
        RandomSeed::random(&mut h.rng),
    );
    let inputs = [
        (old.clone(), h.miner.tree.path(position).unwrap()),
        (dummy, MerklePath::new(0, [EMPTY_LEAF; MERKLE_DEPTH])),
    ];
    let mut bodies = Vec::new();
    let mut witnesses = Vec::new();
    let mut trapdoors = Vec::new();
    let mut signers = Vec::new();
    for (index, (input, path)) in inputs.into_iter().enumerate() {
        let nf = input.nullifier(h.miner.fvk.nk()).unwrap();
        let value = if index == 0 {
            old.value().checked_add(subsidy(height)).unwrap()
        } else {
            Amount::ZERO
        };
        let output = Note::new(
            h.miner.address,
            value,
            Rho::from_nullifier(&nf).unwrap(),
            RandomSeed::random(&mut h.rng),
        );
        let rcv = ValueCommitTrapdoor::random(&mut h.rng);
        let cv = ValueCommitment::commit(i64::from(input.value()) - i64::from(value), &rcv);
        let alpha = SpendAuthRandomizer::random(&mut h.rng);
        let signer =
            RandomizedSigningKey::new(&SpendAuthorizingKey::derive(&h.miner.sk).unwrap(), &alpha)
                .unwrap();
        let encrypted = encrypt_note(&output, &Memo::empty(), None, &cv, &mut h.rng).unwrap();
        bodies.push(ActionBody::new(
            nf,
            signer.verification_key(),
            output.cmx().unwrap(),
            cv,
            encrypted,
        ));
        witnesses.push(ActionWitness {
            spend: SpendWitness {
                note: witness(&input),
                path,
                ak: h.miner.fvk.ak().to_point().unwrap(),
                nk: h.miner.fvk.nk().expose(),
                rivk: h.miner.fvk.rivk().expose(),
                alpha: alpha.expose(),
            },
            output: witness(&output),
            rcv: rcv.expose(),
        });
        trapdoors.push(rcv);
        signers.push(signer);
    }
    let sighash = sighash_of(
        &anchor,
        &bodies.iter().collect::<Vec<_>>(),
        h.chain.params().branch_at(height),
    );
    let public = bodies
        .iter()
        .map(|body| body.public_inputs(&anchor).unwrap())
        .collect::<Vec<_>>();
    let proof = Proof::create(proving_key(), &witnesses, &public, &mut h.rng).unwrap();
    let binding = BindingSigningKey::from_trapdoors(&trapdoors)
        .unwrap()
        .sign(&mut h.rng, &sighash);
    let actions = bodies
        .into_iter()
        .zip(signers)
        .map(|(body, signer)| body.sign(signer.sign(&mut h.rng, &sighash)))
        .collect();
    Transaction::new(anchor, actions, proof, binding)
}

#[test]
fn a_compact_block_carries_the_spends_of_its_own_coinbase() {
    let mut h = Harness::with_params(
        8102,
        ChainParams {
            coinbase_maturity: 3,
            ..ChainParams::test()
        },
    );
    for _ in 0..3 {
        h.extend(vec![]);
    }
    let parent = h.tip_header();
    let spent = h.miner.notes[0].0.nullifier(h.miner.fvk.nk()).unwrap();
    let coinbase = spending_coinbase(&mut h);
    assert!(coinbase.nullifiers().any(|nf| *nf == spent));
    let template = h.make_block(&parent, vec![]);
    let block = replace_coinbase(&mut h, &template, coinbase);
    assert_eq!(h.import(&block).unwrap(), Import::Extended);
    assert!(h.chain.store().contains_nullifier(&spent).unwrap());
    let earlier = null_chain::validate::earlier_coinbase(
        h.chain.store(),
        h.chain.params(),
        block.header().height,
    )
    .unwrap();
    let compact = CompactBlock::from_block(&block, 3, earlier.as_ref()).unwrap();
    // The coinbase's actions wait for its maturity, its spends do not.
    assert!(!compact.actions.iter().any(|a| a.nullifier == spent));
    assert!(compact.coinbase_spends.contains(&spent));
    let decoded = CompactBlock::from_slice(&compact.to_vec()).unwrap();
    assert_eq!(decoded, compact);
}
