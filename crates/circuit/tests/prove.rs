//! End-to-end proving and verifying with the real prover. Slow in debug
//! builds; run with `--release` for realistic timings.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::Instant;

use ff::Field;
use group::Group;
use null_circuit::action::{ActionWitness, NoteWitness, PublicInputs, SpendWitness};
use null_circuit::proof::{proof_len, Proof, ProofBatch, ProvingKey};
use null_circuit::{Error, Fp};
use null_crypto::keys::{Diversifier, FullViewingKey, SpendingKey};
use null_crypto::merkle::MerkleTree;
use null_crypto::pallas;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// A real spend of `value` by a fresh key, with its public inputs.
fn action(rng: &mut ChaCha20Rng, value: u64) -> (ActionWitness, PublicInputs) {
    let fvk = FullViewingKey::derive(&SpendingKey::random(rng)).unwrap();
    let d = Diversifier::random(rng);
    let note = NoteWitness {
        g_d: d.base().unwrap(),
        pk_d: *fvk
            .incoming_viewing_key()
            .unwrap()
            .transmission_key(&d)
            .unwrap()
            .as_point(),
        value,
        rho: Fp::random(&mut *rng),
        psi: Fp::random(&mut *rng),
        rcm: Fp::random(&mut *rng),
    };
    let mut tree = MerkleTree::new();
    let position = tree.append(note.commitment()).unwrap();
    let spend = SpendWitness {
        note,
        path: tree.path(position).unwrap(),
        ak: fvk.ak().to_point().unwrap(),
        nk: fvk.nk().expose(),
        rivk: fvk.rivk().expose(),
        alpha: pallas::Scalar::random(&mut *rng),
    };
    let mut output = NoteWitness {
        g_d: pallas::Point::random(&mut *rng),
        pk_d: pallas::Point::random(&mut *rng),
        value: value / 2,
        rho: Fp::zero(),
        psi: Fp::random(&mut *rng),
        rcm: Fp::random(&mut *rng),
    };
    output.rho = spend.nullifier();
    let witness = ActionWitness {
        spend,
        output,
        rcv: pallas::Scalar::random(&mut *rng),
    };
    let public = PublicInputs::from_witness(tree.root(), &witness).unwrap();
    (witness, public)
}

#[test]
fn two_action_proof_roundtrips_and_rejects_wrong_inputs() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let started = Instant::now();
    let pk = ProvingKey::build().unwrap();
    let vk = pk.verifying_key();
    eprintln!("keygen: {:?}", started.elapsed());

    let (w1, p1) = action(&mut rng, 1_000);
    let (w2, p2) = action(&mut rng, 0);

    let started = Instant::now();
    let proof = Proof::create(&pk, &[w1, w2], &[p1, p2], &mut rng).unwrap();
    eprintln!(
        "prove 2 actions: {:?}, {} bytes",
        started.elapsed(),
        proof.as_bytes().len()
    );

    let started = Instant::now();
    assert!(proof.verify(&vk, &[p1, p2]).is_ok());
    eprintln!("verify: {:?}", started.elapsed());
    assert_eq!(proof_len(2), Some(proof.as_bytes().len()));

    let mut batch = ProofBatch::new();
    batch.add(&proof, &[p1, p2]).unwrap();
    batch.add(&proof, &[p1, p2]).unwrap();
    assert_eq!(batch.len(), 2);
    let started = Instant::now();
    assert!(batch.verify(&vk).is_ok());
    eprintln!("batch verify x2: {:?}", started.elapsed());

    let mut bad = ProofBatch::new();
    bad.add(&proof, &[p1, p2]).unwrap();
    bad.add(&proof, &[p2, p1]).unwrap();
    assert!(matches!(bad.verify(&vk), Err(Error::InvalidProof)));

    let wrong = PublicInputs {
        nf_old: p1.nf_old + Fp::one(),
        ..p1
    };
    assert!(matches!(
        proof.verify(&vk, &[wrong, p2]),
        Err(Error::InvalidProof)
    ));
    assert!(matches!(
        proof.verify(&vk, &[p2, p1]),
        Err(Error::InvalidProof)
    ));
    assert!(matches!(proof.verify(&vk, &[]), Err(Error::CountMismatch)));

    let tampered = Proof::from_bytes({
        let mut bytes = proof.as_bytes().to_vec();
        bytes[10] ^= 1;
        bytes
    });
    assert!(tampered.verify(&vk, &[p1, p2]).is_err());
}

#[test]
fn mismatched_counts_are_rejected_before_proving() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let pk = ProvingKey::build().unwrap();
    let (w, p) = action(&mut rng, 7);
    assert!(matches!(
        Proof::create(&pk, std::slice::from_ref(&w), &[p, p], &mut rng),
        Err(Error::CountMismatch)
    ));
    assert!(matches!(
        Proof::create(&pk, &[], &[], &mut rng),
        Err(Error::CountMismatch)
    ));
}

/// Prints proof size and timing per action class. Run with
/// `cargo test --release -p null-circuit --test prove -- --ignored --nocapture`.
#[test]
#[ignore = "measurement, not a check"]
fn proof_size_per_action_class() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let pk = ProvingKey::build().unwrap();
    let vk = pk.verifying_key();
    for class in [2usize, 4, 8, 16] {
        let (witnesses, public): (Vec<_>, Vec<_>) =
            (0..class).map(|_| action(&mut rng, 10)).unzip();
        let started = Instant::now();
        let proof = Proof::create(&pk, &witnesses, &public, &mut rng).unwrap();
        let proved = started.elapsed();
        let started = Instant::now();
        proof.verify(&vk, &public).unwrap();
        eprintln!(
            "class {class:>2}: {} bytes, prove {proved:?}, verify {:?}",
            proof.as_bytes().len(),
            started.elapsed()
        );
        assert_eq!(proof_len(class), Some(proof.as_bytes().len()));
    }
}
