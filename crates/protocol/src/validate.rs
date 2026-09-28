//! Stateless transaction validation.
//!
//! Stateless means: everything that can be checked from the transaction
//! bytes alone, including the proof. Anchor validity and nullifier
//! freshness belong to the chain layer.

use std::collections::BTreeSet;

use null_circuit::proof::{ProofBatch, VerifyingKey};
use null_crypto::signature::{BatchVerifier, BindingVerificationKey};
use rand_core::{CryptoRng, RngCore};

use crate::consensus::{is_action_class, proof_len, BranchId, TX_VERSION};
use crate::transaction::Transaction;
use crate::{Error, Result};

/// Checks shape rules: version, action class, proof length, and unique
/// nullifiers.
///
/// # Errors
/// Returns [`Error::InvalidTransaction`] naming the first violated rule.
pub fn check_structure(tx: &Transaction) -> Result<()> {
    if tx.version() != TX_VERSION {
        return Err(Error::InvalidTransaction("unknown version"));
    }
    if !is_action_class(tx.actions().len()) {
        return Err(Error::InvalidTransaction(
            "action count is not an allowed class",
        ));
    }
    if tx.proof().as_bytes().len() != proof_len(tx.actions().len())? {
        return Err(Error::InvalidTransaction(
            "proof length does not match action count",
        ));
    }
    let mut seen = BTreeSet::new();
    if !tx.nullifiers().all(|nf| seen.insert(*nf)) {
        return Err(Error::InvalidTransaction("duplicate nullifier"));
    }
    Ok(())
}

/// The public value balance of a regular transaction: its fee.
///
/// # Errors
/// Only on an action count that overflows the fee.
pub fn regular_balance(tx: &Transaction) -> Result<i64> {
    Ok(i64::from(tx.fee()?))
}

/// The public value balance of a coinbase paying `credit` (subsidy plus
/// the fees of the other transactions in its block): it creates value.
///
/// # Errors
/// Only if `credit` does not fit an `i64`, which the cap prevents.
pub fn coinbase_balance(credit: crate::amount::Amount) -> Result<i64> {
    i64::from(credit)
        .checked_neg()
        .ok_or(Error::AmountOutOfRange)
}

/// Queues every signature of `tx` into `batch` for later verification.
/// `balance` is the public value balance the binding signature must
/// prove, see [`regular_balance`] and [`coinbase_balance`]; `branch` is
/// the consensus branch in force where the transaction is being
/// validated, which the signatures must have been made for.
///
/// # Errors
/// Fails if the binding verification key cannot be derived.
pub fn queue_signatures(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    batch: &mut BatchVerifier,
) -> Result<()> {
    let sighash = tx.sighash(branch);
    for action in tx.actions() {
        batch.queue_spend_auth(action.body().rk(), action.spend_auth_sig(), &sighash);
    }
    let bvk = BindingVerificationKey::from_commitments(tx.value_commitments(), balance)?;
    batch.queue_binding(&bvk, tx.binding_signature(), &sighash);
    Ok(())
}

/// Queues the proof of `tx` into `batch` for later verification.
///
/// # Errors
/// Fails if an action carries a non-canonical point.
pub fn queue_proof(tx: &Transaction, batch: &mut ProofBatch) -> Result<()> {
    Ok(batch.add(tx.proof(), &tx.public_inputs()?)?)
}

/// Verifies the proof of one transaction on its own.
///
/// # Errors
/// Returns [`null_circuit::Error::InvalidProof`] if the proof is wrong.
pub fn verify_proof(tx: &Transaction, vk: &VerifyingKey) -> Result<()> {
    Ok(tx.proof().verify(vk, &tx.public_inputs()?)?)
}

/// Runs every stateless check on one regular transaction: structure,
/// signatures, then the proof, cheapest first.
///
/// # Errors
/// Returns the first violation found.
pub fn verify(
    tx: &Transaction,
    branch: BranchId,
    vk: &VerifyingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    verify_with_balance(tx, regular_balance(tx)?, branch, vk, rng)
}

/// As [`verify`], with an explicit public value balance, for coinbases.
///
/// # Errors
/// Returns the first violation found.
pub fn verify_with_balance(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    vk: &VerifyingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    check_structure(tx)?;
    let mut batch = BatchVerifier::new();
    queue_signatures(tx, balance, branch, &mut batch)?;
    batch.verify(rng)?;
    verify_proof(tx, vk)
}

#[cfg(test)]
mod tests {
    use null_crypto::signature::BindingSignature;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::action::tests::sample_action;
    use crate::action::ACTION_LEN;
    use crate::bytes::Encodable;
    use crate::test_keys;
    use crate::transaction::tests::{dummy_proof, sample_anchor};

    fn unsigned_tx(seed: u64, count: usize) -> Transaction {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let actions = (0..count).map(|_| sample_action(&mut rng, b"x")).collect();
        Transaction::new(
            sample_anchor(),
            actions,
            dummy_proof(count),
            BindingSignature::from_bytes([0; 64]),
        )
    }

    #[test]
    fn structure_accepts_every_class() {
        for class in [2, 4, 8, 16] {
            assert!(check_structure(&unsigned_tx(1, class)).is_ok());
        }
    }

    #[test]
    fn structure_rejects_bad_action_counts() {
        for count in [0, 1, 3, 17] {
            assert!(matches!(
                check_structure(&unsigned_tx(2, count)),
                Err(Error::InvalidTransaction(
                    "action count is not an allowed class"
                ))
            ));
        }
    }

    #[test]
    fn structure_rejects_wrong_proof_length() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let actions = (0..2).map(|_| sample_action(&mut rng, b"x")).collect();
        let tx = Transaction::new(
            sample_anchor(),
            actions,
            dummy_proof(4),
            BindingSignature::from_bytes([0; 64]),
        );
        assert!(matches!(
            check_structure(&tx),
            Err(Error::InvalidTransaction(
                "proof length does not match action count"
            ))
        ));
    }

    #[test]
    fn structure_rejects_unknown_version() {
        let mut bytes = unsigned_tx(3, 2).to_vec();
        bytes[0] = 2;
        let tx = Transaction::from_slice(&bytes).unwrap();
        assert!(matches!(
            check_structure(&tx),
            Err(Error::InvalidTransaction("unknown version"))
        ));
    }

    #[test]
    fn structure_rejects_duplicate_nullifiers() {
        let tx = unsigned_tx(4, 2);
        let mut bytes = tx.to_vec();
        let first = 1 + 32 + 1;
        let second = first + ACTION_LEN;
        let nf: Vec<u8> = bytes[first..first + 32].to_vec();
        bytes[second..second + 32].copy_from_slice(&nf);
        let dup = Transaction::from_slice(&bytes).unwrap();
        assert!(matches!(
            check_structure(&dup),
            Err(Error::InvalidTransaction("duplicate nullifier"))
        ));
    }

    #[test]
    fn signatures_over_the_wrong_message_fail() {
        // sample_action signs "x", not the real sighash.
        let tx = unsigned_tx(5, 2);
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        assert!(matches!(
            verify(&tx, BranchId::new(1), test_keys::verifying_key(), &mut rng),
            Err(Error::Crypto(null_crypto::Error::InvalidSignature))
        ));
    }

    #[test]
    fn zero_proof_is_rejected_even_with_valid_structure() {
        let tx = unsigned_tx(7, 2);
        assert!(matches!(
            verify_proof(&tx, test_keys::verifying_key()),
            Err(Error::Circuit(null_circuit::Error::InvalidProof))
        ));
        let mut batch = ProofBatch::new();
        queue_proof(&tx, &mut batch).unwrap();
        assert!(batch.verify(test_keys::verifying_key()).is_err());
    }
}
