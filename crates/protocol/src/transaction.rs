//! The transaction: a fixed-shape bundle of actions with one proof and one
//! binding signature.
//!
//! ```text
//! effecting data = version || anchor || n_actions || action bodies
//! txid           = BLAKE2b-256_{TXID}(effecting data)
//! sighash        = BLAKE2b-256_{SIGHASH}(effecting data || branch id)
//! encoding       = effecting data with signed actions || proof || binding sig
//! ```
//!
//! The txid excludes the proof and every signature, so re-randomizing
//! either cannot change the id. The sighash additionally binds the
//! [`BranchId`] of the consensus rules the transaction is meant for, so
//! it is not replayable across a fork or between networks; the branch is
//! not encoded, validation supplies it. There is no locktime, no expiry,
//! no explicit fee, and no proof length: fee and proof length are
//! functions of the action count.

use null_circuit::action::PublicInputs;
use null_crypto::commitment::ValueCommitment;
use null_crypto::encoding::{base_from_bytes, base_to_bytes, Encoded};
use null_crypto::hash::{blake2b_short, SHORT_OUTPUT_LEN, SIGHASH, TXID};
use null_crypto::pallas;

use crate::consensus::BranchId;
use null_crypto::signature::BindingSignature;

use crate::action::{Action, ActionBody};
use crate::amount::Amount;
use crate::bytes::{Encodable, Reader, Writer};
use crate::consensus::{fee_for_actions, proof_len, TX_VERSION};
use crate::nullifier::Nullifier;
use crate::Result;

/// The root of the note commitment tree a transaction spends against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor(pallas::Base);

impl Anchor {
    /// Wraps a tree root.
    pub fn from_base(root: pallas::Base) -> Self {
        Self(root)
    }

    /// The tree root.
    pub fn inner(&self) -> &pallas::Base {
        &self.0
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> Encoded {
        base_to_bytes(&self.0)
    }
}

impl Encodable for Anchor {
    fn write(&self, w: &mut Writer) {
        w.put(&self.to_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(base_from_bytes(&r.take_array()?)?))
    }
}

pub use null_circuit::proof::Proof;

/// A transaction identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxId([u8; SHORT_OUTPUT_LEN]);

impl TxId {
    /// Wraps raw bytes, as received from the network.
    pub fn from_bytes(bytes: [u8; SHORT_OUTPUT_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; SHORT_OUTPUT_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for TxId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TxId({self})")
    }
}

impl core::fmt::Display for TxId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&null_crypto::encoding::to_hex(&self.0))
    }
}

/// A complete transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    version: u8,
    anchor: Anchor,
    actions: Vec<Action>,
    proof: Proof,
    binding_signature: BindingSignature,
}

impl Transaction {
    /// Assembles a transaction. Validity is checked by [`crate::validate`].
    pub fn new(
        anchor: Anchor,
        actions: Vec<Action>,
        proof: Proof,
        binding_signature: BindingSignature,
    ) -> Self {
        Self {
            version: TX_VERSION,
            anchor,
            actions,
            proof,
            binding_signature,
        }
    }

    /// The version byte.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The anchor.
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    /// The actions.
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// The proof.
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// The binding signature.
    pub fn binding_signature(&self) -> &BindingSignature {
        &self.binding_signature
    }

    /// The fee, fixed by the action count.
    ///
    /// # Errors
    /// Only on an action count so large it overflows, which
    /// [`crate::validate`] rejects first.
    pub fn fee(&self) -> Result<Amount> {
        fee_for_actions(self.actions.len())
    }

    /// Every nullifier revealed, in action order.
    pub fn nullifiers(&self) -> impl Iterator<Item = &Nullifier> {
        self.actions.iter().map(|a| a.body().nullifier())
    }

    /// The circuit public inputs of every action, in action order.
    ///
    /// # Errors
    /// Fails if an action carries a non-canonical point.
    pub fn public_inputs(&self) -> Result<Vec<PublicInputs>> {
        self.actions
            .iter()
            .map(|a| a.body().public_inputs(&self.anchor))
            .collect()
    }

    /// Every net value commitment, in action order.
    pub fn value_commitments(&self) -> impl Iterator<Item = &ValueCommitment> {
        self.actions.iter().map(|a| a.body().cv_net())
    }

    /// The transaction id.
    pub fn txid(&self) -> TxId {
        TxId(blake2b_short(TXID, &[&self.effecting_bytes()]))
    }

    /// The message every signature in this transaction signs, under the
    /// consensus rules identified by `branch`.
    pub fn sighash(&self, branch: BranchId) -> [u8; SHORT_OUTPUT_LEN] {
        blake2b_short(SIGHASH, &[&self.effecting_bytes(), &branch.to_bytes()])
    }

    fn effecting_bytes(&self) -> Vec<u8> {
        let bodies: Vec<&ActionBody> = self.actions.iter().map(Action::body).collect();
        effecting_bytes(self.version, &self.anchor, &bodies)
    }
}

/// The effecting data of a transaction: everything but proof and
/// signatures. Shared by [`Transaction`] and by the builder, which needs
/// the sighash before any signature exists.
fn effecting_bytes(version: u8, anchor: &Anchor, bodies: &[&ActionBody]) -> Vec<u8> {
    let mut w = Writer::default();
    write_header(&mut w, version, anchor, bodies.len());
    for body in bodies {
        body.write(&mut w);
    }
    w.into_bytes()
}

/// The sighash of a transaction under construction, for `branch`.
pub fn sighash_of(
    anchor: &Anchor,
    bodies: &[&ActionBody],
    branch: BranchId,
) -> [u8; SHORT_OUTPUT_LEN] {
    blake2b_short(
        SIGHASH,
        &[
            &effecting_bytes(TX_VERSION, anchor, bodies),
            &branch.to_bytes(),
        ],
    )
}

fn write_header(w: &mut Writer, version: u8, anchor: &Anchor, actions: usize) {
    // Bounded by MAX_ACTIONS in valid transactions; the clamp keeps the
    // encoding total for anything else, and validation rejects it.
    let count = u8::try_from(actions).unwrap_or(u8::MAX);
    w.put_u8(version);
    anchor.write(w);
    w.put_u8(count);
}

impl Encodable for Transaction {
    fn write(&self, w: &mut Writer) {
        write_header(w, self.version, &self.anchor, self.actions.len());
        for action in &self.actions {
            action.write(w);
        }
        w.put(self.proof.as_bytes());
        w.put(&self.binding_signature.to_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.take_u8()?;
        let anchor = Anchor::read(r)?;
        let count = usize::from(r.take_u8()?);
        let actions = (0..count)
            .map(|_| Action::read(r))
            .collect::<Result<Vec<_>>>()?;
        let proof = Proof::from_bytes(r.take(proof_len(count)?)?.to_vec());
        let binding_signature = BindingSignature::from_bytes(r.take_array()?);
        Ok(Self {
            version,
            anchor,
            actions,
            proof,
            binding_signature,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::action::tests::sample_action;
    use crate::action::ACTION_LEN;
    use crate::consensus::FEE_PER_ACTION;

    pub(crate) fn sample_anchor() -> Anchor {
        Anchor::from_base(pallas::Base::from(7u64))
    }

    /// Zero bytes of the right length: shaped like a proof, verifies as nothing.
    pub(crate) fn dummy_proof(actions: usize) -> Proof {
        Proof::from_bytes(vec![0; proof_len(actions).unwrap_or(0)])
    }

    /// A structurally complete transaction whose signatures are over an
    /// arbitrary message, so it encodes but does not verify.
    fn sample_transaction(seed: u64, count: usize) -> Transaction {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let actions = (0..count).map(|_| sample_action(&mut rng, b"x")).collect();
        Transaction::new(
            sample_anchor(),
            actions,
            dummy_proof(count),
            BindingSignature::from_bytes([9; 64]),
        )
    }

    #[test]
    fn encoding_roundtrips_with_expected_length() {
        let tx = sample_transaction(1, 2);
        let bytes = tx.to_vec();
        assert_eq!(
            bytes.len(),
            1 + 32 + 1 + 2 * ACTION_LEN + proof_len(2).unwrap() + 64
        );
        assert_eq!(Transaction::from_slice(&bytes), Ok(tx));
    }

    #[test]
    fn txid_ignores_signatures_and_proof() {
        let tx = sample_transaction(2, 2);
        let mut bytes = tx.to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1; // binding signature
        bytes[1 + 32 + 1 + ACTION_LEN - 1] ^= 1; // first spend auth signature
        let altered = Transaction::from_slice(&bytes).unwrap();
        assert_ne!(altered, tx);
        assert_eq!(altered.txid(), tx.txid());
        assert_eq!(
            altered.sighash(BranchId::new(1)),
            tx.sighash(BranchId::new(1))
        );
    }

    #[test]
    fn txid_changes_with_effecting_data() {
        let tx = sample_transaction(3, 2);
        let mut bytes = tx.to_vec();
        bytes[1] ^= 1; // anchor
        let altered = Transaction::from_slice(&bytes).unwrap();
        assert_ne!(altered.txid(), tx.txid());
    }

    #[test]
    fn sighash_differs_from_txid() {
        let tx = sample_transaction(4, 2);
        assert_ne!(tx.sighash(BranchId::new(1)), *tx.txid().as_bytes());
        assert_ne!(
            tx.sighash(BranchId::new(1)),
            tx.sighash(BranchId::new(2)),
            "the sighash binds the branch"
        );
        assert_eq!(
            tx.txid(),
            tx.txid(),
            "the txid does not depend on the branch"
        );
        let bodies: Vec<&ActionBody> = tx.actions().iter().map(Action::body).collect();
        assert_eq!(
            sighash_of(tx.anchor(), &bodies, BranchId::new(1)),
            tx.sighash(BranchId::new(1))
        );
    }

    #[test]
    fn fee_follows_action_count() {
        assert_eq!(
            sample_transaction(5, 2).fee().unwrap().raw(),
            2 * FEE_PER_ACTION
        );
        assert_eq!(
            sample_transaction(6, 4).fee().unwrap().raw(),
            4 * FEE_PER_ACTION
        );
    }

    #[test]
    fn txid_displays_as_hex() {
        let id = sample_transaction(7, 2).txid();
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(format!("{id:?}"), format!("TxId({text})"));
    }

    #[test]
    fn proof_length_is_fixed_by_the_action_count() {
        let tx = sample_transaction(9, 2);
        let mut bytes = tx.to_vec();
        bytes.pop();
        assert!(Transaction::from_slice(&bytes).is_err(), "one byte short");
        bytes.push(0);
        bytes.push(0);
        assert!(Transaction::from_slice(&bytes).is_err(), "one byte long");
    }

    #[test]
    fn public_inputs_follow_actions() {
        let tx = sample_transaction(10, 2);
        let public = tx.public_inputs().unwrap();
        assert_eq!(public.len(), 2);
        assert_eq!(public[0].anchor, *tx.anchor().inner());
        assert_eq!(
            public[1].nf_old,
            tx.actions()[1].body().nullifier().to_base().unwrap()
        );
    }

    #[test]
    fn iterators_follow_action_order() {
        let tx = sample_transaction(8, 4);
        assert_eq!(tx.nullifiers().count(), 4);
        assert_eq!(tx.value_commitments().count(), 4);
        assert_eq!(
            tx.nullifiers().next(),
            Some(tx.actions()[0].body().nullifier())
        );
        assert_eq!(tx.version(), TX_VERSION);
        assert_eq!(tx.proof(), &dummy_proof(4));
        assert_eq!(tx.binding_signature().to_bytes(), [9; 64]);
    }
}
