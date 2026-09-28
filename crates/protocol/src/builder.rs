//! Builds a balanced, padded, signed and proven transaction from spends
//! and outputs.
//!
//! Callers choose which notes to spend and what to create. The builder
//! pads to the next action class with dummy actions, shuffles so position
//! reveals nothing, derives every per-action secret, signs once the
//! sighash is known, and proves every action in one proof. Input
//! selection and change computation stay in the wallet.

use null_circuit::action::{ActionWitness, NoteWitness, SpendWitness};
use null_circuit::proof::ProvingKey;
use null_crypto::commitment::{ValueCommitTrapdoor, ValueCommitment};
use null_crypto::keys::{
    Diversifier, FullViewingKey, OutgoingViewingKey, SpendAuthorizingKey, SpendingKey,
};
use null_crypto::merkle::{MerklePath, EMPTY_LEAF, MERKLE_DEPTH};
use null_crypto::signature::{BindingSigningKey, RandomizedSigningKey, SpendAuthRandomizer};
use rand_core::{CryptoRng, RngCore};

use crate::action::{Action, ActionBody};
use crate::address::Address;
use crate::amount::{Amount, ValueSum};
use crate::consensus::BranchId;
use crate::consensus::{action_class_for, fee_for_actions};
use crate::memo::Memo;
use crate::note::{Note, RandomSeed, Rho};
use crate::note_encryption::encrypt_note;
use crate::transaction::{sighash_of, Anchor, Proof, Transaction};
use crate::{Error, Result};

/// A note to spend, the key that can spend it, and its place in the tree.
#[derive(Clone, Debug)]
pub struct SpendInfo {
    sk: SpendingKey,
    note: Note,
    path: MerklePath,
}

impl SpendInfo {
    /// A real spend. `path` must lead from the note's commitment to the
    /// anchor the transaction is built against.
    pub fn new(sk: SpendingKey, note: Note, path: MerklePath) -> Self {
        Self { sk, note, path }
    }

    /// A zero-valued spend of a note that never existed. Its nullifier is
    /// well formed and unique, and the circuit accepts it because the
    /// value is zero, so the path is never checked.
    ///
    /// # Errors
    /// Fails only if key derivation fails, which has negligible probability.
    pub fn dummy(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self> {
        let sk = SpendingKey::random(rng);
        let address = random_address(&sk, rng)?;
        let note = Note::new(
            address,
            Amount::ZERO,
            Rho::random(rng),
            RandomSeed::random(rng),
        );
        Ok(Self {
            sk,
            note,
            path: MerklePath::new(0, [EMPTY_LEAF; MERKLE_DEPTH]),
        })
    }

    /// The spent note.
    pub fn note(&self) -> &Note {
        &self.note
    }
}

/// A note to create.
#[derive(Clone, Debug)]
pub struct OutputInfo {
    recipient: Address,
    value: Amount,
    memo: Memo,
    ovk: Option<OutgoingViewingKey>,
}

impl OutputInfo {
    /// A real output. Pass `ovk` so the sender can later recover the note.
    pub fn new(
        recipient: Address,
        value: Amount,
        memo: Memo,
        ovk: Option<OutgoingViewingKey>,
    ) -> Self {
        Self {
            recipient,
            value,
            memo,
            ovk,
        }
    }

    /// A zero-valued output to a random address nobody can decrypt.
    ///
    /// # Errors
    /// Fails only if key derivation fails, which has negligible probability.
    pub fn dummy(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self> {
        let recipient = random_address(&SpendingKey::random(rng), rng)?;
        Ok(Self::new(recipient, Amount::ZERO, Memo::empty(), None))
    }

    /// The value.
    pub fn value(&self) -> Amount {
        self.value
    }
}

fn random_address(sk: &SpendingKey, rng: &mut (impl RngCore + CryptoRng)) -> Result<Address> {
    let ivk = FullViewingKey::derive(sk)?.incoming_viewing_key()?;
    Address::derive(&ivk, Diversifier::random(rng))
}

/// Collects spends and outputs, then builds the transaction.
#[derive(Debug)]
pub struct Builder {
    anchor: Anchor,
    spends: Vec<SpendInfo>,
    outputs: Vec<OutputInfo>,
}

impl Builder {
    /// A builder spending against `anchor`.
    pub fn new(anchor: Anchor) -> Self {
        Self {
            anchor,
            spends: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Adds a spend.
    ///
    /// # Errors
    /// Returns [`Error::TooManyActions`] past the largest class.
    pub fn add_spend(&mut self, spend: SpendInfo) -> Result<&mut Self> {
        action_class_for(self.spends.len().saturating_add(1))?;
        self.spends.push(spend);
        Ok(self)
    }

    /// Adds an output.
    ///
    /// # Errors
    /// Returns [`Error::TooManyActions`] past the largest class.
    pub fn add_output(&mut self, output: OutputInfo) -> Result<&mut Self> {
        action_class_for(self.outputs.len().saturating_add(1))?;
        self.outputs.push(output);
        Ok(self)
    }

    /// The fee this transaction will pay, given what has been added so far.
    ///
    /// # Errors
    /// Returns [`Error::TooManyActions`] if nothing fits.
    pub fn fee(&self) -> Result<Amount> {
        fee_for_actions(self.class()?)
    }

    fn class(&self) -> Result<usize> {
        action_class_for(self.spends.len().max(self.outputs.len()))
    }

    /// Pads, shuffles, balances, encrypts, signs and proves a regular
    /// transaction, one that pays the fee for its action class.
    ///
    /// # Errors
    /// Returns [`Error::Unbalanced`] if spends do not equal outputs plus
    /// fee, or propagates cryptographic and proving errors.
    pub fn build(
        self,
        pk: &ProvingKey,
        branch: BranchId,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transaction> {
        let fee = fee_for_actions(self.class()?)?;
        let balance = i64::from(fee);
        self.build_with_balance(pk, branch, rng, ValueSum::ZERO.plus(fee), balance)
    }

    /// Builds a coinbase: no spends, outputs worth exactly `credit`, the
    /// block subsidy plus the fees of the block's other transactions.
    ///
    /// # Errors
    /// Returns [`Error::InvalidTransaction`] if spends were added,
    /// [`Error::Unbalanced`] if outputs do not sum to `credit`, or
    /// propagates cryptographic and proving errors.
    pub fn build_coinbase(
        self,
        pk: &ProvingKey,
        credit: Amount,
        branch: BranchId,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transaction> {
        if !self.spends.is_empty() {
            return Err(Error::InvalidTransaction("coinbase cannot spend"));
        }
        let balance = i64::from(credit)
            .checked_neg()
            .ok_or(Error::AmountOutOfRange)?;
        self.build_with_balance(pk, branch, rng, ValueSum::ZERO.minus(credit), balance)
    }

    /// Shared tail of both builders. `spent_minus_created` is what the
    /// spends minus the outputs must equal; `balance` is the same value
    /// as an `i64`, the public value balance the binding signature proves.
    /// `branch` is the consensus branch the signatures are valid under.
    fn build_with_balance(
        mut self,
        pk: &ProvingKey,
        branch: BranchId,
        rng: &mut (impl RngCore + CryptoRng),
        spent_minus_created: ValueSum,
        balance: i64,
    ) -> Result<Transaction> {
        let class = self.class()?;
        self.check_balance(spent_minus_created)?;
        self.pad(class, rng)?;
        shuffle(&mut self.spends, rng);
        shuffle(&mut self.outputs, rng);

        let prepared = self
            .spends
            .iter()
            .zip(&self.outputs)
            .map(|(spend, output)| prepare_action(spend, output, rng))
            .collect::<Result<Vec<_>>>()?;

        let bodies: Vec<&ActionBody> = prepared.iter().map(|p| &p.body).collect();
        let sighash = sighash_of(&self.anchor, &bodies, branch);
        let public = bodies
            .iter()
            .map(|body| body.public_inputs(&self.anchor))
            .collect::<Result<Vec<_>>>()?;
        let witnesses: Vec<ActionWitness> = prepared.iter().map(|p| p.witness.clone()).collect();
        let proof = Proof::create(pk, &witnesses, &public, &mut *rng)?;

        if spent_minus_created.to_i64()? != balance {
            return Err(Error::Unbalanced);
        }
        let bsk = BindingSigningKey::from_trapdoors(prepared.iter().map(|p| &p.rcv))?;
        let binding_signature = bsk.sign(rng, &sighash);
        let actions: Vec<Action> = prepared
            .into_iter()
            .map(|p| {
                let sig = p.rsk.sign(rng, &sighash);
                p.body.sign(sig)
            })
            .collect();

        Ok(Transaction::new(
            self.anchor,
            actions,
            proof,
            binding_signature,
        ))
    }

    /// Spent minus created must equal the required difference.
    fn check_balance(&self, spent_minus_created: ValueSum) -> Result<()> {
        let spent = ValueSum::sum(self.spends.iter().map(|s| s.note.value()));
        let created = ValueSum::sum(self.outputs.iter().map(|o| o.value));
        if spent.minus_sum(created) == spent_minus_created {
            Ok(())
        } else {
            Err(Error::Unbalanced)
        }
    }

    fn pad(&mut self, class: usize, rng: &mut (impl RngCore + CryptoRng)) -> Result<()> {
        while self.spends.len() < class {
            self.spends.push(SpendInfo::dummy(rng)?);
        }
        while self.outputs.len() < class {
            self.outputs.push(OutputInfo::dummy(rng)?);
        }
        Ok(())
    }
}

/// An action with the secrets still needed to sign and prove it.
struct PreparedAction {
    body: ActionBody,
    rsk: RandomizedSigningKey,
    rcv: ValueCommitTrapdoor,
    witness: ActionWitness,
}

fn prepare_action(
    spend: &SpendInfo,
    output: &OutputInfo,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<PreparedAction> {
    let fvk = FullViewingKey::derive(&spend.sk)?;
    let nullifier = spend.note.nullifier(fvk.nk())?;

    let rho = Rho::from_nullifier(&nullifier)?;
    let note = Note::new(output.recipient, output.value, rho, RandomSeed::random(rng));
    let cmx = note.cmx()?;

    let rcv = ValueCommitTrapdoor::random(rng);
    let net_value = i64::from(spend.note.value())
        .checked_sub(i64::from(output.value))
        .ok_or(Error::AmountOutOfRange)?;
    let cv_net = ValueCommitment::commit(net_value, &rcv);

    let alpha = SpendAuthRandomizer::random(rng);
    let rsk = RandomizedSigningKey::new(&SpendAuthorizingKey::derive(&spend.sk)?, &alpha)?;
    let rk = rsk.verification_key();

    let encrypted = encrypt_note(&note, &output.memo, output.ovk.as_ref(), &cv_net, rng)?;

    let witness = ActionWitness {
        spend: SpendWitness {
            note: note_witness(&spend.note)?,
            path: spend.path.clone(),
            ak: fvk.ak().to_point()?,
            nk: fvk.nk().expose(),
            rivk: fvk.rivk().expose(),
            alpha: alpha.expose(),
        },
        output: note_witness(&note)?,
        rcv: rcv.expose(),
    };
    Ok(PreparedAction {
        body: ActionBody::new(nullifier, rk, cmx, cv_net, encrypted),
        rsk,
        rcv,
        witness,
    })
}

/// The circuit's view of a note.
fn note_witness(note: &Note) -> Result<NoteWitness> {
    Ok(NoteWitness {
        g_d: note.recipient().g_d()?,
        pk_d: *note.recipient().pk_d().as_point(),
        value: note.value().raw(),
        rho: *note.rho().inner(),
        psi: note.psi(),
        rcm: note.rseed().rcm(note.rho()).expose(),
    })
}

/// Fisher-Yates shuffle with the caller's RNG.
fn shuffle<T>(items: &mut [T], rng: &mut (impl RngCore + CryptoRng)) {
    for i in (1..items.len()).rev() {
        let bound = u64::try_from(i.saturating_add(1)).unwrap_or(u64::MAX);
        // `bound >= 2`, so the modulo is well defined; bias is negligible
        // for the tiny lengths involved.
        #[allow(clippy::arithmetic_side_effects)]
        let j = usize::try_from(rng.next_u64() % bound).unwrap_or(0);
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    /// The branch every test transaction is signed for.
    const BRANCH: BranchId = BranchId::new(1);

    use null_circuit::action::PublicInputs;
    use null_crypto::merkle::MerkleTree;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::consensus::FEE_PER_ACTION;
    use crate::note_encryption::{decrypt_note_with_ivk, decrypt_note_with_ovk};
    use crate::test_keys;
    use crate::validate;

    struct Wallet {
        sk: SpendingKey,
        fvk: FullViewingKey,
        address: Address,
    }

    fn wallet(rng: &mut ChaCha20Rng) -> Wallet {
        let sk = SpendingKey::random(rng);
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let address = Address::derive(
            &fvk.incoming_viewing_key().unwrap(),
            Diversifier::random(rng),
        )
        .unwrap();
        Wallet { sk, fvk, address }
    }

    /// A tree of note commitments standing in for the chain.
    #[derive(Default)]
    struct Ledger {
        tree: MerkleTree,
    }

    impl Ledger {
        /// Creates a note for `w` worth `value` and records it in the tree.
        fn fund(&mut self, rng: &mut ChaCha20Rng, w: &Wallet, value: u64) -> SpendInfo {
            let note = Note::new(
                w.address,
                amount(value),
                Rho::random(rng),
                RandomSeed::random(rng),
            );
            let position = self.tree.append(*note.cmx().unwrap().inner()).unwrap();
            SpendInfo::new(w.sk.clone(), note, self.tree.path(position).unwrap())
        }

        fn anchor(&self) -> Anchor {
            Anchor::from_base(self.tree.root())
        }
    }

    fn amount(raw: u64) -> Amount {
        Amount::from_raw(raw).unwrap()
    }

    /// Alice pays Bob `3_000` from a `100_000` note, keeping the change.
    fn payment(seed: u64) -> (ChaCha20Rng, Wallet, Wallet, Transaction) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (alice, bob) = (wallet(&mut rng), wallet(&mut rng));
        let mut ledger = Ledger::default();
        let spend = ledger.fund(&mut rng, &alice, 100_000);
        let fee = 2 * FEE_PER_ACTION;
        let change = 100_000 - 3_000 - fee;
        let mut b = Builder::new(ledger.anchor());
        b.add_spend(spend).unwrap();
        b.add_output(OutputInfo::new(
            bob.address,
            amount(3_000),
            Memo::from_text("hi").unwrap(),
            Some(alice.fvk.outgoing_viewing_key()),
        ))
        .unwrap();
        b.add_output(OutputInfo::new(
            alice.address,
            amount(change),
            Memo::empty(),
            Some(alice.fvk.outgoing_viewing_key()),
        ))
        .unwrap();
        assert_eq!(b.fee().unwrap().raw(), fee);
        let tx = b.build(test_keys::proving_key(), BRANCH, &mut rng).unwrap();
        (rng, alice, bob, tx)
    }

    #[test]
    fn payment_is_padded_to_two_actions_and_fully_verifies() {
        let (mut rng, _, _, tx) = payment(1);
        assert_eq!(tx.actions().len(), 2);
        assert!(validate::verify(&tx, BRANCH, test_keys::verifying_key(), &mut rng).is_ok());
        assert!(
            matches!(
                validate::verify(&tx, BranchId::new(2), test_keys::verifying_key(), &mut rng),
                Err(Error::Crypto(null_crypto::Error::InvalidSignature))
            ),
            "signatures are bound to the branch they were made for"
        );
    }

    #[test]
    fn recipient_and_sender_can_decrypt_their_outputs() {
        let (_, alice, bob, tx) = payment(2);
        let bob_ivk = bob.fvk.incoming_viewing_key().unwrap();
        let alice_ovk = alice.fvk.outgoing_viewing_key();
        let mut bob_found = 0;
        let mut alice_found = Vec::new();
        for action in tx.actions() {
            let body = action.body();
            let rho = Rho::from_nullifier(body.nullifier()).unwrap();
            if let Ok((note, memo)) =
                decrypt_note_with_ivk(&bob_ivk, body.encrypted_note(), rho, body.cmx())
            {
                assert_eq!(note.value(), amount(3_000));
                assert_eq!(memo.to_text(), Some("hi"));
                bob_found += 1;
            }
            if let Ok((note, _)) = decrypt_note_with_ovk(
                &alice_ovk,
                body.encrypted_note(),
                body.cv_net(),
                rho,
                body.cmx(),
            ) {
                alice_found.push(note.value().raw());
            }
        }
        assert_eq!(bob_found, 1);
        alice_found.sort_unstable();
        assert_eq!(
            alice_found,
            vec![3_000, 100_000 - 3_000 - 2 * FEE_PER_ACTION]
        );
    }

    #[test]
    fn three_outputs_pad_to_four_actions_and_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let fee = 4 * FEE_PER_ACTION;
        let spend = ledger.fund(&mut rng, &alice, 30_000 + fee);
        let mut b = Builder::new(ledger.anchor());
        b.add_spend(spend).unwrap();
        for _ in 0..3 {
            b.add_output(OutputInfo::new(
                alice.address,
                amount(10_000),
                Memo::empty(),
                None,
            ))
            .unwrap();
        }
        let tx = b.build(test_keys::proving_key(), BRANCH, &mut rng).unwrap();
        assert_eq!(tx.actions().len(), 4);
        assert!(validate::verify(&tx, BRANCH, test_keys::verifying_key(), &mut rng).is_ok());
    }

    #[test]
    fn spending_against_the_wrong_anchor_fails_to_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let spend = ledger.fund(&mut rng, &alice, 10_000 + 2 * FEE_PER_ACTION);
        let mut b = Builder::new(Anchor::from_base(null_crypto::pallas::Base::from(99u64)));
        b.add_spend(spend).unwrap();
        b.add_output(OutputInfo::new(
            alice.address,
            amount(10_000),
            Memo::empty(),
            None,
        ))
        .unwrap();
        // The prover does not check constraints; the proof it emits for a
        // path that does not reach the anchor simply fails to verify.
        let tx = b.build(test_keys::proving_key(), BRANCH, &mut rng).unwrap();
        assert_eq!(
            validate::verify(&tx, BRANCH, test_keys::verifying_key(), &mut rng),
            Err(Error::Circuit(null_circuit::Error::InvalidProof))
        );
    }

    #[test]
    fn coinbase_creates_value_and_verifies_with_its_credit() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let miner = wallet(&mut rng);
        let credit = amount(10_000_000);
        let mut b = Builder::new(Ledger::default().anchor());
        b.add_output(OutputInfo::new(
            miner.address,
            credit,
            Memo::empty(),
            Some(miner.fvk.outgoing_viewing_key()),
        ))
        .unwrap();
        let tx = b
            .build_coinbase(test_keys::proving_key(), credit, BRANCH, &mut rng)
            .unwrap();
        assert_eq!(tx.actions().len(), 2);
        let balance = validate::coinbase_balance(credit).unwrap();
        assert!(validate::verify_with_balance(
            &tx,
            balance,
            BRANCH,
            test_keys::verifying_key(),
            &mut rng
        )
        .is_ok());
        // Claiming a different credit, or treating it as a regular
        // transaction, fails the binding signature.
        let other = validate::coinbase_balance(amount(1)).unwrap();
        assert!(validate::verify_with_balance(
            &tx,
            other,
            BRANCH,
            test_keys::verifying_key(),
            &mut rng
        )
        .is_err());
        assert!(validate::verify(&tx, BRANCH, test_keys::verifying_key(), &mut rng).is_err());
    }

    #[test]
    fn coinbase_rejects_spends_and_wrong_output_sums() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let miner = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let mut with_spend = Builder::new(ledger.anchor());
        with_spend
            .add_spend(ledger.fund(&mut rng, &miner, 5))
            .unwrap();
        assert!(matches!(
            with_spend.build_coinbase(test_keys::proving_key(), amount(5), BRANCH, &mut rng),
            Err(Error::InvalidTransaction(_))
        ));
        let mut short = Builder::new(ledger.anchor());
        short
            .add_output(OutputInfo::new(
                miner.address,
                amount(4),
                Memo::empty(),
                None,
            ))
            .unwrap();
        assert!(matches!(
            short.build_coinbase(test_keys::proving_key(), amount(5), BRANCH, &mut rng),
            Err(Error::Unbalanced)
        ));
    }

    #[test]
    fn unbalanced_transactions_are_rejected_before_proving() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let spend = ledger.fund(&mut rng, &alice, 1_000);
        let mut b = Builder::new(ledger.anchor());
        b.add_spend(spend).unwrap();
        b.add_output(OutputInfo::new(
            alice.address,
            amount(1_000),
            Memo::empty(),
            None,
        ))
        .unwrap();
        assert!(matches!(
            b.build(test_keys::proving_key(), BRANCH, &mut rng),
            Err(Error::Unbalanced)
        ));
    }

    #[test]
    fn too_many_spends_are_rejected_early() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let mut b = Builder::new(ledger.anchor());
        for _ in 0..16 {
            b.add_spend(ledger.fund(&mut rng, &alice, 1)).unwrap();
        }
        let extra = ledger.fund(&mut rng, &alice, 1);
        assert!(matches!(b.add_spend(extra), Err(Error::TooManyActions)));
        assert!(b.add_output(OutputInfo::dummy(&mut rng).unwrap()).is_ok());
    }

    #[test]
    fn dummies_have_zero_value_and_distinct_nullifiers() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let a = SpendInfo::dummy(&mut rng).unwrap();
        let b = SpendInfo::dummy(&mut rng).unwrap();
        assert_eq!(a.note().value(), Amount::ZERO);
        assert_eq!(OutputInfo::dummy(&mut rng).unwrap().value(), Amount::ZERO);
        let nf = |s: &SpendInfo| {
            s.note()
                .nullifier(FullViewingKey::derive(&s.sk).unwrap().nk())
                .unwrap()
        };
        assert_ne!(nf(&a), nf(&b));
    }

    #[test]
    fn witness_and_body_agree_on_public_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let alice = wallet(&mut rng);
        let mut ledger = Ledger::default();
        let spend = ledger.fund(&mut rng, &alice, 500);
        let output = OutputInfo::new(alice.address, amount(200), Memo::empty(), None);
        let prepared = prepare_action(&spend, &output, &mut rng).unwrap();
        let anchor = ledger.anchor();
        let from_body = prepared.body.public_inputs(&anchor).unwrap();
        let from_witness = PublicInputs::from_witness(*anchor.inner(), &prepared.witness).unwrap();
        assert_eq!(from_body, from_witness);
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let mut items: Vec<u32> = (0..16).collect();
        shuffle(&mut items, &mut rng);
        let mut sorted = items.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..16).collect::<Vec<_>>());
        assert_ne!(items, sorted, "shuffle left the order unchanged");
    }

    #[test]
    fn tampering_with_a_built_transaction_breaks_verification() {
        let (mut rng, _, _, tx) = payment(10);
        let mut bytes = crate::bytes::Encodable::to_vec(&tx);
        bytes[1] ^= 1; // anchor changes the sighash and the proof inputs
        let tampered = <Transaction as crate::bytes::Encodable>::from_slice(&bytes).unwrap();
        assert!(validate::verify(&tampered, BRANCH, test_keys::verifying_key(), &mut rng).is_err());
    }
}
