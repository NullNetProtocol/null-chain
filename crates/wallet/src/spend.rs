//! Selecting notes and building a payment.

use null_circuit::proof::ProvingKey;
use null_protocol::address::Address;
use null_protocol::amount::Amount;
use null_protocol::builder::{Builder, OutputInfo, SpendInfo};
use null_protocol::consensus::action_class_for;
use null_protocol::consensus::fee_for_actions;
use null_protocol::consensus::{BranchId, MAX_ACTIONS};
use null_protocol::memo::Memo;
use null_protocol::transaction::Transaction;
use rand_core::{CryptoRng, RngCore};

use crate::scan::OwnedNote;
use crate::wallet::Wallet;
use crate::{Error, Result};

/// Most recipients one transaction can pay: one action is kept for the
/// change output.
pub const MAX_RECIPIENTS: usize = MAX_ACTIONS - 1;

/// Picks the fewest largest notes covering `amount` plus the fee of the
/// resulting action class, for a transaction with `outputs` outputs
/// (recipients plus change), and returns them with the fee.
///
/// # Errors
/// Returns [`Error::InsufficientFunds`] when the notes cannot cover it,
/// or a protocol error if the spends would exceed the largest class.
pub fn select_notes<'a>(
    unspent: &[&'a OwnedNote],
    amount: Amount,
    outputs: usize,
) -> Result<(Vec<&'a OwnedNote>, Amount)> {
    let mut sorted: Vec<&OwnedNote> = unspent.to_vec();
    sorted.sort_by_key(|n| core::cmp::Reverse(n.note.value().raw()));
    let mut chosen = Vec::new();
    let mut total = 0u64;
    for note in sorted {
        chosen.push(note);
        total = total.saturating_add(note.note.value().raw());
        let fee = fee_for_actions(action_class(chosen.len(), outputs)?)?;
        let need = amount.raw().saturating_add(fee.raw());
        if total >= need {
            return Ok((chosen, fee));
        }
    }
    let have = total;
    let need = amount
        .raw()
        .saturating_add(fee_for_actions(action_class_for(outputs.max(2))?)?.raw());
    Err(Error::InsufficientFunds { have, need })
}

/// The action count of a transaction with `spends` spends and `outputs`
/// outputs. One spend and one output share each action, so the longer side
/// sets the class.
///
/// # Errors
/// Returns a protocol error past the largest class.
fn action_class(spends: usize, outputs: usize) -> Result<usize> {
    Ok(action_class_for(spends.max(outputs).max(2))?)
}

/// The sum paid to every recipient.
///
/// # Errors
/// Returns a protocol error if the sum overflows the money range.
fn total(payments: &[Payment]) -> Result<Amount> {
    Ok(payments
        .iter()
        .try_fold(Amount::ZERO, |acc, p| acc.checked_add(p.amount))?)
}

/// What a payment would cost if it were built now, without proving it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quote {
    /// The protocol fee, set by the action class.
    pub fee: Amount,
    /// Notes the payment would spend.
    pub spends: usize,
    /// Actions in the transaction, after padding to a class.
    pub actions: usize,
}

/// One consolidation transaction: spend exactly these notes into one main-address output.
#[derive(Clone, Debug)]
pub struct Consolidation {
    /// Positions reserved for this transaction.
    pub positions: Vec<u64>,
    /// The self-payment, after the protocol fee.
    pub payment: Payment,
    /// Fee for the padded action class.
    pub fee: Amount,
}

/// Plans disjoint batches of at most sixteen eligible notes, returning each
/// batch to the wallet's default address. Single notes and batches whose
/// value cannot cover their fee are left alone. `positions`, when supplied,
/// must all still be eligible; this lets callers submit a reviewed quote.
///
/// # Errors
/// Fails on a wallet error, duplicate/unavailable positions, or no useful batch.
pub fn plan_consolidation(
    wallet: &Wallet,
    excluded: &[u64],
    max_note_height: u32,
    positions: Option<&[u64]>,
) -> Result<Vec<Consolidation>> {
    let notes = wallet.unspent()?;
    consolidation_from(
        &notes,
        wallet.keys().default_address()?,
        excluded,
        max_note_height,
        positions,
    )
}

fn consolidation_from(
    notes: &[OwnedNote],
    address: Address,
    excluded: &[u64],
    max_note_height: u32,
    positions: Option<&[u64]>,
) -> Result<Vec<Consolidation>> {
    let excluded: std::collections::HashSet<_> = excluded.iter().copied().collect();
    let wanted = positions.map(|positions| {
        positions
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
    });
    let mut eligible: Vec<_> = notes
        .iter()
        .filter(|n| {
            n.height <= max_note_height
                && !excluded.contains(&n.position)
                && n.note.value().raw() > 0
                && wanted
                    .as_ref()
                    .is_none_or(|wanted| wanted.contains(&n.position))
        })
        .collect();
    if let Some(wanted) = positions {
        if eligible.len() != wanted.len() {
            return Err(Error::Consolidation(
                "inputs changed or are unavailable; request a new quote",
            ));
        }
    }
    eligible.sort_by_key(|n| (core::cmp::Reverse(n.note.value().raw()), n.position));
    let mut batches = Vec::new();
    for notes in eligible
        .chunks(MAX_ACTIONS)
        .filter(|notes| notes.len() >= 2)
    {
        let value = notes
            .iter()
            .try_fold(Amount::ZERO, |sum, n| sum.checked_add(n.note.value()))?;
        let fee = fee_for_actions(action_class(notes.len(), 1)?)?;
        if value.raw() <= fee.raw() {
            continue;
        }
        batches.push(Consolidation {
            positions: notes.iter().map(|n| n.position).collect(),
            payment: Payment {
                recipient: address,
                amount: Amount::from_raw(value.raw().saturating_sub(fee.raw()))?,
                memo: Memo::empty(),
            },
            fee,
        });
    }
    if batches.is_empty() {
        return Err(Error::Consolidation(
            "need at least two available notes whose value covers the fee",
        ));
    }
    // An explicit quote must be reproduced exactly, including its input count.
    if positions.is_some_and(|wanted| {
        batches.iter().map(|b| b.positions.len()).sum::<usize>() != wanted.len()
    }) {
        return Err(Error::Consolidation("inputs changed; request a new quote"));
    }
    Ok(batches)
}

/// The notes `payments` would spend from `unspent`, skipping `excluded`
/// positions and notes above `max_note_height`, with the fee. Change adds
/// one output. [`build_payments`] and [`quote_payments`] both use this, so
/// a quote matches the transaction built from the same notes.
///
/// # Errors
/// [`Error::TooManyRecipients`] past the limit, and
/// [`Error::InsufficientFunds`] when the free notes cannot cover it.
fn plan<'a>(
    unspent: &'a [OwnedNote],
    payments: &[Payment],
    excluded: &[u64],
    max_note_height: u32,
) -> Result<(Vec<&'a OwnedNote>, Amount)> {
    if payments.is_empty() || payments.len() > MAX_RECIPIENTS {
        return Err(Error::TooManyRecipients(MAX_RECIPIENTS));
    }
    let refs: Vec<&OwnedNote> = unspent
        .iter()
        .filter(|n| !excluded.contains(&n.position) && n.height <= max_note_height)
        .collect();
    select_notes(&refs, total(payments)?, payments.len().saturating_add(1))
}

/// The fee and shape `payments` would have if built now from the
/// wallet's unspent notes, with the same selection as [`build_payments`].
/// Notes can arrive or be set aside before the payment is built, so this
/// is exact for the wallet's current state only.
///
/// # Errors
/// As [`build_payments`], except that it needs no spending key.
pub fn quote_payments(
    wallet: &Wallet,
    payments: &[Payment],
    excluded: &[u64],
    max_note_height: u32,
) -> Result<Quote> {
    let unspent = wallet.unspent()?;
    quote_from(&unspent, payments, excluded, max_note_height)
}

fn quote_from(
    unspent: &[OwnedNote],
    payments: &[Payment],
    excluded: &[u64],
    max_note_height: u32,
) -> Result<Quote> {
    let (chosen, fee) = plan(unspent, payments, excluded, max_note_height)?;
    Ok(Quote {
        fee,
        spends: chosen.len(),
        actions: action_class(chosen.len(), payments.len().saturating_add(1))?,
    })
}

/// What to pay, to whom, with which memo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    /// The recipient.
    pub recipient: Address,
    /// The amount.
    pub amount: Amount,
    /// The memo.
    pub memo: Memo,
}

/// A built transaction and the notes it spends.
#[derive(Clone, Debug)]
pub struct Built {
    /// The transaction, proved and signed.
    pub transaction: Transaction,
    /// Positions of the notes it spends, to set aside until it is mined.
    pub spent: Vec<u64>,
}

/// Builds `payment` from the wallet's unspent notes, returning change to
/// its default address. The anchor is the wallet's current tree root, so
/// the wallet must be scanned up to a recent block first.
///
/// # Errors
/// Fails on insufficient funds or a building error.
pub fn build_payment(
    wallet: &Wallet,
    payment: Payment,
    pk: &ProvingKey,
    branch: BranchId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Transaction> {
    Ok(build_payments(wallet, &[payment], pk, branch, &[], u32::MAX, rng)?.transaction)
}

/// Builds one transaction paying every recipient in `payments`, at most
/// [`MAX_RECIPIENTS`], from the wallet's unspent notes other than those
/// at `excluded` positions (notes set aside for pending operations) and
/// those received above `max_note_height` (too few confirmations).
/// Change goes to the wallet's default address.
///
/// # Errors
/// Returns [`Error::WatchOnly`] without a spending key,
/// [`Error::TooManyRecipients`] past the limit, and
/// [`Error::InsufficientFunds`] when the free notes cannot cover it.
pub fn build_payments(
    wallet: &Wallet,
    payments: &[Payment],
    pk: &ProvingKey,
    branch: BranchId,
    excluded: &[u64],
    max_note_height: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Built> {
    let unspent = spendable_notes(wallet)?;
    let (chosen, fee) = plan(&unspent, payments, excluded, max_note_height)?;
    build_selected(wallet, payments, &chosen, fee, pk, branch, rng)
}

/// Builds from every reserved input, without greedy selection dropping small
/// notes at a fee-tier boundary. Used for previously reviewed consolidation batches.
///
/// # Errors
/// Fails if an input is no longer available/confirmed, or on a building error.
pub fn build_reserved_payments(
    wallet: &Wallet,
    payments: &[Payment],
    positions: &[u64],
    pk: &ProvingKey,
    branch: BranchId,
    max_note_height: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Built> {
    let unspent = spendable_notes(wallet)?;
    let chosen = reserved_notes(&unspent, positions, max_note_height)?;
    let fee = fee_for_actions(action_class(
        chosen.len(),
        payments.len().saturating_add(1),
    )?)?;
    build_selected(wallet, payments, &chosen, fee, pk, branch, rng)
}

// Reject watch-only wallets before selection, even when they lack funds.
fn spendable_notes(wallet: &Wallet) -> Result<Vec<OwnedNote>> {
    wallet.keys().spending_key()?;
    wallet.unspent()
}

fn reserved_notes<'a>(
    notes: &'a [OwnedNote],
    positions: &[u64],
    max_height: u32,
) -> Result<Vec<&'a OwnedNote>> {
    let unique: std::collections::HashSet<_> = positions.iter().copied().collect();
    let chosen: Vec<_> = notes
        .iter()
        .filter(|n| unique.contains(&n.position) && n.height <= max_height)
        .collect();
    if chosen.len() != positions.len() || unique.len() != positions.len() || chosen.is_empty() {
        return Err(Error::Consolidation(
            "reserved inputs are no longer available",
        ));
    }
    Ok(chosen)
}

fn build_selected(
    wallet: &Wallet,
    payments: &[Payment],
    chosen: &[&OwnedNote],
    fee: Amount,
    pk: &ProvingKey,
    branch: BranchId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Built> {
    let keys = wallet.keys();
    let sk = keys.spending_key()?;
    let amount = total(payments)?;
    let positions: Vec<u64> = chosen.iter().map(|n| n.position).collect();
    let (paths, anchor) = wallet.witnesses(&positions)?;
    let mut builder = Builder::new(anchor);
    let mut total = 0u64;
    for (owned, path) in chosen.iter().zip(paths) {
        builder.add_spend(SpendInfo::new(sk.clone(), owned.note.clone(), path))?;
        total = total.saturating_add(owned.note.value().raw());
    }
    let ovk = Some(keys.outgoing_viewing_key().clone());
    for payment in payments {
        builder.add_output(OutputInfo::new(
            payment.recipient,
            payment.amount,
            payment.memo.clone(),
            ovk.clone(),
        ))?;
    }
    let change = total.saturating_sub(amount.raw()).saturating_sub(fee.raw());
    if change > 0 {
        builder.add_output(OutputInfo::new(
            keys.default_address()?,
            Amount::from_raw(change)?,
            Memo::empty(),
            ovk,
        ))?;
    }
    Ok(Built {
        transaction: builder.build(pk, branch, rng)?,
        spent: positions,
    })
}

#[cfg(test)]
mod tests {
    use null_crypto::keys::SpendingKey;
    use null_crypto::pallas;
    use null_protocol::consensus::FEE_PER_ACTION;
    use null_protocol::note::{Note, RandomSeed, Rho};
    use null_protocol::nullifier::Nullifier;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::keys::WalletKeys;

    fn owned(rng: &mut ChaCha20Rng, keys: &WalletKeys, value: u64, position: u32) -> OwnedNote {
        let note = Note::new(
            keys.default_address().unwrap(),
            Amount::from_raw(value).unwrap(),
            Rho::random(rng),
            RandomSeed::random(rng),
        );
        let nullifier = Nullifier::from_base(&pallas::Base::from(u64::from(position)));
        OwnedNote {
            note,
            memo: Memo::empty(),
            position: u64::from(position),
            nullifier,
            height: 1,
            spent_at: None,
            txid: None,
            spent_by: None,
        }
    }

    #[test]
    fn selection_prefers_large_notes_and_accounts_for_the_fee() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let notes = [
            owned(&mut rng, &keys, 100, 0),
            owned(&mut rng, &keys, 5_000_000, 1),
            owned(&mut rng, &keys, 3_000_000, 2),
        ];
        let refs: Vec<&OwnedNote> = notes.iter().collect();
        let fee = 2 * FEE_PER_ACTION;

        let (chosen, got_fee) =
            select_notes(&refs, Amount::from_raw(4_000_000).unwrap(), 2).unwrap();
        assert_eq!(chosen.len(), 1, "the largest note covers amount plus fee");
        assert_eq!(chosen[0].position, 1);
        assert_eq!(got_fee.raw(), fee);

        let (chosen, got_fee) =
            select_notes(&refs, Amount::from_raw(6_000_000).unwrap(), 2).unwrap();
        assert_eq!(chosen.len(), 2, "two notes needed");
        assert_eq!(got_fee.raw(), fee);

        let err = select_notes(&refs, Amount::from_raw(100_000_000).unwrap(), 2).unwrap_err();
        assert!(matches!(err, Error::InsufficientFunds { .. }));

        // Three recipients plus change need the four-action class even
        // from one note, and the fee follows the class.
        let (chosen, got_fee) = select_notes(&refs, Amount::from_raw(1_000).unwrap(), 4).unwrap();
        assert_eq!(chosen.len(), 1);
        assert_eq!(got_fee.raw(), 4 * FEE_PER_ACTION);
    }

    fn pay(keys: &WalletKeys, amount: u64) -> Payment {
        Payment {
            recipient: keys.default_address().unwrap(),
            amount: Amount::from_raw(amount).unwrap(),
            memo: Memo::empty(),
        }
    }

    #[test]
    fn consolidation_batches_are_bounded_disjoint_and_pay_the_main_address() {
        let mut rng = ChaCha20Rng::seed_from_u64(51);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let notes: Vec<_> = (0..35)
            .map(|i| owned(&mut rng, &keys, 1_000_000, i))
            .collect();
        let address = keys.default_address().unwrap();
        let batches = consolidation_from(&notes, address, &[], 1, None).unwrap();
        assert_eq!(
            batches
                .iter()
                .map(|b| b.positions.len())
                .collect::<Vec<_>>(),
            [16, 16, 3]
        );
        let positions: Vec<_> = batches
            .iter()
            .flat_map(|b| b.positions.iter().copied())
            .collect();
        assert_eq!(
            positions.len(),
            positions
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
        );
        for batch in &batches {
            assert_eq!(batch.payment.recipient, address);
            assert_eq!(
                batch.payment.amount.raw() + batch.fee.raw(),
                batch.positions.len() as u64 * 1_000_000
            );
        }
        let again = consolidation_from(&notes, address, &[], 1, Some(&positions)).unwrap();
        assert_eq!(
            again.iter().map(|b| &b.positions).collect::<Vec<_>>(),
            batches.iter().map(|b| &b.positions).collect::<Vec<_>>()
        );
        let seventeen = consolidation_from(&notes[..17], address, &[], 1, None).unwrap();
        assert_eq!(
            seventeen.len(),
            1,
            "a trailing single note needs no self-payment"
        );
    }

    #[test]
    fn consolidation_rejects_stale_duplicates_and_uneconomic_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(52);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let mut notes: Vec<_> = (0..3)
            .map(|i| owned(&mut rng, &keys, 1_000_000, i))
            .collect();
        notes[2].height = 10;
        let address = keys.default_address().unwrap();
        assert!(consolidation_from(&notes, address, &[], 1, Some(&[0, 2])).is_err());
        assert!(consolidation_from(&notes, address, &[1], 1, Some(&[0, 1])).is_err());
        assert!(consolidation_from(&notes, address, &[], 1, Some(&[0, 0])).is_err());
        assert!(consolidation_from(&notes, address, &[], 1, Some(&[])).is_err());
        let tiny: Vec<_> = (0..2).map(|i| owned(&mut rng, &keys, 1, i)).collect();
        assert!(consolidation_from(&tiny, address, &[], 1, None).is_err());
        assert_eq!(
            consolidation_from(&notes, address, &[], 1, None).unwrap()[0].positions,
            [0, 1]
        );
    }

    #[test]
    fn reserved_selection_keeps_small_inputs_at_fee_tier_boundaries() {
        let mut rng = ChaCha20Rng::seed_from_u64(53);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let notes = [
            owned(&mut rng, &keys, 1_000_000, 0),
            owned(&mut rng, &keys, 1_000_000, 1),
            owned(&mut rng, &keys, 1, 2),
        ];
        let batch = consolidation_from(&notes, keys.default_address().unwrap(), &[], 1, None)
            .unwrap()
            .pop()
            .unwrap();
        let reserved = reserved_notes(&notes, &batch.positions, 1).unwrap();
        assert_eq!(reserved.len(), 3);
        assert_eq!(batch.fee.raw(), 4 * FEE_PER_ACTION);
        assert!(reserved_notes(&notes, &[0, 9], 1).is_err());
        assert!(reserved_notes(&notes, &[0, 0], 1).is_err());
        assert!(reserved_notes(&notes, &[0, 1], 0).is_err());
    }

    #[test]
    fn quotes_follow_the_notes_selection_would_spend() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let notes: Vec<OwnedNote> = (0..6)
            .map(|i| owned(&mut rng, &keys, 1_000_000, i))
            .collect();

        let one = quote_from(&notes, &[pay(&keys, 500_000)], &[], u32::MAX).unwrap();
        assert_eq!((one.spends, one.actions), (1, 2));
        assert_eq!(one.fee.raw(), 2 * FEE_PER_ACTION);

        // Five small notes outgrow the two-action class the recipient
        // count alone suggests, so the fee grows with them.
        let many = quote_from(&notes, &[pay(&keys, 4_500_000)], &[], u32::MAX).unwrap();
        assert_eq!((many.spends, many.actions), (5, 8));
        assert_eq!(many.fee.raw(), 8 * FEE_PER_ACTION);
    }

    #[test]
    fn quotes_skip_excluded_and_unconfirmed_notes() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let mut notes: Vec<OwnedNote> = (0..2)
            .map(|i| owned(&mut rng, &keys, 1_000_000, i))
            .collect();
        notes[1].height = 10;
        let payment = [pay(&keys, 1_500_000)];
        assert!(quote_from(&notes, &payment, &[], u32::MAX).is_ok());
        for (excluded, max_height) in [(&[0][..], u32::MAX), (&[][..], 9)] {
            let err = quote_from(&notes, &payment, excluded, max_height).unwrap_err();
            assert!(matches!(err, Error::InsufficientFunds { .. }));
        }
    }

    #[test]
    fn quotes_reject_empty_and_oversized_recipient_lists() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let keys = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        let notes = [owned(&mut rng, &keys, 1_000_000, 0)];
        let too_many = vec![pay(&keys, 1); MAX_RECIPIENTS + 1];
        for payments in [&[][..], &too_many[..]] {
            let err = quote_from(&notes, payments, &[], u32::MAX).unwrap_err();
            assert!(matches!(err, Error::TooManyRecipients(_)));
        }
    }
}
