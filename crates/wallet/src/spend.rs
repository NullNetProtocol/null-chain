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
    let keys = wallet.keys();
    let sk = keys.spending_key()?;
    let unspent = wallet.unspent()?;
    let (chosen, fee) = plan(&unspent, payments, excluded, max_note_height)?;
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
