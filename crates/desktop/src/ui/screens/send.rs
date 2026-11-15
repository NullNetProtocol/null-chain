//! Payment form, an exact fee quote, and a review step before anything is
//! proved or sent.

use eframe::egui::{self, RichText, Ui};
use null_desktop::backend::Snapshot;
use serde_json::{json, Value};

use super::{Call, Effect, Reply};
use crate::ui::format::{coins, field, number, payment, text};
use crate::ui::theme::{self, Tone};
use crate::ui::widgets;

/// Lines shown for the memo input.
const MEMO_ROWS: usize = 3;

/// Confirmations a note needs before a payment may spend it.
const MIN_CONFIRMATIONS: u64 = 1;

/// Where the payment is in its journey from form to queue.
#[derive(Default)]
enum Stage {
    /// Filling in the form.
    #[default]
    Editing,
    /// Waiting for the wallet to price a validated payment.
    Quoting(Value),
    /// Showing the payment and its exact fee for confirmation.
    Reviewing { payment: Value, quote: Value },
    /// Waiting for a consolidation plan; no notes have been reserved.
    QuotingConsolidation,
    /// Reviewing the exact consolidation inputs and total fees.
    ReviewingConsolidation(Value),
}

/// Payment inputs and the payment's progress towards the queue.
#[derive(Default)]
pub struct Form {
    recipient: String,
    amount: String,
    memo: String,
    stage: Stage,
    error: Option<String>,
}

impl Form {
    /// Draws the form, or the review card once a payment is priced.
    pub fn show(&mut self, ui: &mut Ui, state: &Snapshot) -> Option<Effect> {
        widgets::page(
            ui,
            "Send NULL",
            "Payments are shielded. Only you and the recipient see the amount and memo.",
            |ui| match &self.stage {
                Stage::Editing => self.edit(ui, state),
                Stage::Quoting(_) | Stage::QuotingConsolidation => {
                    widgets::card(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Calculating the exact fee…");
                        });
                    });
                    None
                }
                Stage::Reviewing { payment, quote } => {
                    let (payment, quote) = (payment.clone(), quote.clone());
                    self.confirm(ui, &payment, &quote)
                }
                Stage::ReviewingConsolidation(quote) => {
                    self.confirm_consolidation(ui, &quote.clone())
                }
            },
        )
    }

    /// Forgets a payment that was priced but not confirmed.
    pub fn discard_review(&mut self) {
        self.stage = Stage::Editing;
    }

    /// Receives the wallet's answer to a [`Reply::Quote`] call.
    pub fn quoted(&mut self, result: Result<Value, String>) {
        if !matches!(self.stage, Stage::Quoting(_)) {
            return;
        }
        let Stage::Quoting(payment) = std::mem::take(&mut self.stage) else {
            return;
        };
        match result {
            Ok(quote) => self.stage = Stage::Reviewing { payment, quote },
            Err(error) => self.error = Some(error),
        }
    }

    /// Receives the consolidation quote, unless its review was discarded.
    pub fn consolidation_quoted(&mut self, result: Result<Value, String>) {
        if !matches!(self.stage, Stage::QuotingConsolidation) {
            return;
        }
        self.stage = Stage::Editing;
        match result {
            Ok(quote) => self.stage = Stage::ReviewingConsolidation(quote),
            Err(error) => self.error = Some(error),
        }
    }

    fn edit(&mut self, ui: &mut Ui, state: &Snapshot) -> Option<Effect> {
        let synced = state
            .wallet
            .as_ref()
            .is_some_and(|w| field(w, "synced").as_bool() == Some(true));
        if !synced {
            widgets::notice(
                ui,
                Tone::Warning,
                "Wait for the wallet to finish scanning before sending.",
            );
        }
        if let Some(error) = &self.error {
            widgets::notice(ui, Tone::Danger, error);
        }
        let spender = state
            .wallet
            .as_ref()
            .is_some_and(|w| field(w, "watch_only").as_bool() != Some(true));
        let payment_effect = widgets::card(ui, |ui| {
            widgets::field_label(ui, "Recipient address", None);
            ui.add(egui::TextEdit::singleline(&mut self.recipient).desired_width(f32::INFINITY));
            widgets::field_label(ui, "Amount", Some("In NULL, up to 8 decimal places."));
            let max = spender.then(|| max_payment(&state.balance)).flatten();
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.amount).desired_width(200.0));
                ui.label(RichText::new("NULL").color(theme::TEXT_MUTED));
                if widgets::secondary_button(ui, "Use max", synced && max.is_some())
                    .on_hover_text("The whole amount one payment can send, after its network fee.")
                    .clicked()
                {
                    if let Some(max) = &max {
                        self.amount.clone_from(max);
                    }
                }
            });
            widgets::caption(ui, &available(&state.balance));
            widgets::field_label(ui, "Memo", Some("Optional. Encrypted to the recipient."));
            ui.add(
                egui::TextEdit::multiline(&mut self.memo)
                    .desired_rows(MEMO_ROWS)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(theme::SPACE_MD);
            widgets::primary_button(ui, "Review payment", synced)
                .clicked()
                .then(|| self.request_quote(&state.node))
        });
        let consolidation_effect = widgets::card(ui, |ui| {
            widgets::card_title(ui, "Consolidate inputs");
            widgets::caption(ui, "Combine mined rewards and other small notes into larger notes at your main address. Review the total network fee before starting.");
            widgets::secondary_button(ui, "Consolidate inputs", synced && spender)
                .clicked()
                .then(|| self.request_consolidation())
        });
        payment_effect.or(consolidation_effect)
    }

    fn request_consolidation(&mut self) -> Effect {
        self.error = None;
        self.stage = Stage::QuotingConsolidation;
        Effect::Call(Call {
            method: "quoteconsolidation".into(),
            params: json!({ "min_confirmations": MIN_CONFIRMATIONS }),
            reply: Reply::ConsolidationQuote,
        })
    }

    fn confirm_consolidation(&mut self, ui: &mut Ui, quote: &Value) -> Option<Effect> {
        widgets::highlighted_card(ui, |ui| {
            widgets::card_title(ui, "Review consolidation");
            widgets::key_value(ui, "Inputs to combine", &number(quote, "input_count"));
            widgets::key_value(ui, "Transactions", &number(quote, "transactions"));
            widgets::key_value(
                ui,
                "Total network fee",
                &format!("{} NULL", coins(quote, "fee")),
            );
            widgets::key_value(
                ui,
                "Returned to your wallet",
                &format!("{} NULL", coins(quote, "amount")),
            );
            widgets::field_label(ui, "Your main address", None);
            widgets::copyable(ui, text(quote, "address"));
            widgets::caption(ui, "The new notes become available after confirmation. For a large wallet, consolidate again after confirmation to combine the resulting notes further.");
            ui.horizontal(|ui| {
                if widgets::primary_button(ui, "Confirm consolidation", true).clicked() {
                    return Some(self.consolidate(quote));
                }
                if widgets::secondary_button(ui, "Cancel", true).clicked() {
                    self.discard_review();
                }
                None
            })
            .inner
        })
    }

    fn consolidate(&mut self, quote: &Value) -> Effect {
        self.discard_review();
        Call::notice(
            "consolidate",
            json!({ "min_confirmations": MIN_CONFIRMATIONS, "inputs": quote.get("inputs"), "max_fee": quote.get("fee") }),
            "Consolidation queued. Follow its progress in Activity.",
        )
    }

    /// Validates the form locally, then asks the wallet to price it.
    fn request_quote(&mut self, node: &Value) -> Effect {
        match payment(&self.recipient, &self.amount, &self.memo, node) {
            Ok(payment) => {
                self.error = None;
                let params = json!({
                    "recipients": [payment],
                    "min_confirmations": MIN_CONFIRMATIONS,
                });
                self.stage = Stage::Quoting(payment);
                Effect::Call(Call {
                    method: "quotepayment".into(),
                    params,
                    reply: Reply::Quote,
                })
            }
            Err(error) => {
                self.error = Some(error.clone());
                Effect::Notify(error)
            }
        }
    }

    fn confirm(&mut self, ui: &mut Ui, payment: &Value, quote: &Value) -> Option<Effect> {
        widgets::highlighted_card(ui, |ui| {
            widgets::caption(ui, "You are sending");
            widgets::display_amount(ui, &coins(payment, "amount"), "NULL");
            ui.add_space(theme::SPACE_SM);
            widgets::field_label(ui, "To", None);
            widgets::copyable(ui, text(payment, "address"));
            let memo = text(payment, "memo");
            if !memo.is_empty() {
                widgets::field_label(ui, "Memo", None);
                ui.label(memo);
            }
            ui.add_space(theme::SPACE_SM);
            ui.separator();
            widgets::key_value(ui, "Network fee", &format!("{} NULL", coins(quote, "fee")));
            widgets::key_value(
                ui,
                "Total deducted",
                &format!("{} NULL", coins(quote, "total")),
            );
            widgets::caption(
                ui,
                "The fee depends only on the transaction's size, never on the amount. \
                 Proving can take several seconds.",
            );
            ui.add_space(theme::SPACE_MD);
            ui.horizontal(|ui| {
                if widgets::primary_button(ui, "Confirm and send", true).clicked() {
                    return Some(self.send(payment));
                }
                if widgets::secondary_button(ui, "Edit", true).clicked() {
                    self.discard_review();
                }
                None
            })
            .inner
        })
    }

    fn send(&mut self, payment: &Value) -> Effect {
        *self = Self::default();
        Call::notice(
            "sendmany",
            json!({ "recipients": [payment], "min_confirmations": MIN_CONFIRMATIONS }),
            "Payment queued. Follow its progress in Activity.",
        )
    }
}

/// The amount "Use max" fills in: the wallet's `max_payment`, as NULL
/// text, or `None` when nothing can be sent.
fn max_payment(balance: &Value) -> Option<String> {
    let raw = text(balance, "max_payment").parse::<u64>().ok()?;
    (raw > 0).then(|| coins(balance, "max_payment"))
}

/// The line under the amount: what the wallet can spend, and when one
/// payment cannot carry all of it, why.
fn available(balance: &Value) -> String {
    let units = |key| text(balance, key).parse::<u64>().ok();
    let line = format!("Available: {} NULL", coins(balance, "spendable"));
    match units("spendable").zip(units("max_payment")) {
        // More than the largest fee is missing: the payment cannot spend
        // every note. Consolidating combines them.
        Some((spendable, max)) if spendable.saturating_sub(max) > largest_fee() => format!(
            "{line}. One payment can send up to {} NULL; consolidate inputs to send more at once.",
            coins(balance, "max_payment")
        ),
        _ => line,
    }
}

/// The fee of the largest transaction.
fn largest_fee() -> u64 {
    null_protocol::consensus::fee_for_actions(null_protocol::consensus::MAX_ACTIONS)
        .map_or(0, null_protocol::amount::Amount::raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoting(payment: &Value) -> Form {
        Form {
            stage: Stage::Quoting(payment.clone()),
            ..Form::default()
        }
    }

    #[test]
    fn use_max_fills_the_largest_payment_and_explains_when_it_falls_short() {
        let balance = json!({ "spendable": "500000000", "max_payment": "499980000" });
        assert_eq!(max_payment(&balance).as_deref(), Some("4.99980000"));
        assert_eq!(available(&balance), "Available: 5.00000000 NULL");

        let many = json!({ "spendable": "2000000000", "max_payment": "1599840000" });
        assert!(available(&many).contains("up to 15.99840000 NULL; consolidate"));

        assert_eq!(
            max_payment(&json!({ "spendable": "100", "max_payment": "0" })),
            None
        );
        assert_eq!(max_payment(&Value::Null), None);
        assert!(available(&Value::Null).starts_with("Available: "));
    }

    #[test]
    fn invalid_payments_show_an_error_and_are_not_priced() {
        let mut form = Form {
            recipient: "not an address".into(),
            amount: "1".into(),
            ..Form::default()
        };
        let effect = form.request_quote(&json!({ "network": "test" }));
        assert!(matches!(effect, Effect::Notify(_)));
        assert!(matches!(form.stage, Stage::Editing));
        assert!(form.error.is_some());
    }

    #[test]
    fn consolidation_is_quoted_and_confirmation_uses_only_the_reviewed_inputs() {
        let mut form = Form::default();
        let Effect::Call(call) = form.request_consolidation() else {
            panic!("expected quote");
        };
        assert_eq!(call.method, "quoteconsolidation");
        assert_eq!(call.reply, Reply::ConsolidationQuote);
        let quote = json!({ "inputs": [3, 7], "fee": "20000" });
        form.consolidation_quoted(Ok(quote.clone()));
        assert!(matches!(form.stage, Stage::ReviewingConsolidation(_)));
        form.quoted(Ok(json!({}))); // A stale payment quote cannot replace this review.
        assert!(matches!(form.stage, Stage::ReviewingConsolidation(_)));
        let Effect::Call(call) = form.consolidate(&quote) else {
            panic!("expected consolidation");
        };
        assert_eq!(call.method, "consolidate");
        assert_eq!(call.params["inputs"], quote["inputs"]);
        assert_eq!(call.params["max_fee"], quote["fee"]);
        assert!(matches!(form.stage, Stage::Editing));
        form.consolidation_quoted(Ok(quote));
        assert!(
            matches!(form.stage, Stage::Editing),
            "a discarded quote stays discarded"
        );
        form.request_consolidation();
        form.consolidation_quoted(Err("busy".into()));
        assert_eq!(form.error.as_deref(), Some("busy"));
    }

    #[test]
    fn a_quote_leads_to_review_and_a_refusal_back_to_the_form() {
        let payment = json!({ "address": "a", "amount": "5", "memo": "" });
        let mut form = quoting(&payment);
        form.quoted(Ok(json!({ "fee": "20000", "total": "20005" })));
        assert!(matches!(&form.stage, Stage::Reviewing { quote, .. } if quote["fee"] == "20000"));

        let mut form = quoting(&payment);
        form.quoted(Err("insufficient funds".into()));
        assert!(matches!(form.stage, Stage::Editing));
        assert_eq!(form.error.as_deref(), Some("insufficient funds"));
    }

    #[test]
    fn late_quotes_after_editing_resumed_are_ignored() {
        let mut form = Form::default();
        form.quoted(Ok(json!({ "fee": "1" })));
        assert!(matches!(form.stage, Stage::Editing));
    }

    #[test]
    fn sending_queues_the_reviewed_payment_and_resets_the_form() {
        let payment = json!({ "address": "a", "amount": "5", "memo": "" });
        let mut form = Form {
            recipient: "a".into(),
            amount: "0.00000005".into(),
            ..quoting(&payment)
        };
        let Effect::Call(call) = form.send(&payment) else {
            panic!("expected a call");
        };
        assert_eq!(call.method, "sendmany");
        assert!(matches!(call.reply, Reply::Notice(_)));
        assert_eq!(
            call.params.get("recipients").and_then(|r| r.get(0)),
            Some(&payment)
        );
        assert!(matches!(form.stage, Stage::Editing));
        assert!(form.recipient.is_empty() && form.amount.is_empty());
    }
}
