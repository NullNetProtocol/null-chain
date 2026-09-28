//! Outgoing payments and received notes.

use eframe::egui::{Align, Layout, RichText, Ui};
use null_desktop::backend::Snapshot;
use serde_json::{json, Value};

use super::{Call, Effect};
use crate::ui::format::{coins, field, number, text};
use crate::ui::theme::{self, Tone};
use crate::ui::widgets;

/// Draws both lists, newest first. Queued payments can be cancelled.
pub fn show(ui: &mut Ui, state: &Snapshot) -> Option<Effect> {
    widgets::page(
        ui,
        "Activity",
        "Payments you sent and notes you received, newest first.",
        |ui| {
            widgets::section(ui, "Sent");
            let effect = list(ui, &state.operations, "No payments sent yet", operation);
            widgets::section(ui, "Received (includes change)");
            list(ui, &state.received, "Nothing received yet", |ui, item| {
                note(ui, item);
                None
            });
            effect
        },
    )
}

fn list(
    ui: &mut Ui,
    items: &Value,
    empty: &str,
    row: impl Fn(&mut Ui, &Value) -> Option<Effect>,
) -> Option<Effect> {
    let items = items.as_array().map_or(&[][..], Vec::as_slice);
    if items.is_empty() {
        widgets::empty_state(ui, empty, "Entries appear here as your wallet scans.");
    }
    items
        .iter()
        .rev()
        .map(|item| widgets::card(ui, |ui| row(ui, item)))
        .fold(None, Option::or)
}

fn operation(ui: &mut Ui, op: &Value) -> Option<Effect> {
    let status = text(op, "status");
    entry(
        ui,
        &format!("Payment #{}", number(op, "operation_id")),
        &format!("−{} NULL", coins(op, "total")),
        (status, status_tone(status)),
        field(op, "txid").as_str(),
    );
    if let Some(error) = field(op, "error").as_str() {
        ui.label(RichText::new(error).color(Tone::Danger.color()));
    }
    let cancellable = field(op, "cancellable").as_bool() == Some(true);
    (cancellable && widgets::secondary_button(ui, "Cancel payment", true).clicked())
        .then(|| cancel(op))
        .flatten()
}

/// Cancels a queued payment before it is proved.
fn cancel(op: &Value) -> Option<Effect> {
    let id = field(op, "operation_id").as_u64()?;
    Some(Call::notice(
        "canceloperation",
        json!([id]),
        "Payment cancelled",
    ))
}

fn note(ui: &mut Ui, note: &Value) {
    let confirmations = field(note, "confirmations").as_u64().unwrap_or(0);
    let badge = if confirmations == 0 {
        ("unconfirmed".to_owned(), Tone::Warning)
    } else {
        (format!("{confirmations} confirmations"), Tone::Success)
    };
    entry(
        ui,
        "Received",
        &format!("+{} NULL", coins(note, "amount")),
        (&badge.0, badge.1),
        field(note, "txid").as_str(),
    );
    if let Some(memo) = memo_text(note) {
        widgets::caption(ui, "Memo");
        ui.label(memo);
    }
}

/// A received note's memo as text; binary memos are not shown.
fn memo_text(note: &Value) -> Option<&str> {
    field(note, "memo")
        .as_str()
        .filter(|m| !m.trim().is_empty())
}

/// One activity row: title and transaction on the left, amount and state on the right.
fn entry(ui: &mut Ui, title: &str, amount: &str, badge: (&str, Tone), txid: Option<&str>) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            widgets::card_title(ui, title);
            if let Some(txid) = txid {
                widgets::hash(ui, txid);
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            widgets::badge(ui, badge.0, badge.1);
            ui.label(RichText::new(amount).monospace().size(theme::TITLE_SIZE));
        });
    });
}

/// Color for a payment operation status reported by the wallet.
fn status_tone(status: &str) -> Tone {
    match status {
        "confirmed" => Tone::Success,
        "failed" => Tone::Danger,
        "queued" | "proving" | "submitted" => Tone::Warning,
        _ => Tone::Neutral,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::screens::Reply;

    #[test]
    fn payment_states_map_to_meaningful_tones() {
        assert_eq!(status_tone("confirmed"), Tone::Success);
        assert_eq!(status_tone("failed"), Tone::Danger);
        for pending in ["queued", "proving", "submitted"] {
            assert_eq!(status_tone(pending), Tone::Warning);
        }
        for other in ["cancelled", "", "unknown"] {
            assert_eq!(status_tone(other), Tone::Neutral);
        }
    }

    #[test]
    fn cancelling_names_the_operation_and_needs_an_id() {
        let Some(Effect::Call(call)) = cancel(&json!({ "operation_id": 7 })) else {
            panic!("expected a call");
        };
        assert_eq!(call.method, "canceloperation");
        assert_eq!(call.params, json!([7]));
        assert!(matches!(call.reply, Reply::Notice(_)));
        assert!(cancel(&json!({})).is_none());
    }

    #[test]
    fn only_non_empty_text_memos_are_shown() {
        assert_eq!(memo_text(&json!({ "memo": "rent" })), Some("rent"));
        for note in [
            json!({}),
            json!({ "memo": null }),
            json!({ "memo": "  " }),
            json!({ "memo": { "hex": "00ff" } }),
        ] {
            assert_eq!(memo_text(&note), None);
        }
    }
}
