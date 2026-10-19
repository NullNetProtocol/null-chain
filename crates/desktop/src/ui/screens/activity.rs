//! Sent payments and received notes in one list, newest first, with
//! filters, search, and pages.

mod timeline;

use eframe::egui::{Align, Layout, RichText, Ui};
use null_desktop::backend::Snapshot;
use serde_json::{json, Value};

use super::{Call, Effect};
use crate::ui::format::{coins, field, local_time, number, short_hash, text, MISSING};
use crate::ui::theme::{self, Tone};
use crate::ui::widgets;
use timeline::{Entry, Filter, Kind, PER_PAGE};

/// What the list shows: kept while the user moves between pages.
#[derive(Default)]
pub struct Form {
    filter: Filter,
    with_change: bool,
    query: String,
    page: usize,
}

impl Form {
    /// Draws the controls and one page of entries. Queued payments can be
    /// cancelled.
    pub fn show(&mut self, ui: &mut Ui, state: &Snapshot) -> Option<Effect> {
        widgets::page(
            ui,
            "Activity",
            "Payments you sent and received, newest first, in your local time.",
            |ui| {
                let all = timeline::entries(&state.operations, &state.received);
                self.controls(ui, &all);
                let shown: Vec<&Entry<'_>> = all
                    .iter()
                    .filter(|e| self.filter.shows(e.kind, self.with_change))
                    .filter(|e| timeline::matches(e, &self.query))
                    .collect();
                self.list(ui, &shown, all.is_empty())
            },
        )
    }

    fn controls(&mut self, ui: &mut Ui, all: &[Entry<'_>]) {
        ui.horizontal_wrapped(|ui| {
            for (filter, label) in Filter::ALL {
                let count = all
                    .iter()
                    .filter(|e| filter.shows(e.kind, self.with_change))
                    .count();
                if widgets::tab(ui, &format!("{label} ({count})"), self.filter == filter).clicked()
                {
                    self.filter = filter;
                    self.page = 0;
                }
            }
            ui.add_space(theme::SPACE_SM);
            if ui.checkbox(&mut self.with_change, "Show change").changed() {
                self.page = 0;
            }
        });
        ui.add_space(theme::SPACE_SM);
        if widgets::search_input(
            ui,
            &mut self.query,
            "Search by transaction, address, label, memo or #payment",
        ) {
            self.page = 0;
        }
        ui.add_space(theme::SPACE_MD);
    }

    fn list(&mut self, ui: &mut Ui, shown: &[&Entry<'_>], wallet_empty: bool) -> Option<Effect> {
        if shown.is_empty() {
            let (title, body) = if wallet_empty {
                (
                    "No activity yet",
                    "Payments appear here as your wallet scans.",
                )
            } else {
                ("Nothing matches", "Try another filter or search.")
            };
            widgets::empty_state(ui, title, body);
            return None;
        }
        let view = timeline::page(shown.len(), self.page, PER_PAGE);
        self.page = view.index;
        widgets::caption(
            ui,
            &format!(
                "Showing {}–{} of {}",
                view.range.start.saturating_add(1),
                view.range.end,
                shown.len()
            ),
        );
        ui.add_space(theme::SPACE_XS);
        let effect = shown
            .get(view.range)
            .unwrap_or_default()
            .iter()
            .map(|entry| widgets::card(ui, |ui| row(ui, entry)))
            .fold(None, Option::or);
        if view.count > 1 {
            if let Some(page) = widgets::pager(ui, view.index, view.count) {
                self.page = page;
            }
        }
        effect
    }
}

fn row(ui: &mut Ui, entry: &Entry<'_>) -> Option<Effect> {
    match entry.kind {
        Kind::Sent => operation(ui, entry),
        Kind::Received | Kind::Mined | Kind::Change => {
            note(ui, entry);
            None
        }
    }
}

/// When an entry happened, or that its date is still being looked up.
fn when(entry: &Entry<'_>) -> String {
    entry.time.map_or_else(|| "Date pending".into(), local_time)
}

fn operation(ui: &mut Ui, entry: &Entry<'_>) -> Option<Effect> {
    let op = entry.item;
    let status = text(op, "status");
    entry_row(
        ui,
        &format!("Payment #{}", number(op, "operation_id")),
        &[when(entry), recipients(op)],
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

/// Who a payment went to: the first address, and how many others.
fn recipients(op: &Value) -> String {
    let list = field(op, "recipients")
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let first = list
        .first()
        .and_then(|r| r.get("address"))
        .and_then(Value::as_str)
        .map_or_else(|| MISSING.to_owned(), short_hash);
    match list.len() {
        0 | 1 => format!("To {first}"),
        n => format!("To {first} and {} more", n.saturating_sub(1)),
    }
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

/// A row's title for a note of `kind`.
fn note_title(kind: Kind) -> &'static str {
    match kind {
        Kind::Mined => "Mining reward",
        Kind::Change => "Change",
        Kind::Received | Kind::Sent => "Received",
    }
}

fn note(ui: &mut Ui, entry: &Entry<'_>) {
    let note = entry.item;
    let confirmations = field(note, "confirmations").as_u64().unwrap_or(0);
    let badge = if confirmations == 0 {
        ("unconfirmed".to_owned(), Tone::Warning)
    } else {
        (format!("{confirmations} confirmations"), Tone::Success)
    };
    let mut details = vec![when(entry)];
    if let Some(label) = field(note, "label").as_str().filter(|l| !l.is_empty()) {
        details.push(format!("To {label}"));
    }
    entry_row(
        ui,
        note_title(entry.kind),
        &details,
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

/// One activity row: title, details, and transaction on the left, amount
/// and state on the right.
fn entry_row(
    ui: &mut Ui,
    title: &str,
    details: &[String],
    amount: &str,
    badge: (&str, Tone),
    txid: Option<&str>,
) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            widgets::card_title(ui, title);
            widgets::caption(ui, &details.join(" · "));
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
    fn note_rows_are_titled_by_kind() {
        assert_eq!(note_title(Kind::Mined), "Mining reward");
        assert_eq!(note_title(Kind::Change), "Change");
        assert_eq!(note_title(Kind::Received), "Received");
    }

    #[test]
    fn rows_say_when_and_to_whom() {
        let pending = Entry {
            kind: Kind::Received,
            item: &Value::Null,
            time: None,
        };
        assert_eq!(when(&pending), "Date pending");
        let dated = Entry {
            time: Some(0),
            ..pending
        };
        assert_eq!(when(&dated), local_time(0));
        let address = "null1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let one = json!({ "recipients": [{ "address": address }] });
        assert_eq!(recipients(&one), format!("To {}", short_hash(address)));
        let three = json!({ "recipients": [{ "address": "a" }, { "address": "b" }, {}] });
        assert_eq!(recipients(&three), "To a and 2 more");
        assert_eq!(recipients(&json!({})), format!("To {MISSING}"));
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
