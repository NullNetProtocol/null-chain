//! Creating, showing, and copying receiving addresses.

use eframe::egui::{self, Ui};
use null_desktop::backend::Snapshot;
use serde_json::{json, Value};

use super::{Call, Effect};
use crate::ui::format::{field, number, text};
use crate::ui::theme;
use crate::ui::widgets;

/// Label for the next address, and which address's QR code is open.
#[derive(Default)]
pub struct Form {
    label: String,
    /// Index of the address whose QR code is shown; the newest by default.
    shown: Option<u64>,
}

impl Form {
    /// Draws the address list and the new-address form.
    pub fn show(&mut self, ui: &mut Ui, state: &Snapshot) -> Option<Effect> {
        widgets::page(
            ui,
            "Receive NULL",
            "Use a new address for each sender.",
            |ui| {
                let entries = state.addresses.as_array().map_or(&[][..], Vec::as_slice);
                if let Some(entry) = self.selected(entries) {
                    widgets::card(ui, |ui| featured(ui, entry));
                }
                let effect = widgets::card(ui, |ui| self.new_address(ui));
                widgets::section(ui, "Your addresses");
                self.addresses(ui, entries);
                effect
            },
        )
    }

    /// The address to feature: the one picked, else the newest.
    fn selected<'a>(&self, entries: &'a [Value]) -> Option<&'a Value> {
        self.shown
            .and_then(|index| {
                entries
                    .iter()
                    .find(|e| field(e, "index").as_u64() == Some(index))
            })
            .or_else(|| entries.last())
    }

    fn new_address(&mut self, ui: &mut Ui) -> Option<Effect> {
        widgets::card_title(ui, "New address");
        widgets::field_label(
            ui,
            "Label",
            Some("Only you see this, for example who will pay you."),
        );
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.label).desired_width(320.0));
            widgets::primary_button(ui, "Create address", true)
                .clicked()
                .then(|| self.request())
        })
        .inner
    }

    fn request(&mut self) -> Effect {
        // The newest address is featured once it arrives.
        self.shown = None;
        Call::notice(
            "getnewaddress",
            json!([std::mem::take(&mut self.label)]),
            "New address created",
        )
    }

    fn addresses(&mut self, ui: &mut Ui, entries: &[Value]) {
        if entries.is_empty() {
            widgets::empty_state(
                ui,
                "No addresses yet",
                "Create one above to start receiving.",
            );
        }
        for entry in entries.iter().rev() {
            widgets::card(ui, |ui| {
                ui.horizontal(|ui| {
                    widgets::card_title(ui, label(entry));
                    widgets::caption(ui, &format!("#{}", number(entry, "index")));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if widgets::secondary_button(ui, "Show QR", true).clicked() {
                            self.shown = field(entry, "index").as_u64();
                        }
                    });
                });
                widgets::copyable(ui, text(entry, "address"));
            });
        }
    }
}

/// The featured address, large, with its QR code.
fn featured(ui: &mut Ui, entry: &Value) {
    ui.horizontal(|ui| {
        widgets::qr_code(ui, text(entry, "address"));
        ui.add_space(theme::SPACE_LG);
        ui.vertical(|ui| {
            widgets::caption(ui, "Share this address or let the sender scan it");
            widgets::card_title(ui, label(entry));
            ui.add_space(theme::SPACE_SM);
            widgets::copyable(ui, text(entry, "address"));
        });
    });
}

/// An address's label, or a placeholder when it has none.
fn label(entry: &Value) -> &str {
    match entry.get("label").and_then(Value::as_str) {
        Some(label) if !label.trim().is_empty() => label,
        _ => "Unlabelled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::screens::Reply;

    #[test]
    fn requesting_an_address_sends_the_label_and_clears_it() {
        let mut form = Form {
            label: "rent".into(),
            shown: Some(0),
        };
        let Effect::Call(call) = form.request() else {
            panic!("expected a call");
        };
        assert_eq!(call.method, "getnewaddress");
        assert_eq!(call.params, json!(["rent"]));
        assert!(matches!(call.reply, Reply::Notice(_)));
        assert!(form.label.is_empty());
        assert_eq!(form.shown, None, "the new address will be featured");
    }

    #[test]
    fn the_featured_address_is_the_chosen_one_or_the_newest() {
        let entries = [json!({ "index": 0 }), json!({ "index": 1 })];
        let mut form = Form::default();
        assert_eq!(form.selected(&entries), entries.get(1));
        form.shown = Some(0);
        assert_eq!(form.selected(&entries), entries.first());
        form.shown = Some(9);
        assert_eq!(
            form.selected(&entries),
            entries.get(1),
            "unknown picks fall back"
        );
        assert_eq!(form.selected(&[]), None);
    }

    #[test]
    fn blank_labels_read_as_unlabelled() {
        assert_eq!(label(&json!({ "label": "rent" })), "rent");
        for entry in [json!({}), json!({ "label": "  " }), json!({ "label": 3 })] {
            assert_eq!(label(&entry), "Unlabelled");
        }
    }
}
