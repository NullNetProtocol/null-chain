//! Balance and wallet synchronization at a glance.

use eframe::egui::{ProgressBar, Ui};
use null_desktop::backend::Snapshot;
use serde_json::Value;

use crate::ui::format::{coins, field, number};
use crate::ui::theme::{self, Tone};
use crate::ui::widgets;

/// Draws the overview. It has no actions.
pub fn show(ui: &mut Ui, state: &Snapshot) {
    widgets::page(
        ui,
        "Overview",
        "Balances update as your wallet scans the local chain.",
        |ui| {
            widgets::card(ui, |ui| {
                widgets::caption(ui, "Spendable balance");
                widgets::display_amount(ui, &coins(&state.balance, "spendable"), "NULL");
                widgets::caption(
                    ui,
                    &format!(
                        "Total including unconfirmed: {} NULL",
                        coins(&state.balance, "total")
                    ),
                );
            });
            if let Some(wallet) = &state.wallet {
                sync(ui, wallet, &state.node);
            }
        },
    );
}

fn sync(ui: &mut Ui, wallet: &Value, node: &Value) {
    ui.columns(3, |columns| {
        let [scanned, chain, pending] = columns else {
            return;
        };
        widgets::stat(scanned, "Wallet height", &number(wallet, "scanned_height"));
        widgets::stat(chain, "Node height", &number(node, "height"));
        widgets::stat(
            pending,
            "Pending payments",
            &number(wallet, "pending_operations"),
        );
    });
    if field(wallet, "synced").as_bool() != Some(true) {
        widgets::card(ui, |ui| {
            widgets::card_title(ui, "Scanning for your payments");
            ui.add(
                ProgressBar::new(progress(wallet, node))
                    .show_percentage()
                    .fill(theme::ACCENT),
            );
        });
    }
    if let Some(error) = field(wallet, "last_error").as_str() {
        widgets::notice(ui, Tone::Danger, error);
    }
}

/// Share of the chain the wallet has scanned, in `0.0..=1.0`.
fn progress(wallet: &Value, node: &Value) -> f32 {
    let scanned = field(wallet, "scanned_height").as_u64().unwrap_or(0);
    match field(node, "height").as_u64() {
        Some(height) if height > 0 => {
            // A progress bar needs only an approximate ratio.
            #[allow(clippy::cast_precision_loss)]
            let ratio = scanned.min(height) as f32 / height as f32;
            ratio
        }
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn progress_is_the_scanned_share_and_never_exceeds_one() {
        let node = json!({ "height": 200 });
        assert!((progress(&json!({ "scanned_height": 50 }), &node) - 0.25).abs() < f32::EPSILON);
        assert!((progress(&json!({ "scanned_height": 900 }), &node) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn progress_is_zero_without_a_known_chain_height() {
        let wallet = json!({ "scanned_height": 5 });
        for node in [json!({}), json!({ "height": 0 }), json!({ "height": "x" })] {
            assert!(progress(&wallet, &node).abs() < f32::EPSILON);
        }
    }
}
