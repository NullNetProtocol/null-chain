//! Embedded node status, local RPC, and storage locations.

use eframe::egui::{self, Ui};
use null_desktop::backend::{Action, Snapshot};
use null_desktop::config::Paths;
use serde_json::Value;

use super::{mining, Effect};
use crate::ui::format::{field, number, text};
use crate::ui::theme::Tone;
use crate::ui::widgets;

/// Draws node status, the mining card and the log file switch, the page's
/// only actions.
pub fn show(
    ui: &mut Ui,
    state: &Snapshot,
    paths: &Paths,
    mining: &mut mining::Form,
) -> Option<Effect> {
    widgets::page(
        ui,
        "Node",
        "The full node runs inside this app and verifies every block itself.",
        |ui| {
            let peers = peer_count(&state.node);
            let (tone, message) = health(&state.node, peers);
            widgets::notice(ui, tone, message);
            ui.columns(3, |columns| {
                let [network, height, connected] = columns else {
                    return;
                };
                widgets::stat(network, "Network", text(&state.node, "network"));
                widgets::stat(height, "Height", &number(&state.node, "height"));
                widgets::stat(connected, "Peers", &peers.to_string());
            });
            let mining_effect = mining.show(ui, state);
            let log_effect = log_file(ui, state.log_file, paths);
            widgets::card(ui, |ui| {
                widgets::card_title(ui, "Best block");
                widgets::copyable(ui, text(&state.node, "best_block_hash"));
                if let Some(addr) = state.rpc {
                    widgets::field_label(ui, "Local RPC", None);
                    widgets::copyable(ui, &format!("http://{addr}"));
                }
            });
            widgets::card(ui, |ui| storage(ui, paths));
            mining_effect.or(log_effect)
        },
    )
}

/// The log file switch. Off by default: the log names peers and
/// transaction ids, which a privacy wallet should not leave on disk
/// unless asked to.
fn log_file(ui: &mut Ui, on: bool, paths: &Paths) -> Option<Effect> {
    widgets::card(ui, |ui| {
        widgets::card_title(ui, "Log file");
        let mut effect = None;
        ui.horizontal(|ui| {
            if widgets::toggle(ui, on, true).clicked() {
                effect = Some(log_request(!on));
            }
            ui.label("Write the node log to a file");
        });
        widgets::copyable(ui, &paths.log.display().to_string());
        widgets::caption(
            ui,
            "Useful when reporting a problem. The log lists the addresses of \
             peers and the ids of transactions, so it stays off unless you \
             switch it on. Logs over 10 MiB move to debug.log.1 at start.",
        );
        effect
    })
}

/// A request to switch the log file on or off.
fn log_request(enabled: bool) -> Effect {
    Effect::Submit(Action::SetLogFile(enabled))
}

fn storage(ui: &mut Ui, paths: &Paths) {
    egui::CollapsingHeader::new("Storage and configuration").show(ui, |ui| {
        for (label, path) in [
            ("Data directory", &paths.data),
            ("Configuration", &paths.config),
            ("Wallet", &paths.wallet),
            ("Log file", &paths.log),
        ] {
            widgets::field_label(ui, label, None);
            widgets::copyable(ui, &path.display().to_string());
        }
        widgets::caption(
            ui,
            "Changes to null.conf take effect after restarting the app.",
        );
    });
}

fn peer_count(node: &Value) -> usize {
    field(node, "peers").as_array().map_or(0, Vec::len)
}

/// One-line node health, most urgent condition first.
fn health(node: &Value, peers: usize) -> (Tone, &'static str) {
    if field(node, "syncing").as_bool() == Some(true) {
        (Tone::Warning, "Synchronizing chain…")
    } else if peers == 0 {
        (
            Tone::Warning,
            "Waiting for peers. Add a peer in null.conf and restart to connect.",
        )
    } else {
        (Tone::Success, "Node is running and connected to peers.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn health_reports_syncing_before_missing_peers() {
        assert_eq!(health(&json!({ "syncing": true }), 0).0, Tone::Warning);
        assert!(health(&json!({}), 0).1.contains("peers"));
        assert_eq!(health(&json!({ "syncing": false }), 2).0, Tone::Success);
    }

    #[test]
    fn the_log_switch_requests_the_new_state() {
        for enabled in [true, false] {
            let Effect::Submit(Action::SetLogFile(asked)) = log_request(enabled) else {
                panic!("not a log request");
            };
            assert_eq!(asked, enabled);
        }
    }

    #[test]
    fn peer_count_is_zero_when_unreported() {
        assert_eq!(peer_count(&json!({ "peers": [{}, {}] })), 2);
        assert_eq!(peer_count(&json!({})), 0);
    }
}
