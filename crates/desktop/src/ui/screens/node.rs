//! Embedded node status, local RPC, and storage locations.

use eframe::egui::{self, Ui};
use null_desktop::backend::{Action, IncomingView, Snapshot};
use null_desktop::config::{Incoming, Paths};
use serde_json::Value;

use super::{mining, Effect};
use crate::ui::format::{field, local_time, number, text};
use crate::ui::theme::Tone;
use crate::ui::widgets;

/// Draws node status, the mining card, the incoming connection switches
/// and the log file switch, the page's only actions.
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
            let incoming_effect = state
                .incoming
                .and_then(|view| incoming(ui, view, &state.network));
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
            mining_effect.or(incoming_effect).or(log_effect)
        },
    )
}

/// The incoming connection switches and whether others reach this node.
fn incoming(ui: &mut Ui, view: IncomingView, network: &Value) -> Option<Effect> {
    widgets::card(ui, |ui| {
        widgets::card_title(ui, "Incoming connections");
        let saved = view.saved;
        let mut effect = None;
        ui.horizontal(|ui| {
            if widgets::toggle(ui, saved.enabled, true).clicked() {
                effect = Some(incoming_request(Incoming {
                    enabled: !saved.enabled,
                    ..saved
                }));
            }
            ui.label("Accept connections from other nodes");
        });
        ui.horizontal(|ui| {
            let usable = saved.enabled && !view.rules.proxied;
            if widgets::toggle(ui, saved.port_mapping && usable, usable).clicked() {
                effect = Some(incoming_request(Incoming {
                    port_mapping: !saved.port_mapping,
                    ..saved
                }));
            }
            ui.label("Open the port on my router automatically (UPnP, NAT-PMP, PCP)");
        });
        if let Some(pending) = pending(view) {
            widgets::caption(ui, pending);
        }
        let (tone, message) = reachability(view, network);
        widgets::notice(ui, tone, &message);
        if let Some(listening) = field(network, "listening").as_str() {
            widgets::field_label(ui, "Listening on", None);
            widgets::copyable(ui, listening);
        }
        widgets::caption(
            ui,
            "Other nodes can only find wallets that accept connections, so each one \
             that does makes the network less dependent on the project's seeds. A \
             reachable node's IP address is shared with other nodes, so anyone can \
             learn that it runs NULL. Your transactions are still relayed with \
             Dandelion++, so they are not tied to that address. Switch this off to \
             only connect out.",
        );
        effect
    })
}

/// A request to save new incoming connection switches.
fn incoming_request(incoming: Incoming) -> Effect {
    Effect::Submit(Action::SetIncoming(incoming))
}

/// Why the saved switches are not what runs, if a restart or the proxy
/// keeps them from it.
fn pending(view: IncomingView) -> Option<&'static str> {
    if view.needs_restart() {
        Some("Restart the app to apply these settings.")
    } else if view.held_off_by_proxy() {
        Some("Incoming connections stay off while peers are reached through a proxy.")
    } else {
        None
    }
}

/// Whether other nodes reach this one, most certain evidence first: a peer
/// from the internet connected in, then what the router said.
fn reachability(view: IncomingView, network: &Value) -> (Tone, String) {
    if !view.running.enabled {
        let reason = if view.rules.proxied {
            "Off while peers are reached through a proxy: a wallet behind Tor \
             does not reveal its address."
        } else {
            "Off: this wallet only connects out."
        };
        return (Tone::Neutral, reason.into());
    }
    if let Some(at) = field(network, "last_public_inbound").as_u64() {
        return (
            Tone::Success,
            format!(
                "Reachable: a node from the internet connected in at {}. {} incoming now.",
                local_time(at),
                number(network, "connections_in")
            ),
        );
    }
    let port = port_of(field(network, "listening").as_str());
    let mapping = field(network, "port_mapping");
    let manual = format!(
        "To accept connections, forward TCP port {port} on your router to this \
         computer and set advertise in null.conf to your public IP and that port."
    );
    match text(mapping, "state") {
        "searching" => (
            Tone::Info,
            format!("Asking your router to open port {port}…"),
        ),
        "mapped" => (
            Tone::Info,
            format!(
                "Your router opened {} ({}). Waiting for a node to connect in to confirm.",
                text(mapping, "external"),
                text(mapping, "protocol")
            ),
        ),
        "not_public" => (
            Tone::Warning,
            format!(
                "Your router opened the port, but its address {} is not public: your \
                 provider puts you behind another NAT, so other nodes cannot reach you.",
                text(mapping, "external")
            ),
        ),
        "failed" => (
            Tone::Warning,
            format!(
                "Your router did not open the port ({}). {manual}",
                text(mapping, "error")
            ),
        ),
        _ => match field(network, "announced").as_str() {
            Some(announced) => (
                Tone::Info,
                format!("Announcing {announced}. Waiting for a node to connect in to confirm."),
            ),
            None => (
                Tone::Warning,
                format!("Listening, but other nodes cannot find this one. {manual}"),
            ),
        },
    }
}

/// The port of a listening address such as `0.0.0.0:19000`.
fn port_of(listening: Option<&str>) -> String {
    listening
        .and_then(|l| l.parse::<std::net::SocketAddr>().ok())
        .map_or_else(
            || null_node::config::DEFAULT_P2P_PORT.to_string(),
            |l| l.port().to_string(),
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
    use null_desktop::config::IncomingRules;
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

    const ON: Incoming = Incoming {
        enabled: true,
        port_mapping: true,
    };
    const OFF: Incoming = Incoming {
        enabled: false,
        port_mapping: true,
    };

    fn view(saved: Incoming, running: Incoming, proxied: bool) -> IncomingView {
        IncomingView {
            saved,
            running,
            rules: IncomingRules {
                proxied,
                ..IncomingRules::default()
            },
        }
    }

    #[test]
    fn a_peer_connecting_in_is_shown_as_proof_of_reachability() {
        let network = json!({ "listening": "0.0.0.0:19000", "last_public_inbound": 1_700_000_000,
            "connections_in": 3, "port_mapping": { "state": "failed", "error": "x" } });
        let (tone, message) = reachability(view(ON, ON, false), &network);
        assert_eq!(tone, Tone::Success);
        assert!(message.contains("3 incoming"), "{message}");
    }

    #[test]
    fn router_answers_are_explained_until_someone_connects_in() {
        let on = view(ON, ON, false);
        let state = |mapping: Value| {
            reachability(
                on,
                &json!({ "listening": "0.0.0.0:19007", "port_mapping": mapping }),
            )
        };
        assert_eq!(state(json!({ "state": "searching" })).0, Tone::Info);
        let mapped =
            state(json!({ "state": "mapped", "protocol": "UPnP", "external": "8.8.8.8:19007" }));
        assert!(mapped.1.contains("8.8.8.8:19007") && mapped.1.contains("UPnP"));
        let cgnat = state(json!({ "state": "not_public", "external": "100.64.0.9:19007" }));
        assert_eq!(cgnat.0, Tone::Warning);
        let failed = state(json!({ "state": "failed", "error": "no router answered" }));
        assert_eq!(failed.0, Tone::Warning);
        assert!(failed.1.contains("port 19007") && failed.1.contains("no router"));
        let manual = reachability(
            on,
            &json!({ "listening": "0.0.0.0:19000",
            "port_mapping": { "state": "off" }, "announced": "1.2.3.4:19000" }),
        );
        assert!(manual.1.contains("1.2.3.4:19000"));
        let hidden = reachability(on, &json!({ "port_mapping": { "state": "off" } }));
        assert!(hidden.1.contains("forward TCP port 19000"));
    }

    #[test]
    fn a_node_that_does_not_listen_says_why() {
        assert!(reachability(view(OFF, OFF, false), &json!({}))
            .1
            .contains("only connects out"));
        assert!(reachability(view(ON, OFF, true), &json!({}))
            .1
            .contains("proxy"));
    }

    #[test]
    fn changed_switches_ask_for_a_restart_unless_a_proxy_overrides_them() {
        assert_eq!(pending(view(ON, ON, false)), None);
        assert!(pending(view(OFF, ON, false)).unwrap().contains("Restart"));
        let nothing = Incoming {
            enabled: false,
            port_mapping: false,
        };
        assert!(pending(view(ON, nothing, true)).unwrap().contains("proxy"));
        // Off with the router switch still saved on is what runs.
        assert_eq!(pending(view(OFF, nothing, false)), None);
    }

    #[test]
    fn the_incoming_switches_request_what_they_show() {
        let Effect::Submit(Action::SetIncoming(asked)) = incoming_request(OFF) else {
            panic!("not an incoming request");
        };
        assert_eq!(asked, OFF);
    }

    #[test]
    fn peer_count_is_zero_when_unreported() {
        assert_eq!(peer_count(&json!({ "peers": [{}, {}] })), 2);
        assert_eq!(peer_count(&json!({})), 0);
    }
}
