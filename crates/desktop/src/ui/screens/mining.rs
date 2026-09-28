//! The built-in miner's switch, threads, and results, shown on the Node
//! page. Mining needs an unlocked wallet and always pays its main address.

use eframe::egui::{self, Ui};
use null_desktop::backend::{Action, Snapshot};
use null_desktop::config::Mining;
use serde_json::Value;

use super::Effect;
use crate::ui::format::{field, number, text};
use crate::ui::theme::{self, Tone};
use crate::ui::widgets;

/// A thread count picked on the slider but not yet applied.
#[derive(Default)]
pub struct Form {
    threads: Option<usize>,
}

impl Form {
    /// Requests `enabled` with the picked thread count, else the saved one.
    fn apply(&mut self, enabled: bool, saved: usize) -> Effect {
        request(enabled, self.threads.take().unwrap_or(saved))
    }

    /// Draws the mining card.
    pub fn show(&mut self, ui: &mut Ui, state: &Snapshot) -> Option<Effect> {
        let mining = &state.mining;
        let unlocked = state.wallet.is_some();
        let active = field(mining, "active").as_bool() == Some(true);
        let saved = saved_threads(mining);
        let max = usize_field(mining, "max_threads").unwrap_or(1).max(1);
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                widgets::card_title(ui, "Mining");
                let (label, tone) = status(unlocked, active);
                widgets::badge(ui, label, tone);
            });
            if !unlocked {
                widgets::caption(
                    ui,
                    "Unlock your wallet to mine. Rewards go to its main address.",
                );
            }
            let mut effect = None;
            ui.horizontal(|ui| {
                if widgets::toggle(ui, active, unlocked).clicked() {
                    effect = Some(self.apply(!active, saved));
                }
                ui.label("Mine new blocks with this computer");
            });
            let mut threads = self.threads.unwrap_or(saved);
            let slider = ui.add_enabled(
                unlocked,
                egui::Slider::new(&mut threads, 1..=max).text(format!("of {max} CPU threads")),
            );
            if slider.changed() {
                self.threads = Some(threads);
            }
            // A running miner takes a new count when the drag ends, or at
            // once for clicks and keys; a stopped one uses it when switched on.
            let released = slider.drag_stopped() || (slider.changed() && !slider.dragged());
            if released && active {
                effect = Some(self.apply(true, saved));
            }
            ui.add_space(theme::SPACE_SM);
            results(ui, mining, active);
            effect
        })
    }
}

/// A request to set the miner's state and threads.
fn request(enabled: bool, threads: usize) -> Effect {
    Effect::Submit(Action::SetMining(Mining { enabled, threads }))
}

/// The badge for the miner's state.
fn status(unlocked: bool, active: bool) -> (&'static str, Tone) {
    match (unlocked, active) {
        (false, _) => ("Locked", Tone::Neutral),
        (true, true) => ("Mining", Tone::Success),
        (true, false) => ("Off", Tone::Neutral),
    }
}

/// The saved thread count, at least one.
fn saved_threads(mining: &Value) -> usize {
    usize_field(mining, "threads").unwrap_or(1).max(1)
}

fn usize_field(value: &Value, key: &str) -> Option<usize> {
    field(value, key)
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
}

fn results(ui: &mut Ui, mining: &Value, active: bool) {
    if active {
        widgets::field_label(ui, "Paying to your main address", None);
        widgets::hash(ui, text(mining, "payout"));
    }
    widgets::key_value(ui, "Blocks found this session", &number(mining, "found"));
    widgets::key_value(
        ui,
        "Of those in the main chain",
        &number(mining, "in_chain"),
    );
    widgets::caption(
        ui,
        "Starting builds the proving key first, which takes a few seconds. Locking the \
         wallet stops mining; it resumes on the next unlock.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn switching_sends_the_new_state_with_the_chosen_threads() {
        let Effect::Submit(Action::SetMining(mining)) = request(true, 3) else {
            panic!("expected a mining action");
        };
        assert_eq!(
            mining,
            Mining {
                enabled: true,
                threads: 3
            }
        );
    }

    #[test]
    fn a_picked_thread_count_is_used_once_then_the_saved_one_again() {
        let mut form = Form { threads: Some(6) };
        let Effect::Submit(Action::SetMining(first)) = form.apply(true, 2) else {
            panic!("expected a mining action");
        };
        assert_eq!(first.threads, 6);
        let Effect::Submit(Action::SetMining(second)) = form.apply(false, 2) else {
            panic!("expected a mining action");
        };
        assert_eq!((second.enabled, second.threads), (false, 2));
    }

    #[test]
    fn the_badge_follows_lock_and_miner_state() {
        assert_eq!(status(false, true).0, "Locked");
        assert_eq!(status(true, true), ("Mining", Tone::Success));
        assert_eq!(status(true, false).0, "Off");
    }

    #[test]
    fn missing_or_zero_threads_read_as_one() {
        assert_eq!(saved_threads(&json!({ "threads": 4 })), 4);
        for mining in [
            json!({}),
            json!({ "threads": 0 }),
            json!({ "threads": "x" }),
        ] {
            assert_eq!(saved_threads(&mining), 1);
        }
    }
}
