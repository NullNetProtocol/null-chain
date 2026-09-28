//! First run, import, unlock, and the one-time recovery phrase backup.

use eframe::egui::Ui;
use null_desktop::backend::{Action, OpenMode};
use zeroize::{Zeroize, Zeroizing};

use super::Effect;
use crate::ui::theme;
use crate::ui::widgets;

/// Which setup step is showing when no wallet exists yet.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Welcome,
    Create,
    Restore,
}

/// Passphrase and recovery phrase inputs. Every buffer zeroizes on drop.
pub struct Form {
    mode: Mode,
    passphrase: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    restore: Zeroizing<String>,
}

impl Default for Form {
    fn default() -> Self {
        Self {
            mode: Mode::Welcome,
            passphrase: Zeroizing::new(String::new()),
            confirmation: Zeroizing::new(String::new()),
            restore: Zeroizing::new(String::new()),
        }
    }
}

impl Form {
    /// Draws welcome, create, import, or unlock depending on wallet state.
    pub fn show(&mut self, ui: &mut Ui, wallet_present: bool) -> Option<Effect> {
        if !wallet_present && self.mode == Mode::Welcome {
            self.welcome(ui);
            return None;
        }
        let (title, subtitle) = self.heading(wallet_present);
        ui.set_max_width(theme::NARROW_WIDTH);
        widgets::page(ui, title, subtitle, |ui| {
            widgets::card(ui, |ui| self.fields(ui, wallet_present))
        })
    }

    fn heading(&self, wallet_present: bool) -> (&'static str, &'static str) {
        if wallet_present {
            (
                "Welcome back",
                "Enter your passphrase to unlock. The node keeps syncing while locked.",
            )
        } else if self.mode == Mode::Restore {
            (
                "Import your wallet",
                "Restore your addresses and funds from a recovery phrase.",
            )
        } else {
            (
                "Create your wallet",
                "Choose a passphrase to encrypt this wallet on your computer.",
            )
        }
    }

    fn welcome(&mut self, ui: &mut Ui) {
        widgets::page(
            ui,
            "Welcome to NULL",
            "Your private wallet and full node, together.",
            |ui| {
                ui.columns(2, |columns| {
                    let [create, restore] = columns else {
                        return;
                    };
                    if choice(
                        create,
                        "Create a new wallet",
                        "Generate a 24-word recovery phrase and back it up.",
                        "Create wallet",
                        true,
                    ) {
                        self.mode = Mode::Create;
                    }
                    if choice(
                        restore,
                        "Already have a wallet?",
                        "Use your recovery phrase to restore your addresses and funds.",
                        "Import recovery phrase",
                        false,
                    ) {
                        self.mode = Mode::Restore;
                    }
                });
            },
        );
    }

    fn fields(&mut self, ui: &mut Ui, wallet_present: bool) -> Option<Effect> {
        if !wallet_present && self.mode == Mode::Restore {
            widgets::field_label(
                ui,
                "Recovery phrase",
                Some("Enter your existing words in their original order."),
            );
            widgets::secret_input(ui, &mut self.restore, "restore", true);
        }
        widgets::field_label(ui, "Wallet passphrase", None);
        widgets::secret_input(ui, &mut self.passphrase, "passphrase", true);
        if !wallet_present {
            widgets::field_label(ui, "Confirm passphrase", None);
            widgets::secret_input(ui, &mut self.confirmation, "confirmation", true);
        }
        ui.add_space(theme::SPACE_MD);
        ui.horizontal(|ui| {
            if widgets::primary_button(ui, self.submit_label(wallet_present), true).clicked() {
                return Some(self.submit(wallet_present));
            }
            (!wallet_present && widgets::secondary_button(ui, "Back", true).clicked())
                .then(|| self.back())
        })
        .inner
    }

    fn submit_label(&self, wallet_present: bool) -> &'static str {
        if wallet_present {
            "Unlock wallet"
        } else if self.mode == Mode::Restore {
            "Import wallet"
        } else {
            "Generate recovery phrase"
        }
    }

    fn submit(&mut self, wallet_present: bool) -> Effect {
        if !wallet_present && (self.passphrase.is_empty() || *self.passphrase != *self.confirmation)
        {
            return Effect::Notify("Enter matching, non-empty passphrases".into());
        }
        let mode = if wallet_present {
            OpenMode::Existing
        } else {
            match self.mode {
                Mode::Restore => OpenMode::Restore(std::mem::take(&mut self.restore)),
                Mode::Welcome | Mode::Create => OpenMode::Create,
            }
        };
        self.restore.zeroize();
        self.confirmation.zeroize();
        let passphrase = std::mem::take(&mut self.passphrase);
        Effect::Submit(Action::Open { passphrase, mode })
    }

    fn back(&mut self) -> Effect {
        self.mode = Mode::Welcome;
        self.passphrase.zeroize();
        self.confirmation.zeroize();
        self.restore.zeroize();
        Effect::Notify(String::new())
    }
}

/// A card offering one way to start; returns whether it was chosen.
fn choice(ui: &mut Ui, title: &str, body: &str, button: &str, primary: bool) -> bool {
    widgets::card(ui, |ui| {
        widgets::card_title(ui, title);
        widgets::caption(ui, body);
        ui.add_space(theme::SPACE_MD);
        if primary {
            widgets::primary_button(ui, button, true).clicked()
        } else {
            widgets::secondary_button(ui, button, true).clicked()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(mode: Mode, passphrase: &str, confirmation: &str) -> Form {
        Form {
            mode,
            passphrase: Zeroizing::new(passphrase.into()),
            confirmation: Zeroizing::new(confirmation.into()),
            restore: Zeroizing::new("abandon ability".into()),
        }
    }

    #[test]
    fn new_wallets_need_matching_non_empty_passphrases() {
        for (a, b) in [("", ""), ("one", "two")] {
            let mut form = filled(Mode::Create, a, b);
            assert!(matches!(form.submit(false), Effect::Notify(_)));
            assert_eq!(*form.passphrase, a, "a rejected form keeps its input");
        }
    }

    #[test]
    fn submitting_moves_secrets_out_and_clears_the_form() {
        let mut form = filled(Mode::Restore, "pass", "pass");
        let Effect::Submit(Action::Open { passphrase, mode }) = form.submit(false) else {
            panic!("expected an open action");
        };
        assert_eq!(*passphrase, "pass");
        assert!(matches!(mode, OpenMode::Restore(words) if *words == "abandon ability"));
        assert!(form.passphrase.is_empty());
        assert!(form.confirmation.is_empty());
        assert!(form.restore.is_empty());
    }

    #[test]
    fn unlocking_needs_no_confirmation() {
        let mut form = filled(Mode::Welcome, "pass", "");
        let effect = form.submit(true);
        assert!(matches!(
            effect,
            Effect::Submit(Action::Open {
                mode: OpenMode::Existing,
                ..
            })
        ));
    }

    #[test]
    fn going_back_erases_every_input() {
        let mut form = filled(Mode::Restore, "pass", "pass");
        assert!(matches!(form.back(), Effect::Notify(message) if message.is_empty()));
        assert!(form.mode == Mode::Welcome);
        assert!(
            form.passphrase.is_empty() && form.confirmation.is_empty() && form.restore.is_empty()
        );
    }
}
