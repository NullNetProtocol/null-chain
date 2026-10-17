//! First run, import, unlock, and the one-time recovery phrase backup.

use eframe::egui::{self, Ui};
use null_desktop::backend::{Action, OpenMode};
use null_wallet::seed::WORD_COUNT;
use zeroize::{Zeroize, Zeroizing};

use super::Effect;
use crate::ui::{brand, theme};

/// Side of the NULL mark above the welcome choices.
const WELCOME_MARK_SIZE: f32 = 72.0;
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
    /// One input per recovery word, so positions cannot be confused.
    restore: Vec<Zeroizing<String>>,
}

impl Default for Form {
    fn default() -> Self {
        Self {
            mode: Mode::Welcome,
            passphrase: Zeroizing::new(String::new()),
            confirmation: Zeroizing::new(String::new()),
            restore: blank_words(),
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
        // The word grid needs room for four columns.
        ui.set_max_width(if self.restoring(wallet_present) {
            theme::CONTENT_WIDTH
        } else {
            theme::NARROW_WIDTH
        });
        widgets::page(ui, title, subtitle, |ui| {
            widgets::card(ui, |ui| self.fields(ui, wallet_present))
        })
    }

    fn restoring(&self, wallet_present: bool) -> bool {
        !wallet_present && self.mode == Mode::Restore
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
        brand::mark(ui, WELCOME_MARK_SIZE);
        ui.add_space(theme::SPACE_LG);
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
        if self.restoring(wallet_present) {
            widgets::field_label(
                ui,
                "Recovery phrase",
                Some("Type one word per box in their original order, or paste the whole phrase into the first box."),
            );
            word_inputs(ui, &mut self.restore);
            spread_pasted(&mut self.restore);
            ui.add_space(theme::SPACE_SM);
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
        let mode = if self.restoring(wallet_present) {
            let Some(phrase) = joined_phrase(&self.restore) else {
                return Effect::Notify(format!("Enter all {WORD_COUNT} recovery words"));
            };
            OpenMode::Restore(phrase)
        } else if wallet_present {
            OpenMode::Existing
        } else {
            OpenMode::Create
        };
        self.restore.iter_mut().for_each(Zeroize::zeroize);
        self.confirmation.zeroize();
        let passphrase = std::mem::take(&mut self.passphrase);
        Effect::Submit(Action::Open { passphrase, mode })
    }

    fn back(&mut self) -> Effect {
        self.mode = Mode::Welcome;
        self.passphrase.zeroize();
        self.confirmation.zeroize();
        self.restore.iter_mut().for_each(Zeroize::zeroize);
        Effect::Notify(String::new())
    }
}

/// One empty input per recovery word.
fn blank_words() -> Vec<Zeroizing<String>> {
    (0..WORD_COUNT).map(|_| Zeroizing::default()).collect()
}

/// Draws the numbered word inputs, [`theme::WORDS_PER_ROW`] to a row.
fn word_inputs(ui: &mut Ui, words: &mut [Zeroizing<String>]) {
    egui::Grid::new("restore-words")
        .num_columns(theme::WORDS_PER_ROW)
        .spacing(egui::vec2(theme::SPACE_MD, theme::SPACE_SM))
        .show(ui, |ui| {
            for (index, word) in words.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    widgets::word_number(ui, index);
                    widgets::word_input(ui, word, &format!("restore-{index}"));
                });
                if index.saturating_add(1) % theme::WORDS_PER_ROW == 0 {
                    ui.end_row();
                }
            }
        });
}

/// Moves the words of an input holding several (a pasted phrase) into it
/// and the inputs after it, one each; words beyond the last are dropped.
fn spread_pasted(words: &mut [Zeroizing<String>]) {
    let Some(start) = words
        .iter()
        .position(|word| word.split_whitespace().nth(1).is_some())
    else {
        return;
    };
    let pasted = words
        .get_mut(start)
        .map(|word| std::mem::take(&mut **word))
        .map(Zeroizing::new)
        .unwrap_or_default();
    for (slot, word) in words.iter_mut().skip(start).zip(pasted.split_whitespace()) {
        slot.zeroize();
        slot.push_str(word);
    }
}

/// The phrase as single-spaced lowercase words, or `None` while any input
/// is blank.
fn joined_phrase(words: &[Zeroizing<String>]) -> Option<Zeroizing<String>> {
    let mut phrase = Zeroizing::new(String::new());
    for word in words {
        let word = Zeroizing::new(word.trim().to_lowercase());
        if word.is_empty() {
            return None;
        }
        if !phrase.is_empty() {
            phrase.push(' ');
        }
        phrase.push_str(&word);
    }
    Some(phrase)
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
            restore: words("abandon ability"),
        }
    }

    /// A full grid holding `phrase`'s words first and filler after.
    fn words(phrase: &str) -> Vec<Zeroizing<String>> {
        let mut grid = blank_words();
        for (slot, word) in grid
            .iter_mut()
            .zip(phrase.split_whitespace().chain(std::iter::repeat("zoo")))
        {
            **slot = word.into();
        }
        grid
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
        assert!(
            matches!(mode, OpenMode::Restore(words) if words.starts_with("abandon ability zoo"))
        );
        assert!(form.passphrase.is_empty());
        assert!(form.confirmation.is_empty());
        assert!(form.restore.iter().all(|word| word.is_empty()));
    }

    #[test]
    fn the_form_has_one_input_per_recovery_word() {
        assert_eq!(Form::default().restore.len(), WORD_COUNT);
    }

    #[test]
    fn importing_needs_every_word_and_keeps_the_input_otherwise() {
        let mut form = filled(Mode::Restore, "pass", "pass");
        *form.restore[7] = "  ".into();
        assert!(matches!(form.submit(false), Effect::Notify(_)));
        assert_eq!(*form.restore[0], "abandon");
        assert_eq!(*form.passphrase, "pass");
    }

    #[test]
    fn words_are_trimmed_lowercased_and_single_spaced() {
        let mut grid = words("");
        *grid[0] = " Abandon\t".into();
        let phrase = joined_phrase(&grid).unwrap();
        assert!(phrase.starts_with("abandon zoo "));
        assert_eq!(phrase.split(' ').count(), WORD_COUNT);
    }

    #[test]
    fn a_pasted_phrase_fills_the_following_inputs() {
        let mut grid = blank_words();
        *grid[0] = "zebra".into();
        *grid[1] = " alpha  bravo\ncharlie ".into();
        spread_pasted(&mut grid);
        let filled: Vec<&str> = grid.iter().take(5).map(|w| w.as_str()).collect();
        assert_eq!(filled, ["zebra", "alpha", "bravo", "charlie", ""]);
    }

    #[test]
    fn pasting_more_words_than_inputs_drops_the_excess() {
        let mut grid = blank_words();
        let long = vec!["word"; WORD_COUNT + 3].join(" ");
        *grid[WORD_COUNT - 2] = long;
        spread_pasted(&mut grid);
        assert_eq!(*grid[WORD_COUNT - 1], "word");
        assert!(grid[..WORD_COUNT - 2].iter().all(|w| w.is_empty()));
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
        assert!(form.passphrase.is_empty() && form.confirmation.is_empty());
        assert!(form.restore.iter().all(|word| word.is_empty()));
    }
}
