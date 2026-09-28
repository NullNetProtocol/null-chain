//! The one-time recovery phrase backup, and a check that it was written
//! down before the phrase is forgotten.

use eframe::egui::{self, RichText, Ui};
use rand::seq::index::sample;
use rand::Rng;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::ui::theme::{self, Tone};
use crate::ui::widgets;

/// Words the user must type back from their written copy.
const CHECKED_WORDS: usize = 3;

/// Words per row in the recovery phrase grid.
const WORDS_PER_ROW: usize = 4;

/// Backup progress for one newly generated phrase.
pub struct Backup {
    /// Zero-based positions to check, in ascending order.
    positions: Vec<usize>,
    /// The user's answers, one per position.
    answers: Vec<Zeroizing<String>>,
    verifying: bool,
    mismatch: bool,
}

impl Backup {
    /// Picks which words of a `words`-word phrase to check.
    pub fn new(words: usize, rng: &mut impl Rng) -> Self {
        let mut positions = sample(rng, words, CHECKED_WORDS.min(words)).into_vec();
        positions.sort_unstable();
        Self {
            answers: positions.iter().map(|_| Zeroizing::default()).collect(),
            positions,
            verifying: false,
            mismatch: false,
        }
    }

    /// Draws the phrase, then the check; returns true once it passes.
    pub fn show(&mut self, ui: &mut Ui, phrase: &str) -> bool {
        if self.verifying {
            self.verify(ui, phrase)
        } else {
            self.display(ui, phrase);
            false
        }
    }

    fn display(&mut self, ui: &mut Ui, phrase: &str) {
        widgets::page(
            ui,
            "Back up your recovery phrase",
            "Write these words down in order. They are shown once and restore your wallet.",
            |ui| {
                widgets::notice(
                    ui,
                    Tone::Warning,
                    "Anyone with these words can spend your funds. Never share them or \
                     store them online.",
                );
                widgets::card(ui, |ui| word_grid(ui, phrase));
                if widgets::primary_button(ui, "I have written it down", true).clicked() {
                    self.verifying = true;
                }
            },
        );
    }

    fn verify(&mut self, ui: &mut Ui, phrase: &str) -> bool {
        widgets::page(
            ui,
            "Check your backup",
            "Type these words from your written copy to confirm it is complete.",
            |ui| {
                if self.mismatch {
                    widgets::notice(
                        ui,
                        Tone::Danger,
                        "Those words do not match. Check your copy, or show the phrase again.",
                    );
                }
                widgets::card(ui, |ui| {
                    for (position, answer) in self.positions.iter().zip(&mut self.answers) {
                        widgets::field_label(
                            ui,
                            &format!("Word #{}", position.saturating_add(1)),
                            None,
                        );
                        widgets::secret_input(ui, answer, &format!("backup-{position}"), false);
                    }
                });
                let mut passed = false;
                ui.horizontal(|ui| {
                    if widgets::primary_button(ui, "Confirm backup", true).clicked() {
                        passed = self.matches(phrase);
                        self.mismatch = !passed;
                    }
                    if widgets::secondary_button(ui, "Show the phrase again", true).clicked() {
                        self.verifying = false;
                        self.mismatch = false;
                    }
                });
                passed
            },
        )
    }

    /// Whether every answer equals its word, ignoring case and surrounding
    /// space, compared in constant time.
    fn matches(&self, phrase: &str) -> bool {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let all = self.positions.iter().zip(&self.answers).fold(
            Choice::from(1),
            |ok, (position, answer)| {
                let typed = Zeroizing::new(answer.trim().to_lowercase());
                let expected = words.get(*position).copied().unwrap_or_default();
                ok & typed.as_bytes().ct_eq(expected.as_bytes())
            },
        );
        !self.positions.is_empty() && bool::from(all)
    }
}

fn word_grid(ui: &mut Ui, phrase: &str) {
    egui::Grid::new("recovery-phrase")
        .num_columns(WORDS_PER_ROW)
        .spacing(egui::vec2(theme::SPACE_LG, theme::SPACE_MD))
        .show(ui, |ui| {
            for (index, word) in phrase.split_whitespace().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(index.saturating_add(1).to_string())
                            .size(theme::SMALL_SIZE)
                            .color(theme::TEXT_MUTED),
                    );
                    ui.label(RichText::new(word).monospace().size(theme::TITLE_SIZE));
                });
                if index.saturating_add(1) % WORDS_PER_ROW == 0 {
                    ui.end_row();
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    const PHRASE: &str = "alpha bravo charlie delta echo foxtrot golf hotel";

    fn answered(backup: &mut Backup, answer: impl Fn(&str) -> String) {
        let words: Vec<&str> = PHRASE.split_whitespace().collect();
        for (position, slot) in backup.positions.iter().zip(&mut backup.answers) {
            *slot = Zeroizing::new(answer(words[*position]));
        }
    }

    #[test]
    fn three_distinct_positions_are_checked_in_order() {
        let backup = Backup::new(24, &mut ChaCha20Rng::seed_from_u64(5));
        assert_eq!(backup.positions.len(), CHECKED_WORDS);
        assert!(backup.positions.windows(2).all(|w| w[0] < w[1]));
        assert!(backup.positions.iter().all(|p| *p < 24));
        assert_eq!(backup.answers.len(), CHECKED_WORDS);
    }

    #[test]
    fn correct_words_pass_regardless_of_case_and_spacing() {
        let mut backup = Backup::new(8, &mut ChaCha20Rng::seed_from_u64(6));
        answered(&mut backup, |word| format!("  {}\t", word.to_uppercase()));
        assert!(backup.matches(PHRASE));
    }

    #[test]
    fn any_wrong_or_missing_word_fails() {
        let mut backup = Backup::new(8, &mut ChaCha20Rng::seed_from_u64(7));
        assert!(!backup.matches(PHRASE), "blank answers");
        answered(&mut backup, str::to_owned);
        backup.answers[1] = Zeroizing::new("zulu".into());
        assert!(!backup.matches(PHRASE));
        answered(&mut backup, |word| format!("{word}s"));
        assert!(!backup.matches(PHRASE), "a prefix is not a match");
    }

    #[test]
    fn a_short_phrase_checks_every_word_and_an_empty_one_never_passes() {
        let backup = Backup::new(2, &mut ChaCha20Rng::seed_from_u64(8));
        assert_eq!(backup.positions, vec![0, 1]);
        assert!(!Backup::new(0, &mut ChaCha20Rng::seed_from_u64(9)).matches(""));
    }
}
