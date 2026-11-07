//! The backup page: shows the recovery phrase again after the passphrase is
//! entered, or stores the phrase in a wallet file created before phrases
//! were kept so it can be shown from then on.

use eframe::egui::Ui;
use null_desktop::backend::{Action, Snapshot};
use null_wallet::seed::WORD_COUNT;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use super::backup::word_grid;
use super::setup::{blank_words, joined_phrase, spread_pasted, word_inputs};
use super::Effect;
use crate::ui::theme::{self, Tone};
use crate::ui::widgets;

/// What the wallet file can do with its recovery phrase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kept {
    /// The phrase is stored and can be shown.
    Stored,
    /// No phrase is stored yet; the user can attach it.
    Missing,
    /// A watch-only wallet: it has no phrase at all.
    WatchOnly,
    /// The first snapshot since unlocking has not arrived.
    Unknown,
}

impl Kept {
    fn of(state: &Snapshot) -> Self {
        let flag = |name| {
            state
                .wallet
                .as_ref()
                .and_then(|info| info.get(name))
                .and_then(Value::as_bool)
        };
        match (flag("watch_only"), flag("seed_phrase_stored")) {
            (Some(true), _) => Self::WatchOnly,
            (_, Some(true)) => Self::Stored,
            (_, Some(false)) => Self::Missing,
            (_, None) => Self::Unknown,
        }
    }
}

/// Inputs and the shown phrase. Every buffer zeroizes on drop, and the
/// shell clears the form on lock and when the user leaves the page.
pub struct Form {
    passphrase: Zeroizing<String>,
    /// One input per word for attaching the phrase.
    words: Vec<Zeroizing<String>>,
    /// The revealed phrase and its seed account, until hidden.
    shown: Option<(Zeroizing<String>, u32)>,
    /// Whether a reveal was asked for on this page and not answered yet.
    /// Clearing the form drops it, so an answer arriving after the user
    /// left the page is discarded instead of shown later.
    awaiting: bool,
}

impl Default for Form {
    fn default() -> Self {
        Self {
            passphrase: Zeroizing::default(),
            words: blank_words(),
            shown: None,
            awaiting: false,
        }
    }
}

impl Form {
    /// Draws the page for an unlocked wallet.
    pub fn show(&mut self, ui: &mut Ui, state: &Snapshot) -> Option<Effect> {
        ui.set_max_width(theme::CONTENT_WIDTH);
        if self.shown.is_some() {
            self.display(ui);
            return None;
        }
        match Kept::of(state) {
            Kept::Stored => self.prompt(ui),
            Kept::Missing => self.attach(ui),
            Kept::WatchOnly => {
                message(
                    ui,
                    "This is a watch-only wallet. It holds a viewing key, not a recovery phrase.",
                );
                None
            }
            Kept::Unknown => {
                message(ui, "Loading wallet details…");
                None
            }
        }
    }

    /// Takes a phrase the backend revealed, unless the request was given
    /// up by leaving the page or locking; the phrase is then erased.
    pub fn revealed(&mut self, phrase: Option<Zeroizing<String>>, account: Option<u32>) {
        self.passphrase.zeroize();
        if std::mem::take(&mut self.awaiting) {
            self.shown = phrase.map(|phrase| (phrase, account.unwrap_or_default()));
        }
    }

    /// Forgets the inputs and any shown phrase.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    fn display(&mut self, ui: &mut Ui) {
        let Some((phrase, account)) = &self.shown else {
            return;
        };
        let mut hide = false;
        widgets::page(
            ui,
            "Your recovery phrase",
            "These words, in this order, restore this wallet on any computer.",
            |ui| {
                widgets::notice(
                    ui,
                    Tone::Warning,
                    "Anyone with these words can spend your funds. Make sure no one can see \
                     your screen, and never store them online.",
                );
                if let Some(warning) = account_warning(*account) {
                    widgets::notice(ui, Tone::Warning, &warning);
                }
                widgets::card(ui, |ui| {
                    word_grid(ui, phrase);
                    ui.add_space(theme::SPACE_SM);
                    widgets::key_value(ui, "Account", &account.to_string());
                });
                hide = widgets::primary_button(ui, "Hide phrase", true).clicked();
            },
        );
        if hide {
            self.shown = None;
        }
    }

    fn prompt(&mut self, ui: &mut Ui) -> Option<Effect> {
        widgets::page(
            ui,
            "Recovery phrase",
            "Show the words that restore this wallet, to check or redo your backup.",
            |ui| {
                widgets::card(ui, |ui| {
                    widgets::field_label(
                        ui,
                        "Wallet passphrase",
                        Some("Asked again because the phrase gives full control of your funds."),
                    );
                    let entered =
                        widgets::secret_input(ui, &mut self.passphrase, "reveal-passphrase", true);
                    ui.add_space(theme::SPACE_MD);
                    let ready = !self.passphrase.is_empty();
                    let clicked =
                        widgets::primary_button(ui, "Show recovery phrase", ready).clicked();
                    ((clicked || entered) && ready).then(|| self.request_reveal())
                })
            },
        )
    }

    fn attach(&mut self, ui: &mut Ui) -> Option<Effect> {
        widgets::page(
            ui,
            "Recovery phrase",
            "Store your recovery phrase in this wallet so it can be shown again.",
            |ui| {
                widgets::notice(
                    ui,
                    Tone::Info,
                    "This wallet was created before NULL kept recovery phrases, so it has none \
                     to show yet. Type the words you wrote down: they are checked against this \
                     wallet before anything is stored.",
                );
                widgets::card(ui, |ui| {
                    widgets::field_label(
                        ui,
                        "Recovery phrase",
                        Some("One word per box, or paste the whole phrase into the first box."),
                    );
                    word_inputs(ui, &mut self.words);
                    spread_pasted(&mut self.words);
                    ui.add_space(theme::SPACE_MD);
                    widgets::primary_button(ui, "Store recovery phrase", true)
                        .clicked()
                        .then(|| self.submit_words())
                })
            },
        )
    }

    fn request_reveal(&mut self) -> Effect {
        self.awaiting = true;
        Effect::Reveal(std::mem::take(&mut self.passphrase))
    }

    fn submit_words(&mut self) -> Effect {
        let Some(phrase) = joined_phrase(&self.words) else {
            return Effect::Notify(format!("Enter all {WORD_COUNT} recovery words"));
        };
        self.words.iter_mut().for_each(Zeroize::zeroize);
        Effect::Submit(Action::AttachSeed { phrase })
    }
}

/// How to restore a phrase whose account is not the desktop's: importing
/// it here would restore account 0, which is a different wallet.
fn account_warning(account: u32) -> Option<String> {
    (account != 0).then(|| {
        format!(
            "This wallet uses account {account} of this phrase. Importing the words in this \
             app restores account 0, a different wallet with other funds. Restore it with \
             nulld create --phrase --account {account} --wallet <file>, and note the account \
             number with your backup."
        )
    })
}

/// A page holding a single line of explanation.
fn message(ui: &mut Ui, text: &str) {
    widgets::page(ui, "Recovery phrase", "", |ui| widgets::caption(ui, text));
}

#[cfg(test)]
mod tests {
    use eframe::egui;
    use serde_json::json;

    use super::*;

    fn unlocked(info: Value) -> Snapshot {
        Snapshot {
            ready: true,
            wallet: Some(info),
            ..Snapshot::default()
        }
    }

    fn render(form: &mut Form, state: &Snapshot) -> Option<Effect> {
        let ctx = egui::Context::default();
        let mut effect = None;
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| effect = form.show(ui, state));
        });
        effect
    }

    #[test]
    fn the_page_follows_what_the_wallet_keeps() {
        let cases = [
            (json!({ "seed_phrase_stored": true }), Kept::Stored),
            (json!({ "seed_phrase_stored": false }), Kept::Missing),
            (
                json!({ "seed_phrase_stored": false, "watch_only": true }),
                Kept::WatchOnly,
            ),
            (json!({}), Kept::Unknown),
        ];
        for (info, kept) in cases {
            let state = unlocked(info);
            assert_eq!(Kept::of(&state), kept);
            assert!(render(&mut Form::default(), &state).is_none());
        }
    }

    #[test]
    fn a_revealed_phrase_shows_until_cleared_and_the_passphrase_is_erased() {
        let mut form = Form {
            passphrase: Zeroizing::new("pw".into()),
            ..Form::default()
        };
        let Effect::Reveal(passphrase) = form.request_reveal() else {
            panic!("expected a reveal");
        };
        assert_eq!(&*passphrase, "pw");
        form.revealed(Some(Zeroizing::new("word ".repeat(24))), Some(0));
        assert!(form.passphrase.is_empty());
        assert!(render(&mut form, &unlocked(json!({}))).is_none());
        assert!(form.shown.is_some());
        form.clear();
        assert!(form.shown.is_none());
    }

    #[test]
    fn a_reveal_answered_after_leaving_the_page_is_discarded() {
        let mut form = Form {
            passphrase: Zeroizing::new("pw".into()),
            ..Form::default()
        };
        let _ = form.request_reveal();
        form.clear();
        form.revealed(Some(Zeroizing::new("word ".repeat(24))), Some(0));
        assert!(form.shown.is_none(), "left before the answer");
        form.revealed(Some(Zeroizing::new("word ".repeat(24))), Some(0));
        assert!(form.shown.is_none(), "never asked");
    }

    #[test]
    fn another_account_is_shown_with_how_to_restore_it() {
        assert!(account_warning(0).is_none());
        let warning = account_warning(7).unwrap();
        assert!(warning.contains("--account 7"), "{warning}");
        let mut form = Form::default();
        let _ = form.request_reveal();
        form.revealed(Some(Zeroizing::new("word ".repeat(24))), Some(7));
        assert_eq!(form.shown.as_ref().map(|(_, account)| *account), Some(7));
        assert!(render(&mut form, &unlocked(json!({}))).is_none());
    }

    #[test]
    fn attaching_needs_every_word_and_erases_the_inputs() {
        let mut form = Form::default();
        assert!(matches!(form.submit_words(), Effect::Notify(_)));
        for word in &mut form.words {
            *word = Zeroizing::new("abandon".into());
        }
        let Effect::Submit(Action::AttachSeed { phrase }) = form.submit_words() else {
            panic!("expected an attach action");
        };
        assert_eq!(phrase.split(' ').count(), WORD_COUNT);
        assert!(form.words.iter().all(|word| word.is_empty()));
    }
}
