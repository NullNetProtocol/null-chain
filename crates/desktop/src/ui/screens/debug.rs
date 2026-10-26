//! In-memory RPC console for the embedded node and current wallet.

use std::collections::VecDeque;

use eframe::egui::{self, Key, Ui};
use null_desktop::backend::Snapshot;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{Call, Effect, Reply};
use crate::ui::theme::{self, Tone};
use crate::ui::widgets;

const MAX_ENTRIES: usize = 100;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

struct Entry {
    command: Zeroizing<String>,
    output: Zeroizing<String>,
    error: bool,
}

/// Console contents are never persisted and are erased when cleared or locked.
#[derive(Default)]
pub struct Form {
    input: Zeroizing<String>,
    entries: VecDeque<Entry>,
    cursor: Option<usize>,
    draft: Zeroizing<String>,
    focus_input: bool,
    completion: Completion,
}

#[derive(Default)]
struct Completion {
    selected: usize,
    dismissed: bool,
}

impl Form {
    /// Draws the console, including when the wallet is locked.
    pub fn show(&mut self, ui: &mut Ui, state: &Snapshot, busy: bool) -> Option<Effect> {
        let can_run = state.ready && !busy;
        widgets::page(ui, "Debug", "Run node and wallet RPC commands.", |ui| {
            widgets::notice(
                ui,
                Tone::Warning,
                "Commands run immediately and can send funds or expose private wallet data. \
                 Only run commands you understand.",
            );
            if state.wallet.is_none() {
                widgets::caption(ui, "Wallet locked. Node commands are still available.");
            }
            widgets::caption(
                ui,
                "Enter a method followed by arguments, a JSON parameter array, or a JSON object. \
                 Use double quotes for text containing spaces. Type a command to see suggestions.",
            );
            syntax_help(ui);
            widgets::card(ui, |ui| {
                widgets::card_title(ui, "Console");
                egui::ScrollArea::vertical()
                    .id_salt("debug-transcript")
                    .max_height(theme::CONSOLE_HEIGHT)
                    .min_scrolled_height(theme::CONSOLE_HEIGHT)
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.entries.is_empty() {
                            widgets::caption(ui, "Type help to list available commands.");
                        }
                        for (index, entry) in self.entries.iter().enumerate() {
                            ui.push_id(index, |ui| {
                                widgets::console_text(ui, &format!("> {}", *entry.command), false);
                                widgets::console_text(ui, &entry.output, entry.error);
                                ui.add_space(theme::SPACE_SM);
                            });
                        }
                    });
                widgets::field_label(ui, "Command", None);
                let (response, enter) = self.command_input(ui, can_run);
                widgets::caption(ui, "Up/Down selects · Tab/Enter completes · Esc dismisses. Without suggestions, Up/Down recalls history.");
                let mut effect = None;
                ui.horizontal(|ui| {
                    if widgets::primary_button(ui, "Run", can_run && !self.input.trim().is_empty())
                        .clicked()
                        || enter
                    {
                        effect = self.execute();
                        if !response.has_focus() {
                            response.request_focus();
                        }
                    }
                    if widgets::secondary_button(ui, "Help", can_run).clicked() {
                        self.input = Zeroizing::new("help".into());
                        effect = self.execute();
                        response.request_focus();
                    }
                    if widgets::secondary_button(ui, "Clear", !busy).clicked() {
                        self.clear();
                        response.request_focus();
                    }
                });
                widgets::caption(
                    ui,
                    "The last 100 commands are kept in memory only. Clear or lock the wallet \
                     to erase the transcript and history. Large results are truncated.",
                );
                effect
            })
        })
    }

    /// Completion consumes Enter before it can submit a command.
    fn command_input(&mut self, ui: &mut Ui, can_run: bool) -> (egui::Response, bool) {
        let response = widgets::console_input(ui, &mut self.input);
        if self.focus_input && ui.is_enabled() {
            if !response.has_focus() {
                response.request_focus();
            }
            self.focus_input = false;
        }
        if response.changed() {
            self.completion = Completion::default();
        }
        let matches = matching_methods(&self.input);
        let visible = response.has_focus() && !self.completion.dismissed && !matches.is_empty();
        let mut accepted = None;
        let mut navigated = false;
        if response.has_focus() {
            ui.memory_mut(|mem| {
                mem.set_focus_lock_filter(
                    response.id,
                    egui::EventFilter {
                        tab: visible,
                        horizontal_arrows: true,
                        vertical_arrows: true,
                        escape: visible,
                    },
                );
            });
            if visible {
                if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::Escape)) {
                    self.completion.dismissed = true;
                }
                for (key, older) in [(Key::ArrowUp, true), (Key::ArrowDown, false)] {
                    if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, key)) {
                        self.completion.selected = if older {
                            self.completion
                                .selected
                                .checked_sub(1)
                                .unwrap_or(matches.len().saturating_sub(1))
                        } else {
                            self.completion
                                .selected
                                .saturating_add(1)
                                .checked_rem(matches.len())
                                .unwrap_or(0)
                        };
                        navigated = true;
                    }
                }
                if !self.completion.dismissed
                    && ui.input_mut(|i| {
                        i.consume_key(egui::Modifiers::NONE, Key::Tab)
                            || i.consume_key(egui::Modifiers::NONE, Key::Enter)
                    })
                {
                    accepted = Some(self.completion.selected);
                }
            } else {
                for (key, older) in [(Key::ArrowUp, true), (Key::ArrowDown, false)] {
                    if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, key)) {
                        self.recall(older);
                        self.completion.dismissed = true;
                        widgets::console_cursor_end(ui, response.id, &self.input);
                    }
                }
            }
        }
        let clicked = widgets::console_suggestions(
            ui,
            &response,
            &matches,
            self.completion.selected,
            visible && !self.completion.dismissed && accepted.is_none(),
            navigated,
        );
        if let Some(method) = accepted.or(clicked).and_then(|index| matches.get(index)) {
            self.input = Zeroizing::new(format!("{method} "));
            self.completion.dismissed = true;
            widgets::console_cursor_end(ui, response.id, &self.input);
            if !response.has_focus() {
                response.request_focus();
            }
        }
        let run = !visible
            && can_run
            && response.has_focus()
            && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::Enter));
        (response, run)
    }

    fn execute(&mut self) -> Option<Effect> {
        let command = Zeroizing::new(self.input.trim().to_owned());
        self.input = Zeroizing::default();
        self.cursor = None;
        self.draft = Zeroizing::default();
        self.completion = Completion::default();
        if command.is_empty() {
            return None;
        }
        let parsed = parse(&command);
        let (output, error) = match &parsed {
            Ok(_) => ("Running…".into(), false),
            Err(error) => (error.clone(), true),
        };
        self.entries.push_back(Entry {
            command,
            output: Zeroizing::new(output),
            error,
        });
        if self.entries.len() > MAX_ENTRIES {
            self.entries.pop_front();
        }
        let (method, params) = parsed.ok()?;
        Some(Effect::Call(Call {
            method,
            params,
            reply: Reply::Debug,
        }))
    }

    /// Appends a completed RPC result or backend error to its command.
    pub fn finished(&mut self, result: Result<Value, String>) {
        self.focus_input = true;
        let Some(entry) = self.entries.back_mut() else {
            return;
        };
        let (text, error) = match result {
            Ok(value) => (
                serde_json::to_string_pretty(&value).unwrap_or_default(),
                false,
            ),
            Err(error) => (error, true),
        };
        entry.output = Zeroizing::new(text);
        if entry.output.len() > MAX_OUTPUT_BYTES {
            let mut end = MAX_OUTPUT_BYTES;
            while !entry.output.is_char_boundary(end) {
                end = end.saturating_sub(1);
            }
            // Replace rather than truncate so the discarded bytes are zeroized too.
            entry.output = Zeroizing::new(format!(
                "{}\n… Result truncated at 64 KiB; use external RPC for the full result.",
                entry.output.get(..end).unwrap_or_default()
            ));
        }
        entry.error = error;
    }

    fn recall(&mut self, older: bool) {
        if !older && self.cursor.is_none() {
            return;
        }
        let next = if older {
            if let Some(index) = self.cursor {
                Some(index.saturating_sub(1))
            } else {
                self.draft = self.input.clone();
                self.entries.len().checked_sub(1)
            }
        } else {
            self.cursor
                .map(|index| index.saturating_add(1))
                .filter(|index| *index < self.entries.len())
        };
        self.input = next
            .and_then(|index| self.entries.get(index))
            .map_or_else(|| self.draft.clone(), |entry| entry.command.clone());
        self.cursor = next;
    }

    /// Erases input, output, and recall history, also used by automatic locking.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Complete only the method token; argument text is never a search query.
fn matching_methods(input: &str) -> Vec<String> {
    let prefix = input.trim_start();
    if prefix.is_empty() || prefix.contains(char::is_whitespace) {
        return Vec::new();
    }
    let mut methods: Vec<String> = null_node::jsonrpc::METHODS
        .iter()
        .chain(null_node::walletd::METHODS)
        .map(|method| (*method).into())
        .collect();
    methods.extend(
        null_node::jsonrpc::METHODS
            .iter()
            .filter(|method| **method != "stop")
            .map(|method| format!("node.{method}")),
    );
    if methods.iter().any(|method| method == prefix) {
        return Vec::new();
    }
    methods.retain(|method| method.starts_with(prefix));
    methods.sort_unstable();
    methods.dedup();
    methods
}

fn syntax_help(ui: &mut Ui) {
    egui::CollapsingHeader::new("Examples and command syntax").show(ui, |ui| {
        widgets::console_text(
            ui,
            "help\ngetblockchaininfo\ngetblockhash 0\ngetblockhash [0]\n\
             getblockhash {\"height\":0}\ngetnewaddress \"Savings account\"\n\
             node.gettransaction <txid>",
            false,
        );
        widgets::caption(
            ui,
            "help lists node and wallet methods. Prefix with node. to select a node \
             method when names overlap. Amounts use the RPC's smallest units. \
             This console accepts RPC methods, not shell commands or nulld flags.",
        );
    });
}

/// RPC syntax only: a method followed by JSON params or individual arguments.
fn parse(command: &str) -> Result<(String, Value), String> {
    let command = command.trim();
    let split = command.find(char::is_whitespace).unwrap_or(command.len());
    let method = command.get(..split).unwrap_or_default();
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_'))
    {
        return Err("Enter an RPC method, for example getblockchaininfo or help.".into());
    }
    let mut rest = command.get(split..).unwrap_or_default().trim();
    if rest.starts_with(['[', '{']) {
        let params =
            serde_json::from_str(rest).map_err(|e| format!("Invalid JSON parameters: {e}"))?;
        return Ok((method.into(), params));
    }
    let mut params = Vec::new();
    while !rest.is_empty() {
        let (value, used) = if rest.starts_with(['"', '[', '{']) {
            let mut stream = serde_json::Deserializer::from_str(rest).into_iter::<Value>();
            let value = stream
                .next()
                .ok_or("Missing argument")?
                .map_err(|e| format!("Invalid JSON argument: {e}"))?;
            (value, stream.byte_offset())
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let token = rest.get(..end).unwrap_or_default();
            let value = serde_json::from_str(token).unwrap_or_else(|_| json!(token));
            (value, end)
        };
        params.push(value);
        rest = rest.get(used..).unwrap_or_default();
        if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
            return Err("Separate arguments with spaces.".into());
        }
        rest = rest.trim_start();
    }
    Ok((method.into(), Value::Array(params)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn accepts_rpc_syntax_and_preserves_json_types() {
        for (command, method, params) in [
            (" help ", "help", json!([])),
            ("getblockhash 0", "getblockhash", json!([0])),
            ("getblockhash [0]", "getblockhash", json!([0])),
            (
                "getblockhash {\"height\":0}",
                "getblockhash",
                json!({"height":0}),
            ),
            (
                "node.gettransaction abc",
                "node.gettransaction",
                json!(["abc"]),
            ),
            (
                "getnewaddress \"Savings account\"",
                "getnewaddress",
                json!(["Savings account"]),
            ),
            (
                "method null true 12 \"12\" [1, 2] {\"memo\":\"héllo\"}",
                "method",
                json!([null, true, 12, "12", [1, 2], {"memo":"héllo"}]),
            ),
            (
                "method \"quote: \\\" hi\"",
                "method",
                json!(["quote: \" hi"]),
            ),
        ] {
            assert_eq!(
                parse(command).unwrap(),
                (method.into(), params),
                "{command}"
            );
        }
    }

    #[test]
    fn rejects_malformed_json_and_shell_syntax() {
        for command in [
            "",
            "   ",
            "$(cmd)",
            "help;",
            "getblockhash [0",
            "method {} trailing",
            "method \"unfinished",
            "method \"one\"two",
            "method {invalid}",
        ] {
            assert!(parse(command).is_err(), "{command}");
        }
    }

    #[test]
    fn routes_results_errors_and_keeps_history_with_a_draft() {
        let mut form = Form {
            input: Zeroizing::new("getblockhash 0".into()),
            ..Form::default()
        };
        let Some(Effect::Call(call)) = form.execute() else {
            panic!("missing call")
        };
        assert_eq!(call.method, "getblockhash");
        assert_eq!(call.params, json!([0]));
        assert_eq!(call.reply, Reply::Debug);
        form.finished(Ok(json!({"height":0})));
        assert!(form.entries[0].output.contains("\"height\": 0"));
        form.input = Zeroizing::new("getbalance".into());
        let _ = form.execute();
        form.finished(Err("wallet is locked".into()));
        assert!(form.entries[1].error);
        assert_eq!(&*form.entries[1].output, "wallet is locked");
        form.input = Zeroizing::new("draft".into());
        form.recall(true);
        assert_eq!(&*form.input, "getbalance");
        form.recall(true);
        form.recall(true);
        assert_eq!(&*form.input, "getblockhash 0");
        form.recall(false);
        form.recall(false);
        assert_eq!(&*form.input, "draft");
        form.clear();
        assert!(form.entries.is_empty() && form.input.is_empty() && form.draft.is_empty());
        assert!(form.cursor.is_none());
    }

    #[test]
    fn bounds_history_and_unicode_output_and_reports_parse_errors_locally() {
        let mut form = Form::default();
        for _ in 0..=MAX_ENTRIES {
            form.input = Zeroizing::new("help".into());
            let _ = form.execute();
        }
        assert_eq!(form.entries.len(), MAX_ENTRIES);
        form.finished(Ok(json!("界".repeat(MAX_OUTPUT_BYTES))));
        let entry = form.entries.back().unwrap();
        assert!(entry.output.contains("Result truncated"));
        assert!(entry.output.len() < MAX_OUTPUT_BYTES + 128);
        form.input = Zeroizing::new("getblockhash [".into());
        assert!(form.execute().is_none());
        assert!(form.entries.back().unwrap().error);
    }

    fn frame(ctx: &egui::Context, form: &mut Form, key: Option<Key>, busy: bool) -> Option<Effect> {
        let mut effect = None;
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 1000.0),
            )),
            events: key
                .map(|key| egui::Event::Key {
                    key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                })
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let _ = ctx.run(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                effect = form.show(
                    ui,
                    &Snapshot {
                        ready: true,
                        ..Snapshot::default()
                    },
                    busy,
                );
            });
        });
        effect
    }

    #[test]
    fn keyboard_runs_commands_and_recalls_history_while_requests_are_serialized() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut form = Form {
            input: Zeroizing::new("getblockhash 0".into()),
            focus_input: true,
            ..Form::default()
        };
        assert!(frame(&ctx, &mut form, None, false).is_none());
        let Some(Effect::Call(call)) = frame(&ctx, &mut form, Some(Key::Enter), false) else {
            panic!("Enter must run the focused command");
        };
        assert_eq!(call.method, "getblockhash");
        assert!(frame(&ctx, &mut form, Some(Key::Enter), true).is_none());
        form.finished(Ok(json!("block hash")));
        assert!(frame(&ctx, &mut form, None, false).is_none());
        form.input = Zeroizing::new("draft".into());
        let _ = frame(&ctx, &mut form, Some(Key::ArrowUp), false);
        assert_eq!(&*form.input, "getblockhash 0");
        assert_eq!(form.cursor, Some(0));
        assert_eq!(&*form.draft, "draft");
        let _ = frame(&ctx, &mut form, Some(Key::ArrowDown), false);
        assert_eq!(form.cursor, None);
        assert_eq!(&*form.input, "draft");
    }

    #[test]
    fn suggestions_use_rpc_methods_and_leave_arguments_and_exact_commands_alone() {
        let matches = matching_methods("getblockc");
        assert_eq!(matches, ["getblockchaininfo", "getblockcount"]);
        assert_eq!(matching_methods("node.getpeer"), ["node.getpeerinfo"]);
        let methods = matching_methods("g");
        assert!(methods.contains(&"getwalletinfo".into()));
        assert_eq!(
            methods
                .iter()
                .filter(|m| m.as_str() == "gettransaction")
                .count(),
            1
        );
        for input in [
            "",
            "  ",
            "getblock",
            "getblockhash ",
            "getblockhash 0",
            "getnewaddress secret",
            "node.st",
        ] {
            assert!(matching_methods(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn suggestions_complete_with_enter_or_tab_and_never_submit_on_selection() {
        for accept_key in [Key::Enter, Key::Tab] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut form = Form {
                input: Zeroizing::new("getblockc".into()),
                focus_input: true,
                ..Form::default()
            };
            let _ = frame(&ctx, &mut form, None, false);
            let _ = frame(&ctx, &mut form, None, false);
            assert!(frame(&ctx, &mut form, Some(Key::ArrowDown), false).is_none());
            assert_eq!(form.completion.selected, 1);
            assert!(frame(&ctx, &mut form, Some(accept_key), false).is_none());
            assert_eq!(&*form.input, "getblockcount ");
            assert!(form.entries.is_empty());
            let Some(Effect::Call(call)) = frame(&ctx, &mut form, Some(Key::Enter), false) else {
                panic!("A separate Enter must run the completed command");
            };
            assert_eq!(call.method, "getblockcount");
        }
    }

    #[test]
    fn escape_dismisses_suggestions_without_changing_the_input_or_running() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut form = Form {
            input: Zeroizing::new("getblockc".into()),
            focus_input: true,
            ..Form::default()
        };
        let _ = frame(&ctx, &mut form, None, false);
        let _ = frame(&ctx, &mut form, None, false);
        assert!(frame(&ctx, &mut form, Some(Key::Escape), false).is_none());
        assert!(form.completion.dismissed);
        assert_eq!(&*form.input, "getblockc");
        assert!(form.entries.is_empty());
    }
}
