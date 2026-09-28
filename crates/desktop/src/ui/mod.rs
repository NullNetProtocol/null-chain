//! Wallet screens. All backend work is asynchronous.
//!
//! Layout: [`theme`] holds every design token, [`widgets`] the building
//! blocks made from them, and [`screens`] one module per page. This module
//! is the shell: navigation, status bar, routing, and performing the
//! [`Effect`]s screens return.

pub mod brand;
mod format;
mod icons;
mod idle;
mod screens;
mod theme;
mod widgets;

use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Frame, Layout, Margin, RichText, Stroke, Ui};
use null_desktop::backend::{Action, Client, Outcome, Snapshot};
use null_desktop::config::Paths;
use screens::{Effect, Reply};
use tokio::sync::{oneshot, watch};
use zeroize::Zeroizing;

use format::text;
use icons::Icon;
use idle::IdleLock;
use screens::backup::Backup;
use theme::Tone;

/// How often to redraw while waiting for backend snapshots.
const REPAINT_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Receive,
    Send,
    Activity,
    Node,
}

impl Page {
    /// Sidebar order, titles, and icons.
    const ALL: [(Self, &'static str, Icon); 5] = [
        (Self::Overview, "Overview", Icon::Overview),
        (Self::Receive, "Receive", Icon::Receive),
        (Self::Send, "Send", Icon::Send),
        (Self::Activity, "Activity", Icon::Activity),
        (Self::Node, "Node", Icon::Node),
    ];
}

/// Screen state that exists without a backend connection.
#[derive(Default)]
struct Screens {
    setup: screens::setup::Form,
    receive: screens::receive::Form,
    send: screens::send::Form,
}

/// A backend request in flight and where its result goes; `None` shows
/// the backend's own message.
struct Pending {
    reply: oneshot::Receiver<Result<Outcome, String>>,
    route: Option<Reply>,
}

pub struct App {
    client: Client,
    snapshots: watch::Receiver<Snapshot>,
    pending: Option<Pending>,
    page: Page,
    paths: Paths,
    screens: Screens,
    /// A new recovery phrase and its backup check, until the check passes.
    seed: Option<(Zeroizing<String>, Backup)>,
    idle: IdleLock,
    message: String,
}

impl App {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        client: Client,
        snapshots: watch::Receiver<Snapshot>,
        paths: Paths,
        lock_after: Option<Duration>,
    ) -> Self {
        theme::apply(&cc.egui_ctx);
        Self {
            client,
            snapshots,
            pending: None,
            page: Page::Overview,
            paths,
            screens: Screens::default(),
            seed: None,
            idle: IdleLock::new(lock_after, Instant::now()),
            message: String::new(),
        }
    }

    fn perform(&mut self, effect: Effect) {
        match effect {
            Effect::Submit(action) => self.submit(action, None),
            Effect::Call(call) => {
                let route = Some(call.reply);
                self.submit(call.into(), route);
            }
            Effect::Notify(message) => self.message = message,
        }
    }

    fn submit(&mut self, action: Action, route: Option<Reply>) {
        match self.client.submit(action) {
            Ok(reply) => {
                self.pending = Some(Pending { reply, route });
                self.message = "Working…".into();
            }
            Err(error) => self.finish(route, Err(error)),
        }
    }

    fn poll(&mut self) {
        let Some(pending) = &mut self.pending else {
            return;
        };
        let result = match pending.reply.try_recv() {
            Ok(result) => result,
            Err(oneshot::error::TryRecvError::Empty) => return,
            Err(oneshot::error::TryRecvError::Closed) => Err("Backend stopped".into()),
        };
        let route = pending.route;
        self.pending = None;
        self.finish(route, result);
    }

    /// Delivers a finished request to the screen that asked for it.
    fn finish(&mut self, route: Option<Reply>, result: Result<Outcome, String>) {
        if route == Some(Reply::Quote) {
            self.screens.send.quoted(
                result
                    .as_ref()
                    .map(|o| o.value.clone())
                    .map_err(Clone::clone),
            );
        }
        self.message = match (route, result) {
            (_, Err(error)) => error,
            (Some(Reply::Notice(notice)), Ok(_)) => notice.into(),
            (Some(Reply::Quote), Ok(_)) => String::new(),
            (None, Ok(outcome)) => {
                if let Some(phrase) = outcome.phrase {
                    let words = phrase.split_whitespace().count();
                    let backup = Backup::new(words, &mut rand::rngs::OsRng);
                    self.seed = Some((phrase, backup));
                }
                outcome.message
            }
        };
    }

    /// Locks the wallet, forgetting any payment awaiting confirmation.
    /// `notice` replaces the backend's message when the lock completes.
    fn lock(&mut self, notice: Option<&'static str>) {
        self.screens.send.discard_review();
        self.submit(Action::Lock, notice.map(Reply::Notice));
    }

    /// Records input and locks an unlocked wallet left idle too long.
    fn check_idle(&mut self, ctx: &egui::Context, state: &Snapshot) {
        let now = Instant::now();
        if ctx.input(|i| !i.events.is_empty() || i.pointer.is_moving()) {
            self.idle.touch(now);
        }
        if self.can_lock(state) && self.idle.expired(now) {
            self.idle.touch(now);
            self.lock(Some("Wallet locked after a period without activity"));
        }
    }

    /// Whether locking now would interrupt nothing the user is looking at.
    fn can_lock(&self, state: &Snapshot) -> bool {
        state.wallet.is_some() && self.pending.is_none() && self.seed.is_none()
    }

    fn sidebar(&mut self, ctx: &egui::Context, state: &Snapshot) {
        egui::SidePanel::left("navigation")
            .exact_width(theme::SIDEBAR_WIDTH)
            .resizable(false)
            .frame(chrome_frame(Margin::same(16)))
            .show(ctx, |ui| {
                brand(ui);
                for (page, title, icon) in Page::ALL {
                    if widgets::nav_item(ui, icon, title, self.page == page).clicked() {
                        self.page = page;
                    }
                    ui.add_space(theme::SPACE_XS);
                }
                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    self.wallet_status(ui, state);
                });
            });
    }

    fn wallet_status(&mut self, ui: &mut Ui, state: &Snapshot) {
        if self.can_lock(state) && widgets::secondary_button(ui, "Lock wallet", true).clicked() {
            self.lock(None);
        }
        let (label, tone) = if state.wallet.is_some() {
            ("Unlocked", Tone::Success)
        } else if state.wallet_present {
            ("Locked", Tone::Neutral)
        } else {
            ("No wallet", Tone::Warning)
        };
        widgets::badge(ui, label, tone);
        // The network is unknown until the node has started.
        let network = text(&state.node, "network");
        if network != format::MISSING {
            widgets::badge(ui, network, Tone::Info);
        }
    }

    fn status_bar(&self, ctx: &egui::Context, state: &Snapshot) {
        egui::TopBottomPanel::bottom("status")
            .frame(chrome_frame(Margin::symmetric(16, 8)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if !state.ready || self.pending.is_some() {
                        ui.spinner();
                    }
                    widgets::caption(
                        ui,
                        if state.ready {
                            &self.message
                        } else if state.error.is_some() {
                            "Backend unavailable"
                        } else {
                            "Starting embedded node…"
                        },
                    );
                });
                if let Some(error) = &state.error {
                    ui.label(RichText::new(error).color(Tone::Danger.color()));
                }
            });
    }

    fn content(&mut self, ui: &mut Ui, state: &Snapshot) -> Option<Effect> {
        if let Some((phrase, backup)) = &mut self.seed {
            if backup.show(ui, phrase) {
                self.seed = None;
                return Some(Effect::Notify("Recovery phrase confirmed".into()));
            }
            return None;
        }
        route(self.page, &mut self.screens, ui, state, &self.paths)
    }
}

/// Draws the page for the current wallet state; locked wallets see setup.
fn route(
    page: Page,
    screens: &mut Screens,
    ui: &mut Ui,
    state: &Snapshot,
    paths: &Paths,
) -> Option<Effect> {
    if page == Page::Node {
        screens::node::show(ui, state, paths);
        return None;
    }
    if state.wallet.is_none() {
        return screens.setup.show(ui, state.wallet_present);
    }
    match page {
        Page::Overview => screens::overview::show(ui, state),
        Page::Activity => return screens::activity::show(ui, state),
        Page::Receive => return screens.receive.show(ui, state),
        Page::Send => return screens.send.show(ui, state),
        Page::Node => {}
    }
    None
}

/// Width of the logo in the sidebar.
const SIDEBAR_LOGO_WIDTH: f32 = 128.0;
/// Extra spacing between tagline letters, as in the brand banner.
const TAGLINE_LETTER_SPACING: f32 = 2.0;

fn brand(ui: &mut Ui) {
    ui.add_space(theme::SPACE_SM);
    ui.horizontal(|ui| {
        ui.add_space(theme::SPACE_SM);
        ui.vertical(|ui| {
            brand::logo(ui, SIDEBAR_LOGO_WIDTH);
            ui.add_space(theme::SPACE_XS);
            ui.label(
                RichText::new("PRIVACY BY DEFAULT")
                    .size(theme::SMALL_SIZE - 2.0)
                    .extra_letter_spacing(TAGLINE_LETTER_SPACING)
                    .color(theme::TEXT_MUTED),
            );
        });
    });
    ui.add_space(theme::SPACE_XL);
}

/// Background for the sidebar and status bar.
fn chrome_frame(margin: Margin) -> Frame {
    Frame::new()
        .fill(theme::CHROME)
        .stroke(Stroke::new(theme::LINE_WIDTH, theme::BORDER))
        .inner_margin(margin)
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        let state = self.snapshots.borrow().clone();
        self.check_idle(ctx, &state);
        self.sidebar(ctx, &state);
        self.status_bar(ctx, &state);
        let effect = egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(theme::BACKGROUND)
                    .inner_margin(theme::page_margin()),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        let enabled = state.ready && self.pending.is_none();
                        ui.add_enabled_ui(enabled, |ui| self.content(ui, &state))
                            .inner
                    })
                    .inner
            })
            .inner;
        if let Some(effect) = effect {
            self.perform(effect);
        }
        ctx.request_repaint_after(REPAINT_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn paths() -> Paths {
        Paths {
            data: PathBuf::from("/data"),
            config: PathBuf::from("/data/null.conf"),
            wallet: PathBuf::from("/data/test/wallet.redb"),
        }
    }

    fn populated() -> Snapshot {
        Snapshot {
            ready: true,
            rpc: Some("127.0.0.1:18448".parse().unwrap()),
            node: json!({ "network": "test", "height": 120, "syncing": false,
                "peers": [{}], "best_block_hash": "ab".repeat(32) }),
            wallet_present: true,
            wallet: Some(json!({ "synced": false, "scanned_height": 60,
                "pending_operations": 1, "last_error": "prover busy" })),
            balance: json!({ "spendable": "150000000", "total": "250000000" }),
            addresses: json!([{ "label": "", "index": 0, "address": "null1xyz" }]),
            operations: json!([
                { "operation_id": 3, "total": "100", "status": "failed",
                  "txid": "cd".repeat(32), "error": "rejected" },
                { "operation_id": 4, "total": "7", "status": "queued", "cancellable": true },
            ]),
            received: json!([{ "amount": "5", "confirmations": 0, "memo": "thanks" }]),
            error: None,
        }
    }

    /// Renders every page headlessly and returns any effect it produced.
    fn render_all(state: &Snapshot) -> Vec<bool> {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut screens = Screens::default();
        let mut produced = Vec::new();
        for (page, _, _) in Page::ALL {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    produced.push(route(page, &mut screens, ui, state, &paths()).is_some());
                });
            });
        }
        produced
    }

    #[test]
    fn every_page_renders_without_input_or_effects() {
        let locked = Snapshot {
            ready: true,
            ..Snapshot::default()
        };
        for state in [Snapshot::default(), locked, populated()] {
            assert_eq!(render_all(&state), vec![false; Page::ALL.len()]);
        }
    }

    #[test]
    fn recovery_phrase_backup_renders_without_being_dismissed() {
        let ctx = egui::Context::default();
        let mut dismissed = true;
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut backup = Backup::new(24, &mut rand::rngs::OsRng);
                dismissed = backup.show(ui, &"word ".repeat(24));
            });
        });
        assert!(!dismissed);
    }
}
