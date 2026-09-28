//! One module per screen.
//!
//! Every screen follows the same shape: a `show` function draws it from a
//! read-only [`Snapshot`](null_desktop::backend::Snapshot), plus the
//! screen's own form state when it has inputs, and returns an [`Effect`]
//! instead of touching the backend. The app shell performs the effect and
//! routes a call's result back as its [`Reply`] says. Screens build their
//! layout from `ui::widgets` and never style egui widgets or name colors
//! directly.

pub mod activity;
pub mod backup;
pub mod node;
pub mod overview;
pub mod receive;
pub mod send;
pub mod setup;

use null_desktop::backend::Action;
use serde_json::Value;

/// What a screen asks the app shell to do after drawing.
pub enum Effect {
    /// Queue a wallet open or lock and show the backend's message.
    Submit(Action),
    /// Invoke a node or wallet method and handle its result.
    Call(Call),
    /// Show a message in the status bar; an empty message clears it.
    Notify(String),
}

/// A node or wallet method invocation requested by a screen.
pub struct Call {
    /// RPC method name.
    pub method: &'static str,
    /// Positional or named parameters.
    pub params: Value,
    /// What to do with the result.
    pub reply: Reply,
}

impl Call {
    /// A call whose success is reported as `notice`.
    pub fn notice(method: &'static str, params: Value, notice: &'static str) -> Effect {
        Effect::Call(Self {
            method,
            params,
            reply: Reply::Notice(notice),
        })
    }
}

/// Where the shell sends a call's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Show this message on success, or the error on failure.
    Notice(&'static str),
    /// Hand the result or error to the send form as a fee quote.
    Quote,
}

impl From<Call> for Action {
    fn from(call: Call) -> Self {
        Action::Call {
            method: call.method.into(),
            params: call.params,
        }
    }
}
