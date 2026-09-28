//! Waiting for the operating system to ask a daemon to stop.
//!
//! Ctrl-C alone is not enough: service managers stop Unix daemons with
//! `SIGTERM`, and Windows closes console programs with close, logoff, and
//! shutdown events. Handlers are installed when [`Shutdown::listen`] is
//! called, so a request that arrives before anyone awaits it is not lost.

use crate::Result;

/// Installed stop-request handlers.
pub struct Shutdown {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
    #[cfg(windows)]
    ctrl_break: tokio::signal::windows::CtrlBreak,
    #[cfg(windows)]
    close: tokio::signal::windows::CtrlClose,
    #[cfg(windows)]
    logoff: tokio::signal::windows::CtrlLogoff,
    #[cfg(windows)]
    power_off: tokio::signal::windows::CtrlShutdown,
}

impl Shutdown {
    /// Installs the handlers. Must be called inside a Tokio runtime.
    ///
    /// # Errors
    /// Fails if the operating system refuses a handler.
    #[cfg(unix)]
    pub fn listen() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    /// Installs the handlers. Must be called inside a Tokio runtime.
    ///
    /// # Errors
    /// Fails if the operating system refuses a handler.
    #[cfg(windows)]
    pub fn listen() -> Result<Self> {
        use tokio::signal::windows;
        Ok(Self {
            ctrl_c: windows::ctrl_c()?,
            ctrl_break: windows::ctrl_break()?,
            close: windows::ctrl_close()?,
            logoff: windows::ctrl_logoff()?,
            power_off: windows::ctrl_shutdown()?,
        })
    }

    /// Resolves when a stop is requested.
    #[cfg(unix)]
    pub async fn requested(mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }

    /// Resolves when a stop is requested.
    #[cfg(windows)]
    pub async fn requested(mut self) {
        tokio::select! {
            _ = self.ctrl_c.recv() => {}
            _ = self.ctrl_break.recv() => {}
            _ = self.close.recv() => {}
            _ = self.logoff.recv() => {}
            _ = self.power_off.recv() => {}
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn sigterm_requests_a_graceful_stop() {
        let shutdown = Shutdown::listen().unwrap();
        let status = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        tokio::time::timeout(Duration::from_secs(10), shutdown.requested())
            .await
            .unwrap();
    }
}
