//! Native desktop entry point. The GUI owns the main thread; a Tokio runtime
//! runs the node, wallet, and RPC on worker threads in this same process.
// Release builds on Windows are GUI programs: without this, Windows opens an
// empty console window beside the app. Debug builds keep it for logs.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod ui;

use clap::Parser;
use null_desktop::backend::Backend;
use null_desktop::config::{Args, Startup};

/// Longest wait at exit for background work still running after shutdown.
const EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let startup = Startup::load(&Args::parse())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let backend = {
        let _guard = runtime.enter();
        Backend::spawn(startup.backend)
    };
    #[cfg(target_os = "linux")]
    install_desktop_entry();
    let client = backend.client.clone();
    let snapshots = backend.snapshots.clone();
    let options = eframe::NativeOptions {
        viewport: with_icon(
            eframe::egui::ViewportBuilder::default()
                .with_title("NULL Wallet")
                .with_app_id(null_desktop::desktop_entry::APP_ID)
                .with_inner_size([1000.0, 720.0])
                .with_min_inner_size([760.0, 580.0]),
        ),
        ..eframe::NativeOptions::default()
    };
    let gui = eframe::run_native(
        "NULL Wallet",
        options,
        Box::new(move |cc| {
            Ok(Box::new(ui::App::new(
                cc,
                client,
                snapshots,
                startup.paths,
                startup.lock_after,
            )))
        }),
    );
    // This also runs after a graphics initialization error. Dropping the
    // runtime then cancels any remaining node networking tasks.
    let shutdown = runtime.block_on(backend.shutdown());
    // The wallet and node have stopped cleanly by now. What may remain is a
    // miner finishing one proof-of-work solve, which is safe to abandon, so
    // closing the window never waits on it.
    runtime.shutdown_timeout(EXIT_GRACE);
    gui?;
    shutdown?;
    Ok(())
}

/// Installs the app menu entry that Wayland compositors read the taskbar
/// icon from. A failure only costs the icon, so it is logged, not fatal.
#[cfg(target_os = "linux")]
fn install_desktop_entry() {
    if let Err(error) = null_desktop::desktop_entry::install_for_user(ui::brand::ICON_PNG) {
        null_node::logging::warn(&format!("desktop entry not installed: {error}"));
    }
}

/// Adds the brand icon for the window, taskbar, and task switcher.
fn with_icon(viewport: eframe::egui::ViewportBuilder) -> eframe::egui::ViewportBuilder {
    match ui::brand::window_icon() {
        Some(icon) => viewport.with_icon(icon),
        None => viewport,
    }
}
