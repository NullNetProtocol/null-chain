//! Native desktop entry point. The GUI owns the main thread; a Tokio runtime
//! runs the node, wallet, and RPC on worker threads in this same process.
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
    let client = backend.client.clone();
    let snapshots = backend.snapshots.clone();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 720.0])
            .with_min_inner_size([760.0, 580.0]),
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
    gui?;
    shutdown?;
    Ok(())
}
