//! The `nulld` binary.

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = null_node::cli::Cli::parse();
    if let Err(error) = null_node::cli::run(cli).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
