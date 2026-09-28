//! The `null-wallet-rpc` binary.

use clap::Parser;

#[tokio::main]
async fn main() {
    let args = null_node::walletd::Args::parse();
    if let Err(error) = null_node::walletd::main(args).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
