//! Helpers shared by the node integration tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use null_node::config::Network;
use null_node::node::{Handle, Request, Response};
use null_protocol::maturity::earlier_origin;
use null_wallet::wallet::Wallet;

/// The test network's coinbase maturity: a node's first reward, mined at
/// height 1, is spendable from this height on.
pub fn first_spendable_height() -> u32 {
    Network::Test.params().coinbase_maturity + 1
}

/// Scans `node`'s chain from genesis to `to` into `wallet`, in tree order,
/// fetching each maturing coinbase as a full-block wallet does.
pub async fn scan_chain(node: &Handle, wallet: &Wallet, to: u32) {
    let maturity = Network::Test.params().coinbase_maturity;
    for h in 0..=to {
        let Response::Block(Some(block)) = node.request(Request::Block(h)).await.unwrap() else {
            panic!("block {h}")
        };
        let earlier = match earlier_origin(h, maturity) {
            Some(origin) => match node.request(Request::Coinbase(origin)).await.unwrap() {
                Response::Coinbase(Some(coinbase)) => Some(*coinbase),
                other => panic!("coinbase {origin}: {other:?}"),
            },
            None => None,
        };
        wallet.scan(&block, maturity, earlier.as_ref()).unwrap();
    }
}
