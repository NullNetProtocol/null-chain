//! The public light-wallet listener: what mobile and browser wallets sync
//! from. JSON-RPC 2.0 over HTTP like [`crate::jsonrpc`], but with no token,
//! a fixed allowlist of read-only methods plus transaction submission, and
//! caps on every request (see [`policy`]). Off unless `--light-listen` is
//! given.
//!
//! A wallet needs the tip and the network's identity ([`getlightinfo`]),
//! block hashes to detect reorgs, compact blocks to find its notes and keep
//! its witness tree ([`null_protocol::compact`]), and a way to submit what
//! it built. Nothing here takes a key, an address or a nullifier: every
//! wallet asks for the same blocks, so the server learns a client's IP and
//! when it submits, never which notes are its own. That is also why
//! `getnullifierstatus` is not offered: asking about a nullifier reveals
//! the note behind it.
//!
//! [`getlightinfo`]: LIGHT_METHODS

use std::time::Duration;

use null_crypto::encoding::to_hex;
use null_p2p::message::PROTOCOL_VERSION;
use null_protocol::bytes::Encodable;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::Network;
use crate::jsonrpc::{serve_policy, unknown_method, Context, Dispatch, Params, Policy, RpcError};
use crate::node::{Event, Request, Response};

/// Every method the light listener answers.
pub const LIGHT_METHODS: &[&str] = &[
    "getlightinfo",
    "getblockhash",
    "getblockhashes",
    "getcompactblock",
    "getcompactblocks",
    "sendrawtransaction",
    "gettransactionstatus",
];

/// Most blocks one ranged call returns.
pub const MAX_RANGE: u32 = 100;
/// A ranged compact-block call stops adding blocks once its hex passes
/// this many bytes; it always returns at least one block, and a full block
/// is far smaller.
pub const MAX_RANGE_BYTES: usize = 4 * 1024 * 1024;
/// Largest request body: the largest transaction as hex, with room for
/// the JSON around it (see the test that checks it).
pub const MAX_LIGHT_BODY: usize = 256 * 1024;
/// Most calls in one batch, so a batch cannot multiply the range caps.
pub const MAX_LIGHT_BATCH: usize = 8;
/// Longest one connection may take, so slow clients cannot hold slots.
pub const LIGHT_DEADLINE: Duration = Duration::from_secs(30);
/// Connections served at once.
pub const MAX_LIGHT_CONNECTIONS: usize = 256;

/// The admission rules of the light listener.
pub fn policy() -> Policy {
    Policy {
        token: None,
        max_body: MAX_LIGHT_BODY,
        max_batch: MAX_LIGHT_BATCH,
        cors: true,
        deadline: Some(LIGHT_DEADLINE),
        max_connections: Some(MAX_LIGHT_CONNECTIONS),
    }
}

/// Serves the light methods forever.
pub async fn serve(listener: TcpListener, events: mpsc::Sender<Event>, network: Network) {
    serve_policy(listener, policy(), Light(Context::new(events, network))).await;
}

/// The light methods, over the node's context.
#[derive(Clone)]
pub struct Light(pub Context);

impl Dispatch for Light {
    async fn call(&self, method: &str, params: &Params) -> Result<Value, RpcError> {
        match method {
            "getlightinfo" => self.info().await,
            "getblockhashes" => self.hashes(params).await,
            "getcompactblocks" => self.compact_blocks(params).await,
            "getblockhash" | "getcompactblock" | "sendrawtransaction" | "gettransactionstatus" => {
                self.0.call(method, params).await
            }
            other => Err(unknown_method(other)),
        }
    }
}

impl Light {
    /// The tip and what identifies the chain, so a wallet can refuse a
    /// server on another network before scanning anything.
    async fn info(&self) -> Result<Value, RpcError> {
        let (height, hash, _, _, syncing) = self.0.tip().await?;
        let genesis = self.hash_at(0).await?.unwrap_or_default();
        let network = self.0.network();
        Ok(json!({
            "network": network.to_string(),
            "genesis": genesis,
            "height": height,
            "best_block_hash": hash.to_string(),
            "syncing": syncing,
            "coinbase_maturity": network.params().coinbase_maturity,
            "protocol_version": PROTOCOL_VERSION,
            "max_range": MAX_RANGE,
        }))
    }

    async fn hash_at(&self, height: u32) -> Result<Option<String>, RpcError> {
        match self.0.ask(Request::Hash(height)).await? {
            Response::Hash(hash) => Ok(hash.map(|h| h.to_string())),
            _ => Ok(None),
        }
    }

    /// Main-chain hashes from `start`, up to `count` and the tip.
    async fn hashes(&self, params: &Params) -> Result<Value, RpcError> {
        let mut hashes = Vec::new();
        for height in range(params)? {
            match self.hash_at(height).await? {
                Some(hash) => hashes.push(hash),
                None => break,
            }
        }
        Ok(json!(hashes))
    }

    /// Compact blocks as hex from `start`, up to `count`, the tip, or
    /// [`MAX_RANGE_BYTES`].
    async fn compact_blocks(&self, params: &Params) -> Result<Value, RpcError> {
        let mut blocks = Vec::new();
        let mut bytes = 0usize;
        for height in range(params)? {
            if bytes >= MAX_RANGE_BYTES {
                break;
            }
            let Response::Compact(Some(block)) = self.0.ask(Request::Compact(height)).await? else {
                break;
            };
            let hex = to_hex(&block.to_vec());
            bytes = bytes.saturating_add(hex.len());
            blocks.push(hex);
        }
        Ok(json!(blocks))
    }
}

/// The heights a ranged call asks for: `start` and `count`, with `count`
/// between 1 and [`MAX_RANGE`].
fn range(params: &Params) -> Result<core::ops::Range<u32>, RpcError> {
    let start: u32 = params.get(0, "start")?;
    let count: u32 = params.get(1, "count")?;
    if !(1..=MAX_RANGE).contains(&count) {
        return Err(RpcError::invalid_params(format!(
            "count must be between 1 and {MAX_RANGE}"
        )));
    }
    Ok(start..start.saturating_add(count))
}

#[cfg(test)]
mod tests {
    use null_protocol::action::ACTION_LEN;
    use null_protocol::consensus::{proof_len, MAX_ACTIONS};

    use super::*;
    use crate::jsonrpc::METHOD_NOT_FOUND;

    /// The encoded size of the largest transaction: version, anchor,
    /// action count, its actions, the proof and the binding signature.
    fn largest_transaction_len() -> usize {
        let actions = MAX_ACTIONS.checked_mul(ACTION_LEN).unwrap();
        [1, 32, 1, actions, proof_len(MAX_ACTIONS).unwrap(), 64]
            .iter()
            .sum()
    }

    #[test]
    fn the_largest_transaction_fits_the_body_limit_as_hex() {
        let hex = 2 * largest_transaction_len();
        assert!(hex + 1024 <= MAX_LIGHT_BODY, "{hex} hex bytes");
    }

    #[test]
    fn ranges_are_bounded() {
        let ok = range(&Params::new(json!([10, MAX_RANGE]))).unwrap();
        assert_eq!(ok, 10..10 + MAX_RANGE);
        assert_eq!(
            range(&Params::new(json!({ "start": 5, "count": 1 }))).unwrap(),
            5..6
        );
        for bad in [
            json!([0, 0]),
            json!([0, MAX_RANGE + 1]),
            json!([0]),
            json!([-1, 1]),
        ] {
            assert!(range(&Params::new(bad.clone())).is_err(), "{bad}");
        }
        assert_eq!(
            range(&Params::new(json!([u32::MAX, 2]))).unwrap(),
            u32::MAX..u32::MAX
        );
    }

    #[test]
    fn the_policy_is_public_and_bounded() {
        let policy = policy();
        assert!(policy.token.is_none());
        assert!(policy.cors);
        assert!(policy.deadline.is_some() && policy.max_connections.is_some());
        assert!(policy.max_batch * MAX_RANGE as usize <= 1000);
    }

    #[tokio::test]
    async fn only_the_allowlisted_methods_exist() {
        let (events, _rx) = mpsc::channel(1);
        let light = Light(Context::new(events, Network::Test));
        for method in [
            "stop",
            "getpeerinfo",
            "getnetworkinfo",
            "getblocktemplate",
            "submitblock",
            "getmininginfo",
            "getnullifierstatus",
            "getrawmempool",
            "getrawtransaction",
            "getblock",
            "help",
            "verifypaymentdisclosure",
            "createchallenge",
        ] {
            let error = light
                .call(method, &Params::new(json!([])))
                .await
                .unwrap_err();
            assert_eq!(error.code, METHOD_NOT_FOUND, "{method}");
            assert!(!LIGHT_METHODS.contains(&method));
        }
    }
}
