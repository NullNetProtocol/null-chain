//! Snapshot building and call routing, off the backend's command loop.
//!
//! Building a snapshot takes a dozen node and wallet calls. While the node
//! is syncing, each node call waits behind block imports, so one snapshot
//! can take seconds. Running it here, on its own task, keeps unlocking,
//! locking and console commands from queueing behind it.

use std::net::SocketAddr;
use std::path::PathBuf;

use null_node::config::Network;
use null_node::jsonrpc::{Context, Dispatch, Params, RpcError, REJECTED};
use null_node::node::{Request, Response};
use null_node::walletd::{self, WalletDaemon};
use null_node::Error;
use serde_json::{json, Value};
use tokio::task::{JoinError, JoinHandle};

use super::Snapshot;
use crate::block_times::{BlockFacts, BlockTimes, LOOKUPS_PER_REFRESH};
use crate::config;

/// The node and, while unlocked, the wallet: what a call or a snapshot
/// needs. Cloning shares the wallet daemon, which keeps the wallet open
/// until every clone is dropped.
#[derive(Clone)]
pub(super) struct Services {
    /// The embedded node's RPC methods.
    pub context: Context,
    /// The unlocked wallet's RPC methods.
    pub wallet: Option<WalletDaemon>,
}

impl Services {
    /// Routes a method to the wallet or the node. Wallet semantics win for
    /// overlapping names such as `gettransaction`; a `node.` prefix
    /// selects the node method.
    pub async fn call(
        &self,
        method: &str,
        params: &Params,
    ) -> std::result::Result<Value, RpcError> {
        if method == "stop" {
            return Err(RpcError::new(
                REJECTED,
                "stop is handled by the application lifecycle",
            ));
        }
        if let Some(method) = method.strip_prefix("node.") {
            if method == "stop" {
                return Err(RpcError::new(
                    REJECTED,
                    "use stop to shut down the whole application",
                ));
            }
            return self.context.call(method, params).await;
        }
        if method == "help" {
            return Ok(json!({ "node": self.context.call("help", params).await?,
                "wallet": walletd::METHODS, "node_prefix": "node." }));
        }
        if walletd::METHODS.contains(&method) {
            self.wallet
                .as_ref()
                .ok_or_else(|| RpcError::new(REJECTED, "wallet is locked"))?
                .call(method, params)
                .await
        } else {
            self.context.call(method, params).await
        }
    }
}

/// The miner as the command loop sees it; the node adds its counters.
pub(super) struct MiningView {
    /// The saved choice.
    pub enabled: bool,
    /// Whether the miner runs.
    pub active: bool,
    /// Worker threads, running or saved.
    pub threads: usize,
    /// The address the running miner pays.
    pub payout: Option<String>,
}

/// Everything one snapshot is built from.
pub(super) struct Inputs {
    /// Node and wallet calls.
    pub services: Services,
    /// The miner's state.
    pub mining: MiningView,
    /// The wallet file, to report whether it exists.
    pub wallet_path: PathBuf,
    /// The RPC listener's address.
    pub addr: SocketAddr,
    /// The network, for its constants.
    pub network: Network,
    /// Whether the log file is written.
    pub log_file: bool,
    /// Incoming connection switches, saved and running.
    pub incoming: super::IncomingView,
    /// Cached block facts, handed back with the snapshot.
    pub block_times: BlockTimes,
}

/// A finished snapshot and the block cache it updated.
pub(super) type Built = (std::result::Result<Snapshot, RpcError>, BlockTimes);

/// A snapshot being built on its own task.
pub(super) struct Refresh {
    /// The command loop's epoch when it started; a result from an older
    /// epoch predates a lock or unlock and is dropped.
    pub epoch: u64,
    /// The task building it.
    pub task: JoinHandle<Built>,
}

impl Refresh {
    /// Starts building a snapshot.
    pub fn spawn(epoch: u64, inputs: Inputs) -> Self {
        Self {
            epoch,
            task: tokio::spawn(inputs.build()),
        }
    }

    /// Stops the task and waits until it has dropped its wallet reference.
    /// It is cancelled at its next await; no wallet write happens in it.
    pub async fn cancel(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Fills the wallet's part of a snapshot. Every call reads the wallet file
/// only, so it answers at once even while the node is busy importing
/// blocks; received notes are left without block times.
pub(super) async fn wallet_fields(
    wallet: &WalletDaemon,
    snapshot: &mut Snapshot,
) -> std::result::Result<(), RpcError> {
    let params = Params::new(json!([]));
    snapshot.wallet = Some(wallet.call("getwalletinfo", &params).await?);
    snapshot.balance = wallet.call("getbalance", &params).await?;
    snapshot.addresses = wallet.call("listaddresses", &params).await?;
    snapshot.operations = wallet.call("listoperations", &params).await?;
    snapshot.received = wallet.call("listreceived", &params).await?;
    Ok(())
}

/// Waits for the running refresh, or forever if there is none, so it can
/// sit in a `select!` beside the command queue.
pub(super) async fn finished(
    refresh: &mut Option<Refresh>,
) -> (u64, std::result::Result<Built, JoinError>) {
    match refresh {
        Some(refresh) => (refresh.epoch, (&mut refresh.task).await),
        None => std::future::pending().await,
    }
}

impl Inputs {
    async fn build(mut self) -> Built {
        let snapshot = self.snapshot().await;
        (snapshot, self.block_times)
    }

    async fn snapshot(&mut self) -> std::result::Result<Snapshot, RpcError> {
        let params = Params::new(json!([]));
        let context = &self.services.context;
        let mut snapshot = Snapshot {
            ready: true,
            rpc: Some(self.addr),
            wallet_present: self.wallet_path.try_exists().map_err(Error::from)?,
            node: context.call("getblockchaininfo", &params).await?,
            log_file: self.log_file,
            incoming: Some(self.incoming),
            network: context.call("getnetworkinfo", &params).await?,
            ..Snapshot::default()
        };
        if let Some(info) = snapshot.node.as_object_mut() {
            info.insert("peers".into(), context.call("getpeerinfo", &params).await?);
        }
        snapshot.mining = self.mining_json().await?;
        if let Some(wallet) = self.services.wallet.clone() {
            wallet_fields(&wallet, &mut snapshot).await?;
            self.date_notes(&mut snapshot.received).await?;
        }
        Ok(snapshot)
    }

    /// Adds block times to received notes, reading blocks it has not cached
    /// yet and dropping cached ones a reorganization replaced.
    async fn date_notes(&mut self, notes: &mut Value) -> std::result::Result<(), RpcError> {
        let params = self.network.params();
        let context = &self.services.context;
        if let Response::Status { height, hash, .. } = context.ask(Request::Status).await? {
            for stale in self
                .block_times
                .follow_tip(hash, height, params.max_reorg_depth)
            {
                let current = match context.ask(Request::Hash(stale)).await? {
                    Response::Hash(hash) => hash,
                    _ => None,
                };
                if current != self.block_times.get(stale).map(|b| b.hash) {
                    self.block_times.remove(stale);
                }
            }
        }
        let maturity = params.coinbase_maturity;
        for height in self
            .block_times
            .missing(notes, maturity, LOOKUPS_PER_REFRESH)
        {
            if let Response::Block(Some(block)) = context.ask(Request::Block(height)).await? {
                self.block_times.insert(height, BlockFacts::from(&*block));
            }
        }
        self.block_times.annotate(notes, maturity);
        Ok(())
    }

    async fn mining_json(&self) -> std::result::Result<Value, RpcError> {
        let (found, in_chain, waits) = match self.services.context.ask(Request::Metrics).await? {
            Response::Metrics(m) => (m.blocks_mined, m.blocks_mined_in_chain, m.mining_waits),
            _ => (0, 0, None),
        };
        let mining = &self.mining;
        Ok(json!({
            "enabled": mining.enabled,
            "active": mining.active,
            "threads": mining.threads,
            "max_threads": config::max_mining_threads(),
            "payout": mining.payout,
            "found": found,
            "in_chain": in_chain,
            "waiting": waits.map(|reason| reason.to_string()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use null_node::node::Event;
    use tokio::sync::mpsc;

    use super::*;

    /// Services whose node never answers: calls that reach it would hang,
    /// so only the routing before them is exercised.
    fn offline() -> (Services, mpsc::Receiver<Event>) {
        let (events, receiver) = mpsc::channel(1);
        (
            Services {
                context: Context::new(events, Network::Test),
                wallet: None,
            },
            receiver,
        )
    }

    fn code(result: std::result::Result<Value, RpcError>) -> i64 {
        result.err().map_or(0, |error| error.code)
    }

    #[tokio::test]
    async fn stop_is_refused_and_wallet_methods_need_an_unlocked_wallet() {
        let (services, _node) = offline();
        let none = Params::new(json!([]));
        for method in ["stop", "node.stop", "getbalance", "getseedphrase"] {
            assert_eq!(
                code(services.call(method, &none).await),
                REJECTED,
                "{method}"
            );
        }
    }

    #[tokio::test]
    async fn a_cancelled_refresh_ends_without_answering() {
        let (services, _node) = offline();
        let refresh = Refresh::spawn(
            7,
            Inputs {
                services,
                mining: MiningView {
                    enabled: false,
                    active: false,
                    threads: 1,
                    payout: None,
                },
                wallet_path: PathBuf::from("missing.redb"),
                addr: "127.0.0.1:1".parse().unwrap(),
                network: Network::Test,
                log_file: false,
                incoming: super::super::IncomingView {
                    saved: config::Incoming {
                        enabled: false,
                        port_mapping: false,
                    },
                    running: config::Incoming {
                        enabled: false,
                        port_mapping: false,
                    },
                    rules: super::super::IncomingRules::default(),
                },
                block_times: BlockTimes::default(),
            },
        );
        assert_eq!(refresh.epoch, 7);
        tokio::time::timeout(std::time::Duration::from_secs(5), refresh.cancel())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn without_a_refresh_nothing_finishes() {
        let mut refresh = None;
        let waited =
            tokio::time::timeout(std::time::Duration::from_millis(20), finished(&mut refresh))
                .await;
        assert!(waited.is_err());
    }
}
