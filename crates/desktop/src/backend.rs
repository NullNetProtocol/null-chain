//! One owner for the embedded node, unlocked wallet, and RPC listener.
//!
//! GUI actions and HTTP calls enter the same bounded command queue. Only
//! this task owns the wallet service; locking waits for its worker to finish.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use null_chain::genesis::genesis;
use null_node::config::{Config as NodeConfig, Network};
use null_node::jsonrpc::{self, Context, Dispatch, Params, RpcError, REJECTED};
use null_node::miner::{self, Miner};
use null_node::node::{self, Request, Response};
use null_node::rpc::{Source, Token};
use null_node::walletd::{self, Service, ServiceConfig};
use null_node::{Error, Result};
use null_wallet::seed::SeedPhrase;
use null_wallet::wallet::Wallet;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::config::{self, Mining};

/// Desktop configuration; the node has no separate control socket.
pub struct Config {
    /// Embedded node settings.
    pub node: NodeConfig,
    /// Combined node/wallet RPC listener; must be loopback.
    pub rpc: SocketAddr,
    /// Token file for external clients. Never sent to the UI.
    pub token_file: PathBuf,
    /// Automatically selected wallet file, shared by create, import, and unlock.
    pub wallet: PathBuf,
    /// Saved mining settings; mining starts on unlock when enabled.
    pub mining: Mining,
    /// The configuration file the mining switch saves to.
    pub settings: PathBuf,
}

/// How to open a wallet.
pub enum OpenMode {
    /// Unlock an existing encrypted wallet.
    Existing,
    /// Generate a seed and create an encrypted wallet.
    Create,
    /// Restore a seed into a new encrypted wallet.
    Restore(Zeroizing<String>),
}

/// Commands available to the local GUI. Secrets are erased on drop.
pub enum Action {
    /// Open a wallet after creating or restoring it if requested.
    Open {
        /// Wallet file encryption passphrase.
        passphrase: Zeroizing<String>,
        /// Creation, restoration, or unlock.
        mode: OpenMode,
    },
    /// Finish the active payment pass and release wallet keys.
    Lock,
    /// Turn the built-in miner on or off, or change its threads. Mining
    /// needs an unlocked wallet and always pays its main (index 0) address.
    /// The choice is saved and resumes on the next unlock.
    SetMining(Mining),
    /// Invoke a method on the same services used by HTTP RPC.
    Call {
        /// RPC method name.
        method: String,
        /// Positional or named parameters.
        params: Value,
    },
}

/// A GUI command result. The seed is delivered once, outside shared snapshots.
pub struct Outcome {
    /// User-facing result.
    pub message: String,
    /// Newly generated recovery phrase, when creating a wallet.
    pub phrase: Option<Zeroizing<String>>,
    /// Result of an [`Action::Call`]; `null` for other actions.
    pub value: Value,
}

impl Outcome {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            phrase: None,
            value: Value::Null,
        }
    }
}

/// Read-only view of the backend. It contains no passphrase or spending key.
#[derive(Clone, Default)]
pub struct Snapshot {
    /// Whether startup has completed.
    pub ready: bool,
    /// Actual RPC address, including an OS-selected port when configured as 0.
    pub rpc: Option<SocketAddr>,
    /// Node status.
    pub node: Value,
    /// Whether the configured wallet already exists, including while locked.
    pub wallet_present: bool,
    /// Wallet synchronization status, or `None` while locked.
    pub wallet: Option<Value>,
    /// Spendable, locked, and total amounts in smallest units.
    pub balance: Value,
    /// Receiving addresses.
    pub addresses: Value,
    /// Persisted outgoing payment operations.
    pub operations: Value,
    /// Received notes, including spent notes.
    pub received: Value,
    /// Built-in miner: saved choice, whether it runs, threads, payout
    /// address, and blocks found and in the main chain.
    pub mining: Value,
    /// Startup or refresh error.
    pub error: Option<String>,
}

enum Command {
    Action(
        Action,
        oneshot::Sender<std::result::Result<Outcome, String>>,
    ),
    Rpc(
        String,
        Params,
        oneshot::Sender<std::result::Result<Value, RpcError>>,
    ),
}

/// A cloneable command sender; holds no wallet or database references.
#[derive(Clone)]
pub struct Client(mpsc::Sender<Command>);

impl Client {
    /// Queues a GUI action without blocking the render thread.
    ///
    /// # Errors
    /// Fails if the backend stopped or its bounded queue is full.
    pub fn submit(
        &self,
        action: Action,
    ) -> std::result::Result<oneshot::Receiver<std::result::Result<Outcome, String>>, String> {
        let (reply, receiver) = oneshot::channel();
        self.0
            .try_send(Command::Action(action, reply))
            .map_err(|_| "Backend is busy or stopped".to_owned())?;
        Ok(receiver)
    }
}

impl Dispatch for Client {
    async fn call(&self, method: &str, params: &Params) -> std::result::Result<Value, RpcError> {
        let (reply, response) = oneshot::channel();
        self.0
            .send(Command::Rpc(method.to_owned(), params.clone(), reply))
            .await
            .map_err(|_| RpcError::new(REJECTED, "desktop stopped"))?;
        response
            .await
            .map_err(|_| RpcError::new(REJECTED, "desktop stopped"))?
    }
}

/// An owned backend task. Shutdown completes before its runtime is dropped.
pub struct Backend {
    /// Shared GUI/RPC command entry point.
    pub client: Client,
    /// Latest published state.
    pub snapshots: watch::Receiver<Snapshot>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<()>>,
}

impl Backend {
    /// Starts asynchronously on the current Tokio runtime.
    pub fn spawn(config: Config) -> Self {
        let (sender, receiver) = mpsc::channel(64);
        let client = Client(sender);
        let (updates, snapshots) = watch::channel(Snapshot::default());
        let (stop, stopped) = oneshot::channel();
        let rpc = client.clone();
        let task = tokio::spawn(async move {
            let result = run(config, receiver, rpc, &updates, stopped).await;
            if let Err(error) = &result {
                updates.send_modify(|state| {
                    state.ready = false;
                    state.error = Some(error.to_string());
                });
            }
            result
        });
        Self {
            client,
            snapshots,
            stop,
            task,
        }
    }

    /// Stops RPC, drains the wallet worker, and stops the node.
    ///
    /// # Errors
    /// Returns startup or backend task failures.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.stop.send(());
        self.task.await.map_err(|_| Error::Stopped)?
    }
}

struct State {
    node: node::Handle,
    context: Context,
    network: Network,
    wallet: Option<Service>,
    wallet_path: PathBuf,
    miner: Option<Miner>,
    mining: Mining,
    settings: PathBuf,
}

async fn run(
    config: Config,
    mut commands: mpsc::Receiver<Command>,
    client: Client,
    updates: &watch::Sender<Snapshot>,
    mut stopped: oneshot::Receiver<()>,
) -> Result<()> {
    if !config.rpc.ip().is_loopback() {
        return Err(Error::Argument(
            "desktop RPC must bind to a loopback address".into(),
        ));
    }
    if config.node.rpc.is_some() || config.node.rpc_http.is_some() {
        return Err(Error::Argument(
            "desktop uses one combined RPC listener".into(),
        ));
    }
    let listener = TcpListener::bind(config.rpc).await?;
    let addr = listener.local_addr()?;
    let token = Token::random(&mut rand::rngs::OsRng);
    if let Some(parent) = config
        .token_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let network = config.node.network;
    let node = node::spawn(config.node).await?;
    // Acquire the chain database before replacing its token: a second
    // instance must not overwrite a running application's credentials.
    if let Err(error) = token.write_to(&config.token_file) {
        node.shutdown().await;
        return Err(error);
    }
    let context = Context::new(node.events(), network);
    let mut state = State {
        node,
        context,
        network,
        wallet: None,
        wallet_path: config.wallet,
        miner: None,
        mining: config.mining.clamped(),
        settings: config.settings,
    };
    let server = tokio::spawn(jsonrpc::serve_with(listener, token, client));
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = &mut stopped => break,
            command = commands.recv() => match command {
                Some(Command::Action(action, reply)) => {
                    let result = state.action(action).await.map_err(|e| e.to_string());
                    let _ = reply.send(result);
                    state.publish(updates, addr).await;
                }
                Some(Command::Rpc(method, params, reply)) => {
                    // Stop means the entire desktop backend, including wallet.
                    let stop = method == "stop";
                    let result = if stop { Ok(json!("stopping")) }
                        else { state.call(&method, &params).await };
                    let _ = reply.send(result);
                    if stop { break; }
                }
                None => break,
            },
            _ = interval.tick() => state.publish(updates, addr).await,
        }
    }
    server.abort();
    let _ = server.await;
    commands.close();
    state.lock().await;
    state.node.shutdown().await;
    updates.send_replace(Snapshot {
        error: Some("Backend stopped".into()),
        ..Snapshot::default()
    });
    Ok(())
}

impl State {
    async fn lock(&mut self) {
        // The miner pays the wallet's address, so it stops with the wallet.
        self.stop_mining();
        if let Some(service) = self.wallet.take() {
            service.shutdown().await;
        }
    }

    /// Asks the miner to stop and lets its workers finish in the
    /// background. Each ends within one solve, which takes seconds on the
    /// main network, and the backend must keep answering the GUI meanwhile.
    fn stop_mining(&mut self) {
        if let Some(miner) = self.miner.take() {
            tokio::spawn(async move {
                if let Err(error) = miner.stop().await {
                    null_node::logging::warn(&format!("miner stopped: {error}"));
                }
            });
        }
    }

    /// Starts the miner for the unlocked wallet's main address.
    fn start_mining(&mut self, threads: usize) -> Result<()> {
        let service = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Argument("unlock your wallet to mine".into()))?;
        let payout = service.daemon.wallet().keys().default_address()?;
        let params = self.network.params();
        self.miner = Some(miner::start(payout, params, threads, self.node.events()));
        Ok(())
    }

    /// Applies and saves a mining choice. Mining keeps its new state even
    /// if saving fails; the message says so.
    fn set_mining(&mut self, mining: Mining) -> Result<Outcome> {
        let mining = mining.clamped();
        if mining.enabled && self.wallet.is_none() {
            return Err(Error::Argument("unlock your wallet to mine".into()));
        }
        self.stop_mining();
        if mining.enabled {
            self.start_mining(mining.threads)?;
        }
        self.mining = mining;
        let message = if mining.enabled {
            format!("Mining with {} threads", mining.threads)
        } else {
            "Mining stopped".into()
        };
        Ok(Outcome::message(
            match config::save_mining(&self.settings, mining) {
                Ok(()) => message,
                Err(error) => format!("{message}, but saving null.conf failed: {error}"),
            },
        ))
    }

    async fn action(&mut self, action: Action) -> Result<Outcome> {
        match action {
            Action::Lock => {
                self.lock().await;
                Ok(Outcome::message("Wallet locked"))
            }
            Action::Open { passphrase, mode } => {
                if self.wallet.is_some() {
                    return Err(Error::Argument("lock the current wallet first".into()));
                }
                let network = self.network;
                let path = self.wallet_path.clone();
                let (wallet, phrase) = tokio::task::spawn_blocking(move || {
                    open_wallet(path, &passphrase, mode, network)
                })
                .await
                .map_err(|_| Error::Stopped)??;
                self.wallet = Some(walletd::start(ServiceConfig {
                    wallet,
                    network,
                    node: Source::Embedded(self.node.events()),
                    sync_interval: Duration::from_secs(1),
                    light: false,
                }));
                if self.mining.enabled {
                    self.start_mining(self.mining.threads)?;
                }
                Ok(Outcome {
                    phrase,
                    ..Outcome::message("Wallet unlocked")
                })
            }
            Action::SetMining(mining) => self.set_mining(mining),
            Action::Call { method, params } => {
                let result = self
                    .call(&method, &Params::new(params))
                    .await
                    .map_err(|e| Error::Argument(e.message))?;
                Ok(Outcome {
                    value: result,
                    ..Outcome::message("Done")
                })
            }
        }
    }

    async fn call(&self, method: &str, params: &Params) -> std::result::Result<Value, RpcError> {
        if method == "stop" {
            return Err(RpcError::new(
                REJECTED,
                "stop is handled by the application lifecycle",
            ));
        }
        // Wallet semantics win for overlapping names such as gettransaction.
        // Prefix node methods with node. to disambiguate them.
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
            let service = self
                .wallet
                .as_ref()
                .ok_or_else(|| RpcError::new(REJECTED, "wallet is locked"))?;
            service.daemon.call(method, params).await
        } else {
            self.context.call(method, params).await
        }
    }

    async fn snapshot(&self, addr: SocketAddr) -> std::result::Result<Snapshot, RpcError> {
        let params = Params::new(json!([]));
        let mut snapshot = Snapshot {
            ready: true,
            rpc: Some(addr),
            wallet_present: self.wallet_path.try_exists().map_err(Error::from)?,
            node: self.context.call("getblockchaininfo", &params).await?,
            ..Snapshot::default()
        };
        if let Some(info) = snapshot.node.as_object_mut() {
            info.insert(
                "peers".into(),
                self.context.call("getpeerinfo", &params).await?,
            );
        }
        snapshot.mining = self.mining_json().await?;
        if let Some(service) = &self.wallet {
            snapshot.wallet = Some(service.daemon.call("getwalletinfo", &params).await?);
            snapshot.balance = service.daemon.call("getbalance", &params).await?;
            snapshot.addresses = service.daemon.call("listaddresses", &params).await?;
            snapshot.operations = service.daemon.call("listoperations", &params).await?;
            snapshot.received = service.daemon.call("listreceived", &params).await?;
        }
        Ok(snapshot)
    }

    async fn mining_json(&self) -> std::result::Result<Value, RpcError> {
        let (found, in_chain) = match self.node.request(Request::Metrics).await? {
            Response::Metrics(m) => (m.blocks_mined, m.blocks_mined_in_chain),
            _ => (0, 0),
        };
        let prefix = self.network.address_prefix();
        Ok(json!({
            "enabled": self.mining.enabled,
            "active": self.miner.is_some(),
            "threads": self.miner.as_ref().map_or(self.mining.threads, |m| m.threads),
            "max_threads": config::max_mining_threads(),
            "payout": self.miner.as_ref().map(|m| m.payout.encode(prefix)),
            "found": found,
            "in_chain": in_chain,
        }))
    }

    async fn publish(&self, updates: &watch::Sender<Snapshot>, addr: SocketAddr) {
        match self.snapshot(addr).await {
            Ok(snapshot) => {
                updates.send_replace(snapshot);
            }
            Err(error) => updates.send_modify(|s| {
                s.wallet_present = self.wallet_path.try_exists().unwrap_or(s.wallet_present);
                // Lock must hide wallet state even when the node failed.
                if self.wallet.is_none() {
                    s.wallet = None;
                    s.balance = Value::Null;
                    s.addresses = Value::Null;
                    s.operations = Value::Null;
                    s.received = Value::Null;
                }
                s.error = Some(error.message);
            }),
        }
    }
}

fn open_wallet(
    path: PathBuf,
    passphrase: &str,
    mode: OpenMode,
    network: Network,
) -> Result<(Wallet, Option<Zeroizing<String>>)> {
    let genesis = genesis(&network.params()).hash();
    if matches!(mode, OpenMode::Existing) {
        return Ok((Wallet::open(path, genesis, passphrase.as_bytes())?, None));
    }
    if passphrase.is_empty() {
        return Err(Error::Argument("choose a wallet passphrase".into()));
    }
    if path.exists() {
        return Err(Error::Argument(
            "a wallet already exists; unlock it to continue".into(),
        ));
    }
    let (seed, fresh) = match mode {
        OpenMode::Create => (SeedPhrase::generate(&mut rand::rngs::OsRng)?, true),
        OpenMode::Restore(words) => (SeedPhrase::parse(&words)?, false),
        OpenMode::Existing => return Err(Error::Argument("expected a new wallet".into())),
    };
    let wallet = Wallet::create(
        path,
        &seed.spending_key(0)?,
        genesis,
        passphrase.as_bytes(),
        &mut rand::rngs::OsRng,
    )?;
    Ok((wallet, fresh.then(|| seed.words())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoring_preserves_the_address_and_never_overwrites_a_wallet() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.redb");
        let restored = directory.path().join("restored.redb");
        let (wallet, phrase) =
            open_wallet(path.clone(), "password", OpenMode::Create, Network::Test).unwrap();
        let address = wallet.keys().default_address().unwrap();
        drop(wallet);
        assert!(open_wallet(path.clone(), "password", OpenMode::Create, Network::Test).is_err());
        assert!(open_wallet(path.clone(), "wrong", OpenMode::Existing, Network::Test).is_err());
        assert!(open_wallet(path, "password", OpenMode::Existing, Network::Main).is_err());
        let (wallet, shown) = open_wallet(
            restored,
            "new password",
            OpenMode::Restore(phrase.unwrap()),
            Network::Test,
        )
        .unwrap();
        assert!(shown.is_none());
        assert_eq!(wallet.keys().default_address().unwrap(), address);
    }

    #[test]
    fn invalid_restoration_and_empty_passwords_do_not_create_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.redb");
        assert!(open_wallet(path.clone(), "", OpenMode::Create, Network::Test).is_err());
        assert!(open_wallet(
            path.clone(),
            "password",
            OpenMode::Restore(Zeroizing::new("not a seed".into())),
            Network::Test
        )
        .is_err());
        assert!(!path.exists());
    }
}
