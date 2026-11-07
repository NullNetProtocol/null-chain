//! One owner for the embedded node, unlocked wallet, and RPC listener.
//!
//! GUI actions and HTTP calls enter the same bounded command queue. Only
//! this task owns the wallet service. Calls and snapshot refreshes run on
//! their own tasks so a slow node, busy importing blocks while it syncs,
//! never holds up unlocking, locking or the next command; locking waits for
//! every one of them, and for the wallet worker, before the keys are gone.

mod refresh;

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::time::Duration;

use null_chain::genesis::genesis;
use null_node::config::{Config as NodeConfig, Network};
use null_node::jsonrpc::{self, Context, Dispatch, Params, RpcError, REJECTED};
use null_node::miner::{self, Miner};
use null_node::node;
use null_node::rpc::{Source, Token};
use null_node::walletd::{self, Service, ServiceConfig, SECRET_METHODS};
use null_node::{Error, Result};
use null_wallet::seed::{AccountPhrase, SeedPhrase};
use null_wallet::wallet::Wallet;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use zeroize::Zeroizing;

use crate::block_times::BlockTimes;
use crate::config::{self, LogFile, Mining};
use refresh::{Built, Inputs, MiningView, Refresh, Services};

/// The seed account the desktop wallet uses.
const ACCOUNT: u32 = 0;
/// Calls run at once; more wait for one to finish, so a flood of RPC
/// requests cannot spawn without bound.
const MAX_CONCURRENT_CALLS: usize = 16;
/// Why the debug console cannot run a seed phrase method.
pub const SECRET_REFUSED: &str =
    "Use the Backup page to show or store the recovery phrase; the console keeps a history.";

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
    /// The saved log file switch and where the log goes.
    pub log: LogFile,
    /// The configuration file the mining and log switches save to.
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
    /// Start or stop writing the log file. The choice is saved.
    SetLogFile(bool),
    /// Show the recovery phrase the wallet file keeps, after checking the
    /// passphrase again; it arrives in [`Outcome::phrase`].
    RevealSeed {
        /// Wallet file encryption passphrase.
        passphrase: Zeroizing<String>,
    },
    /// Store the recovery phrase in a wallet file created before phrases
    /// were kept. It must derive the wallet's own spending key.
    AttachSeed {
        /// The recovery words, space separated.
        phrase: Zeroizing<String>,
    },
    /// Invoke a method on the same services used by HTTP RPC. Methods that
    /// carry the recovery phrase are refused: use the actions above.
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
    /// The recovery phrase: newly generated when creating a wallet, or
    /// the stored one for [`Action::RevealSeed`].
    pub phrase: Option<Zeroizing<String>>,
    /// The seed account a revealed phrase restores: a wallet made with
    /// `nulld create --account` uses another than the desktop's 0.
    pub account: Option<u32>,
    /// Result of an [`Action::Call`]; `null` for other actions.
    pub value: Value,
}

impl Outcome {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            phrase: None,
            account: None,
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
    /// Received notes, including spent notes, each with the `time` its
    /// block was mined (`null` until looked up) and whether it is a `mined`
    /// reward.
    pub received: Value,
    /// Built-in miner: saved choice, whether it runs, threads, payout
    /// address, and blocks found and in the main chain.
    pub mining: Value,
    /// Whether the log file is being written.
    pub log_file: bool,
    /// Startup or refresh error.
    pub error: Option<String>,
}

/// Where a GUI action's result goes.
type ActionReply = oneshot::Sender<std::result::Result<Outcome, String>>;
/// Where an RPC call's result goes.
type RpcReply = oneshot::Sender<std::result::Result<Value, RpcError>>;

enum Command {
    Action(Action, ActionReply),
    Rpc(String, Params, RpcReply),
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
    addr: SocketAddr,
    wallet: Option<Service>,
    wallet_path: PathBuf,
    miner: Option<Miner>,
    mining: Mining,
    log: LogFile,
    settings: PathBuf,
    /// Block facts for dating notes; lent to the running refresh.
    block_times: BlockTimes,
    /// Calls in flight. Each holds the wallet daemon until it finishes.
    calls: JoinSet<()>,
    /// The snapshot being built.
    refresh: Option<Refresh>,
    /// Advanced by every action, so a snapshot begun before one is dropped
    /// instead of showing, say, wallet data after a lock.
    epoch: u64,
    /// Whether another snapshot should follow the running one.
    stale: bool,
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
    // Before the node starts, so the log file has its first lines. A log
    // that cannot be opened only costs the file, so it is not fatal.
    if let Err(error) = config.log.apply() {
        null_node::logging::warn(&format!("log file not written: {error}"));
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
        addr,
        wallet: None,
        wallet_path: config.wallet,
        miner: None,
        mining: config.mining.clamped(),
        log: config.log,
        settings: config.settings,
        block_times: BlockTimes::default(),
        calls: JoinSet::new(),
        refresh: None,
        epoch: 0,
        stale: false,
    };
    let server = tokio::spawn(jsonrpc::serve_with(listener, token, client));
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = &mut stopped => break,
            command = commands.recv() => match command {
                Some(command) => {
                    if state.command(command, updates).await.is_break() {
                        break;
                    }
                }
                None => break,
            },
            (epoch, built) = refresh::finished(&mut state.refresh) => {
                state.refreshed(epoch, built, updates);
            }
            Some(_) = state.calls.join_next() => {}
            _ = interval.tick() => state.start_refresh(),
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
    /// Handles one queued command; breaks the loop on `stop`.
    async fn command(
        &mut self,
        command: Command,
        updates: &watch::Sender<Snapshot>,
    ) -> ControlFlow<()> {
        match command {
            // Stop means the entire desktop backend, including wallet.
            Command::Action(Action::Call { method, .. }, reply) if method == "stop" => {
                let _ = reply.send(Ok(Outcome {
                    value: json!("stopping"),
                    ..Outcome::message("Stopping")
                }));
                ControlFlow::Break(())
            }
            Command::Rpc(method, _, reply) if method == "stop" => {
                let _ = reply.send(Ok(json!("stopping")));
                ControlFlow::Break(())
            }
            Command::Action(Action::Call { method, params }, reply) => {
                if SECRET_METHODS.contains(&method.as_str()) {
                    let _ = reply.send(Err(SECRET_REFUSED.into()));
                } else {
                    self.spawn_call(method, Params::new(params), move |result| {
                        let _ = reply.send(gui_result(result));
                    })
                    .await;
                }
                ControlFlow::Continue(())
            }
            Command::Rpc(method, params, reply) => {
                self.spawn_call(method, params, move |result| {
                    let _ = reply.send(result);
                })
                .await;
                ControlFlow::Continue(())
            }
            Command::Action(action, reply) => {
                let outcome = self.action(action).await.map_err(|e| e.to_string());
                // Answer after publishing, so the GUI that hears "unlocked"
                // already has the wallet to show.
                self.changed(updates).await;
                let _ = reply.send(outcome);
                ControlFlow::Continue(())
            }
        }
    }

    /// Runs a call on its own task, waiting first while too many run.
    async fn spawn_call(
        &mut self,
        method: String,
        params: Params,
        deliver: impl FnOnce(std::result::Result<Value, RpcError>) + Send + 'static,
    ) {
        while self.calls.len() >= MAX_CONCURRENT_CALLS {
            self.calls.join_next().await;
        }
        let services = self.services();
        self.calls
            .spawn(async move { deliver(services.call(&method, &params).await) });
    }

    /// The node and, while unlocked, the wallet daemon.
    fn services(&self) -> Services {
        Services {
            context: self.context.clone(),
            wallet: self.wallet.as_ref().map(|service| service.daemon.clone()),
        }
    }

    /// After an action: drop snapshots begun before it, show at once what
    /// needs no node call, and build a fresh snapshot.
    async fn changed(&mut self, updates: &watch::Sender<Snapshot>) {
        self.epoch = self.epoch.wrapping_add(1);
        self.stale = true;
        self.publish_local(updates, None);
        self.publish_wallet(updates).await;
        self.start_refresh();
    }

    /// Publishes the unlocked wallet's own fields without waiting for the
    /// full snapshot, whose node calls queue behind block imports while
    /// syncing: unlocking shows the wallet at once instead of after them.
    /// A failure is left for the full snapshot to report. Received notes
    /// are only filled when none are shown: actions do not change them,
    /// and the copy here lacks the block times a running refresh holds.
    async fn publish_wallet(&self, updates: &watch::Sender<Snapshot>) {
        let Some(service) = &self.wallet else {
            return;
        };
        let mut fields = Snapshot::default();
        if refresh::wallet_fields(&service.daemon, &mut fields)
            .await
            .is_err()
        {
            return;
        }
        self.block_times.annotate(
            &mut fields.received,
            self.network.params().coinbase_maturity,
        );
        updates.send_modify(|s| {
            s.wallet = fields.wallet;
            s.balance = fields.balance;
            s.addresses = fields.addresses;
            s.operations = fields.operations;
            if s.received.is_null() {
                s.received = fields.received;
            }
        });
    }

    /// Starts a snapshot unless one is being built.
    fn start_refresh(&mut self) {
        if self.refresh.is_some() {
            return;
        }
        self.stale = false;
        let inputs = Inputs {
            services: self.services(),
            mining: self.mining_view(),
            wallet_path: self.wallet_path.clone(),
            addr: self.addr,
            network: self.network,
            log_file: self.log.enabled,
            block_times: std::mem::take(&mut self.block_times),
        };
        self.refresh = Some(Refresh::spawn(self.epoch, inputs));
    }

    /// Publishes a finished snapshot unless an action came after it began.
    fn refreshed(
        &mut self,
        epoch: u64,
        built: std::result::Result<Built, tokio::task::JoinError>,
        updates: &watch::Sender<Snapshot>,
    ) {
        self.refresh = None;
        // The cache holds chain facts, valid across epochs: a lock cancels
        // its refresh before clearing it, so no wallet's lookups leak over.
        let built = built.map(|(snapshot, block_times)| {
            self.block_times = block_times;
            snapshot
        });
        if epoch == self.epoch {
            match built {
                Ok(Ok(snapshot)) => {
                    updates.send_replace(snapshot);
                }
                Ok(Err(error)) => self.publish_local(updates, Some(error.message)),
                Err(error) => self.publish_local(updates, Some(error.to_string())),
            }
        }
        if self.stale {
            self.start_refresh();
        }
    }

    /// Updates what this task knows without a node call: whether a wallet
    /// file exists and, when locked, hiding every wallet field.
    fn publish_local(&self, updates: &watch::Sender<Snapshot>, error: Option<String>) {
        updates.send_modify(|s| {
            s.wallet_present = self.wallet_path.try_exists().unwrap_or(s.wallet_present);
            if self.wallet.is_none() {
                s.wallet = None;
                s.balance = Value::Null;
                s.addresses = Value::Null;
                s.operations = Value::Null;
                s.received = Value::Null;
            }
            if error.is_some() {
                s.error = error;
            }
        });
    }

    /// Waits for every call and stops the refresh, so no task still holds
    /// the wallet.
    async fn drain(&mut self) {
        if let Some(refresh) = self.refresh.take() {
            refresh.cancel().await;
        }
        while self.calls.join_next().await.is_some() {}
    }

    async fn lock(&mut self) {
        // The miner pays the wallet's address, so it stops with the wallet.
        self.stop_mining();
        self.epoch = self.epoch.wrapping_add(1);
        self.drain().await;
        self.block_times.clear();
        if let Some(service) = self.wallet.take() {
            service.shutdown().await;
        }
    }

    /// The unlocked wallet service.
    fn unlocked(&self) -> Result<&Service> {
        self.wallet
            .as_ref()
            .ok_or_else(|| Error::Argument("unlock your wallet first".into()))
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
        self.miner = Some(miner::start(
            payout,
            params,
            threads,
            self.node.events(),
            self.node.tip(),
        ));
        Ok(())
    }

    /// The miner's state for the next snapshot.
    fn mining_view(&self) -> MiningView {
        let prefix = self.network.address_prefix();
        MiningView {
            enabled: self.mining.enabled,
            active: self.miner.is_some(),
            threads: self
                .miner
                .as_ref()
                .map_or(self.mining.threads, |m| m.threads),
            payout: self.miner.as_ref().map(|m| m.payout.encode(prefix)),
        }
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

    fn set_log_file(&mut self, enabled: bool) -> Result<Outcome> {
        let log = LogFile {
            enabled,
            ..self.log.clone()
        };
        log.apply()?;
        self.log = log;
        let message = if enabled {
            format!("Writing the log to {}", self.log.path.display())
        } else {
            "Log file off".into()
        };
        Ok(Outcome::message(
            match config::save_log_file(&self.settings, enabled) {
                Ok(()) => message,
                Err(error) => format!("{message}, but saving null.conf failed: {error}"),
            },
        ))
    }

    async fn open(&mut self, passphrase: Zeroizing<String>, mode: OpenMode) -> Result<Outcome> {
        if self.wallet.is_some() {
            return Err(Error::Argument("lock the current wallet first".into()));
        }
        let network = self.network;
        let path = self.wallet_path.clone();
        let (wallet, phrase) =
            tokio::task::spawn_blocking(move || open_wallet(path, &passphrase, mode, network))
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

    async fn reveal_seed(&self, passphrase: Zeroizing<String>) -> Result<Outcome> {
        let stored = self
            .unlocked()?
            .daemon
            .reveal_seed_phrase(passphrase)
            .await
            .map_err(rpc_failure)?;
        Ok(Outcome {
            phrase: Some(stored.phrase.words()),
            account: Some(stored.account),
            ..Outcome::message("Recovery phrase shown")
        })
    }

    async fn attach_seed(&self, words: &str) -> Result<Outcome> {
        let phrase = AccountPhrase {
            phrase: SeedPhrase::parse(words)?,
            account: ACCOUNT,
        };
        self.unlocked()?
            .daemon
            .attach_seed_phrase(phrase)
            .await
            .map_err(|error| Error::Argument(attach_failure(error.message)))?;
        Ok(Outcome::message("Recovery phrase stored"))
    }

    /// Runs an action other than a call, which [`Self::command`] spawns.
    async fn action(&mut self, action: Action) -> Result<Outcome> {
        match action {
            Action::Lock => {
                self.lock().await;
                Ok(Outcome::message("Wallet locked"))
            }
            Action::Open { passphrase, mode } => self.open(passphrase, mode).await,
            Action::SetMining(mining) => self.set_mining(mining),
            Action::SetLogFile(enabled) => self.set_log_file(enabled),
            Action::RevealSeed { passphrase } => self.reveal_seed(passphrase).await,
            Action::AttachSeed { phrase } => self.attach_seed(&phrase).await,
            Action::Call { .. } => Err(Error::Argument("calls run on their own task".into())),
        }
    }
}

/// A call's result as the GUI receives it.
fn gui_result(
    result: std::result::Result<Value, RpcError>,
) -> std::result::Result<Outcome, String> {
    result
        .map(|value| Outcome {
            value,
            ..Outcome::message("Done")
        })
        .map_err(|error| rpc_failure(error).to_string())
}

/// Explains a phrase that does not match: the desktop stores account 0
/// only, and a wallet from `nulld create --account` needs the CLI.
fn attach_failure(message: String) -> String {
    if message == null_wallet::Error::SeedMismatch.to_string() {
        format!(
            "{message}. This page stores account {ACCOUNT}; for a wallet created with \
             nulld create --account, use nulld attach-seed --account"
        )
    } else {
        message
    }
}

/// An RPC failure as a backend error, keeping its message.
fn rpc_failure(error: RpcError) -> Error {
    Error::Argument(error.message)
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
    let phrase = AccountPhrase {
        phrase: seed,
        account: ACCOUNT,
    };
    let wallet = Wallet::create_from_phrase(
        path,
        &phrase,
        genesis,
        passphrase.as_bytes(),
        &mut rand::rngs::OsRng,
    )?;
    Ok((wallet, fresh.then(|| phrase.phrase.words())))
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
        let phrase_words = phrase.clone().unwrap();
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
        let kept = wallet.reveal_seed_phrase(b"new password").unwrap().unwrap();
        assert_eq!(kept.account, ACCOUNT);
        assert_eq!(*kept.phrase.words(), *phrase_words);
    }

    #[test]
    fn a_mismatched_phrase_points_to_the_cli_for_other_accounts() {
        let mismatch = null_wallet::Error::SeedMismatch.to_string();
        assert!(attach_failure(mismatch.clone()).starts_with(&mismatch));
        assert!(attach_failure(mismatch).contains("nulld attach-seed --account"));
        assert_eq!(attach_failure("wallet is busy".into()), "wallet is busy");
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
