//! The wallet daemon `null-wallet-rpc`: a long-running process that
//! holds one wallet file, keeps it synced from a node, serves the wallet
//! methods over JSON-RPC, and carries send operations from request to
//! confirmation, rebuilding them if their transaction is not mined.
//!
//! The standalone binary runs separately from the node so public infrastructure
//! need not hold keys. Desktop applications can embed the same service with
//! [`start`] and an in-process node connection. See `docs/rpc.md` and
//! `docs/desktop.md`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use null_chain::genesis::genesis;
use null_chain::params::ChainParams;
use null_circuit::proof::ProvingKey;
use null_crypto::encoding::to_hex;
use null_protocol::address::Address;
use null_protocol::amount::Amount;
use null_protocol::bytes::Encodable;
use null_protocol::consensus::{action_class_for, fee_for_actions, next_height};
use null_protocol::disclosure::{Challenge, PaymentDisclosure};
use null_protocol::memo::Memo;
use null_protocol::note::Rho;
use null_protocol::note_encryption::{decrypt_note_with_ovk, recover_output_keys};
use null_protocol::transaction::{Transaction, TxId};
use null_protocol::viewing_key::encode_full_viewing_key;
use null_wallet::operations::{Operation, OperationStatus};
use null_wallet::scan::OwnedNote;
use null_wallet::spend::{build_payments, quote_payments, Built, Payment, MAX_RECIPIENTS};
use null_wallet::wallet::Wallet;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::cli::{fetch_block, passphrase, sync_wallet};
use crate::config::Network;
use crate::jsonrpc::{serve_with, unknown_method, Dispatch, Params, RpcError, REJECTED};
use crate::node::TxStatus;
use crate::paths;
use crate::rpc::{transaction_status, Control, Endpoint, Source, Token};
use crate::shutdown::Shutdown;
use crate::{logging, now, Error, Result};

/// Where the daemon listens unless told otherwise.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:18447";
/// File the generated token is written to, next to the wallet file.
pub const TOKEN_FILE: &str = "wallet-rpc.token";
/// Environment variable holding the daemon's own token.
pub const TOKEN_ENV: &str = "NULL_WALLET_RPC_TOKEN";
/// Seconds between syncs from the node.
pub const DEFAULT_SYNC_SECONDS: u64 = 2;
/// Maximum proof-build attempts for one operation.
const MAX_ATTEMPTS: u32 = 5;

/// Every method, for `help` and for the reference in `docs/rpc.md`.
pub const METHODS: &[&str] = &[
    "getwalletinfo",
    "getnewaddress",
    "listaddresses",
    "getaddressinfo",
    "validateaddress",
    "exportviewingkey",
    "getbalance",
    "listunspent",
    "listreceived",
    "gettransaction",
    "sendmany",
    "getoperationstatus",
    "listoperations",
    "canceloperation",
    "estimatefee",
    "quotepayment",
    "rescan",
    "getpaymentdisclosure",
    "answerchallenge",
    "help",
];

/// Command line of `null-wallet-rpc`.
#[derive(Parser, Debug)]
#[command(
    name = "null-wallet-rpc",
    about = "Wallet daemon: sync, addresses, sends, JSON-RPC"
)]
pub struct Args {
    /// Wallet file, created with `nulld create` or the desktop app;
    /// defaults to `<user data>/<network>/wallet.redb`.
    #[arg(long)]
    pub wallet: Option<PathBuf>,
    /// Network the wallet is for.
    #[arg(long, default_value = "test")]
    pub network: Network,
    /// The node's control socket.
    #[arg(long, default_value = "127.0.0.1:18444")]
    pub node: String,
    /// The node's token; also read from `NULL_RPC_TOKEN`.
    #[arg(
        long,
        env = "NULL_RPC_TOKEN",
        conflicts_with = "node_token_file",
        hide_env_values = true
    )]
    pub node_token: Option<String>,
    /// File holding the node's token; defaults to the `rpc.token` a
    /// default `nulld run` writes, `<user data>/<network>/chain/rpc.token`.
    #[arg(long)]
    pub node_token_file: Option<PathBuf>,
    /// Address to serve the wallet's JSON-RPC on.
    #[arg(long, default_value = DEFAULT_LISTEN)]
    pub listen: SocketAddr,
    /// Token the wallet's JSON-RPC demands; also read from
    /// `NULL_WALLET_RPC_TOKEN`. Generated and written next to the wallet
    /// file when omitted.
    #[arg(long, env = TOKEN_ENV, hide_env_values = true)]
    pub token: Option<String>,
    /// Seconds between syncs from the node.
    #[arg(long, default_value_t = DEFAULT_SYNC_SECONDS)]
    pub sync_interval: u64,
    /// Scan compact blocks instead of full ones: faster, no memos.
    #[arg(long)]
    pub light: bool,
    /// Log level: debug, info, warn or error.
    #[arg(long, default_value = "info")]
    pub log_level: logging::Level,
}

/// Everything the daemon needs to start.
pub struct Config {
    /// The open wallet.
    pub wallet: Wallet,
    /// Its network.
    pub network: Network,
    /// The node to sync from and submit through.
    pub node: Endpoint,
    /// Where to serve JSON-RPC.
    pub listen: SocketAddr,
    /// The token to demand.
    pub token: Token,
    /// How often to sync.
    pub sync_interval: Duration,
    /// Compact rather than full blocks.
    pub light: bool,
}

/// Wallet service configuration without an HTTP listener.
pub struct ServiceConfig {
    /// The unlocked wallet, owned by the service.
    pub wallet: Wallet,
    /// The wallet and node network.
    pub network: Network,
    /// The node, either remote or embedded.
    pub node: Source,
    /// Delay between synchronization passes.
    pub sync_interval: Duration,
    /// Scan compact blocks when true.
    pub light: bool,
}

/// An embedded wallet service. Its owner must await shutdown before locking
/// the wallet, so an active prover cannot retain keys after lock completes.
pub struct Service {
    /// The shared wallet operations used by GUI and RPC adapters.
    pub daemon: WalletDaemon,
    stop: tokio::sync::oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Service {
    /// Finishes the current synchronization/payment pass and releases the
    /// service's wallet references. Callers must release their clones too.
    pub async fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = self.task.await;
    }
}

/// Starts wallet synchronization without binding any sockets.
pub fn start(config: ServiceConfig) -> Service {
    let interval = config.sync_interval;
    let daemon = WalletDaemon::new(config);
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let worker = daemon.clone();
    let task = tokio::spawn(async move {
        loop {
            if !matches!(
                stopped.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ) {
                break;
            }
            // Do not cancel an active proof: spawn_blocking would keep its
            // wallet reference alive after the async task was aborted.
            let outcome = worker.sync_once().await;
            worker.record_outcome(outcome);
            tokio::select! {
                biased;
                _ = &mut stopped => break,
                () = tokio::time::sleep(interval) => {},
                () = worker.0.wake.notified() => {},
            }
        }
    });
    Service { daemon, stop, task }
}

struct Inner {
    wallet: Wallet,
    network: Network,
    params: ChainParams,
    node: Source,
    light: bool,
    proving_key: tokio::sync::OnceCell<Arc<ProvingKey>>,
    node_height: Mutex<Option<u32>>,
    last_error: Mutex<Option<String>>,
    wake: tokio::sync::Notify,
    // A rescan must not roll back the witness tree under an active prover or
    // overwrite an operation while the worker is reconciling it.
    sync_lock: tokio::sync::Mutex<()>,
}

/// The daemon's shared state: cloned into every connection and the sync
/// loop. The wallet needs no lock of its own; its database serializes
/// writers and lets readers proceed.
#[derive(Clone)]
pub struct WalletDaemon(Arc<Inner>);

/// A running daemon.
pub struct Handle {
    /// Where it serves JSON-RPC.
    pub addr: SocketAddr,
    /// The daemon, for tests that want to look inside.
    pub daemon: WalletDaemon,
    server: JoinHandle<()>,
    service: Service,
}

impl Handle {
    /// Requests shutdown. Use [`Self::shutdown_and_wait`] to await completion.
    pub fn shutdown(self) {
        tokio::spawn(self.shutdown_and_wait());
    }

    /// Stops accepting requests and waits for the current wallet pass.
    pub async fn shutdown_and_wait(self) {
        self.server.abort();
        let _ = self.server.await;
        drop(self.daemon);
        self.service.shutdown().await;
    }
}

/// The node token from the flag, the given file, or the default file.
fn node_token(text: Option<String>, file: Option<PathBuf>, network: Network) -> Result<Token> {
    match (text, file) {
        (Some(text), _) => Token::new(&text),
        (None, Some(path)) => Token::from_file(path),
        (None, None) => {
            let path = paths::node_token_file(&paths::default_network_dir(network)?);
            Token::from_file(&path).map_err(|_| {
                Error::Argument(format!(
                    "no node token at {}; pass --node-token, --node-token-file or set NULL_RPC_TOKEN",
                    path.display()
                ))
            })
        }
    }
}

/// Runs the `null-wallet-rpc` command line: opens the wallet, starts the
/// daemon and waits for a stop request.
///
/// # Errors
/// Fails if the wallet cannot be opened or a socket bound.
pub async fn main(args: Args) -> Result<()> {
    logging::set_level(args.log_level);
    let node = Endpoint {
        addr: args.node,
        token: node_token(args.node_token, args.node_token_file, args.network)?,
    };
    let wallet_path = match args.wallet {
        Some(path) => path,
        None => paths::wallet_file(&paths::default_network_dir(args.network)?),
    };
    // Opening creates the database file, so check first rather than leave
    // an empty file behind a mistyped or missing path.
    if !wallet_path.try_exists()? {
        return Err(Error::Argument(format!(
            "no wallet at {}; create one with the desktop app or `nulld create --wallet <file>`",
            wallet_path.display()
        )));
    }
    let genesis = genesis(&args.network.params()).hash();
    let wallet = Wallet::open(&wallet_path, genesis, &passphrase(false)?)?;
    let (token, generated) = match args.token {
        Some(text) => (Token::new(&text)?, false),
        None => (Token::random(&mut rand::rngs::OsRng), true),
    };
    if generated {
        let path = wallet_path
            .parent()
            .map_or_else(|| PathBuf::from(TOKEN_FILE), |dir| dir.join(TOKEN_FILE));
        token.write_to(&path)?;
        logging::info(&format!("token written to {}", path.display()));
    }
    let shutdown = Shutdown::listen()?;
    let handle = run(Config {
        wallet,
        network: args.network,
        node,
        listen: args.listen,
        token,
        sync_interval: Duration::from_secs(args.sync_interval.max(1)),
        light: args.light,
    })
    .await?;
    logging::info(&format!(
        "null-wallet-rpc up on the {} network, json-rpc http://{}/",
        args.network, handle.addr
    ));
    shutdown.requested().await;
    handle.shutdown_and_wait().await;
    Ok(())
}

/// Starts the sync loop and the JSON-RPC server.
///
/// # Errors
/// Fails if the socket cannot be bound.
pub async fn run(config: Config) -> Result<Handle> {
    let listener = TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    let service = start(ServiceConfig {
        wallet: config.wallet,
        network: config.network,
        node: Source::Remote(config.node),
        light: config.light,
        sync_interval: config.sync_interval,
    });
    let daemon = service.daemon.clone();
    let server = tokio::spawn(serve_with(listener, config.token, daemon.clone()));
    Ok(Handle {
        addr,
        daemon,
        server,
        service,
    })
}

impl WalletDaemon {
    fn new(config: ServiceConfig) -> Self {
        Self(Arc::new(Inner {
            wallet: config.wallet,
            network: config.network,
            params: config.network.params(),
            node: config.node,
            light: config.light,
            proving_key: tokio::sync::OnceCell::new(),
            node_height: Mutex::new(None),
            last_error: Mutex::new(None),
            wake: tokio::sync::Notify::new(),
            sync_lock: tokio::sync::Mutex::new(()),
        }))
    }

    /// The wallet.
    pub fn wallet(&self) -> &Wallet {
        &self.0.wallet
    }

    /// Remembers the last sync failure for `getwalletinfo`, logging it
    /// once per distinct message.
    fn record_outcome(&self, outcome: Result<()>) {
        let mut last = self
            .0
            .last_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match outcome {
            Ok(()) => *last = None,
            Err(error) => {
                let message = error.to_string();
                if last.as_deref() != Some(message.as_str()) {
                    logging::warn(&format!("sync: {message}"));
                }
                *last = Some(message);
            }
        }
    }

    /// One sync from the node, then one pass over the operations.
    async fn sync_once(&self) -> Result<()> {
        let _guard = self.0.sync_lock.lock().await;
        self.recover_interrupted_operations()?;
        let mut client = self.0.node.connect().await?;
        let tip = sync_wallet(&mut client, &self.0.wallet, self.0.light).await?;
        *self
            .0
            .node_height
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tip);
        // Restore reservations for every removed confirmation before a queued
        // payment can select notes, including stale records from older writers.
        self.reconcile_operations(&mut client, tip).await?;
        for operation in self.0.wallet.operations()? {
            match operation.status.clone() {
                OperationStatus::Queued => {
                    self.build_and_submit(&mut client, operation, tip).await?;
                }
                OperationStatus::Submitted { built_at, .. } => {
                    self.follow(&mut client, operation, built_at, tip).await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn recover_interrupted_operations(&self) -> Result<()> {
        for previous in self.0.wallet.operations()? {
            let mut op = previous.clone();
            match op.status {
                OperationStatus::Building => op.status = OperationStatus::Queued,
                OperationStatus::Proving => {
                    op.status = OperationStatus::Failed(
                        "interrupted legacy payment: it may already have been broadcast; \
                         reconcile the payment before retrying"
                            .into(),
                    );
                    op.locked.clear();
                }
                _ => continue,
            }
            self.0.wallet.compare_and_swap_operation(&previous, &op)?;
        }
        Ok(())
    }

    async fn reconcile_operations(&self, client: &mut impl Control, tip: u32) -> Result<()> {
        let notes = self.0.wallet.notes()?;
        for previous in self.0.wallet.operations()? {
            if !previous.status.is_pending()
                && !matches!(previous.status, OperationStatus::Confirmed { .. })
            {
                continue;
            }
            let mut op = previous.clone();
            if let Some((transaction, height)) = Self::confirmed_attempt(client, &op, tip).await? {
                op.status = OperationStatus::Confirmed {
                    txid: transaction.txid(),
                    height,
                };
                op.record_transaction(transaction.to_vec());
            } else if let OperationStatus::Confirmed { txid, height } = op.status {
                op.status = OperationStatus::Submitted {
                    txid,
                    built_at: height,
                };
            }
            if op.status.is_pending() {
                Self::reserve_recorded_inputs(&mut op, &notes)?;
            }
            if op != previous {
                self.0.wallet.compare_and_swap_operation(&previous, &op)?;
            }
        }
        Ok(())
    }

    fn reserve_recorded_inputs(op: &mut Operation, notes: &[OwnedNote]) -> Result<()> {
        let mut positions = op.locked.clone();
        for bytes in op.transactions() {
            let tx = Transaction::from_slice(bytes)?;
            positions.extend(notes.iter().filter_map(|note| {
                tx.actions()
                    .iter()
                    .any(|action| action.body().nullifier() == &note.nullifier)
                    .then_some(note.position)
            }));
        }
        // A reorg can put the same note at a different tree position. Nullifiers
        // identify inputs; retained positions alone cannot reserve them safely.
        positions.sort_unstable();
        positions.dedup();
        op.locked = positions;
        Ok(())
    }

    async fn confirmed_attempt(
        client: &mut impl Control,
        op: &Operation,
        tip: u32,
    ) -> Result<Option<(Transaction, u32)>> {
        for bytes in op.transactions() {
            let transaction = Transaction::from_slice(bytes)?;
            if let TxStatus::Confirmed { height, .. } =
                transaction_status(client, transaction.txid()).await?
            {
                if height > tip {
                    // Catch up before releasing the spent notes to selection.
                    return Err(Error::Argument("node advanced during wallet sync".into()));
                }
                return Ok(Some((transaction, height)));
            }
        }
        Ok(None)
    }

    async fn proving_key(&self) -> Result<Arc<ProvingKey>> {
        self.0
            .proving_key
            .get_or_try_init(|| async {
                tokio::task::spawn_blocking(ProvingKey::build)
                    .await
                    .map_err(|_| Error::Stopped)?
                    .map(Arc::new)
                    .map_err(Error::from)
            })
            .await
            .cloned()
    }

    /// Builds, proves and submits a queued operation.
    async fn build_and_submit(
        &self,
        client: &mut impl Control,
        previous: Operation,
        tip: u32,
    ) -> Result<()> {
        let mut op = previous.clone();
        if op.status != OperationStatus::Queued {
            return Ok(());
        }
        if op.attempts >= MAX_ATTEMPTS {
            return self.build_failed(
                &previous,
                tip,
                format!("gave up after {MAX_ATTEMPTS} attempts"),
            );
        }
        op.status = OperationStatus::Building;
        op.attempts = op.attempts.saturating_add(1);
        if !self.0.wallet.compare_and_swap_operation(&previous, &op)? {
            return Ok(());
        }

        let branch = self.0.params.branch_at(next_height(tip)?);
        // A note at height h has tip - h + 1 confirmations.
        let max_note_height = tip
            .saturating_add(1)
            .saturating_sub(op.min_confirmations.max(1));
        let excluded = self.excluded_positions(&op)?;
        let pk = self.proving_key().await?;
        let daemon = self.clone();
        let recipients = op.recipients.clone();
        let built = tokio::task::spawn_blocking(move || {
            build_payments(
                &daemon.0.wallet,
                &recipients,
                pk.as_ref(),
                branch,
                &excluded,
                max_note_height,
                &mut rand::rngs::OsRng,
            )
        })
        .await
        .map_err(|_| Error::Stopped)?;
        match built {
            Ok(built) => self.persist_and_submit(client, op, built, tip).await,
            Err(error) => self.build_failed(&op, tip, error.to_string()),
        }
    }

    /// Notes set aside by pending operations other than `except`.
    fn pending_locks(&self, except: Option<u64>) -> Result<Vec<u64>> {
        Ok(self
            .0
            .wallet
            .operations()?
            .iter()
            .filter(|other| Some(other.id) != except && other.status.is_pending())
            .flat_map(|other| other.locked.iter().copied())
            .collect())
    }

    fn excluded_positions(&self, op: &Operation) -> Result<Vec<u64>> {
        let mut excluded = self.pending_locks(Some(op.id))?;
        let attempts = op
            .transactions()
            .map(|bytes| Transaction::from_slice(bytes))
            .collect::<null_protocol::Result<Vec<_>>>()?;
        // Every replacement must conflict with every retained attempt, including
        // after a reorg changes note positions or selects an older confirmation.
        excluded.extend(self.0.wallet.unspent()?.iter().filter_map(|note| {
            attempts
                .iter()
                .any(|tx| {
                    !tx.actions()
                        .iter()
                        .any(|action| action.body().nullifier() == &note.nullifier)
                })
                .then_some(note.position)
        }));
        Ok(excluded)
    }

    fn build_failed(&self, previous: &Operation, tip: u32, reason: String) -> Result<()> {
        let mut op = previous.clone();
        if let Some(bytes) = &op.transaction {
            // A failed replacement does not prove an earlier broadcast failed.
            // Keep reconciling it, with its inputs reserved, even at the retry cap.
            op.status = OperationStatus::Submitted {
                txid: Transaction::from_slice(bytes)?.txid(),
                built_at: tip,
            };
            self.0.wallet.compare_and_swap_operation(previous, &op)?;
            return Err(Error::Argument(format!(
                "replacement failed; original payment remains pending: {reason}"
            )));
        }
        op.status = OperationStatus::Failed(reason);
        op.locked.clear();
        self.0.wallet.compare_and_swap_operation(previous, &op)?;
        Ok(())
    }

    async fn persist_and_submit(
        &self,
        client: &mut impl Control,
        previous: Operation,
        built: Built,
        tip: u32,
    ) -> Result<()> {
        let mut op = previous.clone();
        op.status = OperationStatus::Submitted {
            txid: built.transaction.txid(),
            built_at: tip,
        };
        op.locked.extend(built.spent);
        op.locked.sort_unstable();
        op.locked.dedup();
        op.record_transaction(built.transaction.to_vec());
        if self.0.wallet.compare_and_swap_operation(&previous, &op)? {
            // The commit above must succeed before the node can see any bytes.
            // Any reply failure leaves the exact transaction and locks intact.
            Self::submit_recorded(client, &op).await?;
        }
        Ok(())
    }

    async fn submit_recorded(client: &mut impl Control, op: &Operation) -> Result<()> {
        let bytes = op.transaction.as_ref().ok_or_else(|| {
            Error::Wallet(null_wallet::Error::Corrupt("pending transaction missing"))
        })?;
        client.call(&format!("submit {}", to_hex(bytes))).await?;
        Ok(())
    }

    /// Queues an expired attempt for rebuilding, or rebroadcasts its saved bytes.
    /// Confirmation of any retained attempt is checked before this pass.
    async fn follow(
        &self,
        client: &mut impl Control,
        mut op: Operation,
        built_at: u32,
        tip: u32,
    ) -> Result<()> {
        let previous = op.clone();
        if op.attempts < MAX_ATTEMPTS && tip.saturating_sub(built_at) > self.0.params.anchor_max_age
        {
            op.status = OperationStatus::Queued;
            // Keep the old transaction for reconciliation and constrain a
            // replacement to its original inputs.
            self.0.wallet.compare_and_swap_operation(&previous, &op)?;
            return Ok(());
        }
        Self::submit_recorded(client, &op).await
    }

    fn scanned_height(&self) -> Result<Option<u32>> {
        Ok(self.0.wallet.scanned_height()?)
    }

    fn node_height(&self) -> Option<u32> {
        *self
            .0
            .node_height
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn confirmations(&self, height: u32) -> Result<u64> {
        Ok(self.scanned_height()?.map_or(0, |tip| {
            u64::from(tip.saturating_sub(height)).saturating_add(1)
        }))
    }

    /// Labels by address index, for annotating notes.
    fn labels(&self) -> Result<std::collections::HashMap<u64, String>> {
        Ok(self
            .0
            .wallet
            .addresses()?
            .into_iter()
            .map(|(index, _, label)| (index, label))
            .collect())
    }

    fn note_json(
        &self,
        note: &OwnedNote,
        labels: &std::collections::HashMap<u64, String>,
        locked: &[u64],
    ) -> Result<Value> {
        let index = self.0.wallet.address_index_of(note.note.recipient());
        Ok(json!({
            "position": note.position,
            "txid": note.txid.map(|t| t.to_string()),
            "height": note.height,
            "confirmations": self.confirmations(note.height)?,
            "amount": note.note.value().raw().to_string(),
            "address": note.note.recipient().encode(self.0.params.address_prefix),
            "address_index": index,
            "label": index.and_then(|i| labels.get(&i).cloned()),
            "memo": memo_json(&note.memo),
            "spent": note.spent_at.is_some(),
            "spent_at": note.spent_at,
            "spent_by": note.spent_by.map(|t| t.to_string()),
            "locked": locked.contains(&note.position),
        }))
    }

    fn parse_address(&self, text: &str) -> core::result::Result<Address, RpcError> {
        Ok(Address::decode(text, self.0.params.address_prefix)?)
    }

    fn recipients(&self, value: &Value) -> core::result::Result<Vec<Payment>, RpcError> {
        let items = value
            .as_array()
            .ok_or_else(|| RpcError::invalid_params("recipients must be an array"))?;
        if items.is_empty() || items.len() > MAX_RECIPIENTS {
            return Err(RpcError::invalid_params(format!(
                "between 1 and {MAX_RECIPIENTS} recipients"
            )));
        }
        items
            .iter()
            .map(|item| {
                let address = item
                    .get("address")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RpcError::invalid_params("recipient address"))?;
                let amount = parse_amount(item.get("amount"))?;
                let memo = match item.get("memo").and_then(Value::as_str) {
                    Some(text) => Memo::from_text(text)?,
                    None => Memo::empty(),
                };
                Ok(Payment {
                    recipient: self.parse_address(address)?,
                    amount,
                    memo,
                })
            })
            .collect()
    }

    fn operation_json(&self, op: &Operation) -> Value {
        let prefix = self.0.params.address_prefix;
        let (txid, height) = match &op.status {
            OperationStatus::Submitted { txid, .. } => (Some(txid.to_string()), None),
            OperationStatus::Confirmed { txid, height } => (Some(txid.to_string()), Some(*height)),
            _ => (None, None),
        };
        json!({
            "operation_id": op.id,
            "status": op.status.name(),
            "created_at": op.created_at,
            "recipients": op.recipients.iter().map(|p| json!({
                "address": p.recipient.encode(prefix),
                "amount": p.amount.raw().to_string(),
                "memo": memo_json(&p.memo),
            })).collect::<Vec<_>>(),
            "total": op.total().to_string(),
            "min_confirmations": op.min_confirmations,
            "txid": txid,
            "height": height,
            "confirmations": height.and_then(|h| self.confirmations(h).ok()),
            "attempts": op.attempts,
            "cancellable": is_cancellable(op),
            "error": match &op.status {
                OperationStatus::Failed(reason) => Some(reason.clone()),
                _ => None,
            },
        })
    }
}

/// Whether an operation can still be cancelled: queued and never
/// broadcast, since an earlier broadcast may still be mined.
fn is_cancellable(op: &Operation) -> bool {
    op.status == OperationStatus::Queued && op.transaction.is_none()
}

/// A memo as text when it is text, else as hex, else null when empty.
fn memo_json(memo: &Memo) -> Value {
    if memo.as_bytes().iter().all(|b| *b == 0) {
        return Value::Null;
    }
    match memo.to_text() {
        Some(text) => json!(text),
        None => json!({ "hex": to_hex(memo.as_bytes()) }),
    }
}

/// An amount given as a decimal string or a number, in smallest units.
fn parse_amount(value: Option<&Value>) -> core::result::Result<Amount, RpcError> {
    let raw = match value {
        Some(Value::String(text)) => text
            .parse::<u64>()
            .map_err(|_| RpcError::invalid_params("amount must be a decimal string"))?,
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| RpcError::invalid_params("amount must be a whole number"))?,
        _ => return Err(RpcError::invalid_params("amount")),
    };
    Ok(Amount::from_raw(raw)?)
}

impl Dispatch for WalletDaemon {
    async fn call(&self, method: &str, params: &Params) -> core::result::Result<Value, RpcError> {
        match method {
            "getwalletinfo" | "getnewaddress" | "listaddresses" | "getaddressinfo"
            | "validateaddress" | "exportviewingkey" | "estimatefee" | "help" => {
                self.wallet_methods(method, params)
            }
            "rescan" => {
                let from: u32 = params.opt(0, "from_height")?.unwrap_or(0);
                let _guard = self.0.sync_lock.lock().await;
                self.0.wallet.rollback_to(from.saturating_sub(1))?;
                self.0.wake.notify_one();
                Ok(json!({ "scanned_height": self.scanned_height()? }))
            }
            "getpaymentdisclosure" => {
                let txid = parse_txid(&params.get::<String>(0, "txid")?)?;
                let index: Option<u32> = params.opt(1, "index")?;
                self.payment_disclosures(txid, index).await
            }
            "answerchallenge" => {
                let hex: String = params.get(0, "challenge")?;
                let challenge = Challenge::from_slice(&null_crypto::encoding::from_hex(&hex)?)?;
                let message = challenge
                    .answer(self.0.wallet.keys().incoming_viewing_key())
                    .map_err(|_| RpcError::new(REJECTED, "challenge is not for this wallet"))?;
                Ok(json!({ "message": message }))
            }
            _ => self.note_methods(method, params),
        }
    }
}

impl WalletDaemon {
    fn wallet_methods(
        &self,
        method: &str,
        params: &Params,
    ) -> core::result::Result<Value, RpcError> {
        let wallet = &self.0.wallet;
        let prefix = self.0.params.address_prefix;
        match method {
            "getwalletinfo" => {
                let scanned = self.scanned_height()?;
                let node = self.node_height();
                let notes = wallet.notes()?;
                let pending = wallet
                    .operations()?
                    .iter()
                    .filter(|op| op.status.is_pending())
                    .count();
                Ok(json!({
                    "network": self.0.network.to_string(),
                    "watch_only": wallet.keys().is_watch_only(),
                    "scanned_height": scanned,
                    "node_height": node,
                    "synced": scanned.is_some() && scanned == node,
                    "notes": notes.len(),
                    "unspent": notes.iter().filter(|n| n.spent_at.is_none()).count(),
                    "balance": wallet.balance()?.to_string(),
                    "pending_operations": pending,
                    "last_error": self.0.last_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
                }))
            }
            "getnewaddress" => {
                let label: String = params.opt(0, "label")?.unwrap_or_default();
                let (index, address) = wallet.new_address(&label)?;
                Ok(json!({ "index": index, "address": address.encode(prefix), "label": label }))
            }
            "listaddresses" => Ok(json!(wallet
                .addresses()?
                .into_iter()
                .map(|(index, address, label)| json!({
                    "index": index,
                    "address": address.encode(prefix),
                    "label": label,
                }))
                .collect::<Vec<_>>())),
            "getaddressinfo" => {
                let address = self.parse_address(&params.get::<String>(0, "address")?)?;
                let index = wallet.address_index_of(&address);
                Ok(json!({
                    "is_mine": index.is_some(),
                    "index": index,
                    "label": index.and_then(|i| self.labels().ok()?.get(&i).cloned()),
                }))
            }
            "validateaddress" => {
                let text: String = params.get(0, "address")?;
                let valid = Address::decode(&text, prefix).is_ok();
                Ok(json!({ "valid": valid, "network": self.0.network.to_string() }))
            }
            "exportviewingkey" => Ok(json!({
                "viewing_key": encode_full_viewing_key(wallet.keys().full_viewing_key(), prefix),
                "watch_only": wallet.keys().is_watch_only(),
            })),
            "estimatefee" => {
                let recipients: usize = params.opt(0, "recipients")?.unwrap_or(1);
                if recipients == 0 || recipients > MAX_RECIPIENTS {
                    return Err(RpcError::invalid_params(format!(
                        "between 1 and {MAX_RECIPIENTS} recipients"
                    )));
                }
                let class = action_class_for(recipients.saturating_add(1).max(2))?;
                Ok(json!({
                    "fee": fee_for_actions(class)?.raw().to_string(),
                    "actions": class,
                }))
            }
            "help" => Ok(json!(METHODS)),
            other => Err(unknown_method(other)),
        }
    }

    fn note_methods(&self, method: &str, params: &Params) -> core::result::Result<Value, RpcError> {
        let wallet = &self.0.wallet;
        match method {
            "getbalance" => {
                let min: u64 = params.opt(0, "min_confirmations")?.unwrap_or(1);
                self.balance_json(min)
            }
            "listunspent" | "listreceived" => {
                let min: u64 = params.opt(0, "min_confirmations")?.unwrap_or(1);
                let since: u32 = params.opt(1, "since_height")?.unwrap_or(0);
                let labels = self.labels()?;
                let locked = wallet.locked_positions()?;
                let notes = if method == "listunspent" {
                    wallet.unspent()?
                } else {
                    wallet.notes()?
                };
                let mut out = Vec::new();
                for note in notes.iter().filter(|n| n.height >= since) {
                    if self.confirmations(note.height)? >= min {
                        out.push(self.note_json(note, &labels, &locked)?);
                    }
                }
                Ok(Value::Array(out))
            }
            "gettransaction" => {
                let txid = parse_txid(&params.get::<String>(0, "txid")?)?;
                self.transaction_json(txid)
            }
            "sendmany" => {
                if wallet.keys().is_watch_only() {
                    return Err(RpcError::new(REJECTED, "watch-only wallet cannot spend"));
                }
                let recipients = self.recipients(&params.get::<Value>(0, "recipients")?)?;
                let min: u32 = params.opt(1, "min_confirmations")?.unwrap_or(1);
                let op = wallet.add_operation(recipients, min, now())?;
                self.0.wake.notify_one();
                Ok(json!({ "operation_id": op.id, "status": op.status.name() }))
            }
            "quotepayment" => {
                let recipients = self.recipients(&params.get::<Value>(0, "recipients")?)?;
                let min: u32 = params.opt(1, "min_confirmations")?.unwrap_or(1);
                self.quote_json(&recipients, min)
            }
            "getoperationstatus" => {
                let id: u64 = params.get(0, "operation_id")?;
                Ok(self.operation_json(&wallet.operation(id)?))
            }
            "listoperations" => {
                let status: Option<String> = params.opt(0, "status")?;
                Ok(json!(wallet
                    .operations()?
                    .iter()
                    .filter(|op| status.as_deref().is_none_or(|s| s == op.status.name()))
                    .map(|op| self.operation_json(op))
                    .collect::<Vec<_>>()))
            }
            "canceloperation" => {
                let id: u64 = params.get(0, "operation_id")?;
                let mut op = wallet.operation(id)?;
                if !is_cancellable(&op) {
                    return Err(RpcError::new(
                        REJECTED,
                        format!(
                            "operation is {}; only queued, never-broadcast ones can be cancelled",
                            op.status.name()
                        ),
                    ));
                }
                let previous = op.clone();
                op.status = OperationStatus::Cancelled;
                if !wallet.compare_and_swap_operation(&previous, &op)? {
                    return Err(RpcError::new(
                        REJECTED,
                        "operation changed; refresh its status",
                    ));
                }
                Ok(self.operation_json(&op))
            }
            other => Err(unknown_method(other)),
        }
    }
}

impl WalletDaemon {
    /// Disclosures for the outputs this wallet sent in `txid`, all of them
    /// or only `index`, each with what it proves.
    async fn payment_disclosures(
        &self,
        txid: TxId,
        index: Option<u32>,
    ) -> core::result::Result<Value, RpcError> {
        let height = self
            .0
            .wallet
            .notes()?
            .iter()
            .find(|n| n.spent_by == Some(txid))
            .and_then(|n| n.spent_at)
            .ok_or_else(|| RpcError::not_found("transaction sent by this wallet"))?;
        let mut client = self.0.node.connect().await?;
        let block = fetch_block(&mut client, height).await?;
        let tx = block
            .transactions()
            .iter()
            .find(|tx| tx.txid() == txid)
            .ok_or_else(|| RpcError::not_found("transaction"))?;
        let ovk = self.0.wallet.keys().outgoing_viewing_key();
        let prefix = self.0.params.address_prefix;
        let mut out = Vec::new();
        for (i, action) in tx.actions().iter().enumerate() {
            let i = u32::try_from(i).unwrap_or(u32::MAX);
            if index.is_some_and(|wanted| wanted != i) {
                continue;
            }
            let body = action.body();
            let Ok((pk_d, esk)) =
                recover_output_keys(ovk, body.encrypted_note(), body.cv_net(), body.cmx())
            else {
                continue;
            };
            let rho = Rho::from_nullifier(body.nullifier())?;
            let Ok((note, memo)) =
                decrypt_note_with_ovk(ovk, body.encrypted_note(), body.cv_net(), rho, body.cmx())
            else {
                continue;
            };
            if note.value().raw() == 0 {
                continue;
            }
            let disclosure = PaymentDisclosure {
                txid,
                index: i,
                pk_d,
                esk,
            };
            out.push(json!({
                "index": i,
                "disclosure": to_hex(&disclosure.to_vec()),
                "address": note.recipient().encode(prefix),
                "amount": note.value().raw().to_string(),
                "memo": memo_json(&memo),
            }));
        }
        if out.is_empty() {
            return Err(RpcError::not_found("output sent by this wallet"));
        }
        Ok(Value::Array(out))
    }

    /// Unspent value split by what a send may use now.
    /// The exact fee `recipients` would pay if queued now, selecting notes
    /// as the payment worker would at the wallet's scanned height.
    fn quote_json(
        &self,
        recipients: &[Payment],
        min_confirmations: u32,
    ) -> core::result::Result<Value, RpcError> {
        let tip = self.scanned_height()?.unwrap_or(0);
        // A note at height h has tip - h + 1 confirmations.
        let max_note_height = tip
            .saturating_add(1)
            .saturating_sub(min_confirmations.max(1));
        let excluded = self.pending_locks(None)?;
        let quote = quote_payments(&self.0.wallet, recipients, &excluded, max_note_height)
            .map_err(|error| match error {
                null_wallet::Error::InsufficientFunds { .. } => {
                    RpcError::new(REJECTED, error.to_string())
                }
                other => RpcError::from(Error::from(other)),
            })?;
        let sent = recipients
            .iter()
            .try_fold(Amount::ZERO, |acc, p| acc.checked_add(p.amount))
            .and_then(|sent| sent.checked_add(quote.fee))
            .map_err(|e| RpcError::from(Error::from(e)))?;
        Ok(json!({
            "fee": quote.fee.raw().to_string(),
            "total": sent.raw().to_string(),
            "spends": quote.spends,
            "actions": quote.actions,
        }))
    }

    fn balance_json(&self, min_confirmations: u64) -> core::result::Result<Value, RpcError> {
        let locked = self.0.wallet.locked_positions()?;
        let mut confirmed = 0u64;
        let mut pending = 0u64;
        let mut set_aside = 0u64;
        for note in self.0.wallet.unspent()? {
            let value = note.note.value().raw();
            if self.confirmations(note.height)? < min_confirmations {
                pending = pending.saturating_add(value);
            } else if locked.contains(&note.position) {
                set_aside = set_aside.saturating_add(value);
            } else {
                confirmed = confirmed.saturating_add(value);
            }
        }
        Ok(json!({
            "spendable": confirmed.to_string(),
            "locked": set_aside.to_string(),
            "pending": pending.to_string(),
            "total": confirmed
                .saturating_add(set_aside)
                .saturating_add(pending)
                .to_string(),
        }))
    }

    /// Our side of one transaction: notes it gave us and notes it spent.
    fn transaction_json(&self, txid: TxId) -> core::result::Result<Value, RpcError> {
        let labels = self.labels()?;
        let locked = self.0.wallet.locked_positions()?;
        let notes = self.0.wallet.notes()?;
        let received: Vec<&OwnedNote> = notes.iter().filter(|n| n.txid == Some(txid)).collect();
        let spent: Vec<&OwnedNote> = notes.iter().filter(|n| n.spent_by == Some(txid)).collect();
        if received.is_empty() && spent.is_empty() {
            return Err(RpcError::not_found("transaction"));
        }
        let sum = |notes: &[&OwnedNote]| -> i128 {
            notes.iter().map(|n| i128::from(n.note.value().raw())).sum()
        };
        let height = received
            .first()
            .map(|n| n.height)
            .or_else(|| spent.first().and_then(|n| n.spent_at));
        let render = |notes: &[&OwnedNote]| -> Result<Vec<Value>> {
            notes
                .iter()
                .map(|n| self.note_json(n, &labels, &locked))
                .collect()
        };
        Ok(json!({
            "txid": txid.to_string(),
            "height": height,
            "confirmations": height.map(|h| self.confirmations(h)).transpose()?,
            "received": render(&received)?,
            "spent": render(&spent)?,
            "net": sum(&received).saturating_sub(sum(&spent)).to_string(),
        }))
    }
}

fn parse_txid(text: &str) -> core::result::Result<TxId, RpcError> {
    let bytes: [u8; 32] = null_crypto::encoding::from_hex(text)?
        .try_into()
        .map_err(|_| RpcError::invalid_params("txid must be 32 bytes"))?;
    Ok(TxId::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use null_crypto::keys::SpendingKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn wallet_file() -> (tempfile::TempDir, Wallet) {
        let dir = tempfile::tempdir().unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(73);
        // The published testnet premine key, never a mainnet key.
        let key = SpendingKey::from_bytes(
            null_crypto::encoding::from_hex(
                "aeee2840de33f371c576fdde22e552725f6e7002c642a64cbfbaa71679dddaf3",
            )
            .unwrap()
            .try_into()
            .unwrap(),
        );
        let wallet = Wallet::create(
            dir.path().join("wallet.redb"),
            &key,
            genesis(&Network::Test.params()).hash(),
            b"pw",
            &mut rng,
        )
        .unwrap();
        (dir, wallet)
    }

    fn reopen(dir: &tempfile::TempDir) -> Wallet {
        Wallet::open(
            dir.path().join("wallet.redb"),
            genesis(&Network::Test.params()).hash(),
            b"pw",
        )
        .unwrap()
    }

    fn daemon(wallet: Wallet, node: Source) -> WalletDaemon {
        WalletDaemon::new(ServiceConfig {
            wallet,
            network: Network::Test,
            node,
            sync_interval: Duration::from_millis(10),
            light: true,
        })
    }

    fn offline_daemon(wallet: Wallet) -> WalletDaemon {
        daemon(wallet, Source::Embedded(tokio::sync::mpsc::channel(1).0))
    }

    fn payment(wallet: &Wallet) -> Operation {
        wallet
            .add_operation(
                vec![Payment {
                    recipient: wallet.keys().address(1u64.into()).unwrap(),
                    amount: Amount::from_raw(1_000).unwrap(),
                    memo: Memo::empty(),
                }],
                1,
                0,
            )
            .unwrap()
    }

    fn recorded_payment(wallet: &Wallet) -> Operation {
        let mut op = payment(wallet);
        let tx = genesis(&Network::Test.params()).transactions()[0].clone();
        op.status = OperationStatus::Submitted {
            txid: tx.txid(),
            built_at: 0,
        };
        op.transaction = Some(tx.to_vec());
        op.locked = vec![0];
        op.attempts = 1;
        wallet.put_operation(&op).unwrap();
        op
    }

    struct ScriptedControl {
        replies: VecDeque<Result<String>>,
        calls: Vec<String>,
    }

    impl ScriptedControl {
        fn new(replies: impl IntoIterator<Item = Result<String>>) -> Self {
            Self {
                replies: replies.into_iter().collect(),
                calls: Vec::new(),
            }
        }
    }

    impl Control for ScriptedControl {
        fn call(&mut self, line: &str) -> impl std::future::Future<Output = Result<String>> + Send {
            self.calls.push(line.into());
            std::future::ready(self.replies.pop_front().expect("unexpected node call"))
        }
    }

    struct CheckBeforeBroadcast<'a> {
        wallet: &'a Wallet,
        id: u64,
        reply: Option<Result<String>>,
    }

    impl Control for CheckBeforeBroadcast<'_> {
        async fn call(&mut self, line: &str) -> Result<String> {
            let saved = self.wallet.operation(self.id).unwrap();
            assert!(matches!(saved.status, OperationStatus::Submitted { .. }));
            assert_eq!(saved.locked, vec![0]);
            assert_eq!(
                line,
                format!("submit {}", to_hex(saved.transaction.as_ref().unwrap()))
            );
            // None simulates termination while waiting for a network response.
            match self.reply.take() {
                Some(reply) => reply,
                None => std::future::pending().await,
            }
        }
    }

    #[tokio::test]
    async fn broadcast_always_has_a_durable_record_and_errors_keep_its_reservation() {
        let (dir, wallet) = wallet_file();
        let daemon = offline_daemon(wallet);
        let tx = genesis(&Network::Test.params()).transactions()[0].clone();
        let mut ids = Vec::new();
        for reply in [
            Some(Ok(tx.txid().to_string())),
            Some(Err(Error::Argument("control socket timed out".into()))),
            Some(Err(Error::Argument("node refused".into()))),
            Some(Err(Error::Io(std::io::ErrorKind::ConnectionReset.into()))),
            None,
        ] {
            let mut op = payment(daemon.wallet());
            op.status = OperationStatus::Building;
            daemon.wallet().put_operation(&op).unwrap();
            ids.push(op.id);
            let succeeds = matches!(reply, Some(Ok(_)));
            let interrupted = reply.is_none();
            let mut client = CheckBeforeBroadcast {
                wallet: daemon.wallet(),
                id: op.id,
                reply,
            };
            let result = tokio::time::timeout(
                Duration::from_millis(50),
                daemon.persist_and_submit(
                    &mut client,
                    op,
                    Built {
                        transaction: tx.clone(),
                        spent: vec![0],
                    },
                    0,
                ),
            )
            .await;
            if interrupted {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().is_ok(), succeeds);
            }
        }
        drop(daemon);
        let wallet = reopen(&dir);
        for id in ids {
            let op = wallet.operation(id).unwrap();
            assert_eq!(
                op.status,
                OperationStatus::Submitted {
                    txid: tx.txid(),
                    built_at: 0
                }
            );
            assert_eq!(op.transaction, Some(tx.to_vec()));
            assert_eq!(op.locked, vec![0]);
        }
    }

    #[test]
    fn interrupted_builds_requeue_but_ambiguous_legacy_sends_require_reconciliation() {
        let (dir, wallet) = wallet_file();
        let mut resumable = payment(&wallet);
        resumable.status = OperationStatus::Building;
        resumable.attempts = 1;
        wallet.put_operation(&resumable).unwrap();
        let mut legacy = payment(&wallet);
        legacy.status = OperationStatus::Proving;
        wallet.put_operation(&legacy).unwrap();
        drop(wallet);
        let daemon = offline_daemon(reopen(&dir));
        daemon.recover_interrupted_operations().unwrap();
        resumable.status = OperationStatus::Queued;
        assert_eq!(daemon.wallet().operation(resumable.id).unwrap(), resumable);
        assert!(
            matches!(daemon.wallet().operation(legacy.id).unwrap().status,
            OperationStatus::Failed(reason) if reason.contains("may already have been broadcast"))
        );
        assert_eq!(
            daemon
                .note_methods("canceloperation", &Params::new(json!([resumable.id])))
                .unwrap()["status"],
            "cancelled"
        );
    }

    #[tokio::test]
    async fn stale_confirmations_reopen_resubmit_and_confirm_at_the_new_height() {
        let (dir, wallet) = wallet_file();
        let mut op = recorded_payment(&wallet);
        let txid = op.status.txid().unwrap();
        op.status = OperationStatus::Confirmed { txid, height: 10 };
        wallet.put_operation(&op).unwrap();
        drop(wallet);
        let daemon = offline_daemon(reopen(&dir));
        // This also works for compact scans, which have no note.spent_by txids.
        assert!(daemon.0.light);
        let mut client = ScriptedControl::new([
            Ok("unknown".into()),
            Ok(txid.to_string()),
            Ok("confirmed 3 1".into()),
        ]);
        daemon.reconcile_operations(&mut client, 0).await.unwrap();
        let pending = daemon.wallet().operation(op.id).unwrap();
        assert_eq!(
            pending.status,
            OperationStatus::Submitted { txid, built_at: 10 }
        );
        assert_eq!(daemon.wallet().locked_positions().unwrap(), vec![0]);
        assert_eq!(pending.transaction, op.transaction);
        daemon.follow(&mut client, pending, 10, 0).await.unwrap();
        assert_eq!(
            client.calls[1],
            format!("submit {}", to_hex(op.transaction.as_ref().unwrap()))
        );
        daemon.reconcile_operations(&mut client, 3).await.unwrap();
        let confirmed = daemon.wallet().operation(op.id).unwrap();
        assert_eq!(
            confirmed.status,
            OperationStatus::Confirmed { txid, height: 3 }
        );
        assert_eq!(
            confirmed.attempts, 1,
            "the same transaction was rebroadcast"
        );
    }

    #[tokio::test]
    async fn expired_transactions_stay_recorded_and_cannot_be_cancelled_before_rebuilding() {
        let (_dir, wallet) = wallet_file();
        let op = recorded_payment(&wallet);
        let daemon = offline_daemon(wallet);
        let mut client = ScriptedControl::new([]);
        daemon
            .follow(&mut client, op.clone(), 0, 101)
            .await
            .unwrap();
        let queued = daemon.wallet().operation(op.id).unwrap();
        assert_eq!(queued.status, OperationStatus::Queued);
        assert_eq!(queued.transaction, op.transaction);
        assert_eq!(queued.locked, op.locked);
        assert!(daemon
            .note_methods("canceloperation", &Params::new(json!([op.id])))
            .is_err());
        // An old transaction mined while a replacement was queued wins before
        // another proof starts.
        let mut client = ScriptedControl::new([Ok("confirmed 99 1".into())]);
        daemon.reconcile_operations(&mut client, 101).await.unwrap();
        assert!(matches!(
            daemon.wallet().operation(op.id).unwrap().status,
            OperationStatus::Confirmed { height: 99, .. }
        ));
    }

    #[tokio::test]
    async fn an_older_attempt_mined_after_a_reorg_is_recognized_and_retained() {
        let (dir, wallet) = wallet_file();
        let mut op = recorded_payment(&wallet);
        let original = genesis(&Network::Main.params()).transactions()[0].clone();
        op.previous_transactions.push(original.to_vec());
        wallet.put_operation(&op).unwrap();
        drop(wallet);
        let daemon = offline_daemon(reopen(&dir));
        let mut client = ScriptedControl::new([Ok("unknown".into()), Ok("confirmed 7 1".into())]);
        daemon.reconcile_operations(&mut client, 7).await.unwrap();
        let confirmed = daemon.wallet().operation(op.id).unwrap();
        assert_eq!(
            confirmed.status,
            OperationStatus::Confirmed {
                txid: original.txid(),
                height: 7
            }
        );
        assert_eq!(confirmed.transaction, Some(original.to_vec()));
        assert_eq!(
            confirmed.previous_transactions,
            vec![op.transaction.unwrap()]
        );
        // Another reorg can remove that confirmation too; both versions survive.
        let mut client = ScriptedControl::new([Ok("unknown".into()), Ok("unknown".into())]);
        daemon.reconcile_operations(&mut client, 0).await.unwrap();
        let pending = daemon.wallet().operation(op.id).unwrap();
        assert_eq!(
            pending.status,
            OperationStatus::Submitted {
                txid: original.txid(),
                built_at: 7
            }
        );
        assert_eq!(
            pending.previous_transactions,
            confirmed.previous_transactions
        );
        assert_eq!(daemon.wallet().locked_positions().unwrap(), vec![0]);
    }

    #[tokio::test]
    async fn failed_replacements_keep_pending_transactions_and_retry_limits_keep_locks() {
        let (_dir, wallet) = wallet_file();
        wallet.scan(&genesis(&Network::Test.params())).unwrap();
        let mut op = recorded_payment(&wallet);
        op.status = OperationStatus::Queued;
        op.attempts = MAX_ATTEMPTS;
        wallet.put_operation(&op).unwrap();
        let daemon = offline_daemon(wallet);
        let mut client = ScriptedControl::new([]);
        assert!(daemon
            .build_and_submit(&mut client, op.clone(), 101)
            .await
            .is_err());
        let pending = daemon.wallet().operation(op.id).unwrap();
        assert!(matches!(pending.status, OperationStatus::Submitted { .. }));
        assert_eq!(pending.transaction, op.transaction);
        assert_eq!(pending.locked, op.locked);
        assert!(daemon
            .build_failed(&pending, 101, "missing original inputs".into())
            .is_err());
        assert_eq!(daemon.wallet().operation(op.id).unwrap(), pending);
        let mut client = ScriptedControl::new([Err(Error::Argument("stale anchor".into()))]);
        assert!(daemon
            .follow(&mut client, pending.clone(), 101, 202)
            .await
            .is_err());
        assert_eq!(daemon.wallet().operation(op.id).unwrap(), pending);
        // A newly present note at a formerly locked position is insufficient:
        // the nullifier must belong to every previous transaction attempt.
        assert!(daemon.excluded_positions(&op).unwrap().contains(&0));
    }

    #[tokio::test]
    async fn cancelled_snapshots_cannot_start_a_prover_and_rescans_wait_for_active_work() {
        let (_dir, wallet) = wallet_file();
        let queued = payment(&wallet);
        let daemon = offline_daemon(wallet);
        daemon
            .note_methods("canceloperation", &Params::new(json!([queued.id])))
            .unwrap();
        let mut client = ScriptedControl::new([]);
        daemon
            .build_and_submit(&mut client, queued.clone(), 0)
            .await
            .unwrap();
        assert_eq!(
            daemon.wallet().operation(queued.id).unwrap().status,
            OperationStatus::Cancelled
        );
        let guard = daemon.0.sync_lock.lock().await;
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            daemon.call("rescan", &Params::new(json!([0])))
        )
        .await
        .is_err());
        drop(guard);
        daemon
            .call("rescan", &Params::new(json!([0])))
            .await
            .unwrap();
    }

    struct LoseSubmissionReply(crate::rpc::Connection);

    impl Control for LoseSubmissionReply {
        async fn call(&mut self, line: &str) -> Result<String> {
            let reply = self.0.call(line).await?;
            if line.starts_with("submit ") {
                return Err(Error::Io(std::io::ErrorKind::ConnectionReset.into()));
            }
            Ok(reply)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_prover_and_a_lost_acceptance_reply_preserve_one_real_payment() {
        let (dir, wallet) = wallet_file();
        wallet.scan(&genesis(&Network::Test.params())).unwrap();
        assert!(wallet.balance().unwrap() > 0);
        let mut op = payment(&wallet);
        op.status = OperationStatus::Building;
        op.attempts = 1;
        wallet.put_operation(&op).unwrap();
        drop(wallet);
        let node = crate::node::spawn(crate::config::Config::test())
            .await
            .unwrap();
        let source = Source::Embedded(node.events());
        let daemon = daemon(reopen(&dir), source.clone());
        daemon.recover_interrupted_operations().unwrap();
        let queued = daemon.wallet().operation(op.id).unwrap();
        assert_eq!(queued.status, OperationStatus::Queued);
        let mut client = LoseSubmissionReply(source.connect().await.unwrap());
        assert!(daemon
            .build_and_submit(&mut client, queued, 0)
            .await
            .is_err());
        let submitted = daemon.wallet().operation(op.id).unwrap();
        let txid = submitted.status.txid().unwrap();
        assert_eq!(submitted.attempts, 2);
        assert!(!submitted.locked.is_empty());
        let mut client = source.connect().await.unwrap();
        assert_eq!(
            transaction_status(&mut client, txid).await.unwrap(),
            TxStatus::Pooled
        );
        drop(daemon);
        let recovered = self::daemon(reopen(&dir), source);
        recovered.sync_once().await.unwrap();
        assert_eq!(recovered.wallet().operation(op.id).unwrap(), submitted);
        let mut relocated = recovered.wallet().notes().unwrap()[0].clone();
        relocated.position = 42;
        let mut reserved = submitted.clone();
        WalletDaemon::reserve_recorded_inputs(&mut reserved, &[relocated]).unwrap();
        assert!(
            reserved.locked.contains(&42),
            "a reorg cannot bypass input reservations by moving a note"
        );
        assert_eq!(
            transaction_status(&mut client, txid).await.unwrap(),
            TxStatus::Pooled
        );
        node.shutdown().await;
    }

    #[test]
    fn amounts_parse_from_strings_and_numbers_only() {
        assert_eq!(parse_amount(Some(&json!("12"))).unwrap().raw(), 12);
        assert_eq!(parse_amount(Some(&json!(7))).unwrap().raw(), 7);
        assert!(parse_amount(Some(&json!("x"))).is_err());
        assert!(parse_amount(Some(&json!(-1))).is_err());
        assert!(parse_amount(Some(&json!(1.5))).is_err());
        assert!(parse_amount(None).is_err());
        assert!(parse_amount(Some(&json!("99999999999999999999"))).is_err());
    }

    #[test]
    fn memos_render_as_text_hex_or_null() {
        assert_eq!(memo_json(&Memo::empty()), Value::Null);
        assert_eq!(memo_json(&Memo::from_text("hi").unwrap()), json!("hi"));
        let mut raw = [0u8; null_protocol::memo::MEMO_LEN];
        raw[0] = 0xff;
        assert!(memo_json(&Memo::from_bytes(raw))["hex"].is_string());
    }

    #[test]
    fn node_tokens_come_from_the_flag_or_a_readable_file() {
        let flag = node_token(Some("secret".into()), None, Network::Test).unwrap();
        assert!(flag.matches("secret"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc.token");
        Token::new("from-file").unwrap().write_to(&path).unwrap();
        let file = node_token(None, Some(path), Network::Test).unwrap();
        assert!(file.matches("from-file"));
        assert!(node_token(None, Some(dir.path().join("missing")), Network::Test).is_err());
    }

    #[test]
    fn quotes_reject_unfunded_payments_and_malformed_recipients() {
        let (_dir, wallet) = wallet_file();
        let address = wallet
            .keys()
            .address(1u64.into())
            .unwrap()
            .encode(Network::Test.address_prefix());
        let daemon = offline_daemon(wallet);
        let quote = |params: Value| daemon.note_methods("quotepayment", &Params::new(params));
        let unfunded = quote(json!([[{ "address": address, "amount": "1000" }]])).unwrap_err();
        assert_eq!(unfunded.code, REJECTED);
        assert!(unfunded.message.contains("insufficient funds"));
        for bad in [
            json!([[]]),
            json!([[{ "address": "nonsense", "amount": "1" }]]),
        ] {
            assert_eq!(quote(bad).unwrap_err().code, crate::jsonrpc::INVALID_PARAMS);
        }
    }

    #[test]
    fn only_queued_never_broadcast_operations_are_cancellable() {
        let (_dir, wallet) = wallet_file();
        let fresh = payment(&wallet);
        assert!(is_cancellable(&fresh));
        let mut requeued = recorded_payment(&wallet);
        requeued.status = OperationStatus::Queued;
        assert!(
            !is_cancellable(&requeued),
            "an earlier broadcast may be mined"
        );
        let daemon = offline_daemon(wallet);
        let listed = daemon
            .note_methods("getoperationstatus", &Params::new(json!([fresh.id])))
            .unwrap();
        assert_eq!(listed["cancellable"], true);
    }
}
