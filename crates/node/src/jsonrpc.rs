//! JSON-RPC 2.0 over HTTP: what exchanges, mining pools and tools
//! integrate against. One `POST` per connection, `Authorization: Bearer
//! <token>` with the control socket's token, batch requests allowed.
//!
//! Every method dispatches to the same [`Request`] enum the line protocol
//! uses, so both interfaces have one behaviour. Method names follow
//! Bitcoin's where the meaning is the same. Amounts are strings in the
//! smallest unit; hashes, ids and encoded objects are lowercase hex;
//! heights are numbers. See `docs/rpc.md`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use null_chain::equihash::PREFIX as EQUIHASH_PREFIX;
use null_chain::genesis::genesis;
use null_chain::params::ChainParams;
use null_chain::target::Target;
use null_circuit::proof::ProvingKey;
use null_crypto::encoding::{from_hex, to_hex};
use null_p2p::message::PROTOCOL_VERSION;
use null_p2p::peer::Direction;
use null_protocol::address::Address;
use null_protocol::amount::{COIN, MAX_MONEY};
use null_protocol::block::{Block, BlockHash, BlockHeader, PowSolution};
use null_protocol::bytes::Encodable;
use null_protocol::consensus::{
    next_height, proof_len, BranchId, ACTION_CLASSES, FEE_PER_ACTION, MAX_ACTIONS,
    MAX_BLOCK_TRANSACTIONS, PREMINE,
};
use null_protocol::disclosure::{Challenge, PaymentDisclosure};
use null_protocol::note::Rho;
use null_protocol::nullifier::Nullifier;
use null_protocol::transaction::{Transaction, TxId};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::config::{Network, MEMPOOL_CAPACITY};
use crate::http::{read_request, respond_with, Request as HttpRequest};
use crate::miner::Template;
use crate::node::{Event, Located, PeerSummary, Request, Response, Submission, TxStatus};
use crate::rpc::Token;
use crate::{now, Error, Result};

/// Largest request body accepted: a full block as hex fits with room.
pub const MAX_BODY: usize = 32 * 1024 * 1024;

/// The JSON-RPC version every request and response carries.
const VERSION: &str = "2.0";
/// A cached template is handed out again for this long after it was
/// built, so a pool asking every second does not cost a proof a second.
const TEMPLATE_REUSE_SECONDS: u64 = 5;
/// A template can be submitted against for this long.
const TEMPLATE_TTL_SECONDS: u64 = 600;
/// Templates kept at once; the oldest go first.
const MAX_TEMPLATES: usize = 64;
/// Longest a long-polling `getblocktemplate` waits for a new tip.
const LONG_POLL: Duration = Duration::from_secs(60);
/// How often a long poll checks the tip.
const LONG_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Standard error codes.
pub const PARSE_ERROR: i64 = -32700;
/// The request is not a well-formed JSON-RPC 2.0 call.
pub const INVALID_REQUEST: i64 = -32600;
/// No such method.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// A parameter is missing or of the wrong kind.
pub const INVALID_PARAMS: i64 = -32602;
/// The node failed while serving the call.
pub const INTERNAL_ERROR: i64 = -32603;
/// The token was missing or wrong.
pub const UNAUTHORIZED: i64 = -32001;
/// The block, transaction or nullifier asked for does not exist.
pub const NOT_FOUND: i64 = -1;
/// The node refused what was submitted; the message says why.
pub const REJECTED: i64 = -2;
/// The node loop is gone.
pub const NODE_STOPPED: i64 = -3;

/// Every method, for `help` and for the reference in `docs/rpc.md`.
pub const METHODS: &[&str] = &[
    "getblockchaininfo",
    "getblockcount",
    "getbestblockhash",
    "getblockhash",
    "getblock",
    "getblockheader",
    "getrawtransaction",
    "gettransactionstatus",
    "sendrawtransaction",
    "getrawmempool",
    "getmempoolinfo",
    "getnullifierstatus",
    "getcompactblock",
    "getpeerinfo",
    "getnetworkinfo",
    "getconnectioncount",
    "uptime",
    "stop",
    "help",
    "getmininginfo",
    "getblocktemplate",
    "submitblock",
    "verifypaymentdisclosure",
    "createchallenge",
];

/// A JSON-RPC error object.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RpcError {
    /// One of the codes above.
    pub code: i64,
    /// What went wrong.
    pub message: String,
    /// Extra detail, when there is any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    /// An error with a code and message.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// An `INVALID_PARAMS` error.
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    /// A `NOT_FOUND` error for `what`.
    pub fn not_found(what: &str) -> Self {
        Self::new(NOT_FOUND, format!("{what} not found"))
    }
}

impl From<null_crypto::Error> for RpcError {
    fn from(error: null_crypto::Error) -> Self {
        Self::invalid_params(error.to_string())
    }
}

impl From<null_protocol::Error> for RpcError {
    fn from(error: null_protocol::Error) -> Self {
        Self::invalid_params(error.to_string())
    }
}

impl From<null_wallet::Error> for RpcError {
    fn from(error: null_wallet::Error) -> Self {
        match error {
            null_wallet::Error::NoOperation(_) => Self::not_found("operation"),
            null_wallet::Error::InsufficientFunds { .. }
            | null_wallet::Error::WatchOnly
            | null_wallet::Error::TooManyRecipients(_) => Self::new(REJECTED, error.to_string()),
            null_wallet::Error::Protocol(_) | null_wallet::Error::Crypto(_) => {
                Self::invalid_params(error.to_string())
            }
            other => Self::new(INTERNAL_ERROR, other.to_string()),
        }
    }
}

impl From<Error> for RpcError {
    fn from(error: Error) -> Self {
        match error {
            Error::Stopped => Self::new(NODE_STOPPED, "node stopped"),
            Error::Argument(message) => Self::invalid_params(message),
            Error::Protocol(_) | Error::Crypto(_) | Error::Circuit(_) => {
                Self::invalid_params(error.to_string())
            }
            other => Self::new(INTERNAL_ERROR, other.to_string()),
        }
    }
}

/// A block template handed to a pool: everything but nonce and solution.
#[derive(Clone, Debug)]
struct CachedTemplate {
    payout: Address,
    header: BlockHeader,
    transactions: Vec<Transaction>,
    created_at: u64,
}

/// Templates by id, so a submission needs only the header fields the
/// pool changed.
#[derive(Default)]
struct TemplateCache {
    entries: HashMap<String, CachedTemplate>,
    next_id: u64,
}

impl TemplateCache {
    /// A recent template for `payout` on `parent`, if one is fresh.
    fn find(
        &self,
        payout: &Address,
        parent: BlockHash,
        at: u64,
    ) -> Option<(String, CachedTemplate)> {
        self.entries
            .iter()
            .filter(|(_, t)| {
                t.payout == *payout
                    && t.header.prev_hash == parent
                    && at.saturating_sub(t.created_at) < TEMPLATE_REUSE_SECONDS
            })
            .max_by_key(|(_, t)| t.created_at)
            .map(|(id, t)| (id.clone(), t.clone()))
    }

    /// Stores a template, dropping expired and surplus ones, and returns
    /// its id.
    fn insert(&mut self, template: CachedTemplate, at: u64) -> String {
        self.entries
            .retain(|_, t| at.saturating_sub(t.created_at) < TEMPLATE_TTL_SECONDS);
        while self.entries.len() >= MAX_TEMPLATES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, t)| t.created_at)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.next_id = self.next_id.saturating_add(1);
        let id = format!("{:016x}", self.next_id);
        self.entries.insert(id.clone(), template);
        id
    }

    fn get(&self, id: &str, at: u64) -> Option<CachedTemplate> {
        self.entries
            .get(id)
            .filter(|t| at.saturating_sub(t.created_at) < TEMPLATE_TTL_SECONDS)
            .cloned()
    }
}

/// What every method has: the way to the node, the network's constants,
/// and the mining state shared by every connection.
#[derive(Clone)]
pub struct Context {
    events: mpsc::Sender<Event>,
    network: Network,
    params: ChainParams,
    /// Built on the first template request; proving a coinbase needs it.
    proving_key: Arc<tokio::sync::OnceCell<Arc<ProvingKey>>>,
    templates: Arc<Mutex<TemplateCache>>,
}

impl Context {
    /// A context for `network`, sending requests to `events`.
    pub fn new(events: mpsc::Sender<Event>, network: Network) -> Self {
        Self {
            events,
            network,
            params: network.params(),
            proving_key: Arc::new(tokio::sync::OnceCell::new()),
            templates: Arc::new(Mutex::new(TemplateCache::default())),
        }
    }

    async fn proving_key(&self) -> core::result::Result<Arc<ProvingKey>, RpcError> {
        self.proving_key
            .get_or_try_init(|| async {
                tokio::task::spawn_blocking(ProvingKey::build)
                    .await
                    .map_err(|_| Error::Stopped)?
                    .map(Arc::new)
                    .map_err(Error::from)
            })
            .await
            .cloned()
            .map_err(RpcError::from)
    }

    async fn fetch_template(&self) -> core::result::Result<Template, RpcError> {
        let (reply, response) = oneshot::channel();
        self.events
            .send(Event::TemplateRequest(reply))
            .await
            .map_err(|_| Error::Stopped)?;
        response.await.map_err(|_| RpcError::from(Error::Stopped))
    }

    /// A template for `payout`: a fresh cached one, or one newly built
    /// and proved on the blocking pool.
    async fn template_for(
        &self,
        payout: Address,
    ) -> core::result::Result<(String, CachedTemplate), RpcError> {
        let (height, tip, _, _, syncing) = self.tip().await?;
        if syncing {
            return Err(RpcError::new(REJECTED, "node is syncing"));
        }
        let at = now();
        if let Some(found) = lock(&self.templates)?.find(&payout, tip, at) {
            return Ok(found);
        }
        let template = self.fetch_template().await?;
        if template.parent.height != height {
            return Err(RpcError::new(REJECTED, "tip moved; ask again"));
        }
        let pk = self.proving_key().await?;
        let (header, transactions) = tokio::task::spawn_blocking(move || {
            template.assemble(&payout, pk.as_ref(), &mut rand::rngs::OsRng)
        })
        .await
        .map_err(|_| Error::Stopped)??;
        // Age a template from when it became usable: proving the coinbase
        // can outlast the reuse window on a slow machine, which would make
        // every template stale on arrival and every request re-prove.
        let ready = now();
        let cached = CachedTemplate {
            payout,
            header,
            transactions,
            created_at: ready,
        };
        let id = lock(&self.templates)?.insert(cached.clone(), ready);
        Ok((id, cached))
    }

    /// Waits until the tip is no longer `seen`, or the long-poll limit.
    async fn wait_for_new_tip(&self, seen: BlockHash) -> core::result::Result<(), RpcError> {
        let deadline = tokio::time::Instant::now().checked_add(LONG_POLL);
        while deadline.is_some_and(|d| tokio::time::Instant::now() < d) {
            if self.tip().await?.1 != seen {
                return Ok(());
            }
            tokio::time::sleep(LONG_POLL_INTERVAL).await;
        }
        Ok(())
    }

    async fn ask(&self, request: Request) -> core::result::Result<Response, RpcError> {
        let (reply, response) = oneshot::channel();
        self.events
            .send(Event::Rpc { request, reply })
            .await
            .map_err(|_| Error::Stopped)?;
        match response.await.map_err(|_| Error::Stopped)? {
            Response::Failed(reason) => Err(RpcError::new(REJECTED, reason)),
            response => Ok(response),
        }
    }

    async fn tip(&self) -> core::result::Result<(u32, BlockHash, usize, usize, bool), RpcError> {
        match self.ask(Request::Status).await? {
            Response::Status {
                height,
                hash,
                peers,
                mempool,
                syncing,
                ..
            } => Ok((height, hash, peers, mempool, syncing)),
            other => Err(unexpected(&other)),
        }
    }

    /// A block by hash, with whether it is in the main chain.
    async fn block_by_hash(
        &self,
        hash: BlockHash,
    ) -> core::result::Result<Option<(Block, bool)>, RpcError> {
        let Response::Block(Some(block)) = self.ask(Request::BlockByHash(hash)).await? else {
            return Ok(None);
        };
        let in_main = matches!(
            self.ask(Request::Hash(block.header().height)).await?,
            Response::Hash(Some(at)) if at == hash
        );
        Ok(Some((*block, in_main)))
    }

    /// A block by height or hash, as the caller wrote it.
    async fn block_by_ref(
        &self,
        reference: &Value,
    ) -> core::result::Result<Option<(Block, bool)>, RpcError> {
        if let Some(height) = reference.as_u64() {
            let height = u32::try_from(height).map_err(|_| RpcError::invalid_params("height"))?;
            return match self.ask(Request::Block(height)).await? {
                Response::Block(Some(block)) => Ok(Some((*block, true))),
                _ => Ok(None),
            };
        }
        let text = reference
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("expected a height or a block hash"))?;
        self.block_by_hash(parse_hash(text)?).await
    }
}

/// Something that answers method calls: the node's methods, or the
/// wallet daemon's.
pub trait Dispatch: Clone + Send + Sync + 'static {
    /// Answers one call.
    fn call(
        &self,
        method: &str,
        params: &Params,
    ) -> impl core::future::Future<Output = core::result::Result<Value, RpcError>> + Send;
}

impl Dispatch for Context {
    async fn call(&self, method: &str, params: &Params) -> core::result::Result<Value, RpcError> {
        dispatch(self, method, params).await
    }
}

/// Serves the node's JSON-RPC forever, one request per connection.
pub async fn serve(
    listener: TcpListener,
    events: mpsc::Sender<Event>,
    token: Token,
    network: Network,
) {
    serve_with(listener, token, Context::new(events, network)).await;
}

/// Serves `dispatcher`'s methods forever behind `token`, one request per
/// connection.
pub async fn serve_with<D: Dispatch>(listener: TcpListener, token: Token, dispatcher: D) {
    while let Ok((stream, _)) = listener.accept().await {
        let dispatcher = dispatcher.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let _ = handle(&mut stream, &dispatcher, &token).await;
        });
    }
}

async fn handle<D: Dispatch>(stream: &mut TcpStream, dispatcher: &D, token: &Token) -> Result<()> {
    let request = match read_request(stream, MAX_BODY).await {
        Ok(request) => request,
        Err(Error::Io(error)) => return Err(Error::Io(error)),
        Err(error) => {
            let body = envelope_error(
                &RpcError::new(INVALID_REQUEST, error.to_string()),
                &Value::Null,
            );
            return respond_json(stream, "400 Bad Request", &body).await;
        }
    };
    if request.method != "POST" {
        let body = envelope_error(&RpcError::new(INVALID_REQUEST, "POST only"), &Value::Null);
        return respond_json(stream, "405 Method Not Allowed", &body).await;
    }
    if !authorized(&request, token) {
        let body = envelope_error(&RpcError::new(UNAUTHORIZED, "unauthorized"), &Value::Null);
        return respond_json(stream, "401 Unauthorized", &body).await;
    }
    let response = match serde_json::from_slice::<Value>(&request.body) {
        Ok(body) => process(dispatcher, body).await,
        Err(error) => envelope_error(&RpcError::new(PARSE_ERROR, error.to_string()), &Value::Null),
    };
    respond_json(stream, "200 OK", &response).await
}

/// Whether the request carries the token as a bearer credential.
fn authorized(request: &HttpRequest, token: &Token) -> bool {
    request
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|presented| token.matches(presented.trim()))
}

async fn respond_json(stream: &mut TcpStream, status: &str, body: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    respond_with(stream, status, "application/json", &bytes).await
}

/// Answers one call or one batch. Public so tests can drive it without
/// a socket.
pub async fn process<D: Dispatch>(dispatcher: &D, body: Value) -> Value {
    match body {
        Value::Array(calls) if calls.is_empty() => {
            envelope_error(&RpcError::new(INVALID_REQUEST, "empty batch"), &Value::Null)
        }
        Value::Array(calls) => {
            let mut answers = Vec::with_capacity(calls.len());
            for call in calls {
                answers.push(call_one(dispatcher, call).await);
            }
            Value::Array(answers)
        }
        call => call_one(dispatcher, call).await,
    }
}

async fn call_one<D: Dispatch>(dispatcher: &D, call: Value) -> Value {
    let id = call.get("id").cloned().unwrap_or(Value::Null);
    match parse_call(&call) {
        Err(error) => envelope_error(&error, &id),
        Ok((method, params)) => match dispatcher.call(&method, &params).await {
            Ok(result) => json!({ "jsonrpc": VERSION, "result": result, "id": id }),
            Err(error) => envelope_error(&error, &id),
        },
    }
}

fn envelope_error(error: &RpcError, id: &Value) -> Value {
    json!({ "jsonrpc": VERSION, "error": error, "id": id })
}

fn parse_call(call: &Value) -> core::result::Result<(String, Params), RpcError> {
    let object = call
        .as_object()
        .ok_or_else(|| RpcError::new(INVALID_REQUEST, "call must be an object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some(VERSION) {
        return Err(RpcError::new(INVALID_REQUEST, "jsonrpc must be \"2.0\""));
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(INVALID_REQUEST, "method must be a string"))?;
    let params = match object.get("params") {
        None | Some(Value::Null) => Params(Value::Array(Vec::new())),
        Some(value @ (Value::Array(_) | Value::Object(_))) => Params(value.clone()),
        Some(_) => {
            return Err(RpcError::new(
                INVALID_REQUEST,
                "params must be an array or an object",
            ))
        }
    };
    Ok((method.to_string(), params))
}

/// Call parameters, positional or named.
#[derive(Clone, Debug)]
pub struct Params(Value);

impl Params {
    /// Parameters from an array or object value.
    pub fn new(value: Value) -> Self {
        Self(value)
    }

    fn raw(&self, index: usize, name: &str) -> Option<&Value> {
        match &self.0 {
            Value::Array(items) => items.get(index),
            Value::Object(map) => map.get(name),
            _ => None,
        }
        .filter(|v| !v.is_null())
    }

    /// The parameter, required.
    ///
    /// # Errors
    /// `INVALID_PARAMS` if absent or of the wrong type.
    pub fn get<T: DeserializeOwned>(
        &self,
        index: usize,
        name: &str,
    ) -> core::result::Result<T, RpcError> {
        self.opt(index, name)?
            .ok_or_else(|| RpcError::invalid_params(format!("missing parameter {name}")))
    }

    /// The parameter, if given.
    ///
    /// # Errors
    /// `INVALID_PARAMS` if present but of the wrong type.
    pub fn opt<T: DeserializeOwned>(
        &self,
        index: usize,
        name: &str,
    ) -> core::result::Result<Option<T>, RpcError> {
        self.raw(index, name)
            .map(|value| {
                serde_json::from_value(value.clone())
                    .map_err(|e| RpcError::invalid_params(format!("parameter {name}: {e}")))
            })
            .transpose()
    }
}

async fn dispatch(
    context: &Context,
    method: &str,
    params: &Params,
) -> core::result::Result<Value, RpcError> {
    let answer = block_methods(context, method, params).await;
    if !is_unknown(&answer) {
        return answer;
    }
    let answer = mining_methods(context, method, params).await;
    if !is_unknown(&answer) {
        return answer;
    }
    let answer = disclosure_methods(context, method, params).await;
    if !is_unknown(&answer) {
        return answer;
    }
    other_methods(context, method, params).await
}

/// Whether a group declined the method, so the next group gets it.
fn is_unknown(answer: &core::result::Result<Value, RpcError>) -> bool {
    matches!(answer, Err(error) if error.code == METHOD_NOT_FOUND)
}

fn lock<T>(mutex: &Mutex<T>) -> core::result::Result<std::sync::MutexGuard<'_, T>, RpcError> {
    mutex
        .lock()
        .map_err(|_| RpcError::new(INTERNAL_ERROR, "template cache poisoned"))
}

/// The methods a mining pool uses.
async fn mining_methods(
    context: &Context,
    method: &str,
    params: &Params,
) -> core::result::Result<Value, RpcError> {
    match method {
        "getmininginfo" => match context.ask(Request::MiningInfo).await? {
            Response::MiningInfo(info) => Ok(json!({
                "height": info.height,
                "best_block_hash": info.hash.to_string(),
                "syncing": info.syncing,
                "next_height": next_height(info.height).map_or(Value::Null, |h| json!(h)),
                "next_target": format!("{:08x}", info.next_target),
                "next_target_hex": target_hex(info.next_target),
                "pow_limit": format!("{:08x}", context.params.pow_limit.to_compact()),
                "subsidy": info.subsidy.to_string(),
                "mempool": info.mempool,
                "work_per_second": info.work_per_second,
                "block_interval": context.params.block_interval,
                "equihash": equihash_json(&context.params),
            })),
            other => Err(unexpected(&other)),
        },
        "getblocktemplate" => {
            let address: String = params.get(0, "payout_address")?;
            let payout = Address::decode(&address, context.params.address_prefix)?;
            if let Some(seen) = params.opt::<String>(1, "longpollid")? {
                context.wait_for_new_tip(parse_hash(&seen)?).await?;
            }
            let (id, template) = context.template_for(payout).await?;
            Ok(template_json(context, &id, &template))
        }
        "submitblock" => {
            let block = if params.opt::<Value>(1, "timestamp")?.is_some() {
                let id: String = params.get(0, "template_id")?;
                let cached = lock(&context.templates)?
                    .get(&id, now())
                    .ok_or_else(|| RpcError::new(REJECTED, "unknown or expired template"))?;
                let mut header = cached.header;
                header.timestamp = params.get(1, "timestamp")?;
                header.nonce = parse_nonce(&params.get::<String>(2, "nonce")?)?;
                header.solution = parse_solution(&params.get::<String>(3, "solution")?)?;
                Block::new(header, cached.transactions)
            } else {
                let hex: String = params.get(0, "block")?;
                Block::from_slice(&from_hex(&hex)?)?
            };
            let hash = block.hash();
            match context.ask(Request::SubmitBlock(Box::new(block))).await? {
                Response::BlockSubmitted(Submission::Rejected(reason)) => {
                    Err(RpcError::new(REJECTED, reason))
                }
                Response::BlockSubmitted(outcome) => Ok(json!({
                    "status": match outcome {
                        Submission::Accepted => "accepted",
                        Submission::Duplicate => "duplicate",
                        Submission::Stale => "stale",
                        Submission::Rejected(_) => "rejected",
                    },
                    "hash": hash.to_string(),
                })),
                other => Err(unexpected(&other)),
            }
        }
        other => Err(unknown_method(other)),
    }
}

fn template_json(context: &Context, id: &str, template: &CachedTemplate) -> Value {
    let header = &template.header;
    let fees: u64 = template
        .transactions
        .iter()
        .skip(1)
        .filter_map(|tx| tx.fee().ok())
        .map(null_protocol::amount::Amount::raw)
        .sum();
    let coinbase_value = null_protocol::consensus::subsidy(header.height)
        .raw()
        .saturating_add(fees);
    json!({
        "template_id": id,
        "height": header.height,
        "prev_hash": header.prev_hash.to_string(),
        "longpollid": header.prev_hash.to_string(),
        "branch": branch_hex(context.params.branch_at(header.height)),
        "version": header.version,
        "timestamp": header.timestamp,
        "min_timestamp": header.timestamp,
        "max_timestamp": now().saturating_add(context.params.max_future_seconds),
        "commitment_root": to_hex(&header.commitment_root.to_bytes()),
        "tx_root": to_hex(&header.tx_root),
        "target": format!("{:08x}", header.target),
        "target_hex": target_hex(header.target),
        "pow_input": to_hex(&header.pow_input()),
        "equihash": equihash_json(&context.params),
        "transaction_count": template.transactions.len(),
        "coinbase_value": coinbase_value.to_string(),
        "fees": fees.to_string(),
        "expires_at": template.created_at.saturating_add(TEMPLATE_TTL_SECONDS),
    })
}

fn equihash_json(params: &ChainParams) -> Value {
    json!({
        "n": params.equihash.n(),
        "k": params.equihash.k(),
        "personalization": to_hex(&EQUIHASH_PREFIX),
        "solution_length": params.equihash.solution_len(),
    })
}

fn target_hex(compact: u32) -> String {
    Target::from_compact(compact)
        .map(|t| format!("{:064x}", t.as_u256()))
        .unwrap_or_default()
}

fn parse_nonce(text: &str) -> core::result::Result<[u8; 32], RpcError> {
    from_hex(text)?
        .try_into()
        .map_err(|_| RpcError::invalid_params("nonce must be 32 bytes"))
}

fn parse_solution(text: &str) -> core::result::Result<PowSolution, RpcError> {
    let bytes = from_hex(text)?;
    let mut padded = [0u8; null_protocol::consensus::POW_SOLUTION_LEN];
    let slot = padded
        .get_mut(..bytes.len())
        .ok_or_else(|| RpcError::invalid_params("solution too long"))?;
    slot.copy_from_slice(&bytes);
    Ok(PowSolution::from_bytes(padded))
}

/// A `METHOD_NOT_FOUND` error.
pub fn unknown_method(method: &str) -> RpcError {
    RpcError::new(METHOD_NOT_FOUND, format!("unknown method {method}"))
}

/// The methods about blocks; any other name is `METHOD_NOT_FOUND`.
async fn block_methods(
    context: &Context,
    method: &str,
    params: &Params,
) -> core::result::Result<Value, RpcError> {
    match method {
        "getblockchaininfo" => blockchain_info(context).await,
        "getblockcount" => Ok(json!(context.tip().await?.0)),
        "getbestblockhash" => Ok(json!(context.tip().await?.1.to_string())),
        "getblockhash" => {
            let height: u32 = params.get(0, "height")?;
            match context.ask(Request::Hash(height)).await? {
                Response::Hash(Some(hash)) => Ok(json!(hash.to_string())),
                _ => Err(RpcError::not_found("block")),
            }
        }
        "getblock" => {
            let reference: Value = params.get(0, "block")?;
            let verbosity: u8 = params.opt(1, "verbosity")?.unwrap_or(1);
            let (block, in_main) = context
                .block_by_ref(&reference)
                .await?
                .ok_or_else(|| RpcError::not_found("block"))?;
            if verbosity == 0 {
                return Ok(json!(to_hex(&block.to_vec())));
            }
            let tip = context.tip().await?.0;
            let next = next_hash(context, &block, in_main).await?;
            Ok(block_json(&block, in_main, tip, next, verbosity >= 2))
        }
        "getblockheader" => {
            let reference: Value = params.get(0, "block")?;
            let (block, in_main) = context
                .block_by_ref(&reference)
                .await?
                .ok_or_else(|| RpcError::not_found("block"))?;
            let tip = context.tip().await?.0;
            let next = next_hash(context, &block, in_main).await?;
            let mut header = block_json(&block, in_main, tip, next, false);
            if let Some(object) = header.as_object_mut() {
                object.remove("tx");
            }
            Ok(header)
        }
        "getcompactblock" => {
            let height: u32 = params.get(0, "height")?;
            match context.ask(Request::Compact(height)).await? {
                Response::Compact(Some(block)) => Ok(json!(to_hex(&block.to_vec()))),
                _ => Err(RpcError::not_found("block")),
            }
        }
        other => Err(unknown_method(other)),
    }
}

/// Every method that is not about blocks.
async fn other_methods(
    context: &Context,
    method: &str,
    params: &Params,
) -> core::result::Result<Value, RpcError> {
    match method {
        "getrawtransaction" => {
            let txid = parse_txid(&params.get::<String>(0, "txid")?)?;
            let verbose: bool = params.opt(1, "verbose")?.unwrap_or(false);
            let Response::Transaction(Some(Located { tx, location })) =
                context.ask(Request::Transaction(txid)).await?
            else {
                return Err(RpcError::not_found("transaction"));
            };
            if !verbose {
                return Ok(json!(to_hex(&tx.to_vec())));
            }
            let tip = context.tip().await?.0;
            Ok(transaction_json(&tx, location, tip))
        }
        "gettransactionstatus" => {
            let txid = parse_txid(&params.get::<String>(0, "txid")?)?;
            let Response::TransactionStatus(status) =
                context.ask(Request::TransactionStatus(txid)).await?
            else {
                return Err(RpcError::new(INTERNAL_ERROR, "unexpected response"));
            };
            let tip = context.tip().await?.0;
            Ok(status_json(status, tip))
        }
        "sendrawtransaction" => {
            let hex: String = params.get(0, "hex")?;
            let tx = Transaction::from_slice(&from_hex(&hex)?)?;
            match context.ask(Request::Submit(Box::new(tx))).await? {
                Response::Submitted(txid) => Ok(json!(txid.to_string())),
                other => Err(unexpected(&other)),
            }
        }
        "getrawmempool" => match context.ask(Request::MempoolTxids).await? {
            Response::Txids(txids) => Ok(json!(txids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>())),
            other => Err(unexpected(&other)),
        },
        "getmempoolinfo" => {
            let (_, _, _, size, _) = context.tip().await?;
            Ok(json!({ "size": size, "capacity": MEMPOOL_CAPACITY }))
        }
        "getnullifierstatus" => {
            let nullifier = parse_nullifier(&params.get::<String>(0, "nullifier")?)?;
            match context.ask(Request::IsSpent(nullifier)).await? {
                Response::Spent(spent) => Ok(json!({ "spent": spent })),
                other => Err(unexpected(&other)),
            }
        }
        "getpeerinfo" => Ok(json!(peers(context)
            .await?
            .iter()
            .map(peer_json)
            .collect::<Vec<_>>())),
        "getnetworkinfo" => {
            let peers = peers(context).await?;
            let count = |direction: Direction| {
                peers
                    .iter()
                    .filter(|p| p.ready && p.direction == direction)
                    .count()
            };
            Ok(json!({
                "network": context.network.to_string(),
                "protocol_version": PROTOCOL_VERSION,
                "connections": peers.iter().filter(|p| p.ready).count(),
                "connections_in": count(Direction::Inbound),
                "connections_out": count(Direction::Outbound),
                "handshaking": peers.iter().filter(|p| !p.ready).count(),
            }))
        }
        "getconnectioncount" => Ok(json!(context.tip().await?.2)),
        "uptime" => match context.ask(Request::Metrics).await? {
            Response::Metrics(metrics) => Ok(json!(metrics.uptime_seconds)),
            other => Err(unexpected(&other)),
        },
        "stop" => match context.ask(Request::Stop).await? {
            Response::Stopping => Ok(json!("stopping")),
            other => Err(unexpected(&other)),
        },
        "help" => Ok(json!(METHODS)),
        other => Err(unknown_method(other)),
    }
}

/// The selective-disclosure methods, which need no keys on the node.
async fn disclosure_methods(
    context: &Context,
    method: &str,
    params: &Params,
) -> core::result::Result<Value, RpcError> {
    match method {
        "verifypaymentdisclosure" => {
            let hex: String = params.get(0, "disclosure")?;
            let disclosure = PaymentDisclosure::from_slice(&from_hex(&hex)?)?;
            verify_disclosure(context, &disclosure).await
        }
        "createchallenge" => {
            let address = Address::decode(
                &params.get::<String>(0, "address")?,
                context.params.address_prefix,
            )?;
            let message: String = params.get(1, "message")?;
            let challenge = Challenge::create(&address, &message, &mut rand::rngs::OsRng)?;
            Ok(json!({ "challenge": to_hex(&challenge.to_vec()) }))
        }
        other => Err(unknown_method(other)),
    }
}

/// Opens the output a disclosure names and reports what it proves, or
/// why it proves nothing. Invalid disclosures are a result, not an
/// error: the caller wants to know.
async fn verify_disclosure(
    context: &Context,
    disclosure: &PaymentDisclosure,
) -> core::result::Result<Value, RpcError> {
    let Response::Transaction(Some(Located { tx, location })) =
        context.ask(Request::Transaction(disclosure.txid)).await?
    else {
        return Ok(json!({ "valid": false, "reason": "transaction not found" }));
    };
    let Some(action) = usize::try_from(disclosure.index)
        .ok()
        .and_then(|i| tx.actions().get(i))
    else {
        return Ok(json!({ "valid": false, "reason": "no such action" }));
    };
    let body = action.body();
    let rho = Rho::from_nullifier(body.nullifier())?;
    match disclosure.open(body.encrypted_note(), rho, body.cmx()) {
        Ok((note, memo)) => {
            let tip = context.tip().await?.0;
            Ok(json!({
                "valid": true,
                "txid": disclosure.txid.to_string(),
                "index": disclosure.index,
                "address": note.recipient().encode(context.params.address_prefix),
                "amount": note.value().raw().to_string(),
                "memo": memo.to_text(),
                "height": location.map(|(h, _)| h),
                "confirmations": location.map_or(0, |(h, _)| confirmations(h, tip, true)),
            }))
        }
        Err(error) => Ok(json!({ "valid": false, "reason": error.to_string() })),
    }
}

async fn blockchain_info(context: &Context) -> core::result::Result<Value, RpcError> {
    let (height, hash, _, _, syncing) = context.tip().await?;
    let params = &context.params;
    let proof_lengths: BTreeMap<String, usize> = ACTION_CLASSES
        .iter()
        .filter_map(|class| proof_len(*class).map(|len| (class.to_string(), len)).ok())
        .collect();
    let next =
        next_height(height).map_or_else(|_| params.branch_at(height), |h| params.branch_at(h));
    Ok(json!({
        "network": context.network.to_string(),
        "height": height,
        "best_block_hash": hash.to_string(),
        "genesis_hash": genesis(params).hash().to_string(),
        "syncing": syncing,
        "branch": branch_hex(params.branch_at(height)),
        "next_branch": branch_hex(next),
        "genesis_branch": branch_hex(params.genesis_branch),
        "upgrades": params.upgrades.iter().map(|u| json!({
            "height": u.height,
            "branch": branch_hex(u.branch),
        })).collect::<Vec<_>>(),
        "block_interval": params.block_interval,
        "difficulty_window": params.difficulty_window,
        "anchor_max_age": params.anchor_max_age,
        "max_reorg_depth": params.max_reorg_depth,
        "max_future_seconds": params.max_future_seconds,
        "pow_limit": format!("{:08x}", params.pow_limit.to_compact()),
        "equihash": { "n": params.equihash.n(), "k": params.equihash.k() },
        "fee_per_action": FEE_PER_ACTION.to_string(),
        "action_classes": ACTION_CLASSES,
        "max_actions": MAX_ACTIONS,
        "proof_lengths": proof_lengths,
        "max_block_transactions": MAX_BLOCK_TRANSACTIONS,
        "coinbase_maturity": params.coinbase_maturity,
        "coin": COIN.to_string(),
        "max_money": MAX_MONEY.to_string(),
        "premine": PREMINE.to_string(),
    }))
}

async fn peers(context: &Context) -> core::result::Result<Vec<PeerSummary>, RpcError> {
    match context.ask(Request::Peers).await? {
        Response::Peers(peers) => Ok(peers),
        other => Err(unexpected(&other)),
    }
}

/// The hash of the block after `block` on the main chain, if any.
async fn next_hash(
    context: &Context,
    block: &Block,
    in_main: bool,
) -> core::result::Result<Option<BlockHash>, RpcError> {
    if !in_main {
        return Ok(None);
    }
    let Ok(next) = next_height(block.header().height) else {
        return Ok(None);
    };
    match context.ask(Request::Hash(next)).await? {
        Response::Hash(hash) => Ok(hash),
        other => Err(unexpected(&other)),
    }
}

fn unexpected(response: &Response) -> RpcError {
    RpcError::new(
        INTERNAL_ERROR,
        format!("unexpected response {}", variant_name(response)),
    )
}

fn variant_name(response: &Response) -> &'static str {
    match response {
        Response::Status { .. } => "status",
        Response::Block(_) => "block",
        Response::Compact(_) => "compact",
        Response::Coinbase(_) => "coinbase",
        Response::Hash(_) => "hash",
        Response::Submitted(_) => "submitted",
        Response::Spent(_) => "spent",
        Response::Metrics(_) => "metrics",
        Response::Transaction(_) => "transaction",
        Response::TransactionStatus(_) => "transaction status",
        Response::Txids(_) => "txids",
        Response::Peers(_) => "peers",
        Response::Stopping => "stopping",
        Response::BlockSubmitted(_) => "block submitted",
        Response::MiningInfo(_) => "mining info",
        Response::Failed(_) => "failed",
    }
}

fn parse_hash(text: &str) -> core::result::Result<BlockHash, RpcError> {
    let bytes: [u8; 32] = from_hex(text)?
        .try_into()
        .map_err(|_| RpcError::invalid_params("block hash must be 32 bytes"))?;
    Ok(BlockHash::from_bytes(bytes))
}

fn parse_txid(text: &str) -> core::result::Result<TxId, RpcError> {
    let bytes: [u8; 32] = from_hex(text)?
        .try_into()
        .map_err(|_| RpcError::invalid_params("txid must be 32 bytes"))?;
    Ok(TxId::from_bytes(bytes))
}

fn parse_nullifier(text: &str) -> core::result::Result<Nullifier, RpcError> {
    let bytes: [u8; 32] = from_hex(text)?
        .try_into()
        .map_err(|_| RpcError::invalid_params("nullifier must be 32 bytes"))?;
    Ok(Nullifier::from_bytes(&bytes)?)
}

/// A branch id as `0x` hex of its 32-bit value.
fn branch_hex(branch: BranchId) -> String {
    format!("0x{:08x}", u32::from_le_bytes(branch.to_bytes()))
}

/// Confirmations Bitcoin-style: blocks including this one up to the tip,
/// or -1 off the main chain.
fn confirmations(height: u32, tip: u32, in_main: bool) -> i64 {
    if in_main {
        i64::from(tip.saturating_sub(height)).saturating_add(1)
    } else {
        -1
    }
}

fn header_json(header: &BlockHeader) -> serde_json::Map<String, Value> {
    let mut object = serde_json::Map::new();
    object.insert("hash".into(), json!(header.hash().to_string()));
    object.insert("height".into(), json!(header.height));
    object.insert("version".into(), json!(header.version));
    object.insert(
        "previousblockhash".into(),
        json!(header.prev_hash.to_string()),
    );
    object.insert("time".into(), json!(header.timestamp));
    object.insert(
        "commitment_root".into(),
        json!(to_hex(&header.commitment_root.to_bytes())),
    );
    object.insert("tx_root".into(), json!(to_hex(&header.tx_root)));
    object.insert("target".into(), json!(format!("{:08x}", header.target)));
    object.insert("target_hex".into(), json!(target_hex(header.target)));
    object.insert("nonce".into(), json!(to_hex(&header.nonce)));
    object.insert("solution".into(), json!(to_hex(header.solution.as_bytes())));
    object
}

fn block_json(
    block: &Block,
    in_main: bool,
    tip: u32,
    next: Option<BlockHash>,
    decode: bool,
) -> Value {
    let header = block.header();
    let mut object = header_json(header);
    object.insert("size".into(), json!(block.to_vec().len()));
    object.insert("in_main_chain".into(), json!(in_main));
    object.insert(
        "confirmations".into(),
        json!(confirmations(header.height, tip, in_main)),
    );
    object.insert(
        "nextblockhash".into(),
        next.map_or(Value::Null, |h| json!(h.to_string())),
    );
    object.insert(
        "transaction_count".into(),
        json!(block.transactions().len()),
    );
    let tx: Vec<Value> = block
        .transactions()
        .iter()
        .enumerate()
        .map(|(index, tx)| {
            if decode {
                let location =
                    in_main.then(|| (header.height, u32::try_from(index).unwrap_or(u32::MAX)));
                transaction_json(tx, location, tip)
            } else {
                json!(tx.txid().to_string())
            }
        })
        .collect();
    object.insert("tx".into(), Value::Array(tx));
    Value::Object(object)
}

/// The public view of a transaction: what the chain itself reveals.
fn transaction_json(tx: &Transaction, location: Option<(u32, u32)>, tip: u32) -> Value {
    let actions: Vec<Value> = tx
        .actions()
        .iter()
        .map(|action| {
            let body = action.body();
            json!({
                "nullifier": to_hex(&body.nullifier().to_bytes()),
                "rk": to_hex(&body.rk().to_bytes()),
                "cmx": to_hex(&body.cmx().to_vec()),
                "cv_net": to_hex(&body.cv_net().to_bytes()),
            })
        })
        .collect();
    let mut object = serde_json::Map::new();
    object.insert("txid".into(), json!(tx.txid().to_string()));
    object.insert("version".into(), json!(tx.version()));
    object.insert("anchor".into(), json!(to_hex(&tx.anchor().to_bytes())));
    object.insert("action_count".into(), json!(tx.actions().len()));
    object.insert("actions".into(), Value::Array(actions));
    object.insert(
        "fee".into(),
        json!(tx.fee().map(|f| f.raw().to_string()).unwrap_or_default()),
    );
    object.insert("size".into(), json!(tx.to_vec().len()));
    object.insert("proof_size".into(), json!(tx.proof().as_bytes().len()));
    match location {
        Some((height, index)) => {
            object.insert("height".into(), json!(height));
            object.insert("index".into(), json!(index));
            object.insert(
                "confirmations".into(),
                json!(confirmations(height, tip, true)),
            );
        }
        None => {
            object.insert("confirmations".into(), json!(0));
        }
    }
    Value::Object(object)
}

fn status_json(status: TxStatus, tip: u32) -> Value {
    match status {
        TxStatus::Pooled => json!({ "status": "pooled", "confirmations": 0 }),
        TxStatus::Confirmed { height, index } => json!({
            "status": "confirmed",
            "height": height,
            "index": index,
            "confirmations": confirmations(height, tip, true),
        }),
        TxStatus::Unknown => json!({ "status": "unknown" }),
    }
}

fn peer_json(peer: &PeerSummary) -> Value {
    json!({
        "id": peer.id,
        "addr": peer.addr.to_string(),
        "target": peer.target,
        "direction": match peer.direction {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        },
        "ready": peer.ready,
        "version": peer.version,
        "best_height": peer.best_height,
        "score": peer.score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_are_validated_before_dispatch() {
        assert!(parse_call(&json!({"jsonrpc": "2.0", "method": "x"})).is_ok());
        assert!(parse_call(&json!({"jsonrpc": "2.0", "method": "x", "params": [1]})).is_ok());
        assert!(parse_call(&json!({"jsonrpc": "2.0", "method": "x", "params": {"a": 1}})).is_ok());
        for bad in [
            json!([]),
            json!({"method": "x"}),
            json!({"jsonrpc": "1.0", "method": "x"}),
            json!({"jsonrpc": "2.0"}),
            json!({"jsonrpc": "2.0", "method": "x", "params": 3}),
        ] {
            assert_eq!(parse_call(&bad).unwrap_err().code, INVALID_REQUEST, "{bad}");
        }
    }

    #[test]
    fn params_are_positional_or_named() {
        let positional = Params(json!([7, "abc"]));
        assert_eq!(positional.get::<u32>(0, "height").unwrap(), 7);
        assert_eq!(positional.get::<String>(1, "hash").unwrap(), "abc");
        assert!(positional.opt::<u32>(2, "missing").unwrap().is_none());
        assert_eq!(
            positional.get::<u32>(2, "missing").unwrap_err().code,
            INVALID_PARAMS
        );
        assert_eq!(
            positional.get::<u32>(1, "hash").unwrap_err().code,
            INVALID_PARAMS
        );
        let named = Params(json!({"height": 7, "verbosity": null}));
        assert_eq!(named.get::<u32>(0, "height").unwrap(), 7);
        assert!(named.opt::<u8>(1, "verbosity").unwrap().is_none());
    }

    #[test]
    fn confirmations_count_from_the_block_to_the_tip() {
        assert_eq!(confirmations(10, 10, true), 1);
        assert_eq!(confirmations(7, 10, true), 4);
        assert_eq!(confirmations(7, 10, false), -1);
        assert_eq!(
            confirmations(11, 10, true),
            1,
            "never below one on the main chain"
        );
    }

    #[test]
    fn hex_parameters_are_checked_for_length() {
        assert_eq!(parse_hash("00").unwrap_err().code, INVALID_PARAMS);
        assert_eq!(parse_txid("zz").unwrap_err().code, INVALID_PARAMS);
        assert!(parse_hash(&"00".repeat(32)).is_ok());
        assert_eq!(branch_hex(BranchId::new(0x5445_5354)), "0x54455354");
    }

    fn cached(payout: Address, parent: BlockHash, created_at: u64) -> CachedTemplate {
        let mut header = null_protocol::block::empty_header(
            1,
            parent,
            null_protocol::transaction::Anchor::from_base(null_crypto::pallas::Base::from(1u64)),
        );
        header.timestamp = created_at;
        CachedTemplate {
            payout,
            header,
            transactions: Vec::new(),
            created_at,
        }
    }

    fn payout(seed: u64) -> Address {
        use rand::SeedableRng;
        let sk = null_crypto::keys::SpendingKey::random(
            &mut rand_chacha::ChaCha20Rng::seed_from_u64(seed),
        );
        null_wallet::keys::WalletKeys::from_spending_key(sk)
            .unwrap()
            .default_address()
            .unwrap()
    }

    #[test]
    fn templates_are_reused_briefly_then_rebuilt_and_expire() {
        let mut cache = TemplateCache::default();
        let parent = BlockHash::from_bytes([1; 32]);
        let a = payout(1);
        let id = cache.insert(cached(a, parent, 100), 100);
        assert_eq!(
            cache.find(&a, parent, 104).map(|(i, _)| i),
            Some(id.clone())
        );
        assert!(
            cache
                .find(&a, parent, 100 + TEMPLATE_REUSE_SECONDS)
                .is_none(),
            "too old to reuse"
        );
        assert!(
            cache.find(&payout(2), parent, 101).is_none(),
            "other payout"
        );
        assert!(
            cache
                .find(&a, BlockHash::from_bytes([2; 32]), 101)
                .is_none(),
            "other parent"
        );
        assert!(cache.get(&id, 100 + TEMPLATE_TTL_SECONDS - 1).is_some());
        assert!(
            cache.get(&id, 100 + TEMPLATE_TTL_SECONDS).is_none(),
            "expired for submission"
        );
        assert!(cache.get("nope", 100).is_none());
    }

    #[test]
    fn the_cache_is_bounded() {
        let mut cache = TemplateCache::default();
        let parent = BlockHash::ZERO;
        let first = cache.insert(cached(payout(1), parent, 0), 0);
        for i in 1..=MAX_TEMPLATES as u64 {
            cache.insert(cached(payout(1), parent, i), i);
        }
        assert_eq!(cache.entries.len(), MAX_TEMPLATES);
        assert!(cache.get(&first, 5).is_none(), "the oldest went first");
    }

    #[test]
    fn solutions_are_padded_to_the_header_field() {
        let solution = parse_solution(&"ab".repeat(10)).unwrap();
        assert_eq!(&solution.as_bytes()[..10], &[0xab; 10]);
        assert!(solution.as_bytes()[10..].iter().all(|b| *b == 0));
        assert!(parse_solution(&"ab".repeat(101)).is_err());
        assert!(parse_nonce(&"00".repeat(31)).is_err());
    }

    #[test]
    fn bearer_tokens_are_required_and_compared() {
        let token = Token::new("secret").unwrap();
        let with = |value: Option<&str>| HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            headers: value
                .map(|v| vec![("authorization".to_string(), v.to_string())])
                .unwrap_or_default(),
            body: Vec::new(),
        };
        assert!(authorized(&with(Some("Bearer secret")), &token));
        assert!(authorized(&with(Some("Bearer  secret ")), &token));
        assert!(!authorized(&with(Some("Bearer wrong")), &token));
        assert!(!authorized(&with(Some("secret")), &token));
        assert!(!authorized(&with(None), &token));
    }
}
