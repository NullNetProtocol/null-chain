//! The event loop. One task owns every piece of state and reacts to
//! events from connections, the clock, the miner and the RPC.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use null_chain::chain::{Chain, Import};
use null_chain::mempool::Mempool;
use null_chain::params::ChainParams;
use null_chain::target::{Target, U256};
use null_chain::validate::{earlier_coinbase, header_lookback, recent_headers};
use null_circuit::proof::VerifyingKey;
use null_p2p::addrbook::AddressBook;
use null_p2p::dandelion::{Dandelion, Route};
use null_p2p::message::{CompactBlock, Inventory, Message, PeerAddr, VersionInfo, MAX_HEADERS};
use null_p2p::peer::{version_info, Direction, Event as PeerEvent, Peer, SELF_CONNECTION};
use null_p2p::sync::{locator, BlockSync};
use null_protocol::block::{Block, BlockHash, BlockHeader};
use null_protocol::compact::CompactBlock as LightBlock;
use null_protocol::consensus::{next_height, MAX_BLOCK_TRANSACTIONS};
use null_protocol::nullifier::Nullifier;
use null_protocol::transaction::{Transaction, TxId};
use null_storage::store::Store;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_core::RngCore;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::config::{Config, MEMPOOL_CAPACITY, OUTBOUND_TARGET};
use crate::i2p::SamSession;
use crate::logging;
use crate::metrics::Metrics;
use crate::miner::Template;
use crate::rpc::{Token, TOKEN_FILE};
use crate::{now, Error, Result};

/// Logs at info level. Re-exported so callers keep using `node::log`.
pub use crate::logging::info as log;

/// Identifies one connection for its lifetime.
pub type PeerId = u64;

/// Seconds a partially reconstructed compact block is kept.
const PENDING_BLOCK_SECONDS: u64 = 60;
/// Compact blocks awaiting transactions at once; more are ignored.
const MAX_PENDING_BLOCKS: usize = 16;
/// Mined blocks remembered for the stale-block counters; older ones are
/// forgotten first.
const MAX_MINED_RECORDS: usize = 100_000;

/// Everything the loop reacts to.
#[derive(Debug)]
pub enum Event {
    /// A connection finished its handshake.
    Connected {
        /// Connection id.
        id: PeerId,
        /// Who dialed.
        direction: Direction,
        /// Remote socket address; the proxy's when one is used.
        addr: SocketAddr,
        /// What was dialed, or the remote address for inbound peers.
        target: String,
        /// Where to queue messages for it.
        outbox: mpsc::Sender<Message>,
    },
    /// A message arrived.
    Message {
        /// Connection id.
        id: PeerId,
        /// The message.
        message: Box<Message>,
    },
    /// A connection ended.
    Disconnected {
        /// Connection id.
        id: PeerId,
    },
    /// A dial was skipped because its name resolves only to this node.
    DialedSelf {
        /// Connection id.
        id: PeerId,
        /// What was dialed.
        target: String,
    },
    /// A dial or handshake failed.
    DialFailed {
        /// Connection id.
        id: PeerId,
        /// What was dialed.
        target: String,
    },
    /// One second passed.
    Tick,
    /// The miner found a block.
    Mined(Box<Block>),
    /// The miner wants a template.
    TemplateRequest(oneshot::Sender<Template>),
    /// A local control request.
    Rpc {
        /// The request.
        request: Request,
        /// Where to answer.
        reply: oneshot::Sender<Response>,
    },
    /// Stop the loop.
    Shutdown,
}

/// Local control requests.
#[derive(Debug)]
pub enum Request {
    /// Height, hash, peers, mempool size.
    Status,
    /// A block by height.
    Block(u32),
    /// A compact block by height, for light clients.
    Compact(u32),
    /// The coinbase of the main-chain block at a height, which wallets
    /// scanning full blocks need when it matures.
    Coinbase(u32),
    /// The hash of the block at a height, for cheap reorg checks.
    Hash(u32),
    /// Submit a transaction.
    Submit(Box<Transaction>),
    /// Whether a nullifier is spent.
    IsSpent(Nullifier),
    /// A metrics snapshot.
    Metrics,
    /// A block by hash, main chain or not.
    BlockByHash(BlockHash),
    /// A main-chain transaction by id, with where it is.
    Transaction(TxId),
    /// Where a transaction is: pool, chain, or nowhere.
    TransactionStatus(TxId),
    /// Every pooled transaction id, oldest first.
    MempoolTxids,
    /// Every connected peer.
    Peers,
    /// Stop the node after answering.
    Stop,
    /// Import a block a pool or external miner found.
    SubmitBlock(Box<Block>),
    /// What a miner needs to know.
    MiningInfo,
}

/// What became of a submitted block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Submission {
    /// It extended the main chain, or reorganized onto it.
    Accepted,
    /// It was already known.
    Duplicate,
    /// Valid but not on the best chain.
    Stale,
    /// Invalid, with the reason.
    Rejected(String),
}

/// The state a miner or pool needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiningInfo {
    /// Tip height.
    pub height: u32,
    /// Tip hash.
    pub hash: BlockHash,
    /// Whether a headers-first sync is in progress; pools should wait.
    pub syncing: bool,
    /// The next block's target, compact form.
    pub next_target: u32,
    /// The next block's subsidy, in smallest units.
    pub subsidy: u64,
    /// Pooled transactions.
    pub mempool: usize,
    /// Expected work per second over the last difficulty window, as a
    /// decimal string of a 256-bit number: solutions the network finds
    /// per second, roughly.
    pub work_per_second: String,
}

/// Where a transaction is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    /// In the mempool, not yet mined.
    Pooled,
    /// In the main chain at this height and index.
    Confirmed {
        /// Block height.
        height: u32,
        /// Position in the block.
        index: u32,
    },
    /// Neither pooled nor in the main chain.
    Unknown,
}

/// A transaction and where it is.
#[derive(Clone, Debug)]
pub struct Located {
    /// The transaction.
    pub tx: Box<Transaction>,
    /// Its main-chain height and index, or `None` while pooled.
    pub location: Option<(u32, u32)>,
}

/// One connected peer, for operators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSummary {
    /// Connection id.
    pub id: PeerId,
    /// Remote socket address; the proxy's when one is used.
    pub addr: SocketAddr,
    /// What was dialed, or the remote address for inbound peers.
    pub target: String,
    /// Who dialed.
    pub direction: Direction,
    /// Past the version handshake.
    pub ready: bool,
    /// The peer's protocol version, once known.
    pub version: Option<u32>,
    /// The peer's tip height at handshake, once known.
    pub best_height: Option<u32>,
    /// Misbehavior score.
    pub score: u32,
}

/// Local control responses.
#[derive(Debug)]
pub enum Response {
    /// Status.
    Status {
        /// Tip height.
        height: u32,
        /// Tip hash.
        hash: BlockHash,
        /// Connected peers.
        peers: usize,
        /// Pooled transactions.
        mempool: usize,
        /// Blocks this node mined since it started.
        mined: usize,
        /// Of those, the ones in the main chain now.
        mined_in_chain: usize,
        /// Whether a headers-first sync from a peer is in progress.
        syncing: bool,
    },
    /// A block, if present.
    Block(Option<Box<Block>>),
    /// A compact block, if present.
    Compact(Option<Box<LightBlock>>),
    /// A coinbase transaction, if its block is present.
    Coinbase(Option<Box<Transaction>>),
    /// A block hash, if present.
    Hash(Option<BlockHash>),
    /// The submitted transaction's id.
    Submitted(TxId),
    /// Whether a nullifier is spent.
    Spent(bool),
    /// A metrics snapshot.
    Metrics(Box<Metrics>),
    /// A transaction, if known.
    Transaction(Option<Located>),
    /// Where a transaction is.
    TransactionStatus(TxStatus),
    /// Transaction ids.
    Txids(Vec<TxId>),
    /// Connected peers.
    Peers(Vec<PeerSummary>),
    /// The node is stopping.
    Stopping,
    /// What became of a submitted block.
    BlockSubmitted(Submission),
    /// Mining state.
    MiningInfo(Box<MiningInfo>),
    /// The request failed.
    Failed(String),
}

struct PeerHandle {
    peer: Peer,
    outbox: mpsc::Sender<Message>,
    addr: SocketAddr,
    target: String,
    /// When the connection finished its handshake.
    connected_at: std::time::Instant,
}

impl PeerHandle {
    /// How a log line names the peer: direction and what was dialed, or
    /// the remote address for inbound peers.
    fn describe(&self) -> String {
        format!("{:?} {}", self.peer.direction(), self.target)
    }
}

/// A compact block waiting for transactions.
struct PendingBlock {
    header: BlockHeader,
    transactions: Vec<Option<Transaction>>,
    received_at: u64,
}

/// Endpoints found to be this node: seed names listing it, or addresses
/// gossiped back to it.
#[derive(Default)]
struct OwnEndpoints {
    /// Dial targets (`host:port`) that reached this node.
    targets: HashSet<String>,
    /// Address-book keys that reached this node.
    addrs: HashSet<([u8; 16], u16)>,
}

/// The node state, owned by the loop task.
pub struct Node {
    params: ChainParams,
    chain: Chain,
    mempool: Mempool,
    book: AddressBook,
    dandelion: Dandelion<PeerId>,
    sync: BlockSync,
    sync_peer: Option<PeerId>,
    peers: HashMap<PeerId, PeerHandle>,
    dialing: HashMap<PeerId, String>,
    configured: Vec<String>,
    /// Our bound listen address, never dialed.
    listen_addr: Option<SocketAddr>,
    /// Targets and addresses that turned out to be this node; never redialed.
    own: OwnEndpoints,
    proxy: Option<SocketAddr>,
    i2p: Option<Arc<SamSession>>,
    max_inbound: usize,
    pending_blocks: HashMap<BlockHash, PendingBlock>,
    next_id: PeerId,
    /// The best tip's hash, watched by miners.
    tip: watch::Sender<BlockHash>,
    /// Version nonces of our outbound connections still handshaking. Each
    /// connection gets its own, so peers cannot link our connections by it,
    /// and an inbound version carrying one is our own dial come back.
    handshakes: HashMap<u64, PeerId>,
    rng: StdRng,
    events: mpsc::Sender<Event>,
    genesis: BlockHash,
    ticks: u64,
    /// Height and hash of every block this node mined, oldest first.
    mined: VecDeque<(u32, BlockHash)>,
    started_at: u64,
    /// Shell command run with the hash of every new main-chain tip.
    block_notify: Option<String>,
}

/// A running node.
pub struct Handle {
    events: mpsc::Sender<Event>,
    tip: watch::Sender<BlockHash>,
    /// Where the node accepts peers, if listening.
    pub listen_addr: Option<SocketAddr>,
    /// Where the control socket listens, if enabled.
    pub rpc_addr: Option<SocketAddr>,
    /// Where the JSON-RPC endpoint listens, if enabled.
    pub rpc_http_addr: Option<SocketAddr>,
    /// The control socket's token, if enabled.
    pub rpc_token: Option<Token>,
    /// Where the metrics endpoint listens, if enabled.
    pub metrics_addr: Option<SocketAddr>,
    task: JoinHandle<()>,
    tasks: JoinSet<()>,
}

impl Handle {
    /// Sends a control request and waits for the answer.
    ///
    /// # Errors
    /// Returns [`Error::Stopped`] if the loop is gone.
    pub async fn request(&self, request: Request) -> Result<Response> {
        let (reply, response) = oneshot::channel();
        self.events
            .send(Event::Rpc { request, reply })
            .await
            .map_err(|_| Error::Stopped)?;
        response.await.map_err(|_| Error::Stopped)
    }

    /// Follows the best tip's hash, for miners that must drop stale work.
    pub fn tip(&self) -> watch::Receiver<BlockHash> {
        self.tip.subscribe()
    }

    /// The event sender, for tasks that feed the loop.
    pub fn events(&self) -> mpsc::Sender<Event> {
        self.events.clone()
    }

    /// Stops the node and waits for the loop to exit.
    pub async fn shutdown(mut self) {
        let _ = self.events.send(Event::Shutdown).await;
        let _ = self.task.await;
        self.tasks.shutdown().await;
    }
}

/// Starts a node from `config`: opens the store, binds sockets, starts
/// the miner and the clock, dials configured peers, and runs the loop.
///
/// # Errors
/// Fails if the store or a socket cannot be opened or key generation fails.
pub async fn spawn(config: Config) -> Result<Handle> {
    let mut tasks = JoinSet::new();
    let params = config.network.params();
    let chain = open_chain(&config, params).await?;
    let genesis = chain.store().hash_at(0)?.ok_or(Error::Stopped)?;
    let i2p = match config.i2p {
        Some(sam) => Some(Arc::new(SamSession::create(sam).await?)),
        None => None,
    };
    let (events, receiver) = mpsc::channel(4_096);
    let tip = watch::Sender::new(chain.tip()?.hash);

    let listen_addr = match bind(config.listen).await? {
        Some((listener, local)) => {
            tasks.spawn(crate::net::listen(listener, events.clone(), 1 << 40));
            Some(local)
        }
        None => None,
    };
    let (rpc_addr, rpc_http_addr, rpc_token) = serve_rpc(&config, &events, &mut tasks).await?;
    let metrics_addr = match bind(config.metrics).await? {
        Some((listener, local)) => {
            tasks.spawn(crate::metrics::serve(listener, events.clone()));
            Some(local)
        }
        None => None,
    };
    if let Some(miner) = config.mine_to {
        let miner = crate::miner::start(
            miner,
            params,
            config.mining_threads,
            events.clone(),
            tip.subscribe(),
        );
        tasks.spawn(async move {
            if let Err(error) = miner.wait().await {
                logging::warn(&format!("miner stopped: {error}"));
            }
        });
    }
    let clock = events.clone();
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if clock.send(Event::Tick).await.is_err() {
                break;
            }
        }
    });

    let rng = StdRng::from_entropy();
    let node = Node {
        params,
        chain,
        mempool: Mempool::new(MEMPOOL_CAPACITY),
        book: AddressBook::new(),
        dandelion: Dandelion::new(now()),
        sync: BlockSync::new(),
        sync_peer: None,
        peers: HashMap::new(),
        dialing: HashMap::new(),
        configured: config.connect.clone(),
        listen_addr,
        own: OwnEndpoints::default(),
        proxy: config.proxy,
        i2p,
        max_inbound: config.max_inbound,
        pending_blocks: HashMap::new(),
        next_id: 1,
        handshakes: HashMap::new(),
        tip: tip.clone(),
        rng,
        events: events.clone(),
        genesis,
        ticks: 0,
        mined: VecDeque::new(),
        started_at: now(),
        block_notify: config.block_notify.clone(),
    };
    let task = tokio::spawn(node.run(receiver));
    Ok(Handle {
        events,
        tip,
        listen_addr,
        rpc_addr,
        rpc_http_addr,
        rpc_token,
        metrics_addr,
        task,
        tasks,
    })
}

/// Starts the control socket and the JSON-RPC endpoint, whichever are
/// configured, behind one token that is written to the data directory.
async fn serve_rpc(
    config: &Config,
    events: &mpsc::Sender<Event>,
    tasks: &mut JoinSet<()>,
) -> Result<(Option<SocketAddr>, Option<SocketAddr>, Option<Token>)> {
    if config.rpc.is_none() && config.rpc_http.is_none() {
        return Ok((None, None, None));
    }
    let token = config
        .rpc_token
        .clone()
        .unwrap_or_else(|| Token::random(&mut rand::rngs::OsRng));
    if let Some(dir) = &config.datadir {
        token.write_to(dir.join(TOKEN_FILE))?;
    }
    let rpc_addr = match bind(config.rpc).await? {
        Some((listener, local)) => {
            tasks.spawn(crate::rpc::serve(listener, events.clone(), token.clone()));
            Some(local)
        }
        None => None,
    };
    let rpc_http_addr = match bind(config.rpc_http).await? {
        Some((listener, local)) => {
            tasks.spawn(crate::jsonrpc::serve(
                listener,
                events.clone(),
                token.clone(),
                config.network,
            ));
            Some(local)
        }
        None => None,
    };
    Ok((rpc_addr, rpc_http_addr, Some(token)))
}

/// Opens the chain store and builds the verifying key.
async fn open_chain(config: &Config, params: ChainParams) -> Result<Chain> {
    let store = match &config.datadir {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            Store::open(dir.join("chain.redb"))?
        }
        None => Store::in_memory()?,
    };
    let vk: VerifyingKey = tokio::task::spawn_blocking(VerifyingKey::build)
        .await
        .map_err(|_| Error::Stopped)??;
    Chain::new(store, params, vk).map_err(|error| match (error, &config.datadir) {
        (null_chain::Error::RulesMismatch, Some(dir)) => Error::Argument(format!(
            "the chain in {} was built under different consensus rules, for example \
             by an older version; delete that directory and restart to resync",
            dir.display()
        )),
        (error, _) => error.into(),
    })
}

/// Binds a listener when an address is configured, returning it with
/// the address it actually got, which matters for port 0.
async fn bind(addr: Option<SocketAddr>) -> Result<Option<(TcpListener, SocketAddr)>> {
    match addr {
        Some(addr) => {
            let listener = TcpListener::bind(addr).await?;
            let local = listener.local_addr()?;
            Ok(Some((listener, local)))
        }
        None => Ok(None),
    }
}

/// The log line for a connection the peer closed.
fn closed_by_peer(id: PeerId, who: &str, lasted_seconds: u64) -> String {
    format!("peer {id} ({who}) closed the connection after {lasted_seconds} s")
}

/// Whether banning `addr`'s IP stops only the peer that misbehaved. Not
/// for outbound peers reached through the proxy or the SAM bridge, whose
/// address is the transport's, nor for loopback: every inbound peer of a
/// Tor hidden service arrives from 127.0.0.1, so one bad onion peer would
/// lock out all of them. Such peers are still disconnected.
fn bannable(addr: SocketAddr, via_transport: bool) -> bool {
    !via_transport && !addr.ip().is_loopback()
}

fn addr_key(addr: SocketAddr) -> ([u8; 16], u16) {
    let ip = match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v6) => v6.octets(),
    };
    (ip, addr.port())
}

fn key_target(key: ([u8; 16], u16)) -> String {
    let ip = std::net::Ipv6Addr::from(key.0);
    ip.to_ipv4_mapped().map_or_else(
        || SocketAddr::from((ip, key.1)).to_string(),
        |v4| SocketAddr::from((v4, key.1)).to_string(),
    )
}

impl Node {
    async fn run(mut self, mut receiver: mpsc::Receiver<Event>) {
        self.dial_configured();
        while let Some(event) = receiver.recv().await {
            if matches!(event, Event::Shutdown) {
                break;
            }
            if let Err(error) = self.handle(event) {
                logging::error(&format!("loop error: {error}"));
            }
        }
    }

    fn handle(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Connected {
                id,
                direction,
                addr,
                target,
                outbox,
            } => self.on_connected(id, direction, addr, target, outbox),
            Event::Message { id, message } => self.on_message(id, *message),
            Event::Disconnected { id } => {
                // A peer still here was not dropped by us: the other side
                // closed, or the connection failed. Say so, since a peer
                // refusing our blocks looks otherwise like a quiet redial.
                if let Some(handle) = self.peers.get(&id) {
                    let lasted = handle.connected_at.elapsed().as_secs();
                    log(&closed_by_peer(id, &handle.describe(), lasted));
                }
                self.remove_peer(id);
                Ok(())
            }
            Event::DialedSelf { id, target } => {
                self.dialing.remove(&id);
                self.mark_own(target, None);
                Ok(())
            }
            Event::DialFailed { id, target } => {
                self.dialing.remove(&id);
                if let Ok(addr) = target.parse::<SocketAddr>() {
                    self.book.failed(addr_key(addr));
                }
                Ok(())
            }
            Event::Tick => {
                self.on_tick();
                Ok(())
            }
            Event::Mined(block) => self.on_mined(&block),
            Event::TemplateRequest(reply) => {
                let template = self.template()?;
                let _ = reply.send(template);
                Ok(())
            }
            Event::Rpc { request, reply } => {
                let stop = matches!(request, Request::Stop);
                let response = self
                    .on_request(request)
                    .unwrap_or_else(|e| Response::Failed(e.to_string()));
                let _ = reply.send(response);
                if stop {
                    let _ = self.events.try_send(Event::Shutdown);
                }
                Ok(())
            }
            Event::Shutdown => Ok(()),
        }
    }

    fn our_version(&self, nonce: u64) -> Result<VersionInfo> {
        Ok(version_info(
            nonce,
            self.chain.tip()?.height,
            self.genesis,
            now(),
        ))
    }

    fn on_connected(
        &mut self,
        id: PeerId,
        direction: Direction,
        addr: SocketAddr,
        target: String,
        outbox: mpsc::Sender<Message>,
    ) -> Result<()> {
        self.dialing.remove(&id);
        if direction == Direction::Inbound {
            let inbound = self
                .peers
                .values()
                .filter(|h| h.peer.direction() == Direction::Inbound)
                .count();
            if inbound >= self.max_inbound || self.book.is_banned(&addr_key(addr).0, now()) {
                return Ok(());
            }
        }
        let nonce = self.rng.next_u64();
        if direction == Direction::Outbound {
            self.handshakes.insert(nonce, id);
        }
        let (peer, events) = Peer::new(direction, self.our_version(nonce)?, now());
        self.peers.insert(
            id,
            PeerHandle {
                peer,
                outbox,
                addr,
                target,
                connected_at: std::time::Instant::now(),
            },
        );
        self.apply_peer_events(id, events);
        Ok(())
    }

    fn remove_peer(&mut self, id: PeerId) {
        self.peers.remove(&id);
        self.handshakes.retain(|_, peer| *peer != id);
        self.dandelion.remove_peer(&id);
        if self.sync_peer == Some(id) {
            self.sync_peer = None;
            self.sync = BlockSync::new();
        }
    }

    fn send(&mut self, id: PeerId, message: Message) {
        let Some(handle) = self.peers.get(&id) else {
            return;
        };
        if handle.outbox.try_send(message).is_err() {
            logging::warn(&format!("peer {id}: outbox stalled, dropping"));
            self.remove_peer(id);
        }
    }

    fn apply_peer_events(&mut self, id: PeerId, events: Vec<PeerEvent>) {
        for event in events {
            match event {
                PeerEvent::Send(message) => self.send(id, message),
                PeerEvent::Ready(info) => self.on_ready(id, &info),
                PeerEvent::Disconnect { reason, ban } => {
                    if reason == SELF_CONNECTION {
                        self.forget_self_peer(id);
                        continue;
                    }
                    let who = self.peers.get(&id).map(PeerHandle::describe);
                    log(&format!(
                        "peer {id} ({}): disconnecting, {reason}",
                        who.unwrap_or_default()
                    ));
                    if ban {
                        self.ban(id);
                    }
                    self.remove_peer(id);
                }
            }
        }
    }

    /// Bans a peer's IP for every port, unless that IP is shared by other
    /// peers (see [`bannable`]).
    fn ban(&mut self, id: PeerId) {
        let Some(handle) = self.peers.get(&id) else {
            return;
        };
        let via_transport = handle.peer.direction() == Direction::Outbound
            && (self.proxy.is_some() || self.i2p.is_some());
        if bannable(handle.addr, via_transport) {
            self.book.ban(addr_key(handle.addr).0, now());
        }
    }

    fn on_ready(&mut self, id: PeerId, info: &VersionInfo) {
        self.handshakes.retain(|_, peer| *peer != id);
        let Some(handle) = self.peers.get_mut(&id) else {
            return;
        };
        let addr = handle.addr;
        let direction = handle.peer.direction();
        log(&format!(
            "peer {id} ready ({direction:?} {}), height {}",
            handle.target, info.best_height
        ));
        if direction == Direction::Outbound {
            self.book.connected(addr_key(addr), now());
            // Record the peer we dialed so it can be gossiped onward,
            // unless it was reached through the proxy or the SAM bridge,
            // where `addr` is the transport's rather than the peer's.
            if self.proxy.is_none() && self.i2p.is_none() {
                let (ip, port) = addr_key(addr);
                self.book.add(
                    PeerAddr {
                        ip,
                        port,
                        last_seen: now(),
                    },
                    now(),
                );
            }
            self.send(id, Message::GetAddr);
        }
        let ours = self.chain.tip().map_or(0, |t| t.height);
        if info.best_height > ours {
            self.start_sync(id);
        }
    }

    fn on_message(&mut self, id: PeerId, message: Message) -> Result<()> {
        if let Message::Version(theirs) = &message {
            if let Some(dialed) = self.own_dial(id, theirs.nonce) {
                // Both ends are us: remember the dial, close both halves.
                self.forget_self_peer(dialed);
                self.remove_peer(id);
                return Ok(());
            }
        }
        let Some(handle) = self.peers.get_mut(&id) else {
            return Ok(());
        };
        let was_ready = handle.peer.is_ready();
        let events = handle.peer.handle(&message, now());
        self.apply_peer_events(id, events);
        if !was_ready || !self.peers.contains_key(&id) {
            return Ok(());
        }
        match message {
            Message::GetAddr => {
                let sample = self.book.sample(100, now(), &mut self.rng);
                self.send(id, Message::Addr(sample));
            }
            Message::Addr(addrs) => {
                self.book.add_many(&addrs, now());
            }
            Message::GetHeaders { locator, stop } => self.on_get_headers(id, &locator, stop)?,
            Message::Headers(headers) => self.on_headers(id, &headers),
            Message::Inv(items) => self.on_inv(id, &items)?,
            Message::GetData(items) => self.on_get_data(id, &items)?,
            Message::Block(block) => {
                self.on_block(Some(id), &block)?;
            }
            Message::Tx(tx) => self.on_tx(Some(id), *tx, false),
            Message::StemTx(tx) => self.on_tx(Some(id), *tx, true),
            Message::CompactBlock(compact) => self.on_compact_block(id, *compact)?,
            Message::GetBlockTxn { hash, indices } => self.on_get_block_txn(id, hash, &indices)?,
            Message::BlockTxn { hash, transactions } => {
                self.on_block_txn(id, hash, transactions)?;
            }
            Message::Version(_)
            | Message::Verack
            | Message::Ping(_)
            | Message::Pong(_)
            | Message::NotFound(_) => {}
        }
        Ok(())
    }

    fn misbehave(&mut self, id: PeerId, points: u32, reason: &'static str) {
        let event = self
            .peers
            .get_mut(&id)
            .and_then(|h| h.peer.misbehave(points, reason));
        if let Some(event) = event {
            self.apply_peer_events(id, vec![event]);
        }
    }

    // ---- sync -------------------------------------------------------

    fn start_sync(&mut self, id: PeerId) {
        if self.sync_peer.is_some() {
            return;
        }
        let Ok(tip) = self.chain.tip() else { return };
        let store = self.chain.store();
        let locator = locator(tip.height, |h| store.hash_at(h).ok().flatten());
        self.sync = BlockSync::new();
        self.sync_peer = Some(id);
        log(&format!("syncing from peer {id} at height {}", tip.height));
        self.send(
            id,
            Message::GetHeaders {
                locator,
                stop: BlockHash::ZERO,
            },
        );
    }

    fn on_get_headers(&mut self, id: PeerId, locator: &[BlockHash], stop: BlockHash) -> Result<()> {
        let store = self.chain.store();
        let tip = self.chain.tip()?;
        let mut start = 0u32;
        for hash in locator {
            let Some(block) = store.block(hash)? else {
                continue;
            };
            let height = block.header().height;
            if store.hash_at(height)? == Some(*hash) {
                start = height.saturating_add(1);
                break;
            }
        }
        let mut headers = Vec::new();
        let mut height = start;
        while height <= tip.height && headers.len() < MAX_HEADERS {
            let Some(hash) = store.hash_at(height)? else {
                break;
            };
            let Some(block) = store.block(&hash)? else {
                break;
            };
            headers.push(block.header().clone());
            if hash == stop {
                break;
            }
            height = height.saturating_add(1);
        }
        self.send(id, Message::Headers(headers));
        Ok(())
    }

    fn on_headers(&mut self, id: PeerId, headers: &[BlockHeader]) {
        if self.sync_peer != Some(id) {
            return;
        }
        let store = self.chain.store();
        let known = |hash: &BlockHash| store.block(hash).ok().flatten().is_some();
        match self.sync.on_headers(headers, known) {
            Ok(_) => self.continue_sync(id),
            Err(_) => self.misbehave(id, 20, "bad headers"),
        }
    }

    /// Requests more headers if the queue has room for them, fills the
    /// block request window, and ends the sync once nothing is left.
    fn continue_sync(&mut self, id: PeerId) {
        if let Some(from) = self.sync.next_headers_request() {
            self.send(
                id,
                Message::GetHeaders {
                    locator: vec![from],
                    stop: BlockHash::ZERO,
                },
            );
        }
        let hashes = self.sync.next_requests(now());
        if !hashes.is_empty() {
            self.send(
                id,
                Message::GetData(hashes.into_iter().map(Inventory::Block).collect()),
            );
        }
        self.finish_sync_if_done();
    }

    fn finish_sync_if_done(&mut self) {
        if self.sync.is_idle() && self.sync.exhausted() {
            if let Some(id) = self.sync_peer.take() {
                log(&format!("synced with peer {id}"));
            }
        }
    }

    fn on_inv(&mut self, id: PeerId, items: &[Inventory]) -> Result<()> {
        let mut wanted = Vec::new();
        for item in items {
            if let Some(handle) = self.peers.get_mut(&id) {
                handle.peer.mark_known(*item);
            }
            let have = match item {
                Inventory::Block(hash) => self.chain.store().block(hash)?.is_some(),
                Inventory::Tx(txid) => self.mempool.contains(txid),
            };
            if !have {
                wanted.push(*item);
            }
        }
        if !wanted.is_empty() {
            self.send(id, Message::GetData(wanted));
        }
        Ok(())
    }

    fn on_get_data(&mut self, id: PeerId, items: &[Inventory]) -> Result<()> {
        let mut missing = Vec::new();
        for item in items {
            match item {
                Inventory::Block(hash) => match self.chain.store().block(hash)? {
                    Some(block) => self.send(id, Message::Block(Box::new(block))),
                    None => missing.push(*item),
                },
                Inventory::Tx(txid) => match self.mempool.get(txid).cloned() {
                    Some(tx) => self.send(id, Message::Tx(Box::new(tx))),
                    None => missing.push(*item),
                },
            }
        }
        if !missing.is_empty() {
            self.send(id, Message::NotFound(missing));
        }
        Ok(())
    }

    // ---- blocks -----------------------------------------------------

    /// Imports a block from a peer, the miner or a submission, applies
    /// its consequences, and says what became of it.
    fn on_block(&mut self, from: Option<PeerId>, block: &Block) -> Result<Submission> {
        let hash = block.hash();
        self.sync.on_block(&hash);
        self.pending_blocks.remove(&hash);
        if let Some(id) = from {
            if let Some(handle) = self.peers.get_mut(&id) {
                handle.peer.mark_known(Inventory::Block(hash));
            }
        }
        let outcome = self.chain.import(block, now(), &mut self.rng);
        let submission = match &outcome {
            Ok(Import::Extended | Import::Reorganized { .. }) => Submission::Accepted,
            Ok(Import::AlreadyKnown) => Submission::Duplicate,
            Ok(Import::SideChain) => Submission::Stale,
            Err(error) => Submission::Rejected(error.to_string()),
        };
        match outcome {
            Ok(Import::Extended) => {
                self.mempool
                    .on_block_applied(block, self.chain.store(), &self.params)?;
                if from.is_none() {
                    self.record_mined(block);
                }
                log(&format!(
                    "{} {} {} ({} txs)",
                    if from.is_none() {
                        "mined block"
                    } else {
                        "block"
                    },
                    block.header().height,
                    hash,
                    block.transactions().len()
                ));
                self.announce_block(block, from);
                self.tip_moved(hash);
            }
            Ok(Import::Reorganized { reverted, applied }) => {
                if from.is_none() {
                    self.record_mined(block);
                }
                logging::warn(&format!(
                    "reorganized: reverted {}, applied {applied}",
                    reverted.len()
                ));
                self.mempool
                    .readmit(&reverted, self.chain.store(), &self.params)?;
                self.evict_mined_since(applied)?;
                self.announce_block(block, from);
                self.tip_moved(hash);
            }
            Ok(Import::SideChain | Import::AlreadyKnown) => {}
            Err(null_chain::Error::Orphan) => {
                if let Some(id) = from {
                    self.start_sync(id);
                }
            }
            Err(error) => {
                logging::warn(&format!("invalid block {hash}: {error}"));
                if let Some(id) = from {
                    self.misbehave(id, 100, "invalid block");
                }
            }
        }
        if let Some(id) = self.sync_peer {
            self.continue_sync(id);
        }
        Ok(submission)
    }

    /// Publishes a new best tip: to miners, so they drop work on the old
    /// one, and to the block-notify command.
    fn tip_moved(&self, hash: BlockHash) {
        self.tip.send_replace(hash);
        self.notify_block(hash);
    }

    /// Runs the block-notify command, if configured, with the new tip's
    /// hash substituted for `%s`, off the loop thread.
    fn notify_block(&self, hash: BlockHash) {
        let Some(command) = &self.block_notify else {
            return;
        };
        let command = command.replace("%s", &hash.to_string());
        tokio::task::spawn_blocking(move || {
            let status = shell(&command).status();
            if let Err(error) = status {
                logging::warn(&format!("blocknotify failed: {error}"));
            }
        });
    }

    /// Relays a newly accepted block as a compact block, or as an
    /// inventory announcement if it has no coinbase.
    fn announce_block(&mut self, block: &Block, from: Option<PeerId>) {
        let hash = block.hash();
        let message = match CompactBlock::from_block(block) {
            Ok(compact) => Message::CompactBlock(Box::new(compact)),
            Err(_) => Message::Inv(vec![Inventory::Block(hash)]),
        };
        self.broadcast(&message, from, Some(Inventory::Block(hash)));
    }

    fn on_compact_block(&mut self, id: PeerId, compact: CompactBlock) -> Result<()> {
        let hash = compact.hash();
        if let Some(handle) = self.peers.get_mut(&id) {
            handle.peer.mark_known(Inventory::Block(hash));
        }
        let store = self.chain.store();
        if store.block(&hash)?.is_some() || self.pending_blocks.contains_key(&hash) {
            return Ok(());
        }
        if store.block(&compact.header.prev_hash)?.is_none() {
            self.start_sync(id);
            return Ok(());
        }
        // The pool holds signatures for the next block's branch; a compact
        // block at a height under another branch needs every transaction
        // from the sender, since the same txid may carry other signatures.
        let pool_usable = pool_matches_branch(
            &self.params,
            self.chain.tip()?.height,
            compact.header.height,
        );
        let mut transactions = vec![Some(compact.coinbase.clone())];
        let mut missing = Vec::new();
        for (i, txid) in compact.txids.iter().enumerate() {
            let tx = pool_usable
                .then(|| self.mempool.get(txid).cloned())
                .flatten();
            if tx.is_none() {
                missing.push(u32::try_from(i.saturating_add(1)).unwrap_or(u32::MAX));
            }
            transactions.push(tx);
        }
        let pending = PendingBlock {
            header: compact.header,
            transactions,
            received_at: now(),
        };
        if missing.is_empty() {
            let block = assemble(&pending)?;
            self.on_block(Some(id), &block)?;
            return Ok(());
        }
        if self.pending_blocks.len() >= MAX_PENDING_BLOCKS {
            return Ok(());
        }
        self.pending_blocks.insert(hash, pending);
        self.send(
            id,
            Message::GetBlockTxn {
                hash,
                indices: missing,
            },
        );
        Ok(())
    }

    fn on_get_block_txn(&mut self, id: PeerId, hash: BlockHash, indices: &[u32]) -> Result<()> {
        let Some(block) = self.chain.store().block(&hash)? else {
            self.send(id, Message::NotFound(vec![Inventory::Block(hash)]));
            return Ok(());
        };
        let transactions: Vec<Transaction> = indices
            .iter()
            .filter_map(|i| {
                usize::try_from(*i)
                    .ok()
                    .and_then(|i| block.transactions().get(i))
                    .cloned()
            })
            .collect();
        self.send(id, Message::BlockTxn { hash, transactions });
        Ok(())
    }

    fn on_block_txn(
        &mut self,
        id: PeerId,
        hash: BlockHash,
        transactions: Vec<Transaction>,
    ) -> Result<()> {
        let Some(pending) = self.pending_blocks.get_mut(&hash) else {
            return Ok(());
        };
        let mut supplied = transactions.into_iter();
        for slot in pending.transactions.iter_mut().filter(|s| s.is_none()) {
            *slot = supplied.next();
        }
        if pending.transactions.iter().all(Option::is_some) {
            let block = assemble(pending)?;
            self.pending_blocks.remove(&hash);
            self.on_block(Some(id), &block)?;
            return Ok(());
        }
        self.pending_blocks.remove(&hash);
        self.misbehave(id, 20, "incomplete block transactions");
        Ok(())
    }

    /// Drops mempool entries mined in the last `count` main-chain blocks.
    fn evict_mined_since(&mut self, count: u32) -> Result<()> {
        let tip = self.chain.tip()?;
        for height in tip.height.saturating_sub(count.saturating_sub(1))..=tip.height {
            if let Some(hash) = self.chain.store().hash_at(height)? {
                if let Some(block) = self.chain.store().block(&hash)? {
                    self.mempool
                        .on_block_applied(&block, self.chain.store(), &self.params)?;
                }
            }
        }
        Ok(())
    }

    fn on_mined(&mut self, block: &Block) -> Result<()> {
        // A block only counts and is logged once it actually lands, in
        // `on_block`. On a trivial target several workers can mine the same
        // height at once; the losers import as side chains and stay silent.
        self.on_block(None, block)?;
        Ok(())
    }

    /// Remembers a block this node mined into the main chain, for the
    /// stale-block counters, dropping the oldest past the cap.
    fn record_mined(&mut self, block: &Block) {
        if self.mined.len() >= MAX_MINED_RECORDS {
            self.mined.pop_front();
        }
        self.mined.push_back((block.header().height, block.hash()));
    }

    /// How many of the blocks this node mined are in the main chain.
    fn mined_in_chain(&self) -> Result<usize> {
        let store = self.chain.store();
        let mut count = 0usize;
        for (height, hash) in &self.mined {
            if store.hash_at(*height)?.as_ref() == Some(hash) {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    fn ready_peers(&self, direction: Direction) -> usize {
        self.peers
            .values()
            .filter(|h| h.peer.is_ready() && h.peer.direction() == direction)
            .count()
    }

    fn metrics(&self) -> Result<Metrics> {
        Ok(Metrics {
            height: self.chain.tip()?.height,
            peers_inbound: self.ready_peers(Direction::Inbound),
            peers_outbound: self.ready_peers(Direction::Outbound),
            mempool: self.mempool.len(),
            blocks_mined: self.mined.len(),
            blocks_mined_in_chain: self.mined_in_chain()?,
            pending_compact_blocks: self.pending_blocks.len(),
            uptime_seconds: now().saturating_sub(self.started_at),
        })
    }

    fn mining_info(&mut self) -> Result<MiningInfo> {
        let template = self.template()?;
        let tip = self.chain.tip()?;
        let next = next_height(tip.height)?;
        Ok(MiningInfo {
            height: tip.height,
            hash: tip.hash,
            syncing: self.sync_peer.is_some(),
            next_target: template.next_target()?.to_compact(),
            subsidy: null_protocol::consensus::subsidy(next).raw(),
            mempool: self.mempool.len(),
            work_per_second: work_per_second(&template.recent)?.to_string(),
        })
    }

    /// The main-chain block at `height`, if the chain reaches it.
    fn block_at(&self, height: u32) -> Result<Option<Block>> {
        let store = self.chain.store();
        Ok(match store.hash_at(height)? {
            Some(hash) => store.block(&hash)?,
            None => None,
        })
    }

    fn template(&mut self) -> Result<Template> {
        let tip = self.chain.tip()?;
        let store = self.chain.store();
        let parent = store
            .block(&tip.hash)?
            .ok_or(Error::Stopped)?
            .header()
            .clone();
        let recent = recent_headers(store, tip.height, header_lookback(&self.params))?;
        let tree = store.tree()?;
        let earlier = earlier_coinbase(store, &self.params, next_height(tip.height)?)?;
        let transactions = self.mempool.select(
            store,
            &self.params,
            MAX_BLOCK_TRANSACTIONS.saturating_sub(1),
        )?;
        Ok(Template {
            parent,
            recent,
            tree,
            transactions,
            earlier,
            params: self.params,
            now: now(),
        })
    }

    // ---- transactions -----------------------------------------------

    fn on_tx(&mut self, from: Option<PeerId>, tx: Transaction, stem: bool) {
        let txid = tx.txid();
        if let Some(id) = from {
            if let Some(handle) = self.peers.get_mut(&id) {
                handle.peer.mark_known(Inventory::Tx(txid));
            }
        }
        if self.mempool.contains(&txid) {
            if !stem {
                self.dandelion.seen_fluffed(&txid);
            }
            return;
        }
        let verifying = self.chain.verifying_key();
        match self.mempool.insert(
            tx.clone(),
            self.chain.store(),
            &self.params,
            verifying,
            &mut self.rng,
        ) {
            Ok(_) => {}
            Err(null_chain::Error::Rejected(reason)) => {
                logging::debug(&format!("tx {txid} rejected: {reason}"));
                return;
            }
            Err(error) => {
                logging::warn(&format!("tx {txid} invalid: {error}"));
                if let Some(id) = from {
                    self.misbehave(id, 20, "invalid transaction");
                }
                return;
            }
        }
        let route = match (from, stem) {
            (Some(id), true) => self.dandelion.route_stem(id, txid, now(), &mut self.rng),
            (None, _) => self.dandelion.route_own(txid, now(), &mut self.rng),
            (Some(_), false) => Route::Fluff,
        };
        self.relay(txid, tx, route, from);
    }

    fn relay(&mut self, txid: TxId, tx: Transaction, route: Route<PeerId>, from: Option<PeerId>) {
        match route {
            Route::Stem(peer) if self.peers.get(&peer).is_some_and(|h| h.peer.is_ready()) => {
                self.send(peer, Message::StemTx(Box::new(tx)));
            }
            Route::Stem(_) | Route::Fluff => {
                self.dandelion.seen_fluffed(&txid);
                self.broadcast(
                    &Message::Inv(vec![Inventory::Tx(txid)]),
                    from,
                    Some(Inventory::Tx(txid)),
                );
            }
        }
    }

    /// Sends to every ready peer except `except` and those already
    /// knowing `item`, marking `item` known.
    fn broadcast(&mut self, message: &Message, except: Option<PeerId>, item: Option<Inventory>) {
        let targets: Vec<PeerId> = self
            .peers
            .iter_mut()
            .filter(|(id, h)| Some(**id) != except && h.peer.is_ready())
            .filter_map(|(id, h)| match item {
                Some(item) => h.peer.mark_known(item).then_some(*id),
                None => Some(*id),
            })
            .collect();
        for id in targets {
            self.send(id, message.clone());
        }
    }

    // ---- clock ------------------------------------------------------

    fn on_tick(&mut self) {
        self.ticks = self.ticks.saturating_add(1);
        let now = now();
        let ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for id in ids {
            let nonce = self.rng.next_u64();
            let events = self
                .peers
                .get_mut(&id)
                .map(|h| h.peer.tick(now, nonce))
                .unwrap_or_default();
            self.apply_peer_events(id, events);
        }
        if !self.sync.timeouts(now).is_empty() {
            logging::warn("sync timed out, restarting");
            self.sync_peer = None;
            self.sync = BlockSync::new();
        }
        self.pending_blocks
            .retain(|_, p| now.saturating_sub(p.received_at) < PENDING_BLOCK_SECONDS);
        for txid in self.dandelion.expired_embargoes(now) {
            if let Some(tx) = self.mempool.get(&txid).cloned() {
                self.relay(txid, tx, Route::Fluff, None);
            }
        }
        if self.dandelion.epoch_expired(now) {
            let inbound: Vec<PeerId> = self.peer_ids(Direction::Inbound);
            let outbound: Vec<PeerId> = self.peer_ids(Direction::Outbound);
            self.dandelion
                .new_epoch(now, &inbound, &outbound, &mut self.rng);
        }
        if self.sync_peer.is_none() {
            let ours = self.chain.tip().map_or(0, |t| t.height);
            let behind = self
                .peers
                .iter()
                .find(|(_, h)| h.peer.version().is_some_and(|v| v.best_height > ours))
                .map(|(id, _)| *id);
            if let Some(id) = behind {
                self.start_sync(id);
            }
        }
        if self.ticks % 5 == 0 {
            self.maintain_connections();
        }
        if self.ticks % 600 == 0 {
            self.book.prune(now);
        }
    }

    fn peer_ids(&self, direction: Direction) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, h)| h.peer.is_ready() && h.peer.direction() == direction)
            .map(|(id, _)| *id)
            .collect()
    }

    fn dial(&mut self, target: String) {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.dialing.insert(id, target.clone());
        let route = crate::net::Route {
            target,
            proxy: self.proxy,
            i2p: self.i2p.clone(),
            own: self.listen_addr,
        };
        crate::net::dial(route, id, self.events.clone());
    }

    /// Configured peers, without any that turned out to be this node.
    fn dialable_configured(&self) -> Vec<String> {
        self.configured
            .iter()
            .filter(|t| !self.own.targets.contains(*t))
            .cloned()
            .collect()
    }

    fn dial_configured(&mut self) {
        for target in self.dialable_configured() {
            self.dial(target);
        }
    }

    /// The outbound connection whose handshake nonce an inbound peer `id`
    /// presented, if any: that inbound connection is our own dial.
    fn own_dial(&self, id: PeerId, nonce: u64) -> Option<PeerId> {
        let inbound = self
            .peers
            .get(&id)
            .is_some_and(|h| h.peer.direction() == Direction::Inbound);
        inbound
            .then(|| self.handshakes.get(&nonce).copied())
            .flatten()
    }

    /// Drops a connection to ourselves. Its outbound side remembers what
    /// was dialed so it is not dialed again; the inbound side just closes.
    fn forget_self_peer(&mut self, id: PeerId) {
        if let Some(handle) = self.peers.get(&id) {
            if handle.peer.direction() == Direction::Outbound {
                let (target, addr) = (handle.target.clone(), handle.addr);
                let reached_directly = self.proxy.is_none() && self.i2p.is_none();
                self.mark_own(target, reached_directly.then_some(addr));
            }
        }
        self.remove_peer(id);
    }

    /// Records a target, and the address it reached when known, as this
    /// node. Logs only the first time, so seeds listing themselves stay quiet.
    fn mark_own(&mut self, target: String, addr: Option<SocketAddr>) {
        if let Some(addr) = addr {
            self.own.addrs.insert(addr_key(addr));
        }
        if !self.own.targets.contains(&target) {
            log(&format!("not dialing {target} again: it is this node"));
            self.own.targets.insert(target);
        }
    }

    fn maintain_connections(&mut self) {
        let outbound = self
            .peers
            .values()
            .filter(|h| h.peer.direction() == Direction::Outbound)
            .count();
        if outbound.saturating_add(self.dialing.len()) >= OUTBOUND_TARGET {
            return;
        }
        let busy: HashSet<String> = self
            .peers
            .values()
            .map(|h| h.target.clone())
            .chain(self.dialing.values().cloned())
            .collect();
        if let Some(target) = self
            .dialable_configured()
            .into_iter()
            .find(|t| !busy.contains(t))
        {
            self.dial(target);
            return;
        }
        let exclude: Vec<([u8; 16], u16)> = self
            .peers
            .values()
            .map(|h| addr_key(h.addr))
            .chain(self.own.addrs.iter().copied())
            .chain(self.listen_addr.map(addr_key))
            .collect();
        if let Some(candidate) = self.book.candidate(&exclude, now(), &mut self.rng) {
            let target = key_target(candidate.key());
            if !busy.contains(&target) {
                self.dial(target);
            }
        }
    }

    // ---- control ----------------------------------------------------

    fn on_request(&mut self, request: Request) -> Result<Response> {
        match request {
            Request::Status => {
                let tip = self.chain.tip()?;
                Ok(Response::Status {
                    height: tip.height,
                    hash: tip.hash,
                    peers: self.peers.values().filter(|h| h.peer.is_ready()).count(),
                    mempool: self.mempool.len(),
                    mined: self.mined.len(),
                    mined_in_chain: self.mined_in_chain()?,
                    syncing: self.sync_peer.is_some(),
                })
            }
            Request::Metrics => Ok(Response::Metrics(Box::new(self.metrics()?))),
            Request::BlockByHash(hash) => Ok(Response::Block(
                self.chain.store().block(&hash)?.map(Box::new),
            )),
            Request::Transaction(txid) => {
                let found = match self.chain.store().transaction(&txid)? {
                    Some((tx, height, index)) => Some(Located {
                        tx: Box::new(tx),
                        location: Some((height, index)),
                    }),
                    None => self.mempool.get(&txid).map(|tx| Located {
                        tx: Box::new(tx.clone()),
                        location: None,
                    }),
                };
                Ok(Response::Transaction(found))
            }
            Request::TransactionStatus(txid) => {
                let status = if self.mempool.contains(&txid) {
                    TxStatus::Pooled
                } else {
                    match self.chain.store().transaction_location(&txid)? {
                        Some((height, index)) => TxStatus::Confirmed { height, index },
                        None => TxStatus::Unknown,
                    }
                };
                Ok(Response::TransactionStatus(status))
            }
            Request::MempoolTxids => Ok(Response::Txids(
                self.mempool.iter().map(Transaction::txid).collect(),
            )),
            Request::Peers => Ok(Response::Peers(
                self.peers
                    .iter()
                    .map(|(id, h)| PeerSummary {
                        id: *id,
                        addr: h.addr,
                        target: h.target.clone(),
                        direction: h.peer.direction(),
                        ready: h.peer.is_ready(),
                        version: h.peer.version().map(|v| v.version),
                        best_height: h.peer.version().map(|v| v.best_height),
                        score: h.peer.score(),
                    })
                    .collect(),
            )),
            Request::Stop => Ok(Response::Stopping),
            Request::SubmitBlock(block) => {
                Ok(Response::BlockSubmitted(self.on_block(None, &block)?))
            }
            Request::MiningInfo => Ok(Response::MiningInfo(Box::new(self.mining_info()?))),
            Request::Block(height) => Ok(Response::Block(self.block_at(height)?.map(Box::new))),
            Request::Compact(height) => {
                let Some(block) = self.block_at(height)? else {
                    return Ok(Response::Compact(None));
                };
                let store = self.chain.store();
                let earlier = earlier_coinbase(store, &self.params, height)?;
                let maturity = self.params.coinbase_maturity;
                let compact = LightBlock::from_block(&block, maturity, earlier.as_ref())?;
                Ok(Response::Compact(Some(Box::new(compact))))
            }
            Request::Coinbase(height) => Ok(Response::Coinbase(
                self.block_at(height)?
                    .and_then(|b| b.transactions().first().cloned())
                    .map(Box::new),
            )),
            Request::Hash(height) => Ok(Response::Hash(self.chain.store().hash_at(height)?)),
            Request::Submit(tx) => {
                let txid = tx.txid();
                self.on_tx(None, *tx, false);
                if self.mempool.contains(&txid) {
                    Ok(Response::Submitted(txid))
                } else {
                    Ok(Response::Failed("transaction not accepted".into()))
                }
            }
            Request::IsSpent(nf) => {
                Ok(Response::Spent(self.chain.store().contains_nullifier(&nf)?))
            }
        }
    }
}

/// The work the headers after the first represent, divided by the
/// seconds they span: how much work per second found them.
fn work_per_second(recent: &[BlockHeader]) -> Result<U256> {
    let (Some(first), Some(last)) = (recent.first(), recent.last()) else {
        return Ok(U256::zero());
    };
    let seconds = last.timestamp.saturating_sub(first.timestamp).max(1);
    let work = recent
        .iter()
        .skip(1)
        .try_fold(U256::zero(), |acc, header| {
            Ok::<_, Error>(acc.saturating_add(Target::from_compact(header.target)?.work()))
        })?;
    Ok(work.checked_div(U256::from(seconds)).unwrap_or_default())
}

/// Builds the block from a fully populated pending entry.
fn assemble(pending: &PendingBlock) -> Result<Block> {
    let transactions: Vec<Transaction> = pending.transactions.iter().flatten().cloned().collect();
    if transactions.len() != pending.transactions.len() {
        return Err(Error::Argument("block incomplete".into()));
    }
    Ok(Block::new(pending.header.clone(), transactions))
}

/// Whether transactions verified for the branch of the block after
/// `tip_height` may fill a compact block at `height`: only when that
/// height is validated under the same branch.
fn pool_matches_branch(params: &ChainParams, tip_height: u32, height: u32) -> bool {
    next_height(tip_height).is_ok_and(|next| params.branch_at(next) == params.branch_at(height))
}

/// The platform shell running `command`: `cmd /C` on Windows, `sh -c` elsewhere.
fn shell(command: &str) -> std::process::Command {
    let (program, flag) = if cfg!(windows) {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    let mut shell = std::process::Command::new(program);
    shell.arg(flag).arg(command);
    shell
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use null_chain::params::Upgrade;
    use null_protocol::consensus::BranchId;

    use super::*;

    static UPGRADE_AT_5: [Upgrade; 1] = [Upgrade {
        height: 5,
        branch: BranchId::new(9),
    }];

    #[tokio::test]
    async fn shutdown_releases_owned_listener_ports() {
        let local = Some("127.0.0.1:0".parse().unwrap());
        let node = spawn(Config {
            listen: local,
            rpc: local,
            rpc_http: local,
            metrics: local,
            ..Config::test()
        })
        .await
        .unwrap();
        let ports = [
            node.listen_addr,
            node.rpc_addr,
            node.rpc_http_addr,
            node.metrics_addr,
        ];
        node.shutdown().await;
        for addr in ports.into_iter().flatten() {
            assert!(
                TcpListener::bind(addr).await.is_ok(),
                "listener survived shutdown: {addr}"
            );
        }
    }

    #[test]
    fn the_pool_fills_compact_blocks_only_on_its_own_branch() {
        let params = ChainParams {
            upgrades: &UPGRADE_AT_5,
            ..ChainParams::test()
        };
        // Tip 3: the pool is verified for height 4, still the old branch.
        assert!(pool_matches_branch(&params, 3, 4));
        assert!(!pool_matches_branch(&params, 3, 5));
        // Tip 4: the pool is verified for height 5, the new branch.
        assert!(!pool_matches_branch(&params, 4, 4));
        assert!(pool_matches_branch(&params, 4, 6));
        assert!(!pool_matches_branch(&params, u32::MAX, 1));
    }

    #[test]
    fn block_notify_runs_through_the_platform_shell() {
        let command = shell("echo %s");
        let args: Vec<_> = command.get_args().collect();
        if cfg!(windows) {
            assert_eq!(command.get_program(), "cmd");
            assert_eq!(args, ["/C", "echo %s"]);
        } else {
            assert_eq!(command.get_program(), "sh");
            assert_eq!(args, ["-c", "echo %s"]);
        }
        assert!(shell("exit 0").status().unwrap().success());
    }

    /// A TCP relay that forwards to `target` once it is set and counts the
    /// connections it accepts: a NAT or public address leading back to us.
    async fn counting_relay(
        target: Arc<std::sync::Mutex<Option<SocketAddr>>>,
        accepted: Arc<std::sync::atomic::AtomicUsize>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let target = target.clone();
                tokio::spawn(async move {
                    let to = loop {
                        if let Some(to) = *target.lock().unwrap() {
                            break to;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    };
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect(to).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        addr
    }

    // Three maintenance rounds (every 5 ticks) would each redial a
    // configured peer; a target found to be ourselves is dialed once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_target_that_reaches_ourselves_is_dialed_only_once() {
        let target = Arc::new(std::sync::Mutex::new(None));
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let relay = counting_relay(target.clone(), accepted.clone()).await;
        let node = spawn(Config {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            connect: vec![relay.to_string()],
            ..Config::test()
        })
        .await
        .unwrap();
        *target.lock().unwrap() = node.listen_addr;
        tokio::time::sleep(Duration::from_secs(16)).await;
        let dials = accepted.load(std::sync::atomic::Ordering::SeqCst);
        node.shutdown().await;
        assert_eq!(dials, 1, "the relay back to ourselves was redialed");
    }

    #[tokio::test]
    async fn a_chain_from_other_consensus_rules_is_refused_naming_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let chain_dir = dir.path().join("chain");
        std::fs::create_dir_all(&chain_dir).unwrap();
        // Stamp the store as a binary with another maturity would.
        let other = ChainParams {
            coinbase_maturity: 1,
            ..ChainParams::test()
        };
        let store = Store::open(chain_dir.join("chain.redb")).unwrap();
        let vk = VerifyingKey::build().unwrap();
        drop(Chain::new(store, other, vk).unwrap());

        let refused = spawn(Config {
            datadir: Some(chain_dir.clone()),
            ..Config::test()
        })
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(refused.contains("different consensus rules"), "{refused}");
        assert!(
            refused.contains(&chain_dir.display().to_string()),
            "{refused}"
        );
    }

    #[test]
    fn shared_addresses_are_never_banned() {
        let public: SocketAddr = "46.19.141.66:51234".parse().unwrap();
        assert!(bannable(public, false));
        assert!(
            !bannable(public, true),
            "the proxy's or SAM bridge's address"
        );
        for tor in ["127.0.0.1:40000", "[::1]:40000"] {
            assert!(!bannable(tor.parse().unwrap(), false), "{tor}");
        }
    }

    #[test]
    fn a_peer_closing_the_connection_is_named_with_how_long_it_lasted() {
        assert_eq!(
            closed_by_peer(6, "Outbound seed1.nullnet.sh:19000", 0),
            "peer 6 (Outbound seed1.nullnet.sh:19000) closed the connection after 0 s"
        );
    }
}
