//! The `nulld` command line.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use null_chain::genesis::genesis;
use null_circuit::proof::ProvingKey;
use null_crypto::encoding::{from_hex, to_hex};
use null_crypto::keys::SpendingKey;
use null_protocol::address::Address;
use null_protocol::amount::Amount;
use null_protocol::block::{Block, BlockHash};
use null_protocol::bytes::Encodable;
use null_protocol::compact::CompactBlock;
use null_protocol::consensus::{next_height, BranchId};
use null_protocol::maturity::earlier_origin;
use null_protocol::memo::Memo;
use null_protocol::transaction::Transaction;
use null_wallet::keys::WalletKeys;
use null_wallet::seed::SeedPhrase;
use null_wallet::spend::{build_payment, Payment};
use null_wallet::wallet::Wallet;

use crate::config::{Config, Network};
use crate::paths;
use crate::rpc::{Client, Control, Endpoint, Token, TOKEN_FILE};
use crate::shutdown::Shutdown;
use crate::{Error, Result};

/// Default control socket.
const DEFAULT_RPC: &str = "127.0.0.1:18444";
/// Environment variable that supplies the wallet passphrase.
const PASSPHRASE_ENV: &str = "NULL_WALLET_PASSPHRASE";
/// Environment variable that supplies the control socket token.
const TOKEN_ENV: &str = "NULL_RPC_TOKEN";
/// Environment variable that supplies a seed phrase to restore from.
const PHRASE_ENV: &str = "NULL_SEED_PHRASE";

/// The node daemon and wallet tools.
#[derive(Parser, Debug)]
#[command(name = "nulld", version)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Where a command finds its wallet: a file under a passphrase, or a
/// spending key kept in memory for the duration of the command.
#[derive(clap::Args, Debug)]
pub struct WalletArgs {
    /// Wallet file.
    #[arg(long, conflicts_with = "sk")]
    pub wallet: Option<PathBuf>,
    /// Spending key, hex; scans from genesis in memory.
    #[arg(long)]
    pub sk: Option<String>,
}

/// How a command reaches a node's control socket.
#[derive(clap::Args, Debug)]
pub struct RpcArgs {
    /// Node control socket.
    #[arg(long, default_value = DEFAULT_RPC)]
    pub rpc: String,
    /// The node's token; also read from `NULL_RPC_TOKEN`.
    #[arg(long, env = TOKEN_ENV, conflicts_with = "rpc_token_file", hide_env_values = true)]
    pub rpc_token: Option<String>,
    /// File holding the node's token, such as `rpc.token` in its data
    /// directory.
    #[arg(long)]
    pub rpc_token_file: Option<PathBuf>,
}

impl RpcArgs {
    /// The token from the flag, the environment or the file.
    ///
    /// # Errors
    /// Returns [`Error::Argument`] when none was given.
    pub fn token(&self) -> Result<Token> {
        match (&self.rpc_token, &self.rpc_token_file) {
            (Some(text), _) => Token::new(text),
            (None, Some(path)) => Token::from_file(path),
            (None, None) => Err(Error::Argument(format!(
                "pass --rpc-token, --rpc-token-file or set {TOKEN_ENV}"
            ))),
        }
    }

    /// The endpoint these arguments describe.
    ///
    /// # Errors
    /// See [`Self::token`].
    pub fn endpoint(&self) -> Result<Endpoint> {
        Ok(Endpoint {
            addr: self.rpc.clone(),
            token: self.token()?,
        })
    }

    /// Connects and authenticates.
    ///
    /// # Errors
    /// Fails without a token, if the socket is unreachable, or with
    /// [`Error::Unauthorized`].
    pub async fn connect(&self) -> Result<Client> {
        self.endpoint()?.connect().await
    }
}

/// Commands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run a node.
    Run {
        /// Network: `test` or `main`.
        #[arg(long, default_value = "test")]
        network: Network,
        /// Data directory holding `chain.redb` and `rpc.token`; defaults to
        /// `<user data>/<network>/chain`, the same chain the desktop app uses.
        #[arg(long)]
        datadir: Option<PathBuf>,
        /// Keep the chain in memory only, for tests and throwaway nodes.
        #[arg(long, conflicts_with = "datadir")]
        in_memory: bool,
        /// Address to accept peers on.
        #[arg(long)]
        listen: Option<SocketAddr>,
        /// Peers to connect to as `host:port`; repeatable.
        #[arg(long)]
        connect: Vec<String>,
        /// Extra seed peers as `host:port`; repeatable.
        #[arg(long)]
        seed: Vec<String>,
        /// SOCKS5 proxy for outbound connections, for example Tor's
        /// `127.0.0.1:9050`.
        #[arg(long)]
        proxy: Option<SocketAddr>,
        /// SAM bridge for I2P `.i2p` peers; the bare flag uses the
        /// default router address.
        #[arg(long, num_args = 0..=1, default_missing_value = crate::i2p::DEFAULT_SAM)]
        i2p: Option<SocketAddr>,
        /// Mine to this address.
        #[arg(long)]
        mine: Option<String>,
        /// Miner worker threads; defaults to one. Ignored without --mine.
        #[arg(long, default_value_t = 1)]
        mining_threads: usize,
        /// Control socket address.
        #[arg(long, default_value = DEFAULT_RPC)]
        rpc: SocketAddr,
        /// Serve JSON-RPC 2.0 over HTTP on this address, behind the same
        /// token as the control socket (`Authorization: Bearer`).
        #[arg(long)]
        rpc_http: Option<SocketAddr>,
        /// Token the control socket demands; also read from
        /// `NULL_RPC_TOKEN`. Generated and written to `rpc.token` in the
        /// data directory when omitted.
        #[arg(long, env = TOKEN_ENV, hide_env_values = true)]
        rpc_token: Option<String>,
        /// Serve Prometheus metrics at `GET /metrics` on this address.
        #[arg(long)]
        metrics: Option<SocketAddr>,
        /// Shell command to run on every new main-chain tip, with `%s`
        /// replaced by the block hash.
        #[arg(long)]
        blocknotify: Option<String>,
        /// Log level: debug, info, warn or error.
        #[arg(long, default_value = "info")]
        log_level: crate::logging::Level,
    },
    /// Generate a seed phrase with its account 0 spending key and default
    /// address, without a file.
    Keygen {
        /// Network to write the address for.
        #[arg(long, default_value = "test")]
        network: Network,
    },
    /// Print a node's status line.
    Status {
        /// The node.
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Create an encrypted wallet file from a new seed phrase, a phrase
    /// to restore, or a spending key.
    Create {
        /// Wallet file to create.
        #[arg(long)]
        wallet: PathBuf,
        /// Spending key to import, hex.
        #[arg(long, conflicts_with = "phrase")]
        sk: Option<String>,
        /// Restore from a seed phrase, taken from `NULL_SEED_PHRASE` or
        /// prompted. A fresh phrase is generated and printed if neither
        /// this nor `--sk` is given.
        #[arg(long)]
        phrase: bool,
        /// Account of the seed phrase to use.
        #[arg(long, default_value_t = 0, conflicts_with = "sk")]
        account: u32,
        /// Create a watch-only wallet from an exported full viewing key:
        /// it sees deposits and spends but cannot sign.
        #[arg(long, conflicts_with_all = ["sk", "phrase"])]
        viewing_key: Option<String>,
        /// Network the wallet is for.
        #[arg(long, default_value = "test")]
        network: Network,
    },
    /// Build the genesis coinbase paying the premine to an address and
    /// write its bytes to a file, for committing as the network's
    /// `genesis_coinbase`. Every run yields a new transaction and so a
    /// new genesis hash.
    GenesisCoinbase {
        /// Network the coinbase is for.
        #[arg(long, default_value = "test")]
        network: Network,
        /// The development fund address.
        #[arg(long)]
        address: String,
        /// Where to write the encoded transaction.
        #[arg(long)]
        out: PathBuf,
    },
    /// Print a wallet's full viewing key, for a watch-only wallet
    /// elsewhere.
    ExportViewingKey {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// Network, for a wallet file.
        #[arg(long, default_value = "test")]
        network: Network,
    },
    /// Show the default address of a wallet.
    Address {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// Network, for a wallet file.
        #[arg(long, default_value = "test")]
        network: Network,
    },
    /// Scan the chain through a node and show the balance.
    Balance {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// The node.
        #[command(flatten)]
        rpc: RpcArgs,
        /// Scan compact blocks instead of full ones. Memos are not
        /// recovered, but the balance and witnesses are the same.
        #[arg(long)]
        light: bool,
    },
    /// Pay an address through a node.
    Send {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// Recipient address.
        #[arg(long)]
        to: String,
        /// Amount in smallest units.
        #[arg(long)]
        amount: u64,
        /// The node.
        #[command(flatten)]
        rpc: RpcArgs,
        /// Scan compact blocks instead of full ones.
        #[arg(long)]
        light: bool,
    },
    /// Serve a faucet: `GET /pay/<address>` sends a fixed amount.
    Faucet {
        /// The wallet paying out.
        #[command(flatten)]
        wallet: WalletArgs,
        /// The node.
        #[command(flatten)]
        rpc: RpcArgs,
        /// Address to serve HTTP on.
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// Amount per request in smallest units.
        #[arg(long, default_value_t = 100_000_000)]
        amount: u64,
    },
}

/// Runs the parsed command.
///
/// # Errors
/// Returns the first failure.
pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run {
            network,
            datadir,
            in_memory,
            listen,
            connect,
            seed,
            proxy,
            i2p,
            mine,
            mining_threads,
            rpc,
            rpc_http,
            rpc_token,
            metrics,
            blocknotify,
            log_level,
        } => {
            crate::logging::set_level(log_level);
            let token = rpc_token.as_deref().map(Token::new).transpose()?;
            run_node(RunOptions {
                network,
                datadir: node_datadir(datadir, in_memory, network)?,
                listen,
                connect,
                seed,
                proxy,
                i2p,
                mine,
                mining_threads,
                rpc,
                rpc_http,
                rpc_token: token,
                metrics,
                blocknotify,
            })
            .await
        }
        Command::Status { rpc } => {
            let mut client = rpc.connect().await?;
            println!("{}", client.call("status").await?);
            Ok(())
        }
        Command::Keygen { network } => keygen(network),
        Command::Create {
            wallet,
            sk,
            phrase,
            account,
            viewing_key,
            network,
        } => match viewing_key {
            Some(text) => create_watch_only(&wallet, &text, network),
            None => create_wallet(&wallet, sk.as_deref(), phrase, account, network),
        },
        Command::ExportViewingKey { wallet, network } => export_viewing_key(&wallet, network),
        Command::GenesisCoinbase {
            network,
            address,
            out,
        } => genesis_coinbase(network, &address, &out).await,
        Command::Address { wallet, network } => show_address(&wallet, network),
        Command::Balance { wallet, rpc, light } => {
            let mut client = rpc.connect().await?;
            let genesis = fetch_genesis(&mut client).await?;
            let maturity = network_of(&genesis)?.params().coinbase_maturity;
            let wallet = open_wallet(&wallet, genesis)?;
            let scanned = sync_wallet(&mut client, &wallet, light, maturity).await?;
            for note in wallet.unspent()? {
                println!(
                    "note at height {} position {}: {}",
                    note.height,
                    note.position,
                    note.note.value().raw()
                );
            }
            println!("scanned to height {scanned}, balance {}", wallet.balance()?);
            Ok(())
        }
        Command::Send {
            wallet,
            to,
            amount,
            rpc,
            light,
        } => send(&wallet, &to, amount, &rpc, light).await,
        Command::Faucet {
            wallet,
            rpc,
            listen,
            amount,
        } => run_faucet(&wallet, &rpc, listen, amount).await,
    }
}

/// Syncs the wallet through the node, then builds and submits a payment.
async fn send(
    wallet: &WalletArgs,
    to: &str,
    amount: u64,
    rpc: &RpcArgs,
    light: bool,
) -> Result<()> {
    let amount = Amount::from_raw(amount)?;
    let mut client = rpc.connect().await?;
    let genesis = fetch_genesis(&mut client).await?;
    let network = network_of(&genesis)?;
    let recipient = Address::decode(to, network.address_prefix())?;
    let wallet = open_wallet(wallet, genesis)?;
    let params = network.params();
    let scanned = sync_wallet(&mut client, &wallet, light, params.coinbase_maturity).await?;
    let branch = params.branch_at(next_height(scanned)?);
    let pk = tokio::task::spawn_blocking(ProvingKey::build)
        .await
        .map_err(|_| Error::Stopped)??;
    let txid = pay(&mut client, &wallet, &pk, recipient, amount, branch).await?;
    println!("submitted {txid}");
    Ok(())
}

/// The chain directory for `nulld run`: the given one, the per-user
/// default, or none for `--in-memory`. Directories are created owner-only.
fn node_datadir(
    datadir: Option<PathBuf>,
    in_memory: bool,
    network: Network,
) -> Result<Option<PathBuf>> {
    if in_memory {
        return Ok(None);
    }
    let dir = match datadir {
        Some(dir) => dir,
        None => paths::chain_dir(&paths::default_network_dir(network)?),
    };
    paths::private_directory(&dir)?;
    Ok(Some(dir))
}

/// Starts a node and runs it until interrupted.
#[allow(clippy::too_many_arguments)] // mirrors the command line options
/// The options `nulld run` was given.
struct RunOptions {
    network: Network,
    datadir: Option<PathBuf>,
    listen: Option<SocketAddr>,
    connect: Vec<String>,
    seed: Vec<String>,
    proxy: Option<SocketAddr>,
    i2p: Option<SocketAddr>,
    mine: Option<String>,
    mining_threads: usize,
    rpc: SocketAddr,
    rpc_http: Option<SocketAddr>,
    rpc_token: Option<Token>,
    metrics: Option<SocketAddr>,
    blocknotify: Option<String>,
}

async fn run_node(opts: RunOptions) -> Result<()> {
    let RunOptions {
        network,
        datadir,
        listen,
        connect,
        seed,
        proxy,
        i2p,
        mine,
        mining_threads,
        rpc,
        rpc_http,
        rpc_token,
        metrics,
        blocknotify,
    } = opts;
    let mine_to = mine
        .map(|a| Address::decode(&a, network.address_prefix()))
        .transpose()?;
    let token_file = datadir.as_ref().map(|dir| dir.join(TOKEN_FILE));
    let token_given = rpc_token.is_some();
    let mut targets = connect;
    targets.extend(seed);
    targets.extend(network.seeds().iter().map(ToString::to_string));
    let config = Config {
        network,
        datadir,
        listen,
        connect: targets,
        proxy,
        i2p,
        mine_to,
        mining_threads,
        rpc: Some(rpc),
        rpc_http,
        rpc_token,
        block_notify: blocknotify,
        metrics,
        max_inbound: crate::config::DEFAULT_MAX_INBOUND,
    };
    let shutdown = Shutdown::listen()?;
    let handle = crate::node::spawn(config).await?;
    let log = crate::node::log;
    log(&format!("nulld up on the {network} network"));
    match handle.listen_addr {
        Some(addr) => log(&format!("peers      listening on {addr}")),
        None => log("peers      outbound only"),
    }
    if i2p.is_some() {
        log("i2p        .i2p peers via the SAM bridge");
    }
    match handle.rpc_addr {
        Some(addr) => log(&format!("control    {addr}")),
        None => log("control    disabled"),
    }
    match handle.rpc_http_addr {
        Some(addr) => log(&format!("json-rpc   http://{addr}/")),
        None => log("json-rpc   disabled"),
    }
    match handle.metrics_addr {
        Some(addr) => log(&format!("metrics    {addr}")),
        None => log("metrics    disabled"),
    }
    // Say where the token is. An in-memory node with a generated token
    // has nowhere to keep it, so it is printed once.
    match (&token_file, token_given, &handle.rpc_token) {
        (Some(path), _, _) => log(&format!("token      {}", path.display())),
        (None, true, _) => log("token      as supplied"),
        (None, false, Some(token)) => log(&format!("token      {}", token.expose())),
        (None, false, None) => {}
    }
    shutdown.requested().await;
    handle.shutdown().await;
    Ok(())
}

/// Builds and submits a payment, returning the transaction id.
///
/// # Errors
/// Fails on insufficient funds, a building error, or a refused submit.
pub async fn pay(
    client: &mut Client,
    wallet: &Wallet,
    pk: &ProvingKey,
    recipient: Address,
    amount: Amount,
    branch: BranchId,
) -> Result<String> {
    let payment = Payment {
        recipient,
        amount,
        memo: Memo::empty(),
    };
    let tx = build_payment(wallet, payment, pk, branch, &mut rand::rngs::OsRng)?;
    client
        .call(&format!("submit {}", to_hex(&tx.to_vec())))
        .await
}

fn sk_from_hex(sk: &str) -> Result<SpendingKey> {
    let bytes: [u8; 32] = from_hex(sk)?
        .try_into()
        .map_err(|_| Error::Argument("spending key must be 32 bytes".into()))?;
    Ok(SpendingKey::from_bytes(bytes))
}

/// The passphrase from the environment, or prompted; confirmed when
/// creating a wallet.
/// The wallet passphrase: from `NULL_WALLET_PASSPHRASE`, else prompted,
/// twice when `confirm` is set.
///
/// # Errors
/// Fails if the terminal cannot be read or the confirmations differ.
pub fn passphrase(confirm: bool) -> Result<Vec<u8>> {
    if let Ok(value) = std::env::var(PASSPHRASE_ENV) {
        return Ok(value.into_bytes());
    }
    let first = rpassword::prompt_password("Passphrase: ")?;
    if confirm {
        let second = rpassword::prompt_password("Confirm passphrase: ")?;
        if first != second {
            return Err(Error::Argument("passphrases differ".into()));
        }
    }
    Ok(first.into_bytes())
}

/// Creates a wallet file from an imported key, a restored phrase, or a
/// fresh phrase, which is printed once.
fn create_wallet(
    path: &Path,
    sk: Option<&str>,
    restore: bool,
    account: u32,
    network: Network,
) -> Result<()> {
    let (sk, fresh) = match (sk, restore) {
        (Some(hex), _) => (sk_from_hex(hex)?, None),
        (None, true) => (seed_phrase()?.spending_key(account)?, None),
        (None, false) => {
            let phrase = SeedPhrase::generate(&mut rand::rngs::OsRng)?;
            (phrase.spending_key(account)?, Some(phrase))
        }
    };
    let passphrase = passphrase(true)?;
    let genesis = genesis(&network.params()).hash();
    let created = Wallet::create(path, &sk, genesis, &passphrase, &mut rand::rngs::OsRng)?;
    if let Some(phrase) = fresh {
        println!("seed_phrase: {}", *phrase.words());
        println!("write the seed phrase down; it restores this wallet on any machine");
    }
    println!(
        "address: {}",
        created
            .keys()
            .default_address()?
            .encode(network.address_prefix())
    );
    Ok(())
}

/// Opens the wallet against the node's network and serves the faucet.
async fn run_faucet(
    wallet: &WalletArgs,
    rpc: &RpcArgs,
    listen: SocketAddr,
    amount: u64,
) -> Result<()> {
    let node = rpc.endpoint()?;
    let mut client = node.connect().await?;
    let genesis = fetch_block(&mut client, 0).await?.hash();
    let network = network_of(&genesis)?;
    let wallet = open_wallet(wallet, genesis)?;
    let amount = Amount::from_raw(amount)?;
    crate::faucet::serve(listen, node, wallet, amount, network).await
}

/// Builds the premine coinbase for `address` and writes it to `out`.
async fn genesis_coinbase(network: Network, address: &str, out: &Path) -> Result<()> {
    let dev = Address::decode(address, network.address_prefix())?;
    let pk = tokio::task::spawn_blocking(ProvingKey::build)
        .await
        .map_err(|_| Error::Stopped)??;
    let tx = null_chain::genesis::build_genesis_coinbase(
        &network.params(),
        &dev,
        &pk,
        &mut rand::rngs::OsRng,
    )?;
    let bytes = tx.to_vec();
    std::fs::write(out, &bytes)?;
    println!("wrote {} bytes, txid {}", bytes.len(), tx.txid());
    Ok(())
}

/// Prints a wallet's full viewing key in its text form.
fn export_viewing_key(wallet: &WalletArgs, network: Network) -> Result<()> {
    let genesis = genesis(&network.params()).hash();
    let wallet = open_wallet(wallet, genesis)?;
    println!(
        "{}",
        null_protocol::viewing_key::encode_full_viewing_key(
            wallet.keys().full_viewing_key(),
            network.address_prefix()
        )
    );
    Ok(())
}

/// Creates a watch-only wallet file from an exported full viewing key.
fn create_watch_only(path: &Path, viewing_key: &str, network: Network) -> Result<()> {
    let fvk =
        null_protocol::viewing_key::decode_full_viewing_key(viewing_key, network.address_prefix())?;
    let passphrase = passphrase(true)?;
    let genesis = genesis(&network.params()).hash();
    let created =
        Wallet::create_watch_only(path, fvk, genesis, &passphrase, &mut rand::rngs::OsRng)?;
    println!(
        "watch-only address: {}",
        created
            .keys()
            .default_address()?
            .encode(network.address_prefix())
    );
    Ok(())
}

/// Prints a fresh seed phrase with its account 0 key and address.
fn keygen(network: Network) -> Result<()> {
    let phrase = SeedPhrase::generate(&mut rand::rngs::OsRng)?;
    let keys = WalletKeys::from_spending_key(phrase.spending_key(0)?)?;
    println!("seed_phrase: {}", *phrase.words());
    println!("spending_key: {}", to_hex(&keys.spending_key()?.to_bytes()));
    println!(
        "address: {}",
        keys.default_address()?.encode(network.address_prefix())
    );
    Ok(())
}

/// Prints a wallet's default address for `network`.
fn show_address(wallet: &WalletArgs, network: Network) -> Result<()> {
    let genesis = genesis(&network.params()).hash();
    let wallet = open_wallet(wallet, genesis)?;
    println!(
        "{}",
        wallet
            .keys()
            .default_address()?
            .encode(network.address_prefix())
    );
    Ok(())
}

/// The network a node is on, from its genesis hash.
fn network_of(genesis: &BlockHash) -> Result<Network> {
    Network::for_genesis(genesis)
        .ok_or_else(|| Error::Argument("node is on an unknown network".into()))
}

/// The seed phrase from the environment, or prompted without echo.
fn seed_phrase() -> Result<SeedPhrase> {
    let text = match std::env::var(PHRASE_ENV) {
        Ok(value) => value,
        Err(_) => rpassword::prompt_password("Seed phrase: ")?,
    };
    Ok(SeedPhrase::parse(&text)?)
}

/// Opens the wallet file with its passphrase, or an in-memory wallet
/// from a spending key.
fn open_wallet(args: &WalletArgs, genesis: BlockHash) -> Result<Wallet> {
    match (&args.wallet, &args.sk) {
        (Some(path), _) => open_wallet_file(path, genesis),
        (None, Some(hex)) => Ok(Wallet::in_memory(
            &sk_from_hex(hex)?,
            genesis,
            &mut rand::rngs::OsRng,
        )?),
        (None, None) => Err(Error::Argument("pass --wallet or --sk".into())),
    }
}

fn open_wallet_file(path: &Path, genesis: BlockHash) -> Result<Wallet> {
    Ok(Wallet::open(path, genesis, &passphrase(false)?)?)
}

/// Brings the wallet up to the node's tip, rolling back first if the
/// node's chain diverged from what the wallet scanned. `maturity` is the
/// network's coinbase maturity: a full-block scan also fetches the coinbase
/// maturing at each height, while compact blocks arrive in tree order
/// already. Returns the tip.
///
/// # Errors
/// Fails on a control socket or wallet error.
pub async fn sync_wallet(
    client: &mut impl Control,
    wallet: &Wallet,
    light: bool,
    maturity: u32,
) -> Result<u32> {
    let tip = status_height(client).await?;
    let mut height = wallet.next_height()?;
    while height > 0 {
        let scanned = height.saturating_sub(1);
        let Some(hash) = wallet.scanned_hash(scanned)? else {
            break;
        };
        let matches = scanned <= tip && fetch_hash(client, scanned).await? == Some(hash);
        if matches {
            break;
        }
        height = scanned;
    }
    if height < wallet.next_height()? {
        wallet.rollback_to(height.saturating_sub(1))?;
    }
    for h in wallet.next_height()?..=tip {
        if light {
            wallet.scan_compact(&fetch_compact(client, h).await?)?;
        } else {
            let block = fetch_block(client, h).await?;
            let earlier = match earlier_origin(h, maturity) {
                Some(origin) => Some(fetch_coinbase(client, origin).await?),
                None => None,
            };
            wallet.scan(&block, maturity, earlier.as_ref())?;
        }
    }
    Ok(tip)
}

/// The genesis hash, over the cheap `hash` request.
async fn fetch_genesis(client: &mut impl Control) -> Result<BlockHash> {
    fetch_hash(client, 0)
        .await?
        .ok_or_else(|| Error::Argument("node has no genesis".into()))
}

/// The hash of the block at `height`, or `None` past the tip. One 32-byte
/// reply, so the reorg check does not re-download whole blocks.
async fn fetch_hash(client: &mut impl Control, height: u32) -> Result<Option<BlockHash>> {
    match client.call(&format!("hash {height}")).await {
        Ok(hex) => Ok(Some(BlockHash::from_bytes(
            from_hex(&hex)?
                .try_into()
                .map_err(|_| Error::Argument("hash length".into()))?,
        ))),
        Err(Error::Argument(reason)) if reason == "not found" => Ok(None),
        Err(error) => Err(error),
    }
}

async fn fetch_compact(client: &mut impl Control, height: u32) -> Result<CompactBlock> {
    let hex = client.call(&format!("compact {height}")).await?;
    Ok(CompactBlock::from_slice(&from_hex(&hex)?)?)
}

async fn status_height(client: &mut impl Control) -> Result<u32> {
    let status = client.call("status").await?;
    status
        .split_whitespace()
        .find_map(|w| w.strip_prefix("height="))
        .and_then(|h| h.parse().ok())
        .ok_or_else(|| Error::Argument("bad status".into()))
}

/// The coinbase of the main-chain block at `height`.
async fn fetch_coinbase(client: &mut impl Control, height: u32) -> Result<Transaction> {
    let hex = client.call(&format!("coinbase {height}")).await?;
    Ok(Transaction::from_slice(&from_hex(&hex)?)?)
}

/// The full block at `height`.
///
/// # Errors
/// Fails if the node has no such block or the reply is malformed.
pub async fn fetch_block(client: &mut impl Control, height: u32) -> Result<Block> {
    let hex = client.call(&format!("block {height}")).await?;
    Ok(Block::from_slice(&from_hex(&hex)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_nodes_have_no_datadir_and_given_ones_are_created() {
        assert_eq!(node_datadir(None, true, Network::Test).unwrap(), None);
        let dir = tempfile::tempdir().unwrap();
        let chain = dir.path().join("nested").join("chain");
        let resolved = node_datadir(Some(chain.clone()), false, Network::Test).unwrap();
        assert_eq!(resolved, Some(chain.clone()));
        assert!(chain.is_dir());
    }

    #[test]
    fn in_memory_and_datadir_flags_conflict() {
        let parsed = Cli::try_parse_from(["nulld", "run", "--in-memory", "--datadir", "x"]);
        assert!(parsed.is_err());
        assert!(Cli::try_parse_from(["nulld", "run", "--in-memory"]).is_ok());
    }
}
