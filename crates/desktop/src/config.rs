//! Persistent desktop settings and automatic application storage.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use null_node::config::{Config as NodeConfig, Network};
use null_node::paths::{self, create_private, private_directory, write_private};
use null_node::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::backend;

/// Desktop command-line overrides. Ordinary startup needs no arguments.
#[derive(Parser, Default)]
#[command(
    name = "null-desktop",
    about = "NULL wallet with an embedded full node"
)]
pub struct Args {
    /// Network override; a new configuration defaults to main.
    #[arg(long)]
    pub network: Option<Network>,
    /// Application data directory; defaults to the operating system's user data location.
    #[arg(long)]
    pub datadir: Option<PathBuf>,
    /// Configuration file; defaults to null.conf inside the application data directory.
    #[arg(long)]
    pub conf: Option<PathBuf>,
    /// Advanced override for an existing or new wallet file.
    #[arg(long)]
    pub wallet: Option<PathBuf>,
    /// Bootstrap peer; repeat for multiple peers.
    #[arg(long)]
    pub connect: Vec<String>,
    /// Accept incoming peer connections at this address.
    #[arg(long)]
    pub listen: Option<SocketAddr>,
    /// Public IP:port to announce when using a forwarded listening port.
    #[arg(long)]
    pub advertise: Option<SocketAddr>,
    /// Combined authenticated RPC listener, loopback only.
    #[arg(long)]
    pub rpc: Option<SocketAddr>,
    /// SOCKS5 proxy for outbound peer connections.
    #[arg(long)]
    pub proxy: Option<SocketAddr>,
    /// Only dial out for this launch: no listener and no router port
    /// mapping, whatever null.conf says. Not saved.
    #[arg(long)]
    pub no_incoming: bool,
}

/// Locations shown in the application's storage details.
#[derive(Clone, Debug)]
pub struct Paths {
    /// Application data directory, containing null.conf and network directories.
    pub data: PathBuf,
    /// Persistent configuration file.
    pub config: PathBuf,
    /// Wallet selected automatically for this launch.
    pub wallet: PathBuf,
    /// Where the log is written when the log file is switched on.
    pub log: PathBuf,
}

/// Validated settings and initialized directories for one desktop launch.
pub struct Startup {
    /// Configuration for the single-process backend.
    pub backend: backend::Config,
    /// Application storage locations.
    pub paths: Paths,
    /// Idle time after which the GUI locks an unlocked wallet; `None` never.
    pub lock_after: Option<Duration>,
}

/// Built-in miner settings, saved in `null.conf` by the mining switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mining {
    /// Mine whenever a wallet is unlocked.
    pub enabled: bool,
    /// Worker threads, from 1 to [`max_mining_threads`].
    pub threads: usize,
}

impl Mining {
    /// These settings with `threads` clamped to what this machine has.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            threads: self.threads.clamp(1, max_mining_threads()),
            ..self
        }
    }
}

/// Logical CPUs on this machine: the most mining threads worth running.
pub fn max_mining_threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Mining threads by default: half the CPUs, so the machine stays usable.
fn default_mining_threads() -> usize {
    (max_mining_threads() / 2).max(1)
}

/// Saves the mining settings into the configuration at `path`, keeping
/// every other setting and comment as it is.
///
/// # Errors
/// Fails if the file cannot be read, parsed, or written.
pub fn save_mining(path: &Path, mining: Mining) -> Result<()> {
    edit_settings(path, |document| {
        document.insert("mine", toml_edit::value(mining.enabled));
        let threads = i64::try_from(mining.threads).unwrap_or(i64::MAX);
        document.insert("mining_threads", toml_edit::value(threads));
    })
}

/// Whether other nodes may connect to this one, saved in `null.conf` by
/// the switches on the Node page. Both default to on: a wallet that only
/// dials out can never be found by other wallets, so without listeners
/// every wallet depends on the project's seeds alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incoming {
    /// Listen for peers.
    pub enabled: bool,
    /// Ask the router to forward the listening port.
    pub port_mapping: bool,
}

/// The rest of `null.conf` that decides what the incoming switches do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IncomingRules {
    /// The explicit `listen` address, if any.
    pub listen: Option<SocketAddr>,
    /// Whether `advertise` says the port is forwarded by hand.
    pub advertised: bool,
    /// Whether peers are dialed through a proxy.
    pub proxied: bool,
}

impl IncomingRules {
    /// What the node runs with when started with `incoming`: a proxy,
    /// a loopback listener or a hand-forwarded port turn parts of it off.
    #[must_use]
    pub fn apply(self, incoming: Incoming) -> Incoming {
        let listening = Listening::from_settings(incoming, self);
        Incoming {
            enabled: listening.listen.is_some(),
            port_mapping: listening.port_mapping,
        }
    }
}

/// How the embedded node listens, derived from the saved settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Listening {
    listen: Option<SocketAddr>,
    /// Whether `listen` is the default, which may move off a taken port.
    fallback: bool,
    port_mapping: bool,
}

impl Listening {
    /// Off when incoming connections are switched off. With a proxy,
    /// only an explicit `listen` is used and no port is mapped: a Tor
    /// user announces nothing, so a public port would only expose them.
    /// Otherwise the explicit `listen`, or every IPv4 interface on the
    /// network's port, which another local node may already hold. The
    /// router is left alone for a loopback listener, which it cannot
    /// reach, and when `advertise` says the port is forwarded by hand.
    fn from_settings(incoming: Incoming, rules: IncomingRules) -> Self {
        let IncomingRules {
            listen,
            advertised,
            proxied,
        } = rules;
        let off = Self {
            listen: None,
            fallback: false,
            port_mapping: false,
        };
        if !incoming.enabled {
            return off;
        }
        if proxied {
            return Self { listen, ..off };
        }
        let bound = listen.unwrap_or(DEFAULT_LISTEN);
        Self {
            listen: Some(bound),
            fallback: listen.is_none(),
            port_mapping: incoming.port_mapping && !advertised && !bound.ip().is_loopback(),
        }
    }
}

/// Where the desktop listens unless `listen` says otherwise: every IPv4
/// interface, so a router mapping can reach it, on the seeds' port.
const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    null_node::config::DEFAULT_P2P_PORT,
);

/// Saves the incoming connection switches into the configuration at
/// `path`, keeping every other setting and comment as it is. They apply
/// at the next start, since the listener is bound when the node starts.
///
/// # Errors
/// Fails if the file cannot be read, parsed, or written.
pub fn save_incoming(path: &Path, incoming: Incoming) -> Result<()> {
    edit_settings(path, |document| {
        document.insert("incoming", toml_edit::value(incoming.enabled));
        document.insert("port_mapping", toml_edit::value(incoming.port_mapping));
    })
}

/// Saves the log file switch into the configuration at `path`, keeping
/// every other setting and comment as it is.
///
/// # Errors
/// Fails if the file cannot be read, parsed, or written.
pub fn save_log_file(path: &Path, enabled: bool) -> Result<()> {
    edit_settings(path, |document| {
        document.insert("log_file", toml_edit::value(enabled));
    })
}

/// Applies `edit` to the configuration at `path`. The file is replaced
/// atomically and stays owner-only on Unix.
fn edit_settings(path: &Path, edit: impl FnOnce(&mut toml_edit::DocumentMut)) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let mut document: toml_edit::DocumentMut = text
        .parse()
        .map_err(|error| Error::Argument(format!("cannot edit {}: {error}", path.display())))?;
    edit(&mut document);
    let temporary = path.with_extension("conf.tmp");
    write_private(&temporary, document.to_string().as_bytes())?;
    fs::rename(&temporary, path)?;
    Ok(())
}

/// Log file name in a network directory.
pub const LOG_FILE: &str = "debug.log";
/// Size above which an existing log moves to `debug.log.1` when logging
/// starts, replacing the previous old log, so the file cannot grow forever.
pub const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

/// The optional log file, off unless the user switches it on: its lines
/// name peer addresses and transaction ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFile {
    /// Whether the log is written.
    pub enabled: bool,
    /// `debug.log` in the network directory.
    pub path: PathBuf,
}

impl LogFile {
    /// Starts writing the log, first moving a log larger than
    /// [`MAX_LOG_BYTES`] aside, or stops writing it.
    ///
    /// # Errors
    /// Fails if the old log cannot be moved or the file opened.
    pub fn apply(&self) -> Result<()> {
        if !self.enabled {
            null_node::logging::clear_file();
            return Ok(());
        }
        rotate_log(&self.path, MAX_LOG_BYTES)?;
        null_node::logging::set_file(&self.path)?;
        Ok(())
    }
}

/// Moves `path` to `<path>.1` when it is larger than `max_bytes`.
fn rotate_log(path: &Path, max_bytes: u64) -> Result<()> {
    match fs::metadata(path) {
        Ok(meta) if meta.len() > max_bytes => fs::rename(path, path.with_extension("log.1"))?,
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    Ok(())
}

/// Default idle minutes before the wallet locks itself.
const DEFAULT_LOCK_MINUTES: u64 = 15;

/// Seconds per minute, for the lock timeout.
const SECONDS_PER_MINUTE: u64 = 60;

// One field per null.conf key, and the file's switches are booleans:
// enums would change the file format users edit by hand.
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    network: String,
    rpc: SocketAddr,
    connect: Vec<String>,
    listen: Option<SocketAddr>,
    advertise: Option<SocketAddr>,
    proxy: Option<SocketAddr>,
    /// Accept peers on `listen`, or on the default listener without one.
    incoming: bool,
    /// Ask the router to forward the listening port.
    port_mapping: bool,
    wallet: Option<PathBuf>,
    /// Minutes without input before the GUI locks the wallet; 0 disables.
    lock_after_minutes: u64,
    /// Mine to the wallet's main address whenever it is unlocked.
    mine: bool,
    /// Mining worker threads.
    mining_threads: usize,
    /// Append the log to `debug.log` in the network directory.
    log_file: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    wallets: BTreeMap<String, PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            network: "main".into(),
            rpc: SocketAddr::from(([127, 0, 0, 1], 18448)),
            connect: Vec::new(),
            listen: None,
            advertise: None,
            proxy: None,
            incoming: true,
            port_mapping: true,
            wallet: None,
            lock_after_minutes: DEFAULT_LOCK_MINUTES,
            mine: false,
            mining_threads: default_mining_threads(),
            log_file: false,
            wallets: BTreeMap::new(),
        }
    }
}

impl Settings {
    /// The saved incoming connection switches.
    fn incoming(&self) -> Incoming {
        Incoming {
            enabled: self.incoming,
            port_mapping: self.port_mapping,
        }
    }

    /// The saved mining settings, clamped to this machine.
    fn mining(&self) -> Mining {
        Mining {
            enabled: self.mine,
            threads: self.mining_threads,
        }
        .clamped()
    }

    /// The idle lock timeout, or `None` when disabled.
    fn lock_after(&self) -> Option<Duration> {
        (self.lock_after_minutes > 0).then(|| {
            Duration::from_secs(self.lock_after_minutes.saturating_mul(SECONDS_PER_MINUTE))
        })
    }

    fn apply(&mut self, args: &Args, cwd: &Path) {
        if let Some(network) = args.network {
            self.network = network.to_string();
        }
        if let Some(rpc) = args.rpc {
            self.rpc = rpc;
        }
        if !args.connect.is_empty() {
            self.connect.clone_from(&args.connect);
        }
        if args.listen.is_some() {
            self.listen = args.listen;
        }
        if args.advertise.is_some() {
            self.advertise = args.advertise;
        }
        if args.proxy.is_some() {
            self.proxy = args.proxy;
        }
        if let Some(wallet) = &args.wallet {
            self.wallet = Some(cwd.join(wallet));
        }
    }
}

impl Startup {
    /// Loads settings, creates missing data directories and null.conf, and finds
    /// the wallet. Existing settings and wallet files are never overwritten.
    /// No seed or passphrase is written to the configuration.
    ///
    /// # Errors
    /// Fails on an inaccessible directory, invalid settings, or a non-loopback RPC.
    pub fn load(args: &Args) -> Result<Self> {
        let cwd = std::env::current_dir()?;
        let data = match &args.datadir {
            Some(path) => cwd.join(path),
            None => paths::user_data_dir()?,
        };
        Self::prepare(args, data, &cwd)
    }

    fn prepare(args: &Args, data: PathBuf, cwd: &Path) -> Result<Self> {
        let config = args
            .conf
            .as_ref()
            .map_or_else(|| data.join("null.conf"), |p| cwd.join(p));
        let (mut settings, fresh) = read_settings(&config)?;
        settings.apply(args, cwd);
        let network: Network = settings.network.parse().map_err(Error::Argument)?;
        if !settings.rpc.ip().is_loopback() {
            return Err(Error::Argument(
                "desktop RPC must bind to a loopback address".into(),
            ));
        }
        let network_dir = paths::network_dir(&data, network);
        // Adopt a scaffold wallet on the first default launch without copying
        // an open database. Persist its absolute path so later launches find it.
        if fresh
            && args.datadir.is_none()
            && settings.wallet.is_none()
            && !paths::wallet_file(&network_dir).try_exists()?
        {
            let legacy = cwd
                .join(".null-desktop")
                .join(network.to_string())
                .join("wallet.redb");
            if legacy.try_exists()? {
                settings.wallets.insert(network.to_string(), legacy);
            }
        }
        let wallet = settings
            .wallet
            .as_ref()
            .or_else(|| settings.wallets.get(&network.to_string()))
            .map_or_else(|| paths::wallet_file(&network_dir), |p| network_dir.join(p));
        let incoming = settings.incoming();
        let launch = Incoming {
            enabled: incoming.enabled && !args.no_incoming,
            ..incoming
        };
        let rules = IncomingRules {
            listen: settings.listen,
            advertised: settings.advertise.is_some(),
            proxied: settings.proxy.is_some(),
        };
        let listening = Listening::from_settings(launch, rules);
        let node = NodeConfig {
            network,
            datadir: Some(paths::chain_dir(&network_dir)),
            listen: listening.listen,
            listen_fallback: listening.fallback,
            port_mapping: listening.port_mapping,
            // A node that does not listen has nothing to advertise, and
            // validation would refuse the saved address.
            advertise: settings.advertise.filter(|_| listening.listen.is_some()),
            // Saved peers first, then the network's seeds, as nulld does.
            // Seeds come from the release, never from null.conf.
            connect: settings
                .connect
                .iter()
                .cloned()
                .chain(
                    network
                        .bootstrap_seeds(settings.proxy.is_some())
                        .into_iter()
                        .map(ToString::to_string),
                )
                .collect(),
            proxy: settings.proxy,
            ..NodeConfig::test()
        };
        // nulld's clap rules do not cover null.conf, so catch a conflicting
        // `advertise` here rather than when the backend starts.
        node.validate()?;
        private_directory(&data)?;
        private_directory(&network_dir)?;
        private_directory(&paths::chain_dir(&network_dir))?;
        if let Some(parent) = wallet.parent() {
            private_directory(parent)?;
        }
        if fresh {
            write_settings(&config, &settings)?;
        }
        let lock_after = settings.lock_after();
        let mining = settings.mining();
        let log = LogFile {
            enabled: settings.log_file,
            path: network_dir.join(LOG_FILE),
        };
        Ok(Self {
            backend: backend::Config {
                node,
                rpc: settings.rpc,
                token_file: network_dir.join("desktop-rpc.token"),
                wallet: wallet.clone(),
                mining,
                incoming,
                incoming_rules: rules,
                log: log.clone(),
                settings: config.clone(),
            },
            paths: Paths {
                data,
                config,
                wallet,
                log: log.path,
            },
            lock_after,
        })
    }
}

fn read_settings(path: &Path) -> Result<(Settings, bool)> {
    match fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)
            .map(|settings| (settings, false))
            .map_err(|error| Error::Argument(format!("cannot read {}: {error}", path.display()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok((Settings::default(), true))
        }
        Err(error) => Err(error.into()),
    }
}

fn write_settings(path: &Path, settings: &Settings) -> Result<()> {
    if let Some(parent) = path.parent() {
        private_directory(parent)?;
    }
    let text =
        toml::to_string_pretty(settings).map_err(|error| Error::Argument(error.to_string()))?;
    let mut file = create_private(path)?;
    file.write_all(
        b"# NULL desktop settings (TOML). Restart the app after editing.\n\
        # Never put your recovery phrase or wallet passphrase in this file.\n\
        # incoming = false: only dial out. port_mapping = false: never ask the\n\
        # router to forward the port (forward it yourself and set advertise).\n\
        # Optional settings (uncomment to enable):\n\
        # listen = \"0.0.0.0:19000\" # Where to accept peers; this is the default.\n\
        # advertise = \"203.0.113.7:19000\" # Your forwarded public IP:port.\n\
        # proxy = \"127.0.0.1:9050\"\n\
        # wallet = \"wallet.redb\" # Relative to the selected network directory.\n\n",
    )?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_launch_creates_mainnet_storage_and_settings_without_a_wallet_or_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let args = Args {
            datadir: Some(data.clone()),
            ..Args::default()
        };
        let startup = Startup::load(&args).unwrap();
        assert!(data.join("main/chain").is_dir());
        assert_eq!(startup.paths.wallet, data.join("main/wallet.redb"));
        assert!(!startup.paths.wallet.exists());
        let (settings, fresh) = read_settings(&startup.paths.config).unwrap();
        assert!(!fresh);
        assert_eq!(settings.network, "main");
        assert!(settings.rpc.ip().is_loopback());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&data).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&startup.paths.config)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn saved_configuration_is_used_and_cli_overrides_do_not_rewrite_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("null.conf");
        let text = "# keep this comment\nnetwork = 'main'\nrpc = '127.0.0.1:0'\nconnect = ['peer:19000']\nwallet = 'custom.redb'\n";
        fs::write(&config, text).unwrap();
        let args = Args {
            datadir: Some(dir.path().into()),
            ..Args::default()
        };
        let startup = Startup::load(&args).unwrap();
        assert_eq!(startup.backend.node.network, Network::Main);
        assert_eq!(
            startup.backend.node.connect.first().map(String::as_str),
            Some("peer:19000"),
            "saved peers come before the network's seeds"
        );
        assert_eq!(startup.paths.wallet, dir.path().join("main/custom.redb"));
        let args = Args {
            datadir: Some(dir.path().into()),
            network: Some(Network::Test),
            ..Args::default()
        };
        let startup = Startup::load(&args).unwrap();
        assert_eq!(startup.paths.wallet, dir.path().join("test/custom.redb"));
        assert_eq!(fs::read_to_string(config).unwrap(), text);
    }

    #[test]
    fn advertised_listener_is_loaded_and_cli_overrides_are_not_saved() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("null.conf");
        let text = "network = 'test'\nlisten = '0.0.0.0:19000'\nadvertise = '127.0.0.1:20000'\n";
        fs::write(&config, text).unwrap();
        let mut args = Args {
            datadir: Some(dir.path().into()),
            ..Args::default()
        };
        let startup = Startup::load(&args).unwrap();
        assert_eq!(
            startup.backend.node.listen,
            Some("0.0.0.0:19000".parse().unwrap())
        );
        assert_eq!(
            startup.backend.node.advertise,
            Some("127.0.0.1:20000".parse().unwrap())
        );
        args.advertise = Some("127.0.0.1:30000".parse().unwrap());
        let startup = Startup::load(&args).unwrap();
        assert_eq!(startup.backend.node.advertise, args.advertise);
        assert_eq!(fs::read_to_string(config).unwrap(), text);
    }

    #[test]
    fn invalid_configuration_is_reported_without_being_replaced() {
        let dir = tempfile::tempdir().unwrap();
        for text in [
            "network = 'invalid'",
            "rpc = '0.0.0.0:18448'",
            "network = 'test'\nlisten = '0.0.0.0:19000'\nadvertise = '127.0.0.1:19000'\nproxy = '127.0.0.1:9050'",
            "unknown = true",
            "broken = [",
        ] {
            fs::write(dir.path().join("null.conf"), text).unwrap();
            assert!(Startup::load(&Args {
                datadir: Some(dir.path().into()),
                ..Args::default()
            })
            .is_err());
            assert_eq!(
                fs::read_to_string(dir.path().join("null.conf")).unwrap(),
                text
            );
        }
    }

    #[test]
    fn the_first_default_launch_remembers_a_legacy_wallet_without_copying_it() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join(".null-desktop/main/wallet.redb");
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        fs::write(&old, b"existing wallet").unwrap();
        let data = dir.path().join("new-data");
        let startup = Startup::prepare(&Args::default(), data.clone(), dir.path()).unwrap();
        assert_eq!(startup.paths.wallet, old);
        let reopened = Startup::prepare(
            &Args::default(),
            data.clone(),
            &dir.path().join("elsewhere"),
        )
        .unwrap();
        assert_eq!(reopened.paths.wallet, old);
        assert_eq!(fs::read(old).unwrap(), b"existing wallet");
        let other = Startup::prepare(
            &Args {
                network: Some(Network::Test),
                ..Args::default()
            },
            data.clone(),
            dir.path(),
        )
        .unwrap();
        assert_eq!(other.paths.wallet, data.join("test/wallet.redb"));
        // Recreating a missing config must prefer a wallet already at the new
        // default location over any old scaffold wallet left behind.
        let preferred_data = dir.path().join("preferred-data");
        let preferred = preferred_data.join("main/wallet.redb");
        fs::create_dir_all(preferred.parent().unwrap()).unwrap();
        fs::write(&preferred, b"current wallet").unwrap();
        let startup = Startup::prepare(&Args::default(), preferred_data, dir.path()).unwrap();
        assert_eq!(startup.paths.wallet, preferred);
    }

    #[test]
    fn first_launch_persists_cli_settings_and_resolves_explicit_paths_from_the_working_directory() {
        let dir = tempfile::tempdir().unwrap();
        let args = Args::try_parse_from([
            "null-desktop",
            "--conf",
            "settings/custom.conf",
            "--wallet",
            "backup.redb",
            "--network",
            "test",
            "--rpc",
            "127.0.0.1:0",
            "--connect",
            "one:19000",
            "--connect",
            "two:19000",
            "--listen",
            "127.0.0.1:19001",
            "--proxy",
            "127.0.0.1:9050",
        ])
        .unwrap();
        let data = dir.path().join("data");
        let startup = Startup::prepare(&args, data, dir.path()).unwrap();
        assert_eq!(
            startup.paths.config,
            dir.path().join("settings/custom.conf")
        );
        assert_eq!(startup.paths.wallet, dir.path().join("backup.redb"));
        assert_eq!(startup.backend.node.connect, ["one:19000", "two:19000"]);
        assert_eq!(startup.backend.node.listen, args.listen);
        assert_eq!(startup.backend.node.proxy, args.proxy);
        let (saved, fresh) = read_settings(&startup.paths.config).unwrap();
        assert!(!fresh);
        assert_eq!(saved.wallet, Some(startup.paths.wallet));
        assert_eq!(saved.connect, startup.backend.node.connect);
        assert!(write_settings(&startup.paths.config, &Settings::default()).is_err());
    }

    #[test]
    fn idle_locking_defaults_to_fifteen_minutes_and_zero_disables_it() {
        assert_eq!(
            Settings::default().lock_after(),
            Some(Duration::from_secs(15 * 60))
        );
        let never: Settings = toml::from_str("lock_after_minutes = 0").unwrap();
        assert_eq!(never.lock_after(), None);
        let older: Settings = toml::from_str("network = \"test\"").unwrap();
        assert_eq!(older.lock_after_minutes, DEFAULT_LOCK_MINUTES);
        assert!(toml::from_str::<Settings>("lock_after_minutes = -1").is_err());
    }

    #[test]
    fn main_network_dials_its_seeds_without_saving_them() {
        let dir = tempfile::tempdir().unwrap();
        let args = Args {
            datadir: Some(dir.path().join("data")),
            network: Some(Network::Main),
            connect: vec!["peer:19000".into()],
            ..Args::default()
        };
        let startup = Startup::load(&args).unwrap();
        let connect = &startup.backend.node.connect;
        assert_eq!(connect.first().map(String::as_str), Some("peer:19000"));
        for seed in Network::Main.seeds() {
            assert!(connect.iter().any(|c| c == seed), "{seed}");
        }
        let (saved, _) = read_settings(&startup.paths.config).unwrap();
        assert_eq!(saved.connect, ["peer:19000"]);
    }

    #[test]
    fn onion_seeds_are_dialed_only_with_a_proxy() {
        let dials_onions = |proxy: Option<SocketAddr>| {
            let dir = tempfile::tempdir().unwrap();
            let args = Args {
                datadir: Some(dir.path().join("data")),
                network: Some(Network::Main),
                proxy,
                ..Args::default()
            };
            let startup = Startup::load(&args).unwrap();
            let connect = &startup.backend.node.connect;
            Network::Main
                .onion_seeds()
                .iter()
                .all(|seed| connect.iter().any(|c| c == seed))
        };
        assert!(!dials_onions(None));
        assert!(dials_onions(Some("127.0.0.1:9050".parse().unwrap())));
    }

    #[test]
    fn mining_settings_save_in_place_and_keep_everything_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("null.conf");
        fs::write(
            &path,
            "# keep me\nnetwork = \"main\" # inline\nmine = false\n",
        )
        .unwrap();
        let mining = Mining {
            enabled: true,
            threads: 1,
        };
        save_mining(&path, mining).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with("# keep me\nnetwork = \"main\" # inline\n"),
            "{text}"
        );
        let (settings, _) = read_settings(&path).unwrap();
        assert_eq!(settings.mining(), mining);
        assert!(!path.with_extension("conf.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(save_mining(&dir.path().join("missing.conf"), mining).is_err());
    }

    #[test]
    fn the_log_file_is_off_by_default_and_saved_in_place() {
        assert!(!Settings::default().log_file, "logging to disk is opt-in");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("null.conf");
        fs::write(&path, "# keep me\nnetwork = \"main\"\n").unwrap();
        save_log_file(&path, true).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with("# keep me\nnetwork = \"main\"\n"),
            "{text}"
        );
        assert!(read_settings(&path).unwrap().0.log_file);
        save_log_file(&path, false).unwrap();
        assert!(!read_settings(&path).unwrap().0.log_file);
        assert!(save_log_file(&dir.path().join("missing.conf"), true).is_err());
    }

    #[test]
    fn incoming_connections_and_port_mapping_are_on_by_default_and_saved_in_place() {
        let defaults = Settings::default().incoming();
        assert!(defaults.enabled && defaults.port_mapping);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("null.conf");
        fs::write(&path, "# keep me\nnetwork = \"main\"\n").unwrap();
        let off = Incoming {
            enabled: false,
            port_mapping: true,
        };
        save_incoming(&path, off).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with("# keep me\nnetwork = \"main\"\n"),
            "{text}"
        );
        assert_eq!(read_settings(&path).unwrap().0.incoming(), off);
        assert!(save_incoming(&dir.path().join("missing.conf"), off).is_err());
    }

    fn rules(listen: Option<SocketAddr>, advertised: bool, proxied: bool) -> IncomingRules {
        IncomingRules {
            listen,
            advertised,
            proxied,
        }
    }

    #[test]
    fn incoming_rules_say_what_a_start_with_the_switches_runs() {
        let on = Incoming {
            enabled: true,
            port_mapping: true,
        };
        let off = Incoming {
            enabled: false,
            port_mapping: true,
        };
        let nothing = Incoming {
            enabled: false,
            port_mapping: false,
        };
        assert_eq!(IncomingRules::default().apply(on), on);
        assert_eq!(IncomingRules::default().apply(off), nothing);
        assert_eq!(rules(None, false, true).apply(on), nothing);
        let forwarded = rules(None, true, false).apply(on);
        assert!(forwarded.enabled && !forwarded.port_mapping);
    }

    #[test]
    fn a_saved_advertisement_does_not_stop_a_start_without_incoming() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("null.conf");
        fs::write(&config, "advertise = '8.8.8.8:19000'\n").unwrap();
        let args = |no_incoming| Args {
            datadir: Some(dir.path().into()),
            no_incoming,
            ..Args::default()
        };
        let flagged = Startup::load(&args(true)).unwrap();
        assert_eq!(flagged.backend.node.listen, None);
        assert_eq!(flagged.backend.node.advertise, None);
        let normal = Startup::load(&args(false)).unwrap();
        assert!(normal.backend.node.advertise.is_some());
        assert!(!normal.backend.node.port_mapping, "forwarded by hand");
        fs::write(&config, "advertise = '8.8.8.8:19000'\nincoming = false\n").unwrap();
        let off = Startup::load(&args(false)).unwrap();
        assert_eq!(off.backend.node.advertise, None);
    }

    #[test]
    fn the_default_listener_takes_every_interface_and_maps_the_port() {
        let on = Incoming {
            enabled: true,
            port_mapping: true,
        };
        let listening = Listening::from_settings(on, rules(None, false, false));
        assert_eq!(listening.listen, Some(DEFAULT_LISTEN));
        assert!(listening.fallback && listening.port_mapping);
        let explicit: SocketAddr = "0.0.0.0:20000".parse().unwrap();
        let chosen = Listening::from_settings(on, rules(Some(explicit), false, false));
        assert_eq!(chosen.listen, Some(explicit));
        assert!(!chosen.fallback, "an explicit port must not move");
        let unmapped = Incoming {
            port_mapping: false,
            ..on
        };
        assert!(!Listening::from_settings(unmapped, rules(None, false, false)).port_mapping);
        let forwarded = Listening::from_settings(on, rules(None, true, false));
        assert!(forwarded.listen.is_some() && !forwarded.port_mapping);
        let local: SocketAddr = "127.0.0.1:18445".parse().unwrap();
        let loopback = Listening::from_settings(on, rules(Some(local), false, false));
        assert_eq!(loopback.listen, Some(local));
        assert!(!loopback.port_mapping, "a router cannot reach loopback");
    }

    #[test]
    fn switching_incoming_off_or_using_a_proxy_stops_listening_by_default() {
        let explicit: SocketAddr = "0.0.0.0:20000".parse().unwrap();
        let off = Incoming {
            enabled: false,
            port_mapping: true,
        };
        assert_eq!(
            Listening::from_settings(off, rules(Some(explicit), false, false)).listen,
            None
        );
        let on = Incoming {
            enabled: true,
            port_mapping: true,
        };
        let proxied = Listening::from_settings(on, rules(None, false, true));
        assert_eq!(proxied.listen, None);
        assert!(!proxied.port_mapping);
        let kept = Listening::from_settings(on, rules(Some(explicit), false, true));
        assert_eq!(kept.listen, Some(explicit));
        assert!(!kept.port_mapping, "a proxied node never maps a port");
    }

    #[test]
    fn a_launch_without_incoming_does_not_listen_or_save_the_choice() {
        let dir = tempfile::tempdir().unwrap();
        let args = Args {
            datadir: Some(dir.path().into()),
            no_incoming: true,
            ..Args::default()
        };
        let startup = Startup::load(&args).unwrap();
        assert_eq!(startup.backend.node.listen, None);
        assert!(!startup.backend.node.port_mapping);
        assert!(
            startup.backend.incoming.enabled,
            "the saved choice stays on"
        );
        let (settings, _) = read_settings(&startup.paths.config).unwrap();
        assert!(settings.incoming);
        let normal = Startup::load(&Args {
            datadir: Some(dir.path().into()),
            ..Args::default()
        })
        .unwrap();
        assert_eq!(normal.backend.node.listen, Some(DEFAULT_LISTEN));
        assert!(normal.backend.node.port_mapping);
    }

    #[test]
    fn large_logs_move_aside_and_small_ones_stay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOG_FILE);
        rotate_log(&path, 4).unwrap();
        assert!(!path.exists(), "a missing log is fine");
        fs::write(&path, "1234").unwrap();
        rotate_log(&path, 4).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "1234");
        fs::write(&path, "12345").unwrap();
        fs::write(dir.path().join("debug.log.1"), "older").unwrap();
        rotate_log(&path, 4).unwrap();
        assert!(!path.exists());
        assert_eq!(
            fs::read_to_string(dir.path().join("debug.log.1")).unwrap(),
            "12345"
        );
    }

    #[test]
    fn mining_threads_are_clamped_to_this_machine() {
        let max = max_mining_threads();
        for (asked, got) in [(0, 1), (1, 1), (max, max), (max + 100, max)] {
            let mining = Mining {
                enabled: true,
                threads: asked,
            };
            assert_eq!(mining.clamped().threads, got, "{asked}");
        }
        assert!(!Settings::default().mine, "mining is opt-in");
        assert!((1..=max).contains(&Settings::default().mining().threads));
    }
}
