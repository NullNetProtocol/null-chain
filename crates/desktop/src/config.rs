//! Persistent desktop settings and automatic application storage.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use null_node::config::{Config as NodeConfig, Network};
use null_node::paths::{self, private_directory};
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
    /// Network override; a new configuration defaults to test.
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
    /// Combined authenticated RPC listener, loopback only.
    #[arg(long)]
    pub rpc: Option<SocketAddr>,
    /// SOCKS5 proxy for outbound peer connections.
    #[arg(long)]
    pub proxy: Option<SocketAddr>,
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

/// Default idle minutes before the wallet locks itself.
const DEFAULT_LOCK_MINUTES: u64 = 15;

/// Seconds per minute, for the lock timeout.
const SECONDS_PER_MINUTE: u64 = 60;

#[derive(Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    network: String,
    rpc: SocketAddr,
    connect: Vec<String>,
    listen: Option<SocketAddr>,
    proxy: Option<SocketAddr>,
    wallet: Option<PathBuf>,
    /// Minutes without input before the GUI locks the wallet; 0 disables.
    lock_after_minutes: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    wallets: BTreeMap<String, PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            network: "test".into(),
            rpc: SocketAddr::from(([127, 0, 0, 1], 18448)),
            connect: Vec::new(),
            listen: None,
            proxy: None,
            wallet: None,
            lock_after_minutes: DEFAULT_LOCK_MINUTES,
            wallets: BTreeMap::new(),
        }
    }
}

impl Settings {
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
        Ok(Self {
            backend: backend::Config {
                node: NodeConfig {
                    network,
                    datadir: Some(paths::chain_dir(&network_dir)),
                    listen: settings.listen,
                    connect: settings.connect,
                    proxy: settings.proxy,
                    ..NodeConfig::test()
                },
                rpc: settings.rpc,
                token_file: network_dir.join("desktop-rpc.token"),
                wallet: wallet.clone(),
            },
            paths: Paths {
                data,
                config,
                wallet,
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
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(
        b"# NULL desktop settings (TOML). Restart the app after editing.\n\
        # Never put your recovery phrase or wallet passphrase in this file.\n\
        # Optional settings (uncomment to enable):\n\
        # listen = \"127.0.0.1:18445\"\n\
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
    fn first_launch_creates_storage_and_settings_without_a_wallet_or_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let args = Args {
            datadir: Some(data.clone()),
            ..Args::default()
        };
        let startup = Startup::load(&args).unwrap();
        assert!(data.join("test/chain").is_dir());
        assert_eq!(startup.paths.wallet, data.join("test/wallet.redb"));
        assert!(!startup.paths.wallet.exists());
        let (settings, fresh) = read_settings(&startup.paths.config).unwrap();
        assert!(!fresh);
        assert_eq!(settings.network, "test");
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
        assert_eq!(startup.backend.node.connect, ["peer:19000"]);
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
    fn invalid_configuration_is_reported_without_being_replaced() {
        let dir = tempfile::tempdir().unwrap();
        for text in [
            "network = 'invalid'",
            "rpc = '0.0.0.0:18448'",
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
        let old = dir.path().join(".null-desktop/test/wallet.redb");
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
        let main = Startup::prepare(
            &Args {
                network: Some(Network::Main),
                ..Args::default()
            },
            data.clone(),
            dir.path(),
        )
        .unwrap();
        assert_eq!(main.paths.wallet, data.join("main/wallet.redb"));
        // Recreating a missing config must prefer a wallet already at the new
        // default location over any old scaffold wallet left behind.
        let preferred_data = dir.path().join("preferred-data");
        let preferred = preferred_data.join("test/wallet.redb");
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
}
