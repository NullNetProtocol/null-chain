//! Per-user storage locations shared by `nulld`, `null-wallet-rpc`, and
//! the desktop app, so all three find the same chain and wallet on Linux,
//! macOS, and Windows without being told where to look.
//!
//! ```text
//! <user data>/                 see [`user_data_dir`]
//!   <network>/                 see [`network_dir`]
//!     chain/chain.redb         the node's datadir, see [`chain_dir`]
//!     chain/rpc.token          the node's control token
//!     chain/peers.dat          the node's saved address book
//!     wallet.redb              see [`wallet_file`]
//!     wallet-rpc.token         null-wallet-rpc's token
//! ```
//!
//! Each database is locked while open, so a `nulld` and a desktop app
//! using the same network directory cannot run at the same time.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::Network;
use crate::{Error, Result};

/// Open options whose newly created files are readable by the owner only
/// on Unix, from the moment they exist. Add the access mode to taste.
pub fn private_open_options() -> OpenOptions {
    // Only Unix sets a mode; elsewhere the builder is returned unchanged.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Makes an already open file owner-only on Unix, for files that may have
/// existed with broader permissions before [`private_open_options`] could
/// apply; a no-op elsewhere.
///
/// # Errors
/// Fails if the permissions cannot be changed.
pub fn restrict(file: &File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

/// Creates `path` for writing, failing if it exists, owner-only on Unix.
///
/// # Errors
/// Fails if the file exists or cannot be created.
pub fn create_private(path: &Path) -> Result<File> {
    Ok(private_open_options()
        .write(true)
        .create_new(true)
        .open(path)?)
}

/// Writes `bytes` to a new owner-only file at `path`, replacing a stale one,
/// and syncs it: tokens, settings and address books are private to the user.
///
/// # Errors
/// Fails if the old file cannot be removed or the new one written.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let mut file = create_private(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Subdirectory of a network directory holding the node's chain and token.
pub const CHAIN_DIR: &str = "chain";
/// Default wallet file name inside a network directory.
pub const WALLET_FILE: &str = "wallet.redb";

/// The operating system's per-user application data directory for NULL:
/// `%LOCALAPPDATA%\Null` on Windows, `~/Library/Application Support/Null`
/// on macOS, and `$XDG_DATA_HOME/null` or `~/.local/share/null` elsewhere.
///
/// # Errors
/// Returns [`Error::Argument`] when the environment names no usable home.
pub fn user_data_dir() -> Result<PathBuf> {
    data_dir_from(|key| std::env::var_os(key))
}

/// [`user_data_dir`] with the environment supplied, for testing.
///
/// # Errors
/// See [`user_data_dir`].
pub fn data_dir_from(mut env: impl FnMut(&str) -> Option<OsString>) -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        Ok(required(env("LOCALAPPDATA").or_else(|| env("APPDATA")))?.join("Null"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(required(env("HOME"))?.join("Library/Application Support/Null"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Ok(data_home_from(&mut env)?.join("null"))
    }
}

/// The value of a required environment variable as a path.
fn required(value: Option<OsString>) -> Result<PathBuf> {
    value
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| Error::Argument("cannot locate user data directory; pass --datadir".into()))
}

/// The XDG base data directory: `$XDG_DATA_HOME` when absolute, else
/// `~/.local/share`. Desktop entries and icons live under it.
///
/// # Errors
/// See [`user_data_dir`].
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn data_home() -> Result<PathBuf> {
    data_home_from(|key| std::env::var_os(key))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn data_home_from(mut env: impl FnMut(&str) -> Option<OsString>) -> Result<PathBuf> {
    if let Some(root) = env("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        return Ok(root);
    }
    Ok(required(env("HOME"))?.join(".local/share"))
}

/// The directory holding one network's chain and wallet.
pub fn network_dir(data: &Path, network: Network) -> PathBuf {
    data.join(network.to_string())
}

/// The node data directory inside a network directory.
pub fn chain_dir(network_dir: &Path) -> PathBuf {
    network_dir.join(CHAIN_DIR)
}

/// The default wallet file inside a network directory.
pub fn wallet_file(network_dir: &Path) -> PathBuf {
    network_dir.join(WALLET_FILE)
}

/// The node's control token file inside a network directory.
pub fn node_token_file(network_dir: &Path) -> PathBuf {
    chain_dir(network_dir).join(crate::rpc::TOKEN_FILE)
}

/// [`network_dir`] under [`user_data_dir`].
///
/// # Errors
/// See [`user_data_dir`].
pub fn default_network_dir(network: Network) -> Result<PathBuf> {
    Ok(network_dir(&user_data_dir()?, network))
}

/// Creates a directory and its parents. New directories are owner-only on
/// Unix; on Windows they inherit the parent's access list, which under the
/// user profile grants only the user, administrators, and SYSTEM.
/// Existing directories are left unchanged.
///
/// # Errors
/// Fails if a directory cannot be created.
pub fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_files_are_replaced_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_private(&path, b"first").unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn default_storage_requires_a_user_location_instead_of_using_the_working_directory() {
        assert!(data_dir_from(|_| None).is_err());
        assert!(data_dir_from(|_| Some(OsString::new())).is_err());
        let dir = data_dir_from(|key| match key {
            "HOME" | "LOCALAPPDATA" => Some(OsString::from("/user")),
            _ => None,
        })
        .unwrap();
        assert!(dir.starts_with("/user"));
        assert!(dir.ends_with("null") || dir.ends_with("Null"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_prefers_local_app_data_and_falls_back_to_roaming() {
        let local = data_dir_from(|key| match key {
            "LOCALAPPDATA" => Some(OsString::from(r"C:\Users\u\AppData\Local")),
            "APPDATA" => Some(OsString::from(r"C:\Users\u\AppData\Roaming")),
            _ => None,
        });
        assert_eq!(
            local.unwrap(),
            PathBuf::from(r"C:\Users\u\AppData\Local\Null")
        );
        let roaming = data_dir_from(|key| {
            (key == "APPDATA").then(|| OsString::from(r"C:\Users\u\AppData\Roaming"))
        });
        assert_eq!(
            roaming.unwrap(),
            PathBuf::from(r"C:\Users\u\AppData\Roaming\Null")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_application_support() {
        let dir = data_dir_from(|key| (key == "HOME").then(|| OsString::from("/Users/u")));
        assert_eq!(
            dir.unwrap(),
            PathBuf::from("/Users/u/Library/Application Support/Null")
        );
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    #[test]
    fn linux_follows_xdg_and_ignores_relative_overrides() {
        let xdg = data_dir_from(|key| (key == "XDG_DATA_HOME").then(|| OsString::from("/data")));
        assert_eq!(xdg.unwrap(), PathBuf::from("/data/null"));
        assert!(
            data_dir_from(|key| (key == "XDG_DATA_HOME").then(|| OsString::from("relative")))
                .is_err()
        );
        let home = data_dir_from(|key| (key == "HOME").then(|| OsString::from("/home/u")));
        assert_eq!(home.unwrap(), PathBuf::from("/home/u/.local/share/null"));
    }

    #[test]
    fn every_network_has_its_own_chain_wallet_and_token() {
        let data = Path::new("data");
        let test = network_dir(data, Network::Test);
        let main = network_dir(data, Network::Main);
        assert_ne!(test, main);
        assert_eq!(chain_dir(&test), data.join("test").join("chain"));
        assert_eq!(wallet_file(&test), data.join("test").join("wallet.redb"));
        assert_eq!(
            node_token_file(&test),
            data.join("test").join("chain").join("rpc.token")
        );
    }

    #[test]
    fn private_directories_are_created_recursively_and_owner_only_on_unix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b");
        private_directory(&path).unwrap();
        private_directory(&path).unwrap();
        assert!(path.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }
}
