//! Seed phrase methods: showing a wallet's stored backup again, and
//! attaching the phrase to a wallet file created before phrases were kept.
//!
//! Showing the phrase asks for the wallet passphrase even though the
//! daemon already holds the unlocked wallet: the RPC token lets a client
//! spend, but the phrase is every account of the seed, and the token is
//! often handed to scripts that should not be able to read it.

use null_wallet::seed::{AccountPhrase, SeedPhrase};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::WalletDaemon;
use crate::jsonrpc::{unknown_method, Params, RpcError, REJECTED};

/// Methods whose parameters or result carry the seed phrase or the wallet
/// passphrase. The desktop debug console refuses them, so neither ends up
/// in its history; the desktop has its own screen for them.
pub const SECRET_METHODS: &[&str] = &["getseedphrase", "setseedphrase"];

/// The answer for a wallet that keeps no phrase.
const NO_PHRASE: &str = "this wallet keeps no seed phrase; attach it with setseedphrase";

impl WalletDaemon {
    /// The stored phrase, once `passphrase` is confirmed. The check runs
    /// the passphrase key derivation, so it runs off the async threads.
    ///
    /// # Errors
    /// Rejects a wrong passphrase and a wallet without a stored phrase.
    pub async fn reveal_seed_phrase(
        &self,
        passphrase: Zeroizing<String>,
    ) -> core::result::Result<AccountPhrase, RpcError> {
        self.blocking(move |wallet| wallet.reveal_seed_phrase(passphrase.as_bytes()))
            .await?
            .ok_or_else(|| RpcError::new(REJECTED, NO_PHRASE))
    }

    /// Stores `phrase` if it derives the wallet's spending key.
    ///
    /// # Errors
    /// Rejects a phrase or account of another wallet, and watch-only wallets.
    pub async fn attach_seed_phrase(
        &self,
        phrase: AccountPhrase,
    ) -> core::result::Result<(), RpcError> {
        self.blocking(move |wallet| wallet.attach_seed_phrase(&phrase))
            .await
    }

    /// `getseedphrase` and `setseedphrase`.
    pub(super) async fn seed_methods(
        &self,
        method: &str,
        params: &Params,
    ) -> core::result::Result<Value, RpcError> {
        match method {
            "getseedphrase" => {
                let passphrase = Zeroizing::new(params.get::<String>(0, "passphrase")?);
                let stored = self.reveal_seed_phrase(passphrase).await?;
                Ok(json!({
                    "seed_phrase": stored.phrase.words().as_str(),
                    "account": stored.account,
                }))
            }
            "setseedphrase" => {
                let words = Zeroizing::new(params.get::<String>(0, "seed_phrase")?);
                let account: u32 = params.opt(1, "account")?.unwrap_or(0);
                let phrase = SeedPhrase::parse(&words)?;
                self.attach_seed_phrase(AccountPhrase { phrase, account })
                    .await?;
                Ok(json!({ "stored": true }))
            }
            other => Err(unknown_method(other)),
        }
    }
}
