//! The seed phrase kept in the wallet file, so the backup can be shown
//! again after it was first written down.
//!
//! The phrase is sealed under the file key like the spending key. Showing
//! it asks for the passphrase again even on an unlocked wallet: whoever
//! holds the phrase holds every account of the seed, which is more than
//! an unlocked session needs. A wallet without a stored phrase (created
//! from a spending key, or before phrases were kept) can have one
//! attached, but only one that derives the wallet's own spending key.

use redb::ReadableDatabase;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{FileKey, Wallet, META, SALT, SEED_PHRASE, TAG_SEED_PHRASE};
use crate::seed::AccountPhrase;
use crate::{Error, Result};

/// Record position of the seed phrase; there is only one.
const PHRASE_POSITION: u64 = 0;

/// Seals `phrase` for the `seed_phrase` meta entry.
pub(super) fn seal_phrase(key: &FileKey, phrase: &AccountPhrase) -> Result<Vec<u8>> {
    key.seal(TAG_SEED_PHRASE, PHRASE_POSITION, &phrase.to_bytes())
}

impl Wallet {
    /// Whether the file keeps a seed phrase that can be shown again.
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn has_seed_phrase(&self) -> Result<bool> {
        Ok(self.meta(SEED_PHRASE)?.is_some())
    }

    /// Stores `phrase` after checking, in constant time, that it derives
    /// this wallet's spending key. Storing it again replaces it.
    ///
    /// # Errors
    /// Returns [`Error::WatchOnly`] for a wallet without a spending key,
    /// [`Error::SeedMismatch`] if the phrase and account derive another
    /// key, or a database error.
    pub fn attach_seed_phrase(&self, phrase: &AccountPhrase) -> Result<()> {
        let own = self.keys.spending_key()?;
        if !bool::from(phrase.spending_key()?.ct_eq(own)) {
            return Err(Error::SeedMismatch);
        }
        let sealed = seal_phrase(&self.file_key, phrase)?;
        let tx = self.db.begin_write()?;
        tx.open_table(META)?
            .insert(SEED_PHRASE, sealed.as_slice())?;
        tx.commit()?;
        Ok(())
    }

    /// The stored seed phrase, once `passphrase` is confirmed to be the
    /// file's; `None` if the file keeps no phrase. Runs the passphrase
    /// key derivation, so it takes as long as unlocking.
    ///
    /// # Errors
    /// Returns [`Error::WrongPassphrase`] for another passphrase or an
    /// in-memory wallet, or a database or decoding error.
    pub fn reveal_seed_phrase(&self, passphrase: &[u8]) -> Result<Option<AccountPhrase>> {
        self.check_passphrase(passphrase)?;
        self.meta(SEED_PHRASE)?
            .map(|sealed| {
                let plain = Zeroizing::new(self.file_key.open(
                    TAG_SEED_PHRASE,
                    PHRASE_POSITION,
                    &sealed,
                )?);
                AccountPhrase::from_bytes(&plain)
            })
            .transpose()
    }

    /// Derives the file key from `passphrase` and compares it with the
    /// unlocked one in constant time.
    fn check_passphrase(&self, passphrase: &[u8]) -> Result<()> {
        let salt = self
            .meta(SALT)?
            .filter(|salt| !salt.is_empty())
            .ok_or(Error::WrongPassphrase)?;
        let derived = FileKey::derive(passphrase, &salt)?;
        if bool::from(derived.0.ct_eq(&self.file_key.0)) {
            Ok(())
        } else {
            Err(Error::WrongPassphrase)
        }
    }

    /// One `meta` entry.
    fn meta(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        Ok(meta.get(name)?.map(|v| v.value().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use null_protocol::block::BlockHash;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::seed::SeedPhrase;

    const PASSPHRASE: &[u8] = b"file passphrase";

    fn phrase(seed: u64, account: u32) -> AccountPhrase {
        AccountPhrase {
            phrase: SeedPhrase::generate(&mut ChaCha20Rng::seed_from_u64(seed)).unwrap(),
            account,
        }
    }

    fn words(phrase: &AccountPhrase) -> String {
        phrase.phrase.words().to_string()
    }

    #[test]
    fn a_wallet_created_from_a_phrase_shows_it_again_only_with_its_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.redb");
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let original = phrase(1, 3);
        drop(
            Wallet::create_from_phrase(&path, &original, BlockHash::ZERO, PASSPHRASE, &mut rng)
                .unwrap(),
        );
        let wallet = Wallet::open(&path, BlockHash::ZERO, PASSPHRASE).unwrap();
        assert!(wallet.has_seed_phrase().unwrap());
        let shown = wallet.reveal_seed_phrase(PASSPHRASE).unwrap().unwrap();
        assert_eq!(words(&shown), words(&original));
        assert_eq!(shown.account, 3);
        assert!(matches!(
            wallet.reveal_seed_phrase(b"guess"),
            Err(Error::WrongPassphrase)
        ));
    }

    #[test]
    fn an_older_wallet_accepts_only_the_phrase_of_its_own_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.redb");
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let own = phrase(2, 0);
        let wallet = Wallet::create(
            &path,
            &own.spending_key().unwrap(),
            BlockHash::ZERO,
            PASSPHRASE,
            &mut rng,
        )
        .unwrap();
        assert!(!wallet.has_seed_phrase().unwrap());
        assert!(wallet.reveal_seed_phrase(PASSPHRASE).unwrap().is_none());
        for wrong in [phrase(3, 0), phrase(2, 1)] {
            assert!(matches!(
                wallet.attach_seed_phrase(&wrong),
                Err(Error::SeedMismatch)
            ));
        }
        assert!(!wallet.has_seed_phrase().unwrap());
        wallet.attach_seed_phrase(&own).unwrap();
        drop(wallet);
        let wallet = Wallet::open(&path, BlockHash::ZERO, PASSPHRASE).unwrap();
        let shown = wallet.reveal_seed_phrase(PASSPHRASE).unwrap().unwrap();
        assert_eq!(words(&shown), words(&own));
    }

    #[test]
    fn the_stored_phrase_is_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.redb");
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let original = phrase(4, 0);
        let wallet =
            Wallet::create_from_phrase(&path, &original, BlockHash::ZERO, PASSPHRASE, &mut rng)
                .unwrap();
        let sealed = wallet.meta(SEED_PHRASE).unwrap().unwrap();
        let entropy = original.phrase.entropy();
        assert!(!sealed
            .windows(entropy.len())
            .any(|w| w == entropy.as_slice()));
    }

    #[test]
    fn watch_only_and_in_memory_wallets_never_reveal_or_attach() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let own = phrase(5, 0);
        let sk = own.spending_key().unwrap();
        let memory = Wallet::in_memory(&sk, BlockHash::ZERO, &mut rng).unwrap();
        assert!(matches!(
            memory.reveal_seed_phrase(b""),
            Err(Error::WrongPassphrase)
        ));
        let fvk = memory.keys().full_viewing_key().clone();
        let watch = Wallet::in_memory_watch_only(fvk, BlockHash::ZERO, &mut rng).unwrap();
        assert!(matches!(
            watch.attach_seed_phrase(&own),
            Err(Error::WatchOnly)
        ));
    }
}
