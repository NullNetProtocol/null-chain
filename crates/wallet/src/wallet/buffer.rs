//! A wallet database kept as one byte image in memory, for platforms
//! without files: the browser wallet stores the image in `IndexedDB` and
//! hands it back on the next visit.
//!
//! The image is exactly what a wallet file would hold, so the same
//! protection applies: the spending key, seed phrase and notes are sealed
//! under the passphrase-derived file key; the witness tree and heights are
//! public chain data. Read it with [`Buffer::to_bytes`] between calls on
//! the wallet (every wallet call commits before it returns, so the image
//! is always a complete database).

use std::io;
use std::sync::{Arc, RwLock};

use null_protocol::block::BlockHash;
use rand_core::{CryptoRng, RngCore};
use redb::{Database, StorageBackend};

use super::Wallet;
use crate::keys::WalletKeys;
use crate::seed::AccountPhrase;
use crate::Result;

/// The byte image a wallet lives in. Clones share the same bytes.
#[derive(Clone, Debug, Default)]
pub struct Buffer(Arc<RwLock<Vec<u8>>>);

impl Buffer {
    /// An empty buffer, for a new wallet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A buffer holding an image from [`Self::to_bytes`].
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Arc::new(RwLock::new(bytes)))
    }

    /// A copy of the image, to persist.
    ///
    /// # Errors
    /// Fails only if a writer panicked while holding the buffer.
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        Ok(self.0.read().map_err(|_| poisoned())?.clone())
    }
}

fn poisoned() -> io::Error {
    io::Error::other("wallet buffer poisoned")
}

fn out_of_range() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "read past the wallet buffer")
}

fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "wallet buffer too large")
}

/// `offset .. offset + len` as indices, if it fits in memory.
fn span(offset: u64, len: usize) -> io::Result<core::ops::Range<usize>> {
    let start = usize::try_from(offset).map_err(|_| too_large())?;
    let end = start.checked_add(len).ok_or_else(too_large)?;
    Ok(start..end)
}

impl StorageBackend for Buffer {
    fn len(&self) -> io::Result<u64> {
        let bytes = self.0.read().map_err(|_| poisoned())?;
        u64::try_from(bytes.len()).map_err(|_| too_large())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let bytes = self.0.read().map_err(|_| poisoned())?;
        let source = bytes
            .get(span(offset, out.len())?)
            .ok_or_else(out_of_range)?;
        out.copy_from_slice(source);
        Ok(())
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| too_large())?;
        self.0.write().map_err(|_| poisoned())?.resize(len, 0);
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut bytes = self.0.write().map_err(|_| poisoned())?;
        let range = span(offset, data.len())?;
        if bytes.len() < range.end {
            bytes.resize(range.end, 0);
        }
        bytes
            .get_mut(range)
            .ok_or_else(out_of_range)?
            .copy_from_slice(data);
        Ok(())
    }
}

impl Wallet {
    /// Creates a wallet for the spending key of `phrase` in an empty
    /// `buffer`, keeping the phrase sealed so it can be shown again; the
    /// buffer counterpart of [`Wallet::create_from_phrase`].
    ///
    /// # Errors
    /// As [`Wallet::create_from_phrase`].
    pub fn create_from_phrase_in(
        buffer: &Buffer,
        phrase: &AccountPhrase,
        genesis: BlockHash,
        passphrase: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let keys = WalletKeys::from_spending_key(phrase.spending_key()?)?;
        let db = Database::builder().create_with_backend(buffer.clone())?;
        Self::create_in_db(db, keys, Some(phrase), genesis, passphrase, rng)
    }

    /// Opens the wallet held in `buffer`; the buffer counterpart of
    /// [`Wallet::open`].
    ///
    /// # Errors
    /// As [`Wallet::open`].
    pub fn open_in(buffer: &Buffer, genesis: BlockHash, passphrase: &[u8]) -> Result<Self> {
        let db = Database::builder().create_with_backend(buffer.clone())?;
        Self::open_db(db, genesis, passphrase)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::seed::SeedPhrase;
    use crate::Error;

    const PASSPHRASE: &[u8] = b"buffer passphrase";

    fn phrase() -> AccountPhrase {
        AccountPhrase {
            phrase: SeedPhrase::generate(&mut ChaCha20Rng::seed_from_u64(7)).unwrap(),
            account: 0,
        }
    }

    #[test]
    fn a_wallet_survives_a_round_trip_through_its_byte_image() {
        let buffer = Buffer::new();
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let wallet = Wallet::create_from_phrase_in(
            &buffer,
            &phrase(),
            BlockHash::ZERO,
            PASSPHRASE,
            &mut rng,
        )
        .unwrap();
        let (_, address) = wallet.new_address("shop").unwrap();
        drop(wallet);

        let image = buffer.to_bytes().unwrap();
        assert!(image.len() > 4096, "{} bytes", image.len());
        let restored = Buffer::from_bytes(image);
        let wallet = Wallet::open_in(&restored, BlockHash::ZERO, PASSPHRASE).unwrap();
        let addresses = wallet.addresses().unwrap();
        assert!(addresses
            .iter()
            .any(|(_, a, label)| *a == address && label == "shop"));
        let shown = wallet.reveal_seed_phrase(PASSPHRASE).unwrap().unwrap();
        assert_eq!(*shown.phrase.words(), *phrase().phrase.words());
    }

    #[test]
    fn an_image_opens_only_with_its_passphrase_and_network() {
        let buffer = Buffer::new();
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        drop(
            Wallet::create_from_phrase_in(
                &buffer,
                &phrase(),
                BlockHash::ZERO,
                PASSPHRASE,
                &mut rng,
            )
            .unwrap(),
        );
        assert!(matches!(
            Wallet::open_in(&buffer, BlockHash::ZERO, b"guess"),
            Err(Error::WrongPassphrase)
        ));
        let other = BlockHash::from_bytes([1; 32]);
        assert!(matches!(
            Wallet::open_in(&buffer, other, PASSPHRASE),
            Err(Error::WrongWallet)
        ));
    }

    #[test]
    fn the_secrets_are_not_in_the_image_in_the_clear() {
        let buffer = Buffer::new();
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let phrase = phrase();
        drop(
            Wallet::create_from_phrase_in(&buffer, &phrase, BlockHash::ZERO, PASSPHRASE, &mut rng)
                .unwrap(),
        );
        let image = buffer.to_bytes().unwrap();
        let key = phrase.spending_key().unwrap().to_bytes();
        let entropy = phrase.phrase.entropy();
        for secret in [key.as_slice(), entropy.as_slice()] {
            assert!(!image.windows(secret.len()).any(|w| w == secret));
        }
    }

    #[test]
    fn garbage_is_not_a_wallet() {
        let garbage = Buffer::from_bytes(vec![0xa5; 4096]);
        assert!(Wallet::open_in(&garbage, BlockHash::ZERO, PASSPHRASE).is_err());
        let empty = Buffer::new();
        assert!(Wallet::open_in(&empty, BlockHash::ZERO, PASSPHRASE).is_err());
    }

    #[test]
    fn reads_past_the_end_fail_and_writes_grow_the_buffer() {
        let buffer = Buffer::from_bytes(vec![1, 2, 3]);
        let mut out = [0u8; 2];
        assert!(buffer.read(2, &mut out).is_err());
        assert!(buffer.read(u64::MAX, &mut out).is_err());
        buffer.write(4, &[9]).unwrap();
        assert_eq!(buffer.to_bytes().unwrap(), vec![1, 2, 3, 0, 9]);
        buffer.set_len(2).unwrap();
        assert_eq!(StorageBackend::len(&buffer).unwrap(), 2);
        buffer.read(0, &mut out).unwrap();
        assert_eq!(out, [1, 2]);
    }
}
