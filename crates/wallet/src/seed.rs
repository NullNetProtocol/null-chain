//! BIP 39 seed phrases on top of the ZIP 32 style derivation.
//!
//! A phrase is 24 English words carrying 256 bits of entropy. The BIP 39
//! seed is derived from it with an empty passphrase, and the account
//! spending key is `m / 32' / 1' / account'` of that seed as in
//! [`null_crypto::zip32`]. The phrase is the backup: anyone holding it
//! holds every account.

use bip39::{Language, Mnemonic};
use null_crypto::keys::SpendingKey;
use null_crypto::zip32::ExtendedSpendingKey;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Words in a generated phrase.
pub const WORD_COUNT: usize = 24;
/// The only language phrases are generated in; parsing accepts it only,
/// so a phrase written down is unambiguous.
const LANGUAGE: Language = Language::English;
/// Phrases carry no extra passphrase: the wallet file has its own.
const SEED_PASSPHRASE: &str = "";

/// A validated seed phrase.
#[derive(Clone)]
pub struct SeedPhrase(Mnemonic);

impl core::fmt::Debug for SeedPhrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SeedPhrase(<secret>)")
    }
}

impl SeedPhrase {
    /// A fresh 24-word phrase.
    ///
    /// # Errors
    /// Cannot fail for the fixed word count; the signature allows the
    /// library's error type to change.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self> {
        Mnemonic::generate_in_with(rng, LANGUAGE, WORD_COUNT)
            .map(Self)
            .map_err(|e| Error::SeedPhrase(e.to_string()))
    }

    /// Parses a phrase, ignoring case and surrounding or repeated
    /// whitespace, and checking the checksum.
    ///
    /// # Errors
    /// Returns [`Error::SeedPhrase`] for anything but a valid English
    /// mnemonic of 12 to 24 words.
    pub fn parse(text: &str) -> Result<Self> {
        let normalized: Zeroizing<String> = Zeroizing::new(
            text.split_whitespace()
                .map(str::to_lowercase)
                .collect::<Vec<_>>()
                .join(" "),
        );
        Mnemonic::parse_in(LANGUAGE, normalized.as_str())
            .map(Self)
            .map_err(|e| Error::SeedPhrase(e.to_string()))
    }

    /// The words, space separated.
    pub fn words(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.words().collect::<Vec<_>>().join(" "))
    }

    /// The spending key of `account`.
    ///
    /// # Errors
    /// Returns a derivation error if `account` is not below `2^31`.
    pub fn spending_key(&self, account: u32) -> Result<SpendingKey> {
        let seed = Zeroizing::new(self.0.to_seed(SEED_PASSPHRASE));
        Ok(ExtendedSpendingKey::account(seed.as_ref(), account)?
            .spending_key()
            .clone())
    }

    /// The phrase's entropy: 16 to 32 bytes, the canonical stored form.
    pub fn entropy(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_entropy())
    }

    /// The phrase carrying `entropy`.
    ///
    /// # Errors
    /// Returns [`Error::SeedPhrase`] unless the length is a BIP 39 one.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        Mnemonic::from_entropy_in(LANGUAGE, entropy)
            .map(Self)
            .map_err(|e| Error::SeedPhrase(e.to_string()))
    }
}

/// Bytes of the account index ahead of the entropy in
/// [`AccountPhrase::to_bytes`].
const ACCOUNT_LEN: usize = 4;

/// A seed phrase together with the account a wallet's spending key comes
/// from: what a wallet file stores so its phrase can be shown again.
#[derive(Clone, Debug)]
pub struct AccountPhrase {
    /// The phrase.
    pub phrase: SeedPhrase,
    /// The account the wallet uses; restoring needs it too.
    pub account: u32,
}

impl AccountPhrase {
    /// The spending key of this account.
    ///
    /// # Errors
    /// As [`SeedPhrase::spending_key`].
    pub fn spending_key(&self) -> Result<SpendingKey> {
        self.phrase.spending_key(self.account)
    }

    /// `account` (little endian, 4 bytes) followed by the entropy.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(self.account.to_le_bytes().to_vec());
        out.extend_from_slice(&self.phrase.entropy());
        out
    }

    /// Parses [`Self::to_bytes`].
    ///
    /// # Errors
    /// Returns [`Error::SeedPhrase`] for a short record or entropy of a
    /// length BIP 39 does not define.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (account, entropy) = bytes
            .split_first_chunk::<ACCOUNT_LEN>()
            .ok_or_else(|| Error::SeedPhrase("record too short".into()))?;
        Ok(Self {
            phrase: SeedPhrase::from_entropy(entropy)?,
            account: u32::from_le_bytes(*account),
        })
    }
}

#[cfg(test)]
mod tests {
    use null_crypto::encoding::to_hex;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::keys::WalletKeys;

    /// The BIP 39 test vector for all-zero entropy.
    const ZERO_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";

    #[test]
    fn generated_phrases_round_trip_and_differ() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let a = SeedPhrase::generate(&mut rng).unwrap();
        let b = SeedPhrase::generate(&mut rng).unwrap();
        assert_eq!(a.words().split(' ').count(), WORD_COUNT);
        assert_ne!(*a.words(), *b.words());
        let parsed = SeedPhrase::parse(&a.words()).unwrap();
        assert_eq!(
            parsed.spending_key(0).unwrap().to_bytes(),
            a.spending_key(0).unwrap().to_bytes()
        );
        assert_eq!(format!("{a:?}"), "SeedPhrase(<secret>)");
    }

    #[test]
    fn parsing_normalizes_and_checks_the_checksum() {
        let shouted = format!("  {}  ", ZERO_PHRASE.to_uppercase().replace(' ', "\n "));
        assert_eq!(*SeedPhrase::parse(&shouted).unwrap().words(), ZERO_PHRASE);
        let wrong_checksum = ZERO_PHRASE.replace("art", "abandon");
        assert!(matches!(
            SeedPhrase::parse(&wrong_checksum),
            Err(Error::SeedPhrase(_))
        ));
        assert!(SeedPhrase::parse("").is_err());
        assert!(SeedPhrase::parse("not words at all").is_err());
    }

    #[test]
    fn entropy_round_trips_and_only_bip39_lengths_are_accepted() {
        let phrase = SeedPhrase::parse(ZERO_PHRASE).unwrap();
        assert_eq!(*phrase.entropy(), vec![0u8; 32]);
        let back = SeedPhrase::from_entropy(&phrase.entropy()).unwrap();
        assert_eq!(*back.words(), ZERO_PHRASE);
        for length in [16, 20, 24, 28] {
            assert!(SeedPhrase::from_entropy(&vec![7u8; length]).is_ok());
        }
        for length in [0, 15, 17, 33] {
            assert!(SeedPhrase::from_entropy(&vec![7u8; length]).is_err());
        }
    }

    #[test]
    fn account_phrases_round_trip_and_reject_garbage() {
        let stored = AccountPhrase {
            phrase: SeedPhrase::generate(&mut ChaCha20Rng::seed_from_u64(2)).unwrap(),
            account: 7,
        };
        let bytes = stored.to_bytes();
        assert_eq!(bytes.len(), ACCOUNT_LEN + 32);
        let back = AccountPhrase::from_bytes(&bytes).unwrap();
        assert_eq!(back.account, 7);
        assert_eq!(*back.phrase.words(), *stored.phrase.words());
        assert_eq!(
            back.spending_key().unwrap().to_bytes(),
            stored.phrase.spending_key(7).unwrap().to_bytes()
        );
        assert!(AccountPhrase::from_bytes(&[]).is_err());
        assert!(AccountPhrase::from_bytes(&bytes[..ACCOUNT_LEN]).is_err());
        assert!(AccountPhrase::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(!format!("{back:?}").contains(&*stored.phrase.words()));
    }

    #[test]
    fn derivation_is_pinned_and_accounts_differ() {
        let phrase = SeedPhrase::parse(ZERO_PHRASE).unwrap();
        let sk0 = phrase.spending_key(0).unwrap();
        let sk1 = phrase.spending_key(1).unwrap();
        assert_ne!(sk0.to_bytes(), sk1.to_bytes());
        assert!(phrase.spending_key(1 << 31).is_err());
        // Pinned so a change in derivation cannot silently orphan wallets.
        assert_eq!(
            to_hex(&sk0.to_bytes()),
            "aeee2840de33f371c576fdde22e552725f6e7002c642a64cbfbaa71679dddaf3",
            "account 0 spending key of the all-zero phrase changed"
        );
        let keys = WalletKeys::from_spending_key(sk0).unwrap();
        assert_eq!(
            keys.default_address()
                .unwrap()
                .encode(null_protocol::address::AddressPrefix::Main),
            "null1qgwtwmahzrkmyrl08tf65wtp0m4tjdvyv3x26f5762mufvljfgjqkvyfas5u3stpavsnjeqqa98",
            "account 0 address of the all-zero phrase changed"
        );
    }
}
