//! A wallet's key material: from a spending key, or from a full viewing
//! key alone for a watch-only wallet that sees notes and spends but
//! cannot sign.

use null_crypto::diversifier::DiversifierIndex;
use null_crypto::keys::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, SpendingKey};
use null_protocol::address::Address;

use crate::{Error, Result};

/// The keys a wallet uses, derived once.
pub struct WalletKeys {
    spending: Option<SpendingKey>,
    fvk: FullViewingKey,
    ivk: IncomingViewingKey,
    ovk: OutgoingViewingKey,
}

impl WalletKeys {
    /// Every key, from the spending key.
    ///
    /// # Errors
    /// Fails if a derived key is degenerate.
    pub fn from_spending_key(sk: SpendingKey) -> Result<Self> {
        let fvk = FullViewingKey::derive(&sk)?;
        let mut keys = Self::from_full_viewing_key(fvk)?;
        keys.spending = Some(sk);
        Ok(keys)
    }

    /// Watch-only keys: everything but the ability to spend.
    ///
    /// # Errors
    /// Fails if a derived key is degenerate.
    pub fn from_full_viewing_key(fvk: FullViewingKey) -> Result<Self> {
        let ivk = fvk.incoming_viewing_key()?;
        let ovk = fvk.outgoing_viewing_key();
        Ok(Self {
            spending: None,
            fvk,
            ivk,
            ovk,
        })
    }

    /// Whether these keys can only watch.
    pub fn is_watch_only(&self) -> bool {
        self.spending.is_none()
    }

    /// The spending key.
    ///
    /// # Errors
    /// Returns [`Error::WatchOnly`] for keys from a viewing key.
    pub fn spending_key(&self) -> Result<&SpendingKey> {
        self.spending.as_ref().ok_or(Error::WatchOnly)
    }

    /// The full viewing key.
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// The incoming viewing key, for trial decryption.
    pub fn incoming_viewing_key(&self) -> &IncomingViewingKey {
        &self.ivk
    }

    /// The outgoing viewing key, for recovering what was sent.
    pub fn outgoing_viewing_key(&self) -> &OutgoingViewingKey {
        &self.ovk
    }

    /// The address at a diversifier index.
    ///
    /// # Errors
    /// Fails if the index yields an invalid diversifier.
    pub fn address(&self, index: DiversifierIndex) -> Result<Address> {
        Ok(Address::from_index(&self.fvk, index)?)
    }

    /// The address at index zero.
    ///
    /// # Errors
    /// See [`Self::address`].
    pub fn default_address(&self) -> Result<Address> {
        self.address(DiversifierIndex::ZERO)
    }

    /// The diversifier index `address` was derived from, if it is one
    /// of ours.
    pub fn index_of(&self, address: &Address) -> Option<DiversifierIndex> {
        self.fvk
            .diversifier_key()
            .index(address.diversifier())
            .ok()
            .filter(|index| self.address(*index).is_ok_and(|ours| ours == *address))
    }
}

impl core::fmt::Debug for WalletKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WalletKeys(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn keys_derive_consistent_addresses() {
        let sk = SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(1));
        let keys = WalletKeys::from_spending_key(sk.clone()).unwrap();
        let again = WalletKeys::from_spending_key(sk).unwrap();
        assert_eq!(
            keys.default_address().unwrap(),
            again.default_address().unwrap()
        );
        assert_ne!(
            keys.default_address().unwrap(),
            keys.address(DiversifierIndex::from(1)).unwrap()
        );
        assert_eq!(format!("{keys:?}"), "WalletKeys(<redacted>)");
    }

    #[test]
    fn watch_only_keys_see_the_same_addresses_but_cannot_spend() {
        let sk = SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(2));
        let full = WalletKeys::from_spending_key(sk).unwrap();
        let watch = WalletKeys::from_full_viewing_key(full.full_viewing_key().clone()).unwrap();
        assert!(watch.is_watch_only());
        assert!(!full.is_watch_only());
        assert!(matches!(watch.spending_key(), Err(Error::WatchOnly)));
        assert!(full.spending_key().is_ok());
        let index = DiversifierIndex::from(7);
        assert_eq!(watch.address(index).unwrap(), full.address(index).unwrap());
    }

    #[test]
    fn our_addresses_map_back_to_their_index() {
        let keys =
            WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(3)))
                .unwrap();
        let other =
            WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(4)))
                .unwrap();
        let index = DiversifierIndex::from(42);
        assert_eq!(keys.index_of(&keys.address(index).unwrap()), Some(index));
        assert_eq!(keys.index_of(&other.default_address().unwrap()), None);
    }
}
