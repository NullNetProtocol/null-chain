//! Diversified payment addresses.
//!
//! An address is a diversifier plus the transmission key derived from it.
//! Raw encoding is `d || pk_d` (43 bytes). Text encoding is bech32m with a
//! human readable part naming the network, so an address for one network
//! is refused by the other instead of paying into a chain the recipient
//! does not use.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use null_crypto::diversifier::DiversifierIndex;
use null_crypto::encoding::{Encoded, ENCODED_LEN};
use null_crypto::keys::{
    DiversifiedTransmissionKey, Diversifier, FullViewingKey, IncomingViewingKey, DIVERSIFIER_LEN,
};
use null_crypto::pallas;

use crate::bytes::{Encodable, Reader, Writer};
use crate::{Error, Result};

/// Human readable part of main network addresses.
const MAIN_HRP: Hrp = Hrp::parse_unchecked("null");
/// Human readable part of test network addresses.
const TEST_HRP: Hrp = Hrp::parse_unchecked("tnull");
/// Human readable part of main network full viewing keys.
const MAIN_VIEWING_HRP: Hrp = Hrp::parse_unchecked("nullview");
/// Human readable part of test network full viewing keys.
const TEST_VIEWING_HRP: Hrp = Hrp::parse_unchecked("tnullview");

/// The network an address is written for. The raw bytes are the same on
/// every network; only the text form differs, so a wallet key pays out
/// on whichever network the text was made for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressPrefix {
    /// The main network, `null1...`.
    Main,
    /// A test network, `tnull1...`.
    Test,
}

impl AddressPrefix {
    /// The bech32m human readable part.
    pub const fn hrp(self) -> Hrp {
        match self {
            Self::Main => MAIN_HRP,
            Self::Test => TEST_HRP,
        }
    }

    /// The bech32m human readable part of an exported full viewing key.
    pub const fn viewing_key_hrp(self) -> Hrp {
        match self {
            Self::Main => MAIN_VIEWING_HRP,
            Self::Test => TEST_VIEWING_HRP,
        }
    }
}

/// Length of the raw address encoding.
pub const ADDRESS_LEN: usize = DIVERSIFIER_LEN + ENCODED_LEN;

/// A shielded payment address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    diversifier: Diversifier,
    pk_d: DiversifiedTransmissionKey,
}

impl Address {
    /// Derives the address for `diversifier` under `ivk`.
    ///
    /// # Errors
    /// Fails if the diversifier is invalid.
    pub fn derive(ivk: &IncomingViewingKey, diversifier: Diversifier) -> Result<Self> {
        Ok(Self {
            diversifier,
            pk_d: ivk.transmission_key(&diversifier)?,
        })
    }

    /// The address at `index` of the wallet owning `fvk`.
    ///
    /// # Errors
    /// Fails if key derivation or the diversifier is invalid.
    pub fn from_index(fvk: &FullViewingKey, index: DiversifierIndex) -> Result<Self> {
        let diversifier = fvk.diversifier_key().diversifier(index)?;
        Self::derive(&fvk.incoming_viewing_key()?, diversifier)
    }

    /// Builds an address from already validated parts.
    pub fn from_parts(diversifier: Diversifier, pk_d: DiversifiedTransmissionKey) -> Self {
        Self { diversifier, pk_d }
    }

    /// The diversifier.
    pub fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// The transmission key.
    pub fn pk_d(&self) -> &DiversifiedTransmissionKey {
        &self.pk_d
    }

    /// The diversified base `g_d`.
    ///
    /// # Errors
    /// Fails if the diversifier is invalid.
    pub fn g_d(&self) -> Result<pallas::Point> {
        Ok(self.diversifier.base()?)
    }

    /// Raw encoding `d || pk_d`.
    pub fn to_bytes(&self) -> [u8; ADDRESS_LEN] {
        let mut out = [0u8; ADDRESS_LEN];
        let (d, pk) = out.split_at_mut(DIVERSIFIER_LEN);
        d.copy_from_slice(self.diversifier.as_bytes());
        pk.copy_from_slice(&self.pk_d.to_bytes());
        out
    }

    /// Parses the raw encoding, validating both parts.
    ///
    /// # Errors
    /// Fails on wrong length, invalid diversifier, or invalid transmission key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: &[u8; ADDRESS_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidAddress("wrong length".into()))?;
        let (d, pk) = raw.split_at(DIVERSIFIER_LEN);
        let diversifier = Diversifier::from_bytes(array_from(d)?);
        diversifier.base()?;
        let pk_d = DiversifiedTransmissionKey::from_bytes(&array_from::<ENCODED_LEN>(pk)?)?;
        Ok(Self::from_parts(diversifier, pk_d))
    }

    /// Bech32m text encoding for `prefix`'s network.
    pub fn encode(&self, prefix: AddressPrefix) -> String {
        // The raw address is short enough that encoding cannot fail.
        bech32::encode::<Bech32m>(prefix.hrp(), &self.to_bytes()).unwrap_or_default()
    }

    /// Parses the bech32m text encoding, requiring the bech32m checksum and
    /// the human readable part of `prefix`'s network.
    ///
    /// # Errors
    /// Fails on any checksum or payload problem, and with
    /// [`Error::InvalidAddress`] if the address is for another network.
    pub fn decode(text: &str, prefix: AddressPrefix) -> Result<Self> {
        let checked = CheckedHrpstring::new::<Bech32m>(text)
            .map_err(|e| Error::InvalidAddress(e.to_string()))?;
        if checked.hrp() != prefix.hrp() {
            return Err(Error::InvalidAddress(
                "address is for another network".into(),
            ));
        }
        let bytes: Vec<u8> = checked.byte_iter().collect();
        Self::from_bytes(&bytes)
    }
}

impl Encodable for Address {
    fn write(&self, w: &mut Writer) {
        w.put(&self.to_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Self::from_bytes(r.take(ADDRESS_LEN)?)
    }
}

/// Copies a slice into a fixed array, or reports a length mismatch.
fn array_from<const N: usize>(slice: &[u8]) -> Result<[u8; N]> {
    slice
        .try_into()
        .map_err(|_| Error::InvalidAddress("wrong length".into()))
}

/// Alias documenting that transmission keys use the common encoding.
pub type TransmissionKeyBytes = Encoded;

#[cfg(test)]
mod tests {
    use null_crypto::keys::{FullViewingKey, SpendingKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    pub(crate) fn address(seed: u64) -> Address {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let ivk = FullViewingKey::derive(&SpendingKey::random(&mut rng))
            .unwrap()
            .incoming_viewing_key()
            .unwrap();
        Address::derive(&ivk, Diversifier::random(&mut rng)).unwrap()
    }

    #[test]
    fn raw_encoding_roundtrips() {
        let addr = address(1);
        assert_eq!(Address::from_bytes(&addr.to_bytes()), Ok(addr));
    }

    #[test]
    fn encodable_matches_raw_encoding() {
        let addr = address(9);
        assert_eq!(addr.to_vec(), addr.to_bytes().to_vec());
        assert_eq!(Address::from_slice(&addr.to_vec()), Ok(addr));
    }

    #[test]
    fn raw_encoding_rejects_wrong_length_and_garbage() {
        assert!(Address::from_bytes(&[0u8; ADDRESS_LEN - 1]).is_err());
        assert!(Address::from_bytes(&[0xFF; ADDRESS_LEN]).is_err());
    }

    #[test]
    fn text_encoding_roundtrips_and_names_the_network() {
        let addr = address(2);
        let main = addr.encode(AddressPrefix::Main);
        let test = addr.encode(AddressPrefix::Test);
        assert!(main.starts_with("null1"), "{main}");
        assert!(test.starts_with("tnull1"), "{test}");
        assert_eq!(Address::decode(&main, AddressPrefix::Main), Ok(addr));
        assert_eq!(Address::decode(&test, AddressPrefix::Test), Ok(addr));
    }

    #[test]
    fn an_address_for_another_network_is_refused() {
        let addr = address(2);
        let main = addr.encode(AddressPrefix::Main);
        let test = addr.encode(AddressPrefix::Test);
        assert!(matches!(
            Address::decode(&main, AddressPrefix::Test),
            Err(Error::InvalidAddress(_))
        ));
        assert!(matches!(
            Address::decode(&test, AddressPrefix::Main),
            Err(Error::InvalidAddress(_))
        ));
    }

    #[test]
    fn text_encoding_rejects_tampering() {
        let text = address(3).encode(AddressPrefix::Main);
        let mut chars: Vec<char> = text.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let tampered: String = chars.into_iter().collect();
        assert!(Address::decode(&tampered, AddressPrefix::Main).is_err());
    }

    #[test]
    fn text_encoding_rejects_wrong_hrp() {
        let raw = address(4).to_bytes();
        let other = bech32::encode::<Bech32m>(Hrp::parse_unchecked("nope"), &raw).unwrap();
        assert!(matches!(
            Address::decode(&other, AddressPrefix::Main),
            Err(Error::InvalidAddress(_))
        ));
    }

    #[test]
    fn text_encoding_rejects_bech32_without_m() {
        let raw = address(5).to_bytes();
        let legacy = bech32::encode::<bech32::Bech32>(MAIN_HRP, &raw).unwrap();
        assert!(Address::decode(&legacy, AddressPrefix::Main).is_err());
    }

    #[test]
    fn indexed_addresses_are_deterministic_distinct_and_recoverable() {
        let fvk = FullViewingKey::derive(&SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(8)))
            .unwrap();
        let a0 = Address::from_index(&fvk, DiversifierIndex::ZERO).unwrap();
        assert_eq!(
            a0,
            Address::from_index(&fvk, DiversifierIndex::ZERO).unwrap()
        );
        let a1 = Address::from_index(&fvk, DiversifierIndex::from(1)).unwrap();
        assert_ne!(a0, a1);
        let recovered = fvk.diversifier_key().index(a1.diversifier()).unwrap();
        assert_eq!(recovered, DiversifierIndex::from(1));
    }

    #[test]
    fn different_diversifiers_give_different_addresses() {
        assert_ne!(address(6), address(7));
    }
}
