//! Text form of an exported full viewing key: bech32m over the key's
//! canonical bytes with a network-specific human readable part, so a
//! key for one network is refused by the other, like an address.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::Bech32m;
use null_crypto::keys::{FullViewingKey, FULL_VIEWING_KEY_LEN};

use crate::address::AddressPrefix;
use crate::{Error, Result};

/// Encodes `fvk` for `prefix`'s network.
pub fn encode_full_viewing_key(fvk: &FullViewingKey, prefix: AddressPrefix) -> String {
    // 96 bytes is well within bech32m's limit, so encoding cannot fail.
    bech32::encode::<Bech32m>(prefix.viewing_key_hrp(), &fvk.to_bytes()).unwrap_or_default()
}

/// Parses a key exported for `prefix`'s network.
///
/// # Errors
/// Fails on a checksum or length problem, and with
/// [`Error::InvalidAddress`] if the key is for another network.
pub fn decode_full_viewing_key(text: &str, prefix: AddressPrefix) -> Result<FullViewingKey> {
    let checked =
        CheckedHrpstring::new::<Bech32m>(text).map_err(|e| Error::InvalidAddress(e.to_string()))?;
    if checked.hrp() != prefix.viewing_key_hrp() {
        return Err(Error::InvalidAddress(
            "viewing key is for another network".into(),
        ));
    }
    let bytes: [u8; FULL_VIEWING_KEY_LEN] = checked
        .byte_iter()
        .collect::<Vec<u8>>()
        .try_into()
        .map_err(|_| Error::InvalidAddress("viewing key length".into()))?;
    Ok(FullViewingKey::from_bytes(&bytes)?)
}

#[cfg(test)]
mod tests {
    use null_crypto::keys::SpendingKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn viewing_keys_round_trip_and_name_their_network() {
        let sk = SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(3));
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let main = encode_full_viewing_key(&fvk, AddressPrefix::Main);
        let test = encode_full_viewing_key(&fvk, AddressPrefix::Test);
        assert!(main.starts_with("nullview1"), "{main}");
        assert!(test.starts_with("tnullview1"), "{test}");
        assert_eq!(
            decode_full_viewing_key(&main, AddressPrefix::Main)
                .unwrap()
                .to_bytes(),
            fvk.to_bytes()
        );
        assert!(decode_full_viewing_key(&main, AddressPrefix::Test).is_err());
        assert!(decode_full_viewing_key("nullview1qqqq", AddressPrefix::Main).is_err());
        assert!(decode_full_viewing_key(&main[..main.len() - 1], AddressPrefix::Main).is_err());
    }
}
