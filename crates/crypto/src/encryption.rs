//! Key agreement and authenticated encryption for note ciphertexts.
//!
//! ```text
//! sender:    esk random,  epk = [esk] g_d,  shared = [esk] pk_d
//! receiver:  shared = [ivk] epk
//! key       = KDF(shared, epk)
//! ct        = ChaCha20-Poly1305(key, nonce = 0, pt)
//! ```
//!
//! The nonce is zero because every key is used exactly once. The outgoing
//! cipher key `ock` lets the sender, or anyone with its `ovk`, recover
//! `pk_d` and `esk` and therefore the note.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ff::Field;
use pasta_curves::pallas;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::curve::is_identity;
use crate::encoding::{point_from_bytes, point_to_bytes, Encoded};
use crate::hash::{blake2b_short, NOTE_KDF, OCK, SHORT_OUTPUT_LEN};
use crate::keys::{DiversifiedTransmissionKey, IncomingViewingKey, OutgoingViewingKey};
use crate::secret::SecretScalar;
use crate::{Error, Result};

/// Byte length of the authentication tag appended to every ciphertext.
pub const TAG_LEN: usize = 16;
/// Byte length of a symmetric key.
pub const SYMMETRIC_KEY_LEN: usize = SHORT_OUTPUT_LEN;

/// `esk`: the sender's ephemeral secret.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct EphemeralSecretKey(SecretScalar);

impl EphemeralSecretKey {
    /// Wraps a scalar, normally derived from the note's random seed.
    pub fn from_scalar(scalar: pallas::Scalar) -> Self {
        Self(SecretScalar::new(scalar))
    }

    /// Samples a fresh secret, for tests and dummy outputs.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::from_scalar(pallas::Scalar::random(rng))
    }

    /// Canonical encoding, for the outgoing plaintext.
    pub fn to_bytes(&self) -> Encoded {
        crate::encoding::scalar_to_bytes(&self.0.expose())
    }

    /// Decodes a canonical scalar.
    ///
    /// # Errors
    /// Returns [`Error::InvalidScalar`] on a non-canonical encoding.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        crate::encoding::scalar_from_bytes(bytes).map(Self::from_scalar)
    }

    /// `epk = [esk] g_d`.
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn public_key(&self, g_d: &pallas::Point) -> EphemeralPublicKey {
        EphemeralPublicKey(g_d * self.0.expose())
    }

    /// `shared = [esk] pk_d`.
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn agree(&self, pk_d: &DiversifiedTransmissionKey) -> SharedSecret {
        SharedSecret(pk_d.as_point() * self.0.expose())
    }
}

/// `epk`: the public half of the ephemeral key, sent in the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EphemeralPublicKey(pallas::Point);

impl EphemeralPublicKey {
    /// `shared = [ivk] epk`.
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn agree(&self, ivk: &IncomingViewingKey) -> SharedSecret {
        SharedSecret(self.0 * ivk.expose())
    }

    /// Compressed encoding.
    pub fn to_bytes(&self) -> Encoded {
        point_to_bytes(&self.0)
    }

    /// Decodes a compressed point, rejecting the identity.
    ///
    /// # Errors
    /// Returns [`Error::InvalidPoint`] on a non-canonical encoding and
    /// [`Error::DegenerateKey`] for the identity.
    pub fn from_bytes(bytes: &Encoded) -> Result<Self> {
        let point = point_from_bytes(bytes)?;
        if is_identity(&point) {
            return Err(Error::DegenerateKey);
        }
        Ok(Self(point))
    }
}

/// The Diffie-Hellman shared secret between sender and receiver.
pub struct SharedSecret(pallas::Point);

impl SharedSecret {
    /// Derives the symmetric note encryption key.
    pub fn kdf(&self, epk: &EphemeralPublicKey) -> SymmetricKey {
        SymmetricKey(blake2b_short(
            NOTE_KDF,
            &[&point_to_bytes(&self.0), &epk.to_bytes()],
        ))
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// A single-use symmetric key for ChaCha20-Poly1305.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; SYMMETRIC_KEY_LEN]);

impl SymmetricKey {
    /// `ock = PRF_ovk(cv, cmx, epk)`: the outgoing cipher key.
    pub fn outgoing(ovk: &OutgoingViewingKey, cv: &Encoded, cmx: &Encoded, epk: &Encoded) -> Self {
        Self(blake2b_short(OCK, &[ovk.as_bytes(), cv, cmx, epk]))
    }

    /// A random key, for outputs whose sender does not want to recover them.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; SYMMETRIC_KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.0))
    }

    /// Encrypts `plaintext`. The output is `plaintext.len() + TAG_LEN` bytes.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Encryption only fails when the plaintext exceeds 2^38 bytes.
        self.cipher()
            .encrypt(&zero_nonce(), plaintext)
            .unwrap_or_default()
    }

    /// Decrypts and authenticates `ciphertext`.
    ///
    /// # Errors
    /// Returns [`Error::DecryptionFailed`] if the tag does not match.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.cipher()
            .decrypt(&zero_nonce(), ciphertext)
            .map_err(|_| Error::DecryptionFailed)
    }

    /// Decrypts a leading fragment of a ciphertext without the
    /// authentication tag, for compact-block detection.
    ///
    /// The AEAD reserves the first `ChaCha20` block for the Poly1305 key
    /// and encrypts the plaintext from block one, so this seeks to byte 64
    /// of the keystream before `XOR`ing. The caller must confirm the note
    /// against its commitment, since nothing here is authenticated.
    #[must_use]
    pub fn decrypt_lead(&self, lead: &[u8]) -> Vec<u8> {
        let mut cipher = ChaCha20::new(Key::from_slice(&self.0), &Nonce::default());
        // Byte 64 is the start of block one; block zero is the MAC key.
        cipher.seek(64u32);
        let mut out = lead.to_vec();
        cipher.apply_keystream(&mut out);
        out
    }
}

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

fn zero_nonce() -> Nonce {
    Nonce::default()
}

#[cfg(test)]
mod tests {
    use group::Group;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::keys::{Diversifier, FullViewingKey, SpendingKey};

    struct Receiver {
        ivk: IncomingViewingKey,
        g_d: pallas::Point,
        pk_d: DiversifiedTransmissionKey,
    }

    fn receiver(seed: u64) -> Receiver {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let ivk = FullViewingKey::derive(&SpendingKey::random(&mut rng))
            .unwrap()
            .incoming_viewing_key()
            .unwrap();
        let d = Diversifier::random(&mut rng);
        Receiver {
            g_d: d.base().unwrap(),
            pk_d: ivk.transmission_key(&d).unwrap(),
            ivk,
        }
    }

    #[test]
    fn sender_and_receiver_derive_the_same_key() {
        let r = receiver(1);
        let esk = EphemeralSecretKey::random(&mut ChaCha20Rng::seed_from_u64(2));
        let epk = esk.public_key(&r.g_d);
        let sender_key = esk.agree(&r.pk_d).kdf(&epk);
        let receiver_key = epk.agree(&r.ivk).kdf(&epk);
        assert_eq!(sender_key.0, receiver_key.0);
    }

    #[test]
    fn wrong_receiver_derives_a_different_key() {
        let (a, b) = (receiver(3), receiver(4));
        let esk = EphemeralSecretKey::random(&mut ChaCha20Rng::seed_from_u64(5));
        let epk = esk.public_key(&a.g_d);
        assert_ne!(
            esk.agree(&a.pk_d).kdf(&epk).0,
            epk.agree(&b.ivk).kdf(&epk).0
        );
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips_and_detects_tampering() {
        let key = SymmetricKey::random(&mut ChaCha20Rng::seed_from_u64(6));
        let ct = key.encrypt(b"hello");
        assert_eq!(ct.len(), 5 + TAG_LEN);
        assert_eq!(key.decrypt(&ct), Ok(b"hello".to_vec()));

        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert_eq!(key.decrypt(&tampered), Err(Error::DecryptionFailed));

        let other = SymmetricKey::random(&mut ChaCha20Rng::seed_from_u64(7));
        assert_eq!(other.decrypt(&ct), Err(Error::DecryptionFailed));
    }

    #[test]
    fn decrypt_lead_matches_the_aead_on_the_leading_bytes() {
        let key = SymmetricKey::random(&mut ChaCha20Rng::seed_from_u64(20));
        let plaintext: Vec<u8> = (0u8..80).collect();
        let ciphertext = key.encrypt(&plaintext);
        for lead in [0usize, 1, 52, 80] {
            let recovered = key.decrypt_lead(&ciphertext[..lead]);
            assert_eq!(recovered, &plaintext[..lead], "lead {lead}");
        }
    }

    #[test]
    fn outgoing_key_depends_on_every_input() {
        let ovk = OutgoingViewingKey::from_bytes([1; 32]);
        let base = SymmetricKey::outgoing(&ovk, &[2; 32], &[3; 32], &[4; 32]);
        assert_ne!(
            base.0,
            SymmetricKey::outgoing(
                &OutgoingViewingKey::from_bytes([9; 32]),
                &[2; 32],
                &[3; 32],
                &[4; 32]
            )
            .0
        );
        assert_ne!(
            base.0,
            SymmetricKey::outgoing(&ovk, &[9; 32], &[3; 32], &[4; 32]).0
        );
        assert_ne!(
            base.0,
            SymmetricKey::outgoing(&ovk, &[2; 32], &[9; 32], &[4; 32]).0
        );
        assert_ne!(
            base.0,
            SymmetricKey::outgoing(&ovk, &[2; 32], &[3; 32], &[9; 32]).0
        );
    }

    #[test]
    fn ephemeral_keys_roundtrip_bytes_and_reject_identity() {
        let esk = EphemeralSecretKey::random(&mut ChaCha20Rng::seed_from_u64(8));
        assert_eq!(
            EphemeralSecretKey::from_bytes(&esk.to_bytes())
                .unwrap()
                .to_bytes(),
            esk.to_bytes()
        );
        let epk = esk.public_key(&receiver(9).g_d);
        assert_eq!(EphemeralPublicKey::from_bytes(&epk.to_bytes()), Ok(epk));
        let identity = point_to_bytes(&pallas::Point::identity());
        assert_eq!(
            EphemeralPublicKey::from_bytes(&identity),
            Err(Error::DegenerateKey)
        );
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let esk = EphemeralSecretKey::random(&mut ChaCha20Rng::seed_from_u64(10));
        let shared = esk.agree(&receiver(11).pk_d);
        assert_eq!(format!("{shared:?}"), "SharedSecret(<redacted>)");
        assert_eq!(
            format!("{:?}", shared.kdf(&esk.public_key(&receiver(11).g_d))),
            "SymmetricKey(<redacted>)"
        );
    }
}
