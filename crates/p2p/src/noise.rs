//! The encrypted session: Noise `NN` over Curve25519, ChaCha20-Poly1305
//! and `BLAKE2b`. Both sides use fresh ephemeral keys only, so a connection
//! carries no long-term identity; it hides traffic from passive observers
//! and forces an active attacker to sit in the middle of every session.
//!
//! Noise messages are capped at 65535 bytes, so the session chunks the
//! plaintext stream: each wire chunk is `u16 LE length || ciphertext`.

use std::sync::Arc;

use snow::{Builder, HandshakeState, StatelessTransportState};

use crate::{Error, Result};

/// The Noise protocol name.
pub const PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2b";
/// Largest Noise message.
const NOISE_MAX: usize = 65_535;
/// Authentication tag length.
const TAG_LEN: usize = 16;
/// Largest plaintext per chunk.
const CHUNK_PLAINTEXT: usize = NOISE_MAX - TAG_LEN;
/// Bytes of a chunk's length prefix.
const CHUNK_PREFIX: usize = 2;

/// Which side of the handshake we are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Sends the first handshake message.
    Initiator,
    /// Replies to it.
    Responder,
}

/// The two-message handshake.
pub struct Handshake {
    state: HandshakeState,
}

impl Handshake {
    /// Starts a handshake in `role`.
    ///
    /// # Errors
    /// Fails if the Noise builder rejects the pattern, which it cannot.
    pub fn new(role: Role) -> Result<Self> {
        let builder = Builder::new(
            PATTERN
                .parse()
                .map_err(|_| Error::Noise("pattern".into()))?,
        );
        let state = match role {
            Role::Initiator => builder.build_initiator()?,
            Role::Responder => builder.build_responder()?,
        };
        Ok(Self { state })
    }

    /// The next handshake message to send.
    ///
    /// # Errors
    /// Fails if it is not our turn to write.
    pub fn write(&mut self) -> Result<Vec<u8>> {
        let mut out = vec![0u8; NOISE_MAX];
        let len = self.state.write_message(&[], &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    /// Consumes the peer's handshake message.
    ///
    /// # Errors
    /// Fails on a malformed or out-of-turn message.
    pub fn read(&mut self, message: &[u8]) -> Result<()> {
        let mut payload = vec![0u8; NOISE_MAX];
        self.state.read_message(message, &mut payload)?;
        Ok(())
    }

    /// Whether both messages have been exchanged.
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Turns the finished handshake into a session, split into a writer
    /// and a reader so the two directions can run on separate tasks.
    ///
    /// # Errors
    /// Fails if the handshake is not finished.
    pub fn into_session(self) -> Result<(SessionWriter, SessionReader)> {
        let state = Arc::new(self.state.into_stateless_transport_mode()?);
        Ok((
            SessionWriter {
                state: Arc::clone(&state),
                nonce: 0,
            },
            SessionReader {
                state,
                nonce: 0,
                inbound: Vec::new(),
            },
        ))
    }
}

impl core::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Handshake")
    }
}

/// The sending half of a session.
pub struct SessionWriter {
    state: Arc<StatelessTransportState>,
    nonce: u64,
}

impl SessionWriter {
    /// Encrypts `plaintext` into wire bytes, chunked as needed.
    ///
    /// # Errors
    /// Fails if the session's nonce space is exhausted.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len().saturating_add(CHUNK_PREFIX + TAG_LEN));
        let chunks: Vec<&[u8]> = if plaintext.is_empty() {
            vec![plaintext]
        } else {
            plaintext.chunks(CHUNK_PLAINTEXT).collect()
        };
        for chunk in chunks {
            let mut ciphertext = vec![0u8; NOISE_MAX];
            let len = self
                .state
                .write_message(self.nonce, chunk, &mut ciphertext)?;
            self.nonce = self
                .nonce
                .checked_add(1)
                .ok_or_else(|| Error::Noise("nonce exhausted".into()))?;
            out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_le_bytes());
            out.extend_from_slice(ciphertext.get(..len).unwrap_or(&[]));
        }
        Ok(out)
    }
}

impl core::fmt::Debug for SessionWriter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionWriter")
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

/// The receiving half of a session.
pub struct SessionReader {
    state: Arc<StatelessTransportState>,
    nonce: u64,
    inbound: Vec<u8>,
}

impl SessionReader {
    /// Feeds received wire bytes and returns every plaintext byte that
    /// complete chunks yield.
    ///
    /// # Errors
    /// Fails on a forged or reordered chunk; the connection must close.
    pub fn open(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        self.inbound.extend_from_slice(wire);
        let mut plaintext = Vec::new();
        while let Some(len) = self.next_chunk_len() {
            let end = CHUNK_PREFIX.saturating_add(len);
            let Some(chunk) = self.inbound.get(CHUNK_PREFIX..end) else {
                break;
            };
            let mut buffer = vec![0u8; NOISE_MAX];
            let n = self.state.read_message(self.nonce, chunk, &mut buffer)?;
            self.nonce = self
                .nonce
                .checked_add(1)
                .ok_or_else(|| Error::Noise("nonce exhausted".into()))?;
            plaintext.extend_from_slice(buffer.get(..n).unwrap_or(&[]));
            self.inbound.drain(..end);
        }
        Ok(plaintext)
    }

    /// The length of the next buffered chunk, if its prefix has arrived.
    fn next_chunk_len(&self) -> Option<usize> {
        let prefix: [u8; CHUNK_PREFIX] = self.inbound.get(..CHUNK_PREFIX)?.try_into().ok()?;
        Some(usize::from(u16::from_le_bytes(prefix)))
    }
}

impl core::fmt::Debug for SessionReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionReader")
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

/// Both halves of one side of a session.
pub type SessionPair = (SessionWriter, SessionReader);

/// Runs both sides of a handshake in memory, for tests and tools.
///
/// # Errors
/// Propagates handshake errors.
pub fn pair() -> Result<(SessionPair, SessionPair)> {
    let mut a = Handshake::new(Role::Initiator)?;
    let mut b = Handshake::new(Role::Responder)?;
    let m1 = a.write()?;
    b.read(&m1)?;
    let m2 = b.write()?;
    a.read(&m2)?;
    Ok((a.into_session()?, b.into_session()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_completes_in_two_messages() {
        let mut a = Handshake::new(Role::Initiator).unwrap();
        let mut b = Handshake::new(Role::Responder).unwrap();
        assert!(!a.is_finished());
        b.read(&a.write().unwrap()).unwrap();
        a.read(&b.write().unwrap()).unwrap();
        assert!(a.is_finished() && b.is_finished());
    }

    #[test]
    fn sessions_carry_small_and_large_payloads_both_ways() {
        let ((mut aw, mut ar), (mut bw, mut br)) = pair().unwrap();
        let small = b"hello".to_vec();
        let large: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        for payload in [small, large, Vec::new()] {
            let wire = aw.seal(&payload).unwrap();
            assert_eq!(br.open(&wire).unwrap(), payload);
            let back = bw.seal(&payload).unwrap();
            assert_eq!(ar.open(&back).unwrap(), payload);
        }
    }

    #[test]
    fn partial_chunks_wait_and_tampering_fails() {
        let ((mut aw, _), (_, mut br)) = pair().unwrap();
        let wire = aw.seal(b"payload").unwrap();
        assert!(br.open(&wire[..5]).unwrap().is_empty());
        assert_eq!(br.open(&wire[5..]).unwrap(), b"payload");

        let mut forged = aw.seal(b"more").unwrap();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(br.open(&forged).is_err());
    }

    #[test]
    fn replayed_chunks_are_rejected() {
        let ((mut aw, _), (_, mut br)) = pair().unwrap();
        let wire = aw.seal(b"once").unwrap();
        assert_eq!(br.open(&wire).unwrap(), b"once");
        assert!(br.open(&wire).is_err(), "nonce advanced, replay fails");
    }

    #[test]
    fn ciphertext_differs_from_plaintext_and_between_sessions() {
        let ((mut a, _), _) = pair().unwrap();
        let ((mut c, _), _) = pair().unwrap();
        let x = a.seal(b"same").unwrap();
        let y = c.seal(b"same").unwrap();
        assert_ne!(x, y);
        assert!(!x.windows(4).any(|w| w == b"same"));
    }
}
