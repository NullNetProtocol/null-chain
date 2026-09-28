//! Length-prefixed framing: `u32 LE length || message bytes`.

use crate::message::{Message, MAX_MESSAGE_LEN};
use crate::{Error, Result};

/// Bytes of the length prefix.
const PREFIX_LEN: usize = 4;

/// Encodes one message as a frame.
pub fn frame(message: &Message) -> Vec<u8> {
    let body = message.encode();
    let mut out = Vec::with_capacity(PREFIX_LEN.saturating_add(body.len()));
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Accumulates stream bytes and yields complete messages.
#[derive(Debug, Default)]
pub struct Framer {
    buffer: Vec<u8>,
}

impl Framer {
    /// An empty framer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends received bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Bytes buffered but not yet parsed.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// The next complete message, if one is buffered.
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] for an oversized frame, or a decode
    /// error; both should end the connection.
    pub fn next_message(&mut self) -> Result<Option<Message>> {
        let Some(prefix) = self.buffer.get(..PREFIX_LEN) else {
            return Ok(None);
        };
        let len = usize::try_from(u32::from_le_bytes(prefix.try_into().unwrap_or([0; 4])))
            .map_err(|_| Error::TooLarge(usize::MAX))?;
        if len > MAX_MESSAGE_LEN {
            return Err(Error::TooLarge(len));
        }
        let end = PREFIX_LEN.saturating_add(len);
        let Some(body) = self.buffer.get(PREFIX_LEN..end) else {
            return Ok(None);
        };
        let message = Message::decode(body)?;
        self.buffer.drain(..end);
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_survive_arbitrary_splits() {
        let messages = [Message::Ping(1), Message::Verack, Message::Pong(2)];
        let bytes: Vec<u8> = messages.iter().flat_map(frame).collect();
        for split in 0..bytes.len() {
            let mut framer = Framer::new();
            framer.push(&bytes[..split]);
            let mut got = Vec::new();
            while let Some(m) = framer.next_message().unwrap() {
                got.push(m);
            }
            framer.push(&bytes[split..]);
            while let Some(m) = framer.next_message().unwrap() {
                got.push(m);
            }
            assert_eq!(got, messages, "split at {split}");
            assert_eq!(framer.pending(), 0);
        }
    }

    #[test]
    fn oversized_frames_are_rejected_before_the_body_arrives() {
        let mut framer = Framer::new();
        framer.push(&u32::MAX.to_le_bytes());
        assert!(matches!(framer.next_message(), Err(Error::TooLarge(_))));
    }

    #[test]
    fn garbage_bodies_are_errors() {
        let mut framer = Framer::new();
        framer.push(&1u32.to_le_bytes());
        framer.push(&[250]);
        assert!(framer.next_message().is_err());
    }
}
