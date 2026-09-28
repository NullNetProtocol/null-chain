use thiserror::Error;

/// Errors produced by the networking layer.
#[derive(Debug, Error)]
pub enum Error {
    /// A message did not decode.
    #[error(transparent)]
    Protocol(#[from] null_protocol::Error),
    /// A frame or message exceeds its size limit.
    #[error("message too large: {0} bytes")]
    TooLarge(usize),
    /// A message has an unknown type tag.
    #[error("unknown message tag {0}")]
    UnknownTag(u8),
    /// A list in a message exceeds its limit.
    #[error("list too long: {0}")]
    ListTooLong(&'static str),
    /// The Noise handshake or transport failed.
    #[error("noise: {0}")]
    Noise(String),
    /// The socket failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The peer closed the connection.
    #[error("connection closed")]
    Closed,
    /// The peer did not complete the handshake in time.
    #[error("handshake timed out")]
    HandshakeTimeout,
    /// The peer violated the protocol.
    #[error("peer misbehaved: {0}")]
    Misbehavior(&'static str),
    /// A header sequence does not chain.
    #[error("headers do not chain: {0}")]
    BadHeaders(&'static str),
}

impl From<snow::Error> for Error {
    fn from(error: snow::Error) -> Self {
        Self::Noise(error.to_string())
    }
}
