use thiserror::Error;

/// Errors produced by the node.
#[derive(Debug, Error)]
pub enum Error {
    /// Chain state or validation failed.
    #[error(transparent)]
    Chain(#[from] null_chain::Error),
    /// Storage failed.
    #[error(transparent)]
    Storage(#[from] null_storage::Error),
    /// Networking failed.
    #[error(transparent)]
    P2p(#[from] null_p2p::Error),
    /// A protocol type failed to decode or build.
    #[error(transparent)]
    Protocol(#[from] null_protocol::Error),
    /// Proving or key generation failed.
    #[error(transparent)]
    Circuit(#[from] null_circuit::Error),
    /// A key or encoding error.
    #[error(transparent)]
    Crypto(#[from] null_crypto::Error),
    /// The wallet failed.
    #[error(transparent)]
    Wallet(#[from] null_wallet::Error),
    /// A socket failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The node loop is gone.
    #[error("node stopped")]
    Stopped,
    /// A command line or RPC argument is invalid.
    #[error("invalid argument: {0}")]
    Argument(String),
    /// The control socket refused the token.
    #[error("control socket refused the token")]
    Unauthorized,
}
