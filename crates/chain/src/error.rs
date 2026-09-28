use thiserror::Error;

/// Errors produced by the chain layer.
#[derive(Debug, Error)]
pub enum Error {
    /// The block store failed.
    #[error(transparent)]
    Storage(#[from] null_storage::Error),
    /// A transaction or block violated a protocol rule.
    #[error(transparent)]
    Protocol(#[from] null_protocol::Error),
    /// A proof failed to verify.
    #[error(transparent)]
    Circuit(#[from] null_circuit::Error),
    /// A signature failed to verify.
    #[error(transparent)]
    Crypto(#[from] null_crypto::Error),
    /// The proof-of-work solution is invalid.
    #[error(transparent)]
    Equihash(#[from] crate::equihash::Error),
    /// A header field is wrong.
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    /// A block body is wrong.
    #[error("invalid block: {0}")]
    InvalidBlock(&'static str),
    /// The block's parent is unknown.
    #[error("orphan block: parent unknown")]
    Orphan,
    /// The store was built under other consensus rules or another
    /// circuit, or under rules it did not record.
    #[error(
        "store was built under different or unrecorded consensus rules or circuit; delete it and resync"
    )]
    RulesMismatch,
    /// A compact target encoding is malformed.
    #[error("invalid compact target")]
    InvalidTarget,
    /// The mempool refused a transaction.
    #[error("mempool rejected the transaction: {0}")]
    Rejected(crate::mempool::Rejection),
}
