use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not the canonical encoding of a Pallas base field element.
    #[error("bytes are not a canonical Pallas base field element")]
    InvalidBase,
    /// The bytes are not the canonical encoding of a Pallas scalar field element.
    #[error("bytes are not a canonical Pallas scalar field element")]
    InvalidScalar,
    /// The bytes are not the canonical encoding of a Pallas point.
    #[error("bytes are not a canonical Pallas point")]
    InvalidPoint,
    /// A derived key was zero or the identity, which has negligible probability
    /// for honest inputs and would be unsafe to use.
    #[error("derived key is degenerate (zero or identity)")]
    DegenerateKey,
    /// A diversifier did not map to a valid diversified base.
    #[error("diversifier does not map to a valid diversified base")]
    InvalidDiversifier,
    /// A signature did not verify, or a batch of signatures contained a bad one.
    #[error("signature verification failed")]
    InvalidSignature,
    /// An authenticated ciphertext failed to decrypt.
    #[error("decryption failed")]
    DecryptionFailed,
    /// A diversifier index cannot be incremented further.
    #[error("diversifier index space exhausted")]
    DiversifierIndexOverflow,
    /// A hierarchical derivation argument was out of range.
    #[error("invalid derivation: {0}")]
    InvalidDerivation(&'static str),
    /// A string is not valid hexadecimal.
    #[error("invalid hexadecimal")]
    InvalidHex,
    /// An invariant this crate relies on was violated by a dependency.
    #[error("internal error: {0}")]
    Internal(&'static str),
}
