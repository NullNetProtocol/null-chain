use thiserror::Error;

/// Errors produced by proving and verifying.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// The proving system reported an error, kept as its message so the
    /// error stays comparable.
    #[error("proving system: {0}")]
    Halo2(String),
    /// A witness could not be turned into public inputs.
    #[error(transparent)]
    Crypto(#[from] null_crypto::Error),
    /// The number of witnesses and public inputs differ, or is zero.
    #[error("witness and public input counts must match and be non-zero")]
    CountMismatch,
    /// The proof did not verify.
    #[error("proof verification failed")]
    InvalidProof,
}

impl From<halo2_proofs::plonk::Error> for Error {
    fn from(error: halo2_proofs::plonk::Error) -> Self {
        Self::Halo2(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halo2_errors_convert_to_their_message() {
        let converted: Error = halo2_proofs::plonk::Error::Synthesis.into();
        assert!(matches!(converted, Error::Halo2(ref m) if !m.is_empty()));
        assert_eq!(converted.clone(), converted);
    }
}
