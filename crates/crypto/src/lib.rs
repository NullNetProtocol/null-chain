//! Cryptographic building blocks for the coin.
//!
//! This crate composes audited primitives (`pasta_curves`, `blake2b_simd`) into
//! the key hierarchy, commitments and encodings the protocol layer needs. It
//! never implements a primitive itself.
//!
//! Layering inside the crate, lowest first:
//!
//! - [`hash`]: domain-separated `BLAKE2b` and hash-to-field helpers.
//! - [`encoding`]: canonical 32-byte encodings for field elements and points.
//! - [`secret`]: zeroizing, constant-time wrappers around field elements.
//! - [`curve`]: fixed generators, hash-to-curve and Pedersen helpers.
//! - [`keys`]: the spending key hierarchy and diversified addresses.
//! - [`commitment`]: value and note commitments.
//! - [`signature`]: `RedPallas` spend authorization and binding signatures.
//! - [`encryption`]: key agreement and authenticated encryption for notes.
//! - [`poseidon`]: the circuit-friendly hash, one typed function per use.
//! - [`merkle`]: the note commitment tree primitives.
//! - [`diversifier`]: diversifier indices and their encryption into diversifiers.
//! - [`zip32`]: hierarchical derivation of spending keys from a seed.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod commitment;
pub mod curve;
pub mod diversifier;
pub mod encoding;
pub mod encryption;
mod error;
pub mod hash;
pub mod keys;
pub mod merkle;
pub mod poseidon;
pub mod secret;
pub mod signature;
pub mod zip32;

pub use error::Error;
pub use pasta_curves::pallas;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
