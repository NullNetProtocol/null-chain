//! Proof of work, difficulty adjustment, block validation and chain state.
//!
//! - [`equihash`]: the proof-of-work puzzle, verifier and solver.
//! - [`target`]: compact difficulty targets and cumulative work.
//! - [`difficulty`]: the LWMA retarget rule.
//! - [`params`]: per-network constants.
//! - [`pow`]: the header-level proof-of-work check and miner loop.
//! - [`genesis`]: the first block.
//! - [`validate`]: stateful block validation against the store.
//! - [`chain`]: importing blocks, including reorganizations.
//! - [`mempool`]: the arrival-order transaction pool.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod chain;
pub mod difficulty;
pub mod equihash;
mod error;
pub mod genesis;
pub mod mempool;
pub mod params;
pub mod pow;
pub mod target;
pub mod validate;

pub use error::Error;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
