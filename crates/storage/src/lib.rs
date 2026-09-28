//! Persistent chain state: the note commitment tree frontier, the
//! nullifier set and the block store, all in one `redb` database so a
//! block is applied or reverted atomically.
//!
//! - [`tree`]: the commitment tree frontier and its encoding.
//! - [`store`]: the database, its tables, and atomic apply and revert.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod error;
pub mod store;
pub mod tree;

pub use error::Error;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
