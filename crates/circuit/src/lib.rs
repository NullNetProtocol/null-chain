//! The Halo2 action circuit.
//!
//! Built in layers, see `docs/circuit.md`:
//!
//! 1. Poseidon layer: note integrity, membership or dummy, nullifier, rho
//!    chaining. Implemented in [`gadgets::note`] and [`gadgets::merkle`].
//! 2. ECC layer: spend authority, randomized key, value commitment,
//!    non-identity checks. Implemented in [`gadgets::ecc`].
//! 3. Range layer: 64-bit value checks. Implemented in [`gadgets::range`].
//!
//! [`action`] combines the layers into the circuit that is proven, and
//! [`proof`] generates keys, proves and verifies bundles of actions.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod action;
pub mod constants;
mod error;
pub mod gadgets;
pub mod proof;

pub use error::Error;

pub use pasta_curves::pallas::Base as Fp;
