# CLAUDE.md

Guidance for working on this repository. Read this before touching code.

## What this project is

A shielded-only privacy cryptocurrency written from scratch in Rust. Every
transaction is private by construction: there are no transparent addresses.
Design lineage is Zcash Orchard (whole-pool anonymity set via zero-knowledge
membership proofs, no trusted setup) with lessons from Monero (uniform
transaction shapes, Dandelion++ propagation, proof of work). The two
priorities, in order, are anonymity and performance. `TODO.md` is the
roadmap and the single source of truth for what is done and what is next.

## Workspace layout

```
crates/
  crypto/     curves, hashes, key derivation, commitments, encoding helpers
  circuit/    Halo2 action circuit (spend + output) and its tests
  protocol/   notes, nullifiers, addresses, amounts, transaction format, rules
  chain/      proof of work, difficulty, block validation, chain state
  storage/    commitment tree, nullifier set, block store
  p2p/        peer discovery, block sync, Dandelion++ transaction relay
  wallet/     scanning, note management, transaction building
  node/       daemon binary and RPC
```

Dependency direction is strictly downward: `node -> wallet/p2p/chain ->
storage -> protocol -> circuit -> crypto`. A crate never depends on one
above it. If something is needed in two crates, it belongs in the lower one.

## Non-negotiable rules

1. **Every piece of logic gets a unit test.** A function without a test is
   not done. Put tests in a `#[cfg(test)] mod tests` block at the bottom of
   the same file. Cross-crate behaviour goes in `tests/` of the higher crate.
2. **No duplicated code.** If two places do the same thing, extract a helper.
   Three lines repeated twice is already a helper. Prefer small, named,
   single-purpose functions over long bodies with comments.
3. **No unsafe.** `unsafe_code = "forbid"` is set at the workspace level.
4. **Never implement a cryptographic primitive yourself.** Curves, hashes,
   field arithmetic, proving systems and signatures come from audited crates
   (`pasta_curves`, `halo2_proofs`, `blake2b_simd`, `curve25519-dalek`).
   We compose primitives; we do not write them.
5. **Library crates never panic on input.** No `unwrap`, `expect`, `panic!`,
   indexing that can go out of bounds, or arithmetic that can overflow on
   data that came from the network, disk, or a user. Return `Result` with a
   `thiserror` error type defined in the crate's `error.rs`. `unwrap` is
   acceptable only in tests and on values proven constant at compile time.
   Each crate root carries `#![cfg_attr(test, allow(clippy::unwrap_used, ...))]`
   so tests stay terse; never widen that allow to non-test code.
6. **Secrets are handled in constant time and zeroized.** Anything derived
   from a spending key implements `Zeroize` and `ZeroizeOnDrop`, compares
   with `subtle::ConstantTimeEq`, and is never `Debug`-printed in full.
7. **Every hash is domain separated.** All BLAKE2b calls use a
   personalization string defined once as a named constant in
   `crypto::hash`. Never reuse a personalization across purposes.
8. **Serialization is canonical.** One byte layout per type, one
   `to_bytes`/`from_bytes` pair, and a roundtrip test. Reject non-canonical
   encodings; never "fix them up".
9. **Anything variable in a transaction is a fingerprint.** Fixed action
   counts padded with dummies, fixed fee tiers, no locktime, no expiry, one
   version. Adding a field to a transaction requires a privacy argument in
   the PR description.
10. **Public items are documented.** `missing_docs` is a warning that is
    treated as an error in CI. Explain what, why, and any invariant.

## Code style

- `cargo fmt` and `cargo clippy --workspace --all-targets -- -D warnings`
  must both pass before any commit. Clippy pedantic lints are enabled in the
  workspace `Cargo.toml`; allow a lint locally only with a comment saying why.
- Newtypes over raw arrays and field elements. `Nullifier(pallas::Base)`,
  not a bare `pallas::Base`. This makes misuse a type error.
- Conversions between types live in `From`/`TryFrom` impls, not free
  functions with ad-hoc names.
- Constants are `const` or `static` with a doc comment and a name that says
  what they are for, in the module that owns them. No magic numbers.
- Keep functions short. If a function needs section comments, split it.
- Use `rayon` for embarrassingly parallel work at the block level, never
  inside a primitive. Batch verification before parallelization.
- Prefer iterators and `?` over manual loops and `match` on `Result`.
- Feature flags only for optional transports and backends, never to change
  consensus behaviour.

## Testing conventions

- Deterministic tests use a seeded RNG (`rand_chacha::ChaCha20Rng::seed_from_u64`).
  Randomized tests must print or embed the seed on failure.
- Every encoding has a roundtrip test and a "reject garbage" test.
- Every consensus rule has a test that passes and a test that fails.
- Every cryptographic property we rely on has a test that demonstrates it
  (homomorphism of value commitments, hiding of note commitments, etc.).
- Circuits are tested with `halo2_proofs::dev::MockProver` in unit tests and
  with a real prover in `tests/` behind `--release`.
- Property tests use `proptest` when the input space is large.
- Test names read as sentences: `value_commitments_are_additively_homomorphic`.

## Commands

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps
```

## Workflow

- Update `TODO.md` in the same commit as the work it describes. Tick items
  off and add newly discovered ones.
- One logical change per commit. The message says what and why.
- When a design decision is made, record it briefly in `docs/decisions.md`
  with the date, the alternatives considered and the reason.
- Never commit generated proving parameters, keys, or anything under
  `target/`.

## Security posture

- The circuit is the consensus. A soundness bug means invisible inflation.
  Any change to `crates/circuit` requires a second review and a full test
  run in release mode.
- Assume the network observer, the peer, and the disk are all adversarial.
- Wallet scanning must not leak timing information about which outputs
  belong to the wallet.
