//! Equihash: the generalized birthday problem as proof of work.
//!
//! A solution is `2^k` indices into a stream of `n`-bit hashes derived from
//! the header and a nonce, arranged as a binary tree in which every pair
//! of siblings collides on the next `n / (k + 1)` bits and the root XORs to
//! zero. Verification is a tree walk; solving is Wagner's algorithm, which
//! sorts and pairs candidates round by round and is bounded by memory.
//!
//! Hashing follows the Zcash construction exactly, with a chain-specific
//! personalization prefix, so the verifier is cross-checked against the
//! `equihash` crate in tests by swapping the prefix for Zcash's.

// Parameters are validated by `Params::new`, so every arithmetic
// expression on them is bounded; index arithmetic is bounded by the
// candidate count `2^(n/(k+1)+1)`, which fits `u32` by construction.
#![allow(clippy::arithmetic_side_effects)]

use blake2b_simd::{Params as Blake2bParams, State};

/// Byte length of the personalization prefix.
pub const PREFIX_LEN: usize = 8;

/// Our personalization prefix. Zcash uses `ZcashPoW`.
pub const PREFIX: [u8; PREFIX_LEN] = *b"nullPoW_";

/// Why a solution or parameter set was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// `(n, k)` violates the constraints in [`Params::new`].
    #[error("invalid equihash parameters")]
    InvalidParams,
    /// The solution bytes have the wrong length.
    #[error("solution has the wrong length")]
    SolutionLength,
    /// Two siblings do not collide on the required bits.
    #[error("siblings do not collide")]
    Collision,
    /// A right subtree's first index is not larger than the left's.
    #[error("index tree out of order")]
    OutOfOrder,
    /// An index appears twice.
    #[error("duplicate indices")]
    DuplicateIndices,
    /// The root of the tree does not XOR to zero.
    #[error("root hash is not zero")]
    NonZeroRoot,
}

/// The `(n, k)` parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    n: u32,
    k: u32,
}

impl Params {
    /// Validates the parameters: `n` a multiple of 8 and of `k + 1`,
    /// `3 <= k < n`, and a collision chunk that fits in 32 bits.
    ///
    /// # Errors
    /// Returns [`Error::InvalidParams`] otherwise.
    pub fn new(n: u32, k: u32) -> Result<Self, Error> {
        let valid = n % 8 == 0
            && k >= 3
            && k < n
            && n % (k.saturating_add(1)) == 0
            && n / (k + 1) <= 24
            && n <= 512;
        valid.then_some(Self { n, k }).ok_or(Error::InvalidParams)
    }

    /// `n`.
    pub fn n(self) -> u32 {
        self.n
    }

    /// `k`.
    pub fn k(self) -> u32 {
        self.k
    }

    /// Bits that must collide per round.
    fn collision_bits(self) -> u32 {
        self.n / (self.k + 1)
    }

    /// Chunks per hash: one per round plus the root remainder.
    fn chunks(self) -> usize {
        self.k as usize + 1
    }

    /// Hashes carved out of each `BLAKE2b` output.
    fn indices_per_output(self) -> u32 {
        512 / self.n
    }

    /// `BLAKE2b` output length in bytes.
    fn output_len(self) -> usize {
        (self.indices_per_output() * self.n / 8) as usize
    }

    /// Number of candidate indices.
    fn index_count(self) -> u32 {
        1 << (self.collision_bits() + 1)
    }

    /// Indices in a solution.
    pub fn solution_indices(self) -> usize {
        1 << self.k
    }

    /// Bits per index in the minimal encoding.
    fn index_bits(self) -> u32 {
        self.collision_bits() + 1
    }

    /// Byte length of an encoded solution.
    pub fn solution_len(self) -> usize {
        self.solution_indices() * self.index_bits() as usize / 8
    }
}

/// An `(n, k)` instance bound to a personalization prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Equihash {
    params: Params,
    prefix: [u8; PREFIX_LEN],
}

impl Equihash {
    /// An instance with our prefix.
    pub fn new(params: Params) -> Self {
        Self::with_prefix(params, PREFIX)
    }

    /// An instance with an explicit prefix, for cross-checks.
    pub fn with_prefix(params: Params, prefix: [u8; PREFIX_LEN]) -> Self {
        Self { params, prefix }
    }

    /// The parameters.
    pub fn params(&self) -> Params {
        self.params
    }

    /// The hasher state after absorbing `input` and `nonce`.
    fn state(&self, input: &[u8], nonce: &[u8]) -> State {
        let mut personalization = [0u8; 16];
        personalization[..PREFIX_LEN].copy_from_slice(&self.prefix);
        personalization[PREFIX_LEN..12].copy_from_slice(&self.params.n.to_le_bytes());
        personalization[12..].copy_from_slice(&self.params.k.to_le_bytes());
        let mut state = Blake2bParams::new()
            .hash_length(self.params.output_len())
            .personal(&personalization)
            .to_state();
        state.update(input);
        state.update(nonce);
        state
    }

    /// The hash of candidate `index`, as `k + 1` collision chunks.
    fn hash(&self, state: &State, index: u32) -> Vec<u32> {
        let mut out = vec![0u32; self.params.chunks()];
        self.hash_into(state, index, &mut out);
        out
    }

    /// Writes the chunks of candidate `index` into `out`.
    fn hash_into(&self, state: &State, index: u32, out: &mut [u32]) {
        let per_output = self.params.indices_per_output();
        let mut state = state.clone();
        state.update(&(index / per_output).to_le_bytes());
        let output = state.finalize();
        let width = (self.params.n / 8) as usize;
        let start = ((index % per_output) as usize).saturating_mul(width);
        let slice = output
            .as_bytes()
            .get(start..start.saturating_add(width))
            .unwrap_or(&[]);
        let bits = self.params.collision_bits();
        for (i, chunk) in out.iter_mut().enumerate() {
            *chunk = read_bits(slice, (i as u64).saturating_mul(u64::from(bits)), bits);
        }
    }

    /// Verifies `solution` for `input` and `nonce`.
    ///
    /// # Errors
    /// Returns the first rule the solution violates.
    pub fn verify(&self, input: &[u8], nonce: &[u8], solution: &[u8]) -> Result<(), Error> {
        let indices = indices_from_minimal(self.params, solution)?;
        let state = self.state(input, nonce);
        let root = self.validate_tree(&state, &indices)?;
        if root.hash.iter().all(|c| *c == 0) {
            Ok(())
        } else {
            Err(Error::NonZeroRoot)
        }
    }

    fn validate_tree(&self, state: &State, indices: &[u32]) -> Result<Node, Error> {
        if let [index] = indices {
            return Ok(Node {
                hash: self.hash(state, *index),
                indices: vec![*index],
            });
        }
        let (left, right) = indices.split_at(indices.len() / 2);
        let a = self.validate_tree(state, left)?;
        let b = self.validate_tree(state, right)?;
        let round = a.round();
        if a.hash.get(round) != b.hash.get(round) {
            return Err(Error::Collision);
        }
        if !a.first_before(&b) {
            return Err(Error::OutOfOrder);
        }
        if !a.disjoint(&b) {
            return Err(Error::DuplicateIndices);
        }
        Ok(a.merge(&b))
    }

    /// Finds every solution for `input` and `nonce`, as minimal encodings.
    ///
    /// Wagner's algorithm over flat byte tables: each round bucket-sorts
    /// the entries by their next chunk, pairs entries within a bucket, and
    /// keeps only the XOR of the remaining chunks plus two parent
    /// references. Chunks are packed into three bytes and the tables are
    /// dropped as soon as the next round exists, so memory is about
    /// `2^(n/(k+1)+1)` entries times a few dozen bytes.
    pub fn solve(&self, input: &[u8], nonce: &[u8]) -> Vec<Vec<u8>> {
        let state = self.state(input, nonce);
        let count = self.params.index_count() as usize;
        let width = self.params.chunks();
        let mut table = ChunkTable::with_entries(count, width);
        let mut scratch = vec![0u32; width];
        for index in 0..count {
            self.hash_into(
                &state,
                u32::try_from(index).unwrap_or(u32::MAX),
                &mut scratch,
            );
            table.set(index, &scratch);
        }
        let mut parents: Vec<Vec<(u32, u32)>> = Vec::with_capacity(self.params.k as usize);
        for _ in 0..self.params.k {
            let (next, next_parents) = pair_round(&table, self.params.collision_bits());
            table = next;
            parents.push(next_parents);
        }
        let mut solutions = Vec::new();
        let mut seen: Vec<Vec<u32>> = Vec::new();
        for entry in 0..table.entries() {
            if !table.is_zero(entry) {
                continue;
            }
            let indices = reconstruct(
                &parents,
                parents.len(),
                u32::try_from(entry).unwrap_or(u32::MAX),
            );
            let mut sorted = indices.clone();
            sorted.sort_unstable();
            if sorted.windows(2).any(|w| w.first() == w.get(1)) || seen.contains(&sorted) {
                continue;
            }
            seen.push(sorted);
            solutions.push(minimal_from_indices(self.params, &indices));
        }
        solutions
    }
}

/// Bytes per stored chunk; collision widths are at most 24 bits.
const CHUNK_BYTES: usize = 3;

/// A flat table of entries, each `width` chunks of [`CHUNK_BYTES`].
struct ChunkTable {
    bytes: Vec<u8>,
    width: usize,
}

impl ChunkTable {
    fn with_entries(entries: usize, width: usize) -> Self {
        Self {
            bytes: vec![0u8; entries.saturating_mul(width).saturating_mul(CHUNK_BYTES)],
            width,
        }
    }

    fn entries(&self) -> usize {
        self.bytes.len() / (self.width.max(1) * CHUNK_BYTES)
    }

    fn offset(&self, entry: usize, chunk: usize) -> usize {
        (entry * self.width + chunk) * CHUNK_BYTES
    }

    fn chunk(&self, entry: usize, chunk: usize) -> u32 {
        let at = self.offset(entry, chunk);
        self.bytes.get(at..at + CHUNK_BYTES).map_or(0, |b| {
            b.iter()
                .fold(0u32, |acc, byte| (acc << 8) | u32::from(*byte))
        })
    }

    fn set(&mut self, entry: usize, chunks: &[u32]) {
        for (i, value) in chunks.iter().enumerate() {
            let at = self.offset(entry, i);
            if let Some(slot) = self.bytes.get_mut(at..at + CHUNK_BYTES) {
                slot.copy_from_slice(&value.to_be_bytes()[1..]);
            }
        }
    }

    /// Appends the XOR of two entries' chunks after the first one. When
    /// the source has a single chunk, the pair collided on everything and
    /// a zero placeholder chunk is appended instead.
    fn push_xor(&mut self, source: &ChunkTable, a: usize, b: usize) {
        if source.width <= 1 {
            self.bytes.extend_from_slice(&[0; CHUNK_BYTES]);
            return;
        }
        let (sa, sb) = (source.offset(a, 1), source.offset(b, 1));
        let len = (source.width - 1) * CHUNK_BYTES;
        let (ra, rb) = (
            source.bytes.get(sa..sa + len).unwrap_or(&[]),
            source.bytes.get(sb..sb + len).unwrap_or(&[]),
        );
        self.bytes.extend(ra.iter().zip(rb).map(|(x, y)| x ^ y));
    }

    fn is_zero(&self, entry: usize) -> bool {
        let at = self.offset(entry, 0);
        self.bytes
            .get(at..at + self.width * CHUNK_BYTES)
            .is_some_and(|b| b.iter().all(|x| *x == 0))
    }
}

/// A partial solution as the verifier sees it: XOR of its leaves' hashes
/// and its leaf indices.
#[derive(Clone, Debug)]
struct Node {
    hash: Vec<u32>,
    indices: Vec<u32>,
}

impl Node {
    /// The round this node was produced in, i.e. the chunk to collide next.
    fn round(&self) -> usize {
        self.indices.len().trailing_zeros() as usize
    }

    fn first_before(&self, other: &Self) -> bool {
        self.indices.first() < other.indices.first()
    }

    fn disjoint(&self, other: &Self) -> bool {
        self.indices.iter().all(|i| !other.indices.contains(i))
    }

    /// The parent of two siblings, left first.
    fn merge(&self, other: &Self) -> Self {
        let hash = self
            .hash
            .iter()
            .zip(&other.hash)
            .map(|(a, b)| a ^ b)
            .collect();
        let (left, right) = if self.first_before(other) {
            (self, other)
        } else {
            (other, self)
        };
        let mut indices = left.indices.clone();
        indices.extend_from_slice(&right.indices);
        Self { hash, indices }
    }
}

/// Most entries paired within one bucket, to bound degenerate inputs.
const MAX_BUCKET: usize = 64;

/// One round: bucket-sort the entries by their first chunk, then pair
/// every two entries of a bucket. Returns the next table, one chunk
/// narrower, and the parents of each new entry.
fn pair_round(table: &ChunkTable, collision_bits: u32) -> (ChunkTable, Vec<(u32, u32)>) {
    let entries = table.entries();
    let buckets = 1usize << collision_bits;
    let key = |entry: usize| table.chunk(entry, 0) as usize;

    // Counting sort by key: `starts[b]` is where bucket `b` begins.
    let mut starts = vec![0u32; buckets + 1];
    for entry in 0..entries {
        if let Some(slot) = starts.get_mut(key(entry) + 1) {
            *slot += 1;
        }
    }
    for b in 0..buckets {
        let below = starts.get(b).copied().unwrap_or(0);
        if let Some(slot) = starts.get_mut(b + 1) {
            *slot += below;
        }
    }
    let mut fill = starts.clone();
    let mut order = vec![0u32; entries];
    for entry in 0..entries {
        let k = key(entry);
        let slot = fill.get(k).copied().unwrap_or(0) as usize;
        if let Some(cell) = order.get_mut(slot) {
            *cell = u32::try_from(entry).unwrap_or(u32::MAX);
        }
        if let Some(f) = fill.get_mut(k) {
            *f += 1;
        }
    }
    drop(fill);

    let mut next = ChunkTable {
        bytes: Vec::with_capacity(table.bytes.len()),
        width: table.width.saturating_sub(1).max(1),
    };
    let mut parents = Vec::with_capacity(entries);
    for window in starts.windows(2) {
        let (Some(&from), Some(&to)) = (window.first(), window.get(1)) else {
            continue;
        };
        let run = order.get(from as usize..to as usize).unwrap_or(&[]);
        let run = run.get(..run.len().min(MAX_BUCKET)).unwrap_or(run);
        for (i, &a) in run.iter().enumerate() {
            for &c in run.iter().skip(i + 1) {
                next.push_xor(table, a as usize, c as usize);
                parents.push((a, c));
            }
        }
    }
    (next, parents)
}

/// Rebuilds the leaf indices of `entry` at `round`, ordered so that at
/// every level the left subtree has the smaller first index.
fn reconstruct(parents: &[Vec<(u32, u32)>], round: usize, entry: u32) -> Vec<u32> {
    if round == 0 {
        return vec![entry];
    }
    let (a, b) = parents
        .get(round - 1)
        .and_then(|p| p.get(entry as usize))
        .copied()
        .unwrap_or((0, 0));
    let left = reconstruct(parents, round - 1, a);
    let right = reconstruct(parents, round - 1, b);
    let (mut first, second) = if left.first() < right.first() {
        (left, right)
    } else {
        (right, left)
    };
    first.extend(second);
    first
}

/// Reads `bits` bits starting at bit `offset`, MSB first.
fn read_bits(bytes: &[u8], offset: u64, bits: u32) -> u32 {
    (0..bits).fold(0u32, |acc, i| {
        let position = offset.saturating_add(u64::from(i));
        let byte = usize::try_from(position / 8)
            .ok()
            .and_then(|p| bytes.get(p))
            .copied()
            .unwrap_or(0);
        let bit = (byte >> (7 - (position % 8))) & 1;
        (acc << 1) | u32::from(bit)
    })
}

/// Packs each index into `index_bits` bits, MSB first.
fn minimal_from_indices(params: Params, indices: &[u32]) -> Vec<u8> {
    let bits = params.index_bits();
    let mut out = vec![0u8; params.solution_len()];
    for (i, index) in indices.iter().enumerate() {
        for b in 0..bits {
            let bit = (index >> (bits - 1 - b)) & 1;
            let position = (i as u64)
                .saturating_mul(u64::from(bits))
                .saturating_add(u64::from(b));
            if let Some(byte) = usize::try_from(position / 8)
                .ok()
                .and_then(|p| out.get_mut(p))
            {
                *byte |= (bit as u8) << (7 - (position % 8));
            }
        }
    }
    out
}

/// Inverse of [`minimal_from_indices`].
fn indices_from_minimal(params: Params, minimal: &[u8]) -> Result<Vec<u32>, Error> {
    if minimal.len() != params.solution_len() {
        return Err(Error::SolutionLength);
    }
    let bits = params.index_bits();
    Ok((0..params.solution_indices())
        .map(|i| read_bits(minimal, (i as u64).saturating_mul(u64::from(bits)), bits))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small enough to solve in milliseconds.
    fn tiny() -> Params {
        Params::new(48, 5).unwrap()
    }

    #[test]
    fn parameter_constraints_are_enforced() {
        assert!(Params::new(200, 9).is_ok());
        assert!(Params::new(192, 7).is_ok());
        assert!(Params::new(96, 5).is_ok());
        assert_eq!(
            Params::new(200, 8),
            Err(Error::InvalidParams),
            "n not multiple of k+1"
        );
        assert_eq!(
            Params::new(100, 4),
            Err(Error::InvalidParams),
            "n not multiple of 8"
        );
        assert_eq!(Params::new(48, 2), Err(Error::InvalidParams), "k too small");
    }

    #[test]
    fn solution_length_matches_zcash_for_known_parameters() {
        assert_eq!(Params::new(200, 9).unwrap().solution_len(), 1344);
        assert_eq!(Params::new(144, 5).unwrap().solution_len(), 100);
        assert_eq!(Params::new(192, 7).unwrap().solution_len(), 400);
        assert_eq!(Params::new(120, 4).unwrap().solution_len(), 50);
        assert_eq!(Params::new(96, 5).unwrap().solution_len(), 68);
    }

    #[test]
    fn bit_helpers_roundtrip() {
        let p = tiny();
        let indices: Vec<u32> = (0..u32::try_from(p.solution_indices()).unwrap())
            .map(|i| i * 7 % p.index_count())
            .collect();
        let minimal = minimal_from_indices(p, &indices);
        assert_eq!(minimal.len(), p.solution_len());
        assert_eq!(indices_from_minimal(p, &minimal).unwrap(), indices);
        assert_eq!(
            indices_from_minimal(p, &minimal[1..]),
            Err(Error::SolutionLength)
        );
        assert_eq!(read_bits(&[0b1010_0000], 0, 4), 0b1010);
        assert_eq!(read_bits(&[0b0000_0001, 0b1000_0000], 7, 2), 0b11);
        let nibbles: Vec<u32> = (0..4).map(|i| read_bits(&[0xAB, 0xCD], i * 4, 4)).collect();
        assert_eq!(nibbles, vec![0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn solver_output_verifies_and_tampering_is_rejected() {
        let eq = Equihash::new(tiny());
        // Tiny parameters yield about two solutions per nonce on average;
        // take the first nonce that yields any.
        let (nonce, solutions) = (1u8..=64)
            .map(|i| ([i; 32], eq.solve(b"header", &[i; 32])))
            .find(|(_, solutions)| !solutions.is_empty())
            .expect("some nonce solves");
        let other_nonce = [nonce[0].wrapping_add(100); 32];
        for solution in &solutions {
            assert_eq!(eq.verify(b"header", &nonce, solution), Ok(()));
            assert!(eq.verify(b"other", &nonce, solution).is_err());
            assert!(eq.verify(b"header", &other_nonce, solution).is_err());
            let mut bad = solution.clone();
            bad[0] ^= 1;
            assert!(eq.verify(b"header", &nonce, &bad).is_err());
            assert_eq!(
                eq.verify(b"header", &nonce, &solution[1..]),
                Err(Error::SolutionLength)
            );
        }
    }

    #[test]
    fn prefix_separates_chains() {
        let ours = Equihash::new(tiny());
        let theirs = Equihash::with_prefix(tiny(), *b"ZcashPoW");
        let solutions = ours.solve(b"h", &[0; 32]);
        for solution in &solutions {
            assert!(theirs.verify(b"h", &[0; 32], solution).is_err());
        }
    }

    /// Prints solve time for the parameter set in `EQUIHASH_BENCH`, e.g.
    /// `EQUIHASH_BENCH=192,7 cargo test --release -p null-chain --lib
    /// bench_parameter_set -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn bench_parameter_set() {
        let spec = std::env::var("EQUIHASH_BENCH").unwrap_or_else(|_| "96,5".into());
        let (n, k) = spec.split_once(',').expect("n,k");
        let (n, k): (u32, u32) = (n.trim().parse().unwrap(), k.trim().parse().unwrap());
        let eq = Equihash::new(Params::new(n, k).unwrap());
        let started = std::time::Instant::now();
        let solutions = eq.solve(b"bench", &[3; 32]);
        let elapsed = started.elapsed();
        for s in &solutions {
            assert_eq!(eq.verify(b"bench", &[3; 32], s), Ok(()));
        }
        eprintln!(
            "({n}, {k}): {} solutions in {elapsed:?}, solution {} bytes",
            solutions.len(),
            eq.params().solution_len()
        );
    }

    #[test]
    fn matches_the_equihash_crate_under_zcash_personalization() {
        // Same hashing, same tree rules, same minimal encoding as Zcash.
        let p = Params::new(96, 5).unwrap();
        let zcash = Equihash::with_prefix(p, *b"ZcashPoW");
        let input = b"block header bytes";
        let nonce = [7u8; 32];
        let solutions = zcash.solve(input, &nonce);
        assert!(!solutions.is_empty());
        for solution in &solutions {
            assert_eq!(zcash.verify(input, &nonce, solution), Ok(()));
            assert!(equihash::is_valid_solution(96, 5, input, &nonce, solution).is_ok());
        }
        let mut bad = solutions[0].clone();
        bad[5] ^= 0x10;
        assert!(equihash::is_valid_solution(96, 5, input, &nonce, &bad).is_err());
        assert!(zcash.verify(input, &nonce, &bad).is_err());
    }
}
