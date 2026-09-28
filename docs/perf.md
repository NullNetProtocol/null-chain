# Performance numbers

Measured on the development machine, single proof per bundle, `K = 12`,
fixed-base window tables for `G_spend`, `R` and `V`. Update when the
circuit changes; the numbers are the target any optimization must beat.

## Action circuit, release build (2026-09-13, depth 48)

| Actions | Proof size | Prove | Verify (single) |
|---|---|---|---|
| 2 | 8 736 B | 0.78 s | 9.9 ms |
| 4 | 14 496 B | 1.43 s | 8.6 ms |
| 8 | 26 016 B | 2.58 s | 9.7 ms |
| 16 | 49 056 B | 4.79 s | 20.7 ms |

Verification is batched per block in the chain crate; single-proof
verification times vary by a few milliseconds between runs.

The Merkle depth went from 32 to 48 so the tree cannot fill in the
lifetime of the chain (`docs/decisions.md`, 2026-09-13). Depth 40 and 48
both overflow the 2 048 rows of `K = 11` and both fit `K = 12`; at
`K = 12` the depths cost the same (0.74 s against 0.78 s for two
actions), so the deeper tree was free once the doubling was paid.
Proving is about 1.55 times slower than at depth 32 and the proof grows
by 64 bytes per class. Same-day numbers at depth 32, `K = 11`, on the
same machine: 0.48 / 0.87 / 1.60 / 3.00 s.

### Before the depth change (2026-09-09, depth 32, `K = 11`)

| Actions | Proof size | Prove | Verify (single) |
|---|---|---|---|
| 2 | 8 672 B | 0.49 s | 3.2 ms |
| 4 | 14 432 B | 0.84 s | 5.3 ms |
| 8 | 25 952 B | 1.55 s | 8.6 ms |
| 16 | 48 992 B | 2.94 s | 14.2 ms |

Key generation took about 0.8 s.

The window tables replaced four variable-base multiplications (about
1 000 rows each in the ECC columns) with two 85-window and one 22-window
fixed-base multiplications. Proving time did not move: the circuit was
bound by the Poseidon columns, where the 32 Merkle levels and the four
other hashes needed more than 1 024 rows, so `K` stayed at 11 and the
prover did the same amount of polynomial work. The proof grew by 64 bytes
per two actions because the short-scalar gate raised the maximum gate
degree by one, adding a quotient chunk. With `K = 12` the Poseidon
columns hold 48 levels plus the four hashes in under 4 096 rows, so
there is room for more constraints before the next doubling.

Before the tables (2026-09-08): 8 608 / 14 304 / 25 696 / 48 480 B and
0.49 / 0.83 / 1.47 / 2.72 s for the same classes.

Reproduce with:

```
cargo test --release -p null-circuit --test prove -- --ignored --nocapture
```

## Equihash solver, release build, single thread (2026-09-09)

Sort-and-pair Wagner solver with parent references, one nonce each.

| Set | Collision width | Solve | Peak memory | Solution |
|---|---|---|---|---|
| 96,5 | 16 | 43 ms | 47 MB | 68 B |
| 200,9 | 20 | 1.4 s | 222 MB | 1344 B |
| 120,4 | 24 | 12.8 s | 1.84 GB | 50 B |
| 144,5 | 24 | 15.3 s | 2.10 GB | 100 B |
| 168,6 | 24 | 18.2 s | 2.37 GB | 200 B |
| 192,7 | 24 | 21.2 s | 2.63 GB | 400 B |

Memory hardness follows the collision width, so every set from 120,4 up
is in the same class. Mainnet uses 144,5. After packing chunks into
three bytes and offsets into four (2026-09-09), 144,5 peaks at 1.80 GB;
parent references account for 1.3 GB of that. Known solvers for this
width sit between 1.5 and 2 GB, which is the point of the width: the
memory requirement is what resists dedicated hardware.

Reproduce with:

```
EQUIHASH_BENCH=144,5 cargo test --release -p null-chain --lib bench_parameter_set -- --ignored --nocapture
```

## Nullifier set on redb (2026-09-09)

One million inserts in one transaction: 0.43 s. One hundred thousand
point lookups against them: 66 ms, or 0.66 us each. A bloom filter in
front of the table is not worth its false-positive handling at this cost.

```
cargo test --release -p null-storage nullifier_lookup_cost -- --ignored --nocapture
```
