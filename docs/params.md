# Parameters

The consensus and node parameters in force, with their source. Values
marked *provisional* are not finalized for a real launch. Keep this in
sync with the code; the code is authoritative.

## Per network

From `ChainParams::mainnet()` / `::test()` in `crates/chain/src/params.rs`.

| Parameter | mainnet | test | Meaning |
|---|---|---|---|
| Name and ticker | Null network, `NULL` | | the unit is 100,000,000 smallest units |
| Address prefix | `null1` | `tnull1` | bech32m human readable part; viewing keys `nullview1` / `tnullview1` |
| Equihash `(n, k)` | `(144, 5)` | `(48, 5)` | proof-of-work; mainnet needs ~1.8 GB per solver thread, test is trivial |
| PoW limit (nBits) | `0x1f07ffff` | `0x207fffff` | easiest allowed target; test is much easier |
| Block interval | 120 s | 5 s | target spacing for the difficulty rule |
| Difficulty window | 60 blocks | 6 blocks | blocks the LWMA rule averages |
| Genesis timestamp | 1757000000 | 1000000 | ~2025-09-04 UTC on mainnet; arbitrary on test |
| Anchor max age | 100 blocks | 100 blocks | how long a commitment root stays a valid anchor |
| Max future drift | 7200 s (2 h) | 7200 s (2 h) | how far ahead a block timestamp may be |
| Max reorg depth | 200 blocks | 200 blocks | deepest reorg accepted; older frontiers pruned |
| Coinbase maturity | 100 blocks | 10 blocks | a reward mined at `h` enters the note tree at `h + M - 1` and is spendable at `h + M`; genesis exempt |
| Checkpoints | none | none | *provisional* — filled at launch |
| Genesis branch id | `0x4d41494e` | `0x54455354` | rule-set id bound into every sighash; differs per network |
| Upgrades | none | none | scheduled `(height, branch)` activations, see `docs/upgrades.md` |
| Seed peers | `seed1`–`seed5.nullnet.sh:19000` | none | resolved when dialed; pass `--connect`/`--seed` on test |

Genesis is unmined (limit target, no PoW) and identified by hash. It
carries one transaction, the coinbase paying the premine (below); its
commitment root is the tree after that transaction's outputs. The
transaction bytes are committed per network in `crates/chain/src/genesis/`
and re-generated with `nulld genesis-coinbase --network <net> --address
<dev address> --out <file>`; every run yields a new proof and so a new
genesis hash, which must then be re-pinned. On the test network the
premine pays the all-zero seed phrase's account 0, whose spending key is
`aeee2840de33f371c576fdde22e552725f6e7002c642a64cbfbaa71679dddaf3`
(address `tnull1qgwtwmahzrkmyrl08tf65wtp0m4tjdvyv3x26f5762mufvljfgjqkvyfas5u3stpavsnjmdzm47`),
so anyone can fund a test wallet from it. On mainnet it pays a
*placeholder* address whose key was discarded: **regenerate it with the
real development fund address before launch**, or the premine is burned.
The mainnet genesis hash is pinned in
`crates/chain/src/genesis.rs`:
`6c49fc018f0f7d2ee744e55c28df974b96c8daa68a7b5f3ee52b60cba31d14d6`.

## Money and emission

From `crates/protocol/src/amount.rs` and `consensus.rs`. The whole
schedule is *provisional*.

| Parameter | Value |
|---|---|
| `COIN` | 100,000,000 units |
| `MAX_MONEY` | 21,000,000 coins |
| Premine (development fund) | 1,050,000 coins, 5% of `MAX_MONEY`, paid by the genesis coinbase |
| Initial block subsidy | 9.5 coins |
| Halving interval | 1,050,000 blocks (~4 years at 120 s blocks; emission plus premine sums to `MAX_MONEY`) |
| Genesis subsidy | 0 (the premine is not a subsidy; `subsidy(0)` stays zero) |

## Transaction shape

From `crates/protocol/src/consensus.rs`. These are uniform by design; see
`CLAUDE.md` §9 and `docs/protocol.md`.

| Parameter | Value |
|---|---|
| Action classes | 2, 4, 8, 16 (dummy-padded) |
| Max actions | 16 |
| Fee | `FEE_PER_ACTION` × actions, 10,000 units per action (no fee field) |
| Max transactions per block | 512 |
| Transaction version | 1 |
| Block version | 1 |
| PoW solution length | 100 bytes |

Proof size per action class (release build, see `docs/perf.md`): 8,736 /
14,496 / 26,016 / 49,056 bytes for 2 / 4 / 8 / 16 actions.

## Circuit

From `crates/circuit`. A change here re-pins the verifying key hash.

| Parameter | Value |
|---|---|
| Curve | Pallas |
| Proving system | Halo2 (IPA, no trusted setup) |
| `K` | 12 |
| Merkle tree depth | 48 |
| Fixed bases | `G_spend`, `R` (full scalar), `V` (short scalar) |

## Node defaults

From `crates/node/src/config.rs` and `cli.rs`. These are local operator
settings, not consensus.

| Parameter | Value |
|---|---|
| Control socket | `127.0.0.1:18444` |
| Outbound peer target | 8 |
| Max inbound peers | 125 |
| Mempool capacity | 10,000 transactions |
| Mining threads | 1 (set with `--mining-threads`) |
