# Design decisions

One entry per decision. Newest at the bottom. Each entry records the date,
the alternatives considered and why the choice was made, so it does not get
re-litigated without new information.

## 2026-09-07: Shielded-only pool, no transparent addresses

Alternatives: Zcash-style optional shielding; Monero-style always-on ring
signatures.

Chosen: every note lives in one shielded pool. Real-world deanonymization of
Zcash comes almost entirely from transparent addresses and pool migration.
Removing them removes the leak class. Cost: the supply cannot be audited
from outside, so circuit soundness is the whole security argument.

## 2026-09-07: Whole-pool membership proofs over decoy rings

Alternatives: Monero rings of 16; FCMP++ curve trees; Halo2 Merkle
membership.

Chosen: Halo2 Merkle membership as in Orchard, no trusted setup, audited
Rust crates exist. FCMP++ stays an open comparison item in `TODO.md`
because its prover may be cheaper.

## 2026-09-07: Pallas curve, Orchard-style key hierarchy

Alternatives: Ed25519 with Monero-style keys; Jubjub with Sapling keys.

Chosen: Pallas so the same curve works inside and outside the circuit
through the Pasta cycle. Key hierarchy mirrors Orchard (ask, nk, rivk, ivk,
diversified pk_d) because it is the best-analysed design for
diversified addresses with viewing keys.

## 2026-09-07: Placeholder hashes for commitments and nullifier PRF

The note commitment and the nullifier PRF currently use domain-separated
BLAKE2b mapped to field elements. They are hiding and binding but not
circuit friendly. They will be swapped for Sinsemilla and Poseidon in
Phase 3. Every call site goes through one function so the swap is local.

## 2026-09-07: Proof of work over proof of stake

Private proof of stake would require proving stake weight without revealing
it. That is open research. Proof of work has no such interaction with
privacy and is well understood. The hash function is still undecided.

## 2026-09-07: Provisional monetary constants

`COIN = 10^8`, `MAX_MONEY = 21_000_000 * COIN`. These are placeholders so
the amount type has a cap to enforce. The real emission schedule is a
Phase 2 item.

## 2026-09-07: Poseidon only, no Sinsemilla

Alternatives: Sinsemilla for commitments and Merkle tree with Poseidon for
the nullifier PRF, as Orchard does.

Chosen: Poseidon for everything (note commitment, Merkle tree, nullifier
PRF, ivk commitment). One primitive to audit, fast outside the circuit
where wallet scanning and node validation happen. Accepted cost: more
circuit rows than Sinsemilla for long inputs. Parameters come from the
`halo2_gadgets` reference set and are never tuned.

## 2026-09-07: Halo2 Merkle membership, FCMP++ rejected

Alternatives: FCMP++ curve trees.

Chosen: Halo2 with a depth-32 Merkle tree, confirming the earlier lean.
Production record, general-purpose circuit, batched verification, and it
keeps the Pallas key hierarchy. FCMP++ would force Ed25519 plus the Helios
and Selene curves and has no production record yet. The membership proof
sits behind a trait so a curve-tree backend could be added later.

## 2026-09-07: Pure Rust proof of work, RandomX rejected

Alternatives: RandomX through a C binding; a plain SHA3/BLAKE3 hash.

Chosen: a memory-hard function implemented in pure Rust, to keep one
toolchain, reproducible builds and no FFI. Accepted cost: weaker GPU
resistance than RandomX and no existing miner software. The exact
function (Argon2id, Balloon or another audited construction) and its
memory parameters are still to be chosen and benchmarked; the choice lives
behind a `ProofOfWork` trait in `chain`.

## 2026-09-07: Deterministic fee, no fee field, no fee market

Alternatives: free fee chosen by the wallet (Monero); a small set of fee
tiers chosen by the wallet; a hidden fee as an implicit shielded output to
the miner.

Chosen: `fee = FEE_PER_ACTION * action_count`. The action count is already
visible from the bundle size class, so the fee adds no information and
needs no field in the transaction. The verifier computes it and includes
it in the value balance. The coinbase output value is subsidy plus the sum
of fees, both publicly computable, while the miner's address stays
shielded. Accepted cost: no fee market; blocks fill first come first
served. If ever needed, at most two priority multipliers may be added,
each being a new fingerprint dimension. `FEE_PER_ACTION` is provisional
and will be set with the emission schedule.

## 2026-09-07: Equihash proof of work with chain-specific parameters

Alternatives: Argon2d, Balloon, Cuckatoo, a RandomX rewrite, a plain hash.

Chosen: Equihash. It has years of production use on Zcash, an audited
pure Rust verifier (the `equihash` crate from librustzcash), and
asymmetric verification: nodes and light clients check a header in
microseconds. Argon2 and Balloon were rejected because no chain uses them
as proof of work, so there is no track record in that role.

Parameters `(n, k)` and the BLAKE2b personalization are chain specific and
still to be chosen by benchmark; the Zcash `(200, 9)` and Bitcoin Gold
`(144, 5)` sets are excluded because ASICs exist for them. Accepted costs:
the solver (miner) must be written in Rust, the proof is over a kilobyte
per header, and memory-hardness only delays dedicated hardware. The
implementation lives behind the `ProofOfWork` trait in `chain`.

## 2026-09-07: Reuse Zcash's RedPallas parameters through `reddsa`

Alternatives: fork `reddsa` to use our own basepoints and hash
personalization; implement RedDSA ourselves.

Chosen: use `reddsa::orchard` as published. Its spend authorization and
binding basepoints and its `H*` personalization are Zcash's, and the crate
seals them. Forking would mean maintaining a copy of audited signature
code for a cosmetic difference. Consequences: `ak` lives on the RedPallas
spend authorization basepoint, and our value commitment randomness base
`R` is defined as the RedPallas binding basepoint, so binding signatures
verify against sums of our value commitments. Cross-chain replay is
prevented by the transaction sighash, which will carry a chain-specific
personalization.

## 2026-09-07: Note encryption layout

Note plaintext is `version || d || value || rseed || memo` (564 bytes) under
ChaCha20-Poly1305 with a zero nonce and a single-use key from
`BLAKE2b(shared_secret || epk)`. The outgoing plaintext is `pk_d || esk`
(64 bytes) under `ock = BLAKE2b(ovk || cv || cmx || epk)`. Both mirror Orchard.
Outputs the sender does not want to recover get a random `ock` and random
outgoing plaintext, so the ciphertext shape never reveals that choice.

## 2026-09-08: Transaction layout, txid and sighash

Encoding is `version || anchor || n_actions || actions || proof || binding
signature`, with each action `nullifier || rk || cmx || cv_net || epk ||
enc_ciphertext || out_ciphertext || spend_auth_sig` (884 bytes). The txid
and the sighash are BLAKE2b-256 over the effecting data only (`version ||
anchor || n_actions || action bodies`), under different personalizations.
Proof and signatures are excluded so re-randomizing them cannot change the
id. Alternative rejected: hashing the full encoding, which would make the
txid malleable by anyone who can re-randomize a proof.

## 2026-09-08: Builder pads, shuffles, and signs in `protocol`

The transaction builder lives in the protocol crate rather than the wallet
because dummy padding, shuffling and the balance rule are consensus-shaped
privacy properties, and tests of validation need a producer of valid
transactions. The wallet will only do input selection and change. Spends
and outputs are shuffled independently so position reveals nothing about
which actions are real.

## 2026-09-08: Poseidon domain separation by input length

All Poseidon uses share the `P128Pow5T3` parameters and are separated only
by input length, which `halo2_poseidon` encodes in the capacity element:
Merkle nodes take 2 inputs, ivk 3, nullifier 4, note commitment 6. The
alternative of a tag input per use was rejected because it would double
the cost of every Merkle level, the dominant circuit cost. A test asserts
that the lengths stay distinct. Merkle levels are not tagged because the
depth is fixed at 32 and leaves and nodes already differ in input length.

The note commitment became a field element rather than a curve point, so
`cmx` and `cm` are the same value. The nullifier became
`Poseidon(nk, rho, psi, cm)` instead of the Orchard point construction,
which no longer had a purpose once `cm` was not a point.

## 2026-09-08: Note commitment hashes full coordinates, not x plus sign

Alternative: hash `x` and a sign bit, packed with the value into one word,
which saves one Poseidon permutation per commitment.

Chosen: hash both affine coordinates of `g_d` and `pk_d`, eight inputs in
total. Proving a sign bit in-circuit needs `y = 2h + s` with a 254-bit
range check on `h`, which costs far more than the extra permutation. The
ECC chip already exposes both coordinate cells for free.

## 2026-09-08: Variable-base multiplication with constant bases

Alternative: precomputed fixed-base window tables as Orchard uses, which
need generated `u` and `z` constants per base.

Chosen for now: witness `G_spend`, `V` and `R` as points pinned to
constants and use the variable-base gadget. The whole action circuit fits
in `K = 11`, the same as Orchard, so the optimization is not urgent. The
`FixedPoints` type parameter is satisfied by uninhabited types. Window
tables stay on the roadmap as an optimization with a measurable target.

## 2026-09-08: Keys generated at startup, verifying key pinned by hash

Alternative: ship serialized proving and verifying keys with the binary.

Chosen: derive both keys from the circuit at startup, which takes under a
second at `K = 11`, and pin a `BLAKE2b` hash of the pinned verifying key
description in a unit test. Every node computes identical keys because
key generation is deterministic, and no key file can drift from the code.
The test fails on any circuit change, so the hash must be updated in the
same commit as the change, which makes circuit edits visible in review.

## 2026-09-08: Proof length is a consensus rule, not a field

The transaction encoding carries the proof without a length prefix. The
length is a fixed function of the action class, checked during stateless
validation, so a transaction cannot vary in size for a given class. The
table of lengths lives next to the circuit and is verified against real
proofs in the circuit crate's tests, so a circuit change that alters
proof size fails a test before it can desynchronize nodes.

## 2026-09-08: redb for chain state

Alternatives: RocksDB, LMDB through `heed`, sled, fjall.

Chosen: `redb`. Pure Rust, matching the pure-Rust proof-of-work decision;
ACID with one writer and snapshot readers, so a block import is one
atomic write across the block, height, nullifier and frontier tables; a
B-tree, which fits point lookups on nullifiers and hashes at one small
write batch per block. RocksDB is proven at larger scale but is a C++
build dependency with a tuning surface this workload does not need. sled
is unmaintained; fjall is young and an LSM is the wrong shape for these
reads. The store exposes typed operations so the backend can change.

## 2026-09-08: Frontier per height instead of a reversible tree

The commitment tree is stored as a frontier, and one frontier is kept per
block height (about a kilobyte each). Reverting a block restores the
previous height's frontier instead of undoing appends, and anchor
validity is a lookup of recent frontiers' roots. Old frontiers can be
pruned later without changing the interface.

## 2026-09-08: Own Equihash implementation, `equihash` crate as oracle

The `equihash` crate hardcodes Zcash's personalization and ships no pure
Rust solver, so the chain crate implements both verifier and solver with
a chain-specific prefix. The construction, tree rules and minimal
encoding match Zcash exactly, which a test proves by running our solver
under the `ZcashPoW` prefix and validating its output with the crate.
The solver is the straightforward sort-and-pair form of Wagner's
algorithm; it is fast for test parameters and will need index trees and
bucket sorting before `(192, 7)` is practical for miners.

## 2026-09-08: Coinbase as an ordinary transaction with a negative balance

Alternative: a separate coinbase format.

Chosen: the coinbase is the block's first transaction and uses the same
format, circuit and validation as every other transaction. Its only
difference is the public value balance the binding signature proves:
minus the subsidy plus the block's fees, instead of plus its own fee. Its
spends are all dummies, which the circuit already allows. This keeps the
transaction shape uniform, so a coinbase output is indistinguishable
from any other note once it is in the tree.

## 2026-09-08: Fixed-size solution field with zero padding

The header's solution field is `POW_SOLUTION_LEN` bytes, sized for the
provisional mainnet parameters. Smaller parameter sets, used in tests,
occupy a prefix and the remainder must be zero. When `(n, k)` is final the
constant is set to the exact solution length and the padding disappears.

## 2026-09-08: Mempool refuses when full instead of evicting

With fixed fees there is nothing to rank transactions by, so the pool is
a queue: the oldest are mined first. When it is full, new transactions
are refused rather than evicting the oldest, because evicting the oldest
would drop exactly the transactions about to be mined and let sustained
spam starve everyone. Readmission after a reorganization skips
signature and proof verification, since the transactions were valid when
mined, but re-checks anchors and nullifiers against the new state.

## 2026-09-08: Noise NN transport, no long-term peer identity

Alternatives: plaintext TCP; Noise XX with static keys; TLS.

Chosen: `Noise_NN_25519_ChaChaPoly_BLAKE2b`, ephemeral keys only. Every
connection is encrypted against passive observers and carries no
identity that could link a node across connections, which suits a privacy
network. An active attacker can sit in the middle of a session, as with
Bitcoin's BIP 324; peer authentication is a later, opt-in addition.
Noise frames cap at 65535 bytes, so the session chunks the message stream
under a two-byte length; the message framing above it is independent.

## 2026-09-08: Pure protocol state machines, thin transport

Peer handshake, address book, sync and Dandelion++ take messages, time
and randomness as arguments and return events, so they are unit-tested
without sockets. Only the transport touches TCP. The node event loop that
connects the machines to the chain and mempool is Phase 7 work.

## 2026-09-08: No user agent, no optional fields in the wire protocol

Version messages carry the protocol version, a nonce, the tip height, the
genesis hash and a timestamp. There is no user agent string and no
service bits: every implementation speaks identical bytes, so a node
cannot be fingerprinted by what it announces.

## 2026-09-08: One task owns all node state

Alternative: shared state behind locks, with each connection task acting
on the chain and mempool directly.

Chosen: a single event loop task owns the chain, mempool, peers, sync and
Dandelion state and reacts to events from connection tasks, the clock,
the miner and the control socket. No locks, no ordering surprises, and
every state transition happens in one place. Proving and solving run on
blocking threads and hand results back as events. The control socket is
a line protocol on localhost so a wallet process can scan and submit
without opening the database, which redb locks to one process.

## 2026-09-08: Wallet file holds viewing data, never the spending key

Alternatives: store the spending key encrypted under a passphrase; store
nothing and rescan every time.

Chosen for now: the wallet file stores leaves, owned notes with their
spent height, and the hash of every scanned block, bound by fingerprint
to one viewing key and one network. The spending key is supplied per
command. A copy of the file reveals balances and memos but cannot spend.
Encrypting the file and storing the key under a memory-hard passphrase
derivation are roadmap items; doing them properly needs an audited KDF
choice, which is not worth rushing for a local testnet.

Reorganizations are handled by comparing stored block hashes with the
node from the wallet's tip backwards and rolling back to the last match,
which unspends notes and drops leaves and notes created above it.

## 2026-09-09: Equihash (144, 5) for mainnet

Alternatives measured: (200, 9), (120, 4), (168, 6), (192, 7), see
`docs/perf.md`.

Chosen: (144, 5). Memory hardness is set by the collision width
`n / (k + 1)`, which is 24 for every candidate from (120, 4) up, so they
share one hardness class. Within it, (144, 5) has a 100-byte solution
against 400 for (192, 7), so headers are four times smaller and
verification does 32 hashes instead of 128. Miner software for this set
exists and typically accepts a custom personalization string, which
helps bootstrapping and also means existing farms can point at the chain;
that is true of any parameter set with public miners. An earlier note in
this file said ASICs exist for (144, 5); that is not established, and the
choice does not rest on it. The header layout changed with the solution
length, so the genesis hash was re-pinned.

## 2026-09-09: Checkpoints and a maximum reorganization depth

Nodes refuse a reorganization that would revert a checkpointed block or
that is deeper than `max_reorg_depth` (200 blocks), and prune commitment
tree frontiers older than that depth. Without the limit, a node would
have to keep every frontier forever to be able to revert. The checkpoint
lists are empty until launch.

## 2026-09-09: Tor through SOCKS5, no feature flag

Alternative: an embedded Tor client behind a feature flag.

Chosen: a `--proxy` option that sends every outbound connection through a
SOCKS5 proxy with the hostname, so Tor resolves `.onion` names. It is
pure Rust, a few dozen lines, and needs no feature flag. Bans are not
applied to outbound peers reached through the proxy, since their socket
address is the proxy's. Inbound onion services are configured in Tor
itself.

## 2026-09-09: Compact blocks with a prefilled coinbase

A new block is relayed as its header, its coinbase and the ids of the
other transactions. The coinbase is included because no mempool ever
holds it; everything else is usually already pooled, so a block costs a
few hundred bytes to relay. Missing transactions are fetched by index.
Initial sync still moves full blocks.

## 2026-09-09: Wallet encryption

The wallet file now holds the spending key and every note record under
ChaCha20-Poly1305 with a key derived from the passphrase by Argon2id
(64 MiB, three passes, one lane, random 16-byte salt). Record nonces are
the tree position with a kind tag, so no two records share one. Tree
leaves and scanned heights stay in the clear: they are public chain data
and encrypting them would only slow scanning. In-memory wallets use a
random key. Argon2id was chosen because it is the memory-hard standard
with an audited pure Rust implementation; the parameters take a fraction
of a second on a laptop and cost an attacker 64 MiB per guess.

## 2026-09-09: Five-second blocks on the test network

The test network's block interval was one second. With a trivial target
a block is found on the first nonce, so block time equals proving time,
which is deterministic, and a miner that started earlier stayed ahead
forever: in a six-container run one miner won every block. Real proof of
work is random because many nonces are needed. Five-second blocks make
the difficulty rule demand that work, and both miners win their share.
Unit tests set timestamps explicitly and are unaffected.

## 2026-09-09: Sharded witness tree in the wallet

The wallet used to store every leaf of the commitment tree and rebuild
the full tree for each payment, which is linear in the chain's history.
It now keeps a `shardtree` (depth 32, shards of height 16) in three redb
tables: shards, the cap above them, and one checkpoint per scanned block.
Leaves the wallet owns are marked and kept; everything else prunes to
subtree roots, so the file grows with the number of owned notes. A spend
removes the note's mark as of the block's checkpoint, and a rollback
truncates the tree to the checkpoint at the surviving height, which
restores marks removed above it. The wallet retains 256 checkpoints,
more than the chain's maximum reorganization depth of 200; rolling back
past them fails rather than producing a wrong tree, and the wallet must
then be recreated from the seed. Witnesses are computed in a read
transaction; the store is generic over the table handle, and writes
through a read-only handle are refused. The `Node` wrapper that the
chain's frontier already used moved to `null_crypto::merkle` so both
trees share one definition.

## 2026-09-09: Fixed-base window tables

The circuit multiplied its three fixed generators with the variable-base
gadget, pinning the base to a constant, because that needed no generated
constants. It now uses the ECC chip's fixed-base windows: `z` and `u`
tables for `G_spend` and `R` over 85 windows and for `V` over 22 windows,
generated once by `tests/gen_tables.rs` and verified against the
generators by `tests/fixed_bases.rs`. The net value `v_old - v_new` is
witnessed as magnitude and sign for the short multiplication, with one
gate tying it to the two note values; the chip's own gates bound the
magnitude to 64 bits and the sign to `1` or `-1`. Measured effect: about
3 000 ECC rows freed, no change in proving time because the Poseidon
columns keep `K` at 11, and 64 more proof bytes per two actions from one
extra quotient chunk. The tables are kept because they are the standard
construction, the freed rows are what future constraints will use, and
the alternative would have been to re-measure again at that point.

## 2026-09-09: Control socket token

The control socket was unauthenticated on localhost, so any local
process could submit transactions or read the chain through it. Each
session must now begin with `auth <token>`; the token is a random 32-byte
hex string the node writes owner-readable to `rpc.token` in its data
directory, or a string the operator passes with `--rpc-token` or
`NULL_RPC_TOKEN`. Clients take it as a flag, a file or the environment
variable. A token was chosen over a Unix socket because the containerized
testnet and remote wallets talk to nodes over TCP, and over TLS because
the socket is meant for localhost or a private network where a shared
secret is enough and a certificate would be one more thing to manage.
The comparison is constant time and three refusals close a session.

## 2026-09-09: BIP 39 seed phrases

A wallet's backup is a 24-word English BIP 39 phrase. The BIP 39 seed is
derived with an empty passphrase and the account key is
`m / 32' / 1' / account'` of that seed, so the phrase alone restores
every account. English only, so a phrase written down is unambiguous;
no "25th word", because the wallet file already has a passphrase and a
second one is what people lose. `nulld create` prints the phrase once
when it generates one, restores from `--phrase` (read from the
environment or a hidden prompt, never from the command line), or still
imports a raw spending key. The account 0 key and address of the
all-zero test phrase are pinned in a test so the derivation cannot
change without notice.

## 2026-09-09: Metrics endpoint and stale-block counters

`--metrics <addr>` serves the Prometheus text format at `/metrics` on
its own listener, unauthenticated because it reveals nothing a peer
could not infer and scrapers expect that; it binds nowhere unless asked.
The node remembers the height and hash of every block it mined (the
last 100 000) and reports how many are in the main chain now, on the
status line and as `null_blocks_mined{state}`; the difference is the
stale rate a miner should watch. The faucet's request parsing moved to
`node::http` so both tiny servers share it.

## 2026-09-09: I2P via the SAM bridge

`--i2p <sam address>` reaches `.i2p` peers through a router's SAM v3
bridge, the analogue of `--proxy` for Tor. The node creates one transient
SAM session at startup, keeps its control socket open for the process
lifetime, and opens a stream through it for each `.i2p` target; other
targets still use the proxy or a direct connection. A transient
destination is used because the node is a client here, not a published
service; a persistent destination and an inbound listener over I2P are a
later step. Only the three SAM commands a stream client needs are
implemented, and the reply parser accepts a line only when it carries
`RESULT=OK`. Outbound peers reached this way are never address-banned,
since their address is the bridge's, the same rule the proxy already had.

## 2026-09-09: Work-equalized scanning

Trial decryption of an action that is not ours stops at the cipher's
authentication tag; for ours it goes on to two scalar multiplications,
a hash to the curve and two Poseidon hashes. The scanner now performs
that work on a stand-in note for every action that fails to decrypt,
so an observer of the wallet's timing learns nothing from the cost per
action. This is work equalization rather than branch-free code: the
wallet is single-user software where the goal is to keep a co-located
observer from reading ownership off the CPU, not to run inside an
adversary's enclave. The cost is about doubling the constant part of
scanning, which stays dominated by the AEAD and key agreement per
action.

## 2026-09-09: Light client over compact blocks

A light wallet scans compact blocks rather than full ones. The node
serves them with `compact <height>`: per action the nullifier, the note
commitment, the ephemeral key and the leading 52 bytes of the note
ciphertext, which is the note plaintext up to but not including the memo.
The wallet decrypts the lead with ChaCha20 seeked past the AEAD's MAC
block (the lead is unauthenticated, so the note is accepted only once it
matches the commitment), rebuilds the note and confirms it against the
commitment. Every commitment lets the light wallet append to the same
sharded witness tree a full wallet keeps, and every nullifier lets it
detect spends, so its balance and witnesses are identical; only memos are
lost, and a found note can be fetched in full to recover one. Detection
does the same commitment work on a stand-in note for every action that
is not ours, as the full scanner does. Fuzzy message detection, which
would let a server scan on the wallet's behalf without learning which
notes are its own, is left for later; the compact-block path already
removes the need to download full transactions.

## 2026-09-10: Address gossip actually bootstraps

The node had ADDR/GETADDR gossip and an address book with candidate
selection, but nothing ever inserted a locally known address: a dialed
seed was not added to the book (`connected` only updated existing
entries), inbound peers were not added, and the node did not advertise
its own listen address. So the gossip had nothing to propagate and the
network ran seeds-only in practice. A node now adds each peer it dials
to its book once the handshake completes, unless the peer was reached
through the proxy or the SAM bridge, where the recorded address is the
transport's. That makes seed addresses gossipable: a third node given
only a relay discovers the seed the relay learned, as the discovery test
shows. Learning inbound peers' listen addresses would need a self-
advertisement in the handshake and is left for later.

## 2026-09-10: Control-socket client hardening

The control-socket client read a reply with an unbounded `read_line` and
no timeout, so a hung node stalled the CLI forever and a large or hostile
reply could grow memory without limit. `Client::call` now reads within a
30-second timeout and buffers at most 128 MiB per reply (generous, since a
full block's hex is tens of megabytes), reporting a clear error on a
timeout, a closed socket or an over-long reply. A new `hash <height>`
request returns just the 32-byte block hash, so the wallet's reorg check
and genesis lookup no longer re-download whole blocks; the forward scan
still fetches full or compact blocks as before.

## 2026-09-10: Multi-threaded mining

Mining was one worker: a single loop trying one nonce at a time, and the
Equihash solver has no internal parallelism, so a miner used one core for
the proof-of-work search. `--mining-threads N` now runs N workers that
share one proving key and each mine from a random nonce, so they explore
disjoint nonce ranges with overwhelming probability and their throughput
adds up. Each mining attempt runs on the blocking pool rather than with
`block_in_place`, so many workers use many cores without starving the
async runtime. The default is one thread. On the test network the gain is
muted because the trivial target makes coinbase proving, which already
uses halo2's multicore feature, the dominant cost; on mainnet, where the
Equihash search dominates, N workers scale nearly linearly.

## 2026-09-10: Leveled, colored logging

Node output moved from a bare timestamped line to a small leveled logger
(`node::logging`): `HH:MM:SS LEVEL  message`, with the level tag colored
when standard output is a terminal and `NO_COLOR` is unset, plain
otherwise. Levels are debug, info, warn, error; `--log-level` sets the
threshold, default info, so routine mempool rejects (debug) stay hidden
unless asked for. Peer churn and block acceptance log at info, reorgs and
invalid input at warn, loop and miner failures at error. It is
dependency-free — two atomics for the level and the resolved color choice
— rather than pulling in a logging framework, matching the rest of the
codebase.

## 2026-09-12: Fixes from the internal security review

`docs/audit.md` reviewed the code and found seven issues. Three
were fixed immediately; the rest are tracked in `TODO.md`.

RC-01, side-chain block poisoning. The txid and transaction root exclude
proofs and signatures, and side-chain blocks were stored under their
header hash after only proof-of-work, root and checkpoint checks. A
corrupted body could therefore be stored under a valid hash and the real
body refused as already known. Alternatives: commit to authorization
data in the header (a consensus change and a fingerprint of nothing
useful), or allow a stored body to be replaced (keeps unverified data on
disk). Chosen: verify everything stateless, meaning structure, balances,
one signature batch and one proof batch, before storing a side-chain
block. Proof of work already gates the cost, and a side-chain block that
later wins a reorganization is simply verified twice.

RC-03, wallet nonce reuse. Note records were sealed under a nonce derived
from the record tag and tree position, and rewritten in place on spend
and rollback, so the same key and nonce encrypted different plaintexts.
Alternatives: a per-wallet counter stored atomically with each record
(deterministic, but threads mutable state through every write), or a
random nonce per seal. Chosen: a random 96-bit nonce from the operating
system stored ahead of each ciphertext, with the layout version, record
tag and position as associated data. Existing wallet files must be
recreated from their seed phrase; there are no mainnet wallets.

RC-07, height saturation. `saturating_add(1)` on the height let a block
at `u32::MAX` be followed by another at the same height. Chosen:
`consensus::next_height` returns `HeightExhausted` there, and validation,
storage and the miner all use it. Terminal behaviour is now defined as
refusal rather than silent index overwrite.

## 2026-09-12: Remaining review fixes: handshake bound, header pacing, address prefixes

RC-04. The inbound cap counted only peers past the Noise handshake, and
the handshake had no deadline. Chosen: a semaphore of 32 pending-inbound
slots acquired before `accept` and released when the handshake ends,
plus a ten-second handshake timeout in the transport. The alternative of
a single combined cap was rejected because handshaking and connected
peers have different costs and lifetimes; two small bounds are easier to
reason about than one shared budget.

RC-05. The header queue grew by one message per request with no global
bound. Chosen: the syncer paces header requests itself, one outstanding
at a time and only while the queue is under a low-water mark of two
messages, giving a hard cap of three messages (6,000 headers). Exceeding
the cap is misbehavior. The node's `sync_exhausted` flag moved into the
syncer so the pacing rule has every input in one place. Contextual
header checks before download were considered and deferred: they would
need the difficulty window for the peer's branch, and the ban on the
first invalid block already limits the damage.

RC-06. Every address was written `null1...` regardless of network.
Chosen: an `AddressPrefix` enum in the protocol crate (`coin` main,
`tcoin` test) carried in `ChainParams`, with encode and decode taking the
prefix explicitly. Commands with `--network` use it directly; commands
that talk to a node infer the network from the node's genesis hash rather
than taking another flag that could be set wrong. Binding the genesis
hash into the signature domain was not done: replay across networks
already fails on the anchor, and it would change the transaction format.

## 2026-09-13: Merkle depth 48 (RC-02)

The security review found that the depth-32 tree fills in about two
years at the maximum block load (512 transactions of 16 actions every
120 seconds), after which no block can be produced. Zcash has the same
2^32 limit per pool and no rollover rule; its answer would be a network
upgrade to a new pool, which partitions the anonymity set by pool.

Alternatives: keep depth 32 and rely on fees and a future upgrade, as
Zcash does; an epoch rollover to a fresh tree, which needs no circuit
change because nullifiers do not depend on tree position, but reveals
the epoch of every spent note through the anchor; a deeper tree.

Measured before choosing: depth 40 and 48 both overflow the 2 048 rows
of `K = 11` and both fit `K = 12`, and at `K = 12` they cost the same.
Proving is about 1.55 times slower than before (0.78 s against 0.48 s
for two actions, 4.8 s against 3.0 s for sixteen); verification and
block validation are unchanged in practice; proofs grow by 64 bytes.

Chosen: depth 48 at `K = 12`. The lifetime at full load exceeds 100,000
years, the whole pool stays one anonymity set, and the spare rows at
`K = 12` are headroom for later constraints. Positions widened to 64
bits throughout. A full tree remains a consensus failure (`TreeFull`
makes the block invalid), now unreachable rather than two years away.
The verifying key hash and the mainnet genesis hash are re-pinned; every
proof, chain database and wallet database from before is invalid, which
is acceptable before the public testnet and impossible after mainnet.

## 2026-09-13: Network upgrade mechanism

Until now there was no way to change consensus rules: the block and
transaction versions are single constants and nothing gated a rule on
height. The depth change above is exactly the kind of change that could
not have shipped after launch.

Alternatives: Bitcoin-style version bits with miner signalling, rejected
as a fingerprint in headers and needless coordination for a chain with
one implementation; Zcash's consensus branch id in the sighash with
activation by height, adopted; a branch field in each transaction,
rejected as a fingerprint and as redundant with the sighash binding.

Chosen: `ChainParams` gains a per-network `genesis_branch` and an
`upgrades` schedule of `(height, branch)`; `branch_at(height)` is the
single source of which rules apply. The branch is hashed into the
sighash and nowhere else, so an upgrade invalidates every transaction
signed for the old rules without any change to the transaction format,
and the two networks' different genesis branches make cross-network
replay fail at the signature rather than only at the anchor. The mempool
empties on the block before an activation; readmission after a
reorganization filters by branch. `docs/upgrades.md` is the procedure.

## 2026-09-14: Re-review fixes: rules digest, branch-aware mempool, side-chain header context

RC-08. A database built by a binary with another upgrade schedule or
circuit passed the genesis check and was trusted. Alternatives: rewind to
the earliest affected activation and revalidate, rejected because
frontiers are pruned beyond the reorganization depth so a rewind is not
generally possible; ignore, rejected because a future upgrade may change
monetary rules. Chosen: record a digest of genesis branch, schedule and
verifying key in the store and refuse to open a store recorded under
another digest, telling the operator to resync.

RC-09 and RC-11. The mempool emptied only when the block before an
activation was applied, which a reorganization to a lower tip never
does, and compact-block reconstruction pulled from the pool by txid
without regard to branch. Alternatives: capture the branch before every
import and compare after, which puts the burden on each caller; tag each
pool entry with its branch. Chosen: the pool records the one branch it is
verified for and re-derives the next block's branch from the store's tip
on every insert, readmit, select and applied block, emptying itself on
any difference. Compact blocks then need only a per-block check: the
pool is consulted only when the compact block's height is under the
pool's branch.

RC-10. Side-chain blocks were verified against their own declared target
rather than the expected one, with no limit, and the stateless path did
not check nullifier duplicates across transactions, so one Equihash
solution at a free target bought a full proof batch and a stored block.
Chosen: side-chain headers are validated exactly like main-chain headers
against a window of their own ancestry, found by following previous-hash
links rather than the height index, and block-wide nullifier uniqueness
moved ahead of signature and proof verification on both paths. Invalid
branch caching and side-chain storage caps were considered and deferred:
every stored side-chain block now carries real proof of work, which is
the bound that matters.

## 2026-09-14: Header lookback (RC-13) and legacy stores (RC-08 remainder)

RC-13. The validator read `max(difficulty_window, 11)` headers while the
difficulty rule needs `difficulty_window + 1` and the node's template
path correctly asked for that. On the test network the median span
covered the difference; on mainnet, with a window of 60, the validator
always fed the rule one header short and so always expected the easiest
target, which would have made every retargeted block from the bundled
miner invalid while custom miners stayed at the limit. Chosen: one
function, `validate::header_lookback`, used by the validator, the
template and the test harness, and an end-to-end test with a window
longer than the median span that mines through a retarget and rejects
the easiest target on both paths. The lesson recorded here: a derived
count that two components must agree on gets one definition, and the
test network must have at least one configuration where the dominant
term is the same as on mainnet.

RC-08 remainder. The digest was stamped onto any store without one,
including a store with history from a binary that recorded no rules.
Chosen: stamp only a store holding genesis alone; refuse the rest. The
alternative of trusting pre-digest stores once was rejected because the
whole point of the digest is that nothing decides which rules validated
old history except a record made at the time.

## 2026-09-14: JSON-RPC 2.0 over HTTP, transaction index, store layout version

Exchanges, pools and explorers integrate against JSON-RPC; nobody will
integrate against the line protocol. Alternatives: replace the line
protocol, rejected because the CLI and the sync tests use it and it is
the simpler thing to keep; an HTTP framework, rejected because the
existing minimal HTTP reader needed only bounded `POST` bodies, and a
framework would be the largest dependency in the tree; a separate RPC
process, rejected as needless. Chosen: a `jsonrpc` module in the node
that parses the envelope, checks a bearer token (the same token as the
control socket), and dispatches to the same `Request` enum, so both
interfaces have one behaviour. `serde` and `serde_json` are the first
non-cryptographic dependencies of any size; they are the standard.

The store gained a txid to `(height, index)` table because "is my
withdrawal confirmed" is the one question every exchange asks and the
chain had no way to answer it by id. With it came a layout version in
the meta table: a store written by earlier code is refused with a clear
message rather than opened with an empty index, and every future table
change bumps the version instead of migrating in place, since nothing
before launch is worth a migration.

## 2026-09-14: Mining pool interface

A pool cannot build a coinbase here: it is a shielded transaction with a
proof. Alternatives: hand the pool the proving key and a library and
let it build its own, rejected because it puts a 0.8 s proof and our
circuit code inside every pool's stack; a stratum server in the node,
rejected because pools run their own and want only a template source.
Chosen: `getblocktemplate(payout_address)` builds and proves the
coinbase in the node and returns the finished header fields plus the
exact proof-of-work input bytes, and `submitblock` takes back only what
the pool changed (timestamp, nonce, solution) by template id, or a full
block. Templates are cached per payout address for five seconds so a
polling pool costs one proof per five seconds, and kept for ten minutes
for submission. Long polling is implemented by checking the tip every
250 ms for up to a minute rather than by a channel from the loop; it is
simpler, the cost is nil, and it cannot miss a change. `--blocknotify`
covers pools built around a hook. The template path reuses the miner's
own assembly code, so the built-in miner and a pool produce identical
blocks for identical inputs.

## 2026-09-14: Wallet daemon

Exchanges need a long-running wallet with an RPC: deposit addresses,
deposit detection, withdrawals. Alternatives: build the wallet into the
node under a flag, as Bitcoin Core once did, rejected because the node is
public infrastructure and should hold no keys; a library only, leaving
the daemon to integrators, rejected because every integrator would write
the same fragile send loop. Chosen: `null-wallet-rpc`, a separate
process in the node crate that reuses the node's JSON-RPC transport
through a `Dispatch` trait, so both services have one envelope, one
token scheme and one error code table.

Sends are asynchronous operations persisted in the wallet file. Proving
takes seconds, an anchor expires after 100 blocks, and a node can lose a
pooled transaction, so the daemon owns the whole lifecycle: build, prove,
submit, resubmit every sync, confirm when the spend is seen, rebuild
when the anchor is stale, give up after five attempts. Notes chosen for a
pending operation are locked so a second send cannot pick them, which is
the double-spend protection an exchange expects from its own wallet.

The wallet database serializes writers and admits concurrent readers, so
the daemon shares the wallet without a mutex and proving never blocks a
balance query. Watch-only wallets come from an exported full viewing
key, encoded like an address with a network-specific prefix; they see
notes, memos and spends but hold no spending key, which is how deposit
hosts should run. Note records now carry the transaction that created
and the one that spent them, so a transaction can be viewed from the
wallet's side; a compact scan cannot know these and leaves them empty.

## 2026-09-14: Selective disclosure

Exchanges ask for two proofs in their first week: that a withdrawal
paid a customer, and that a customer controls a deposit address.

Payment disclosure reveals the transmission key and ephemeral secret of
one output, recovered by the sender from its outgoing viewing key; the
verifier decrypts and checks the result against the action's commitment
and ephemeral key, which the existing sender-side decryption already
did, now split into two halves. The alternative of a zero-knowledge
proof of payment was rejected as far more machinery for the same
statement; the disclosure reveals exactly one output's contents to the
party it is handed to, which is what a dispute needs.

Address ownership is proved by challenge: encrypt a message to the
address, the owner reads it back. The alternative, a signature by a key
tied to the address, was rejected because the only key tied to an
address is the incoming viewing key, a scalar for which no audited
signature scheme over the diversified base exists, and writing one
would break the rule against implementing primitives. The challenge
uses note encryption as is, works for watch-only wallets, and is what a
deposit host can answer.

## 2026-09-18: The network is Null; the name replaces `coin` everywhere

The project's placeholder name `coin` was in every identifier: crate
and module names, the binaries, environment variables, address and
viewing key prefixes, Prometheus metric names, deploy paths, and the
hash personalizations and hash-to-curve domains that consensus depends
on. Chosen: rename all of it to `null`, including the consensus-visible
strings, before anything ships. Leaving the old name inside domain
separators would have been invisible to users and puzzling to every
auditor. Because the name is the same length, every personalization
keeps its layout; because the hash-to-curve domains changed, the
circuit's fixed-base tables were regenerated and the verifying key,
mainnet genesis and pinned seed derivation were re-pinned. Every
database and wallet file from before is invalid, as with every
consensus change before launch. The generic word "coin" in prose,
`coinbase`, and the ZIP 32 coin type are not names and stay.

Ticker: `NULL`. Checked on CoinGecko on 2026-09-18: two micro-cap tokens
use it (market capitalizations of roughly $10,000 and $170,000, ranked
below 4,000), no major coin does, and `NUL` and `NLL` are unused. A
four-letter ticker matching the network name beats a three-letter
abbreviation nobody would recognize; if an exchange needs to
disambiguate, it will suffix as it does for every collision.

## 2026-09-18: Premine as a development fund

A development fund is needed and the chain has no transparent outputs
to pay it into. Alternatives: a founders' output in every coinbase for
some years, as Zcash did, rejected because on a shielded chain the
validator cannot see who a coinbase pays; enforcing it would need a
"validator-visible note" whose randomness is derived from the height,
which is a new consensus mechanism and marks one output of every
coinbase for years. A private mining period, rejected as unverifiable.
Chosen: a single coinbase transaction embedded in the genesis block that
pays the premine to the development fund address. Its binding signature
commits to exactly the premine, a test verifies the embedded bytes for
that balance, and the amount is a public constant, so the fund's size is
provable without revealing the note; after genesis the fund is notes
like any other. Nothing about later blocks changes.

Size: five percent of `MAX_MONEY`, carved out of the emission by
lowering the initial subsidy from 10 to 9.5 coins, so the cap and the
halving schedule are untouched. Both numbers are provisional, as the
whole schedule is. The mainnet transaction committed today pays a
placeholder address whose key was discarded, so a launch that forgot to
regenerate it would burn the premine rather than hand it to whoever
found a key in the repository; `nulld genesis-coinbase` regenerates it
for the real address, which changes the genesis hash. The test network's
premine pays a published key so anyone can fund a test wallet from it.
Custody of the fund is a key-management question the code does not
solve: there is no multisig, so split the fund across several notes to
separately held keys at generation time or soon after.


## 2026-09-21: Embedded native desktop scaffold

The desktop requirement is one OS process containing UI, node, wallet, and
RPC. Chosen: an egui/eframe executable with a Tokio runtime, embedding the
existing node and a transport-independent wallet service. Tauri/Electron
would add webview/renderer processes; a launcher for the existing daemons
would also miss the requirement. Native rendering keeps everything in Rust.

GUI and authenticated loopback RPC commands share one backend owner and one
wallet service/payment queue. The wallet uses the node event channel, reusing
the control codec to avoid duplicating synchronization logic. A typed local
API can replace that codec later. Wallet methods win name collisions; node
methods remain available through the `node.` prefix.

Wallet lock/shutdown waits for an active pass and its blocking prover to
finish before dropping wallet references. The node now owns its top-level
listener/miner/clock tasks. The desktop owns and drops the runtime on exit.
The existing separated node/wallet daemons remain the deployment option for
public infrastructure. The desktop deliberately relaxes their process
isolation: unlocked wallet keys share a process with the P2P node.

## 2026-09-22: Durable payment intent and reorganization recovery

A transaction and its input reservations are committed before the node can
receive its bytes. The existing `submitted` state now means durable intent
to broadcast; a missing reply cannot prove rejection. Retrying sends the
same bytes and uses the node's transaction index to discover confirmation.
The line control interface gains `txstatus`, reusing the existing node
request so compact-scanning wallets do not depend on full note txids.

New prover claims use a distinct `Building` disk tag, displayed as
`proving`. Interrupted new builds can safely resume. Reusing the legacy
tag was rejected: old code could broadcast and crash before saving any
transaction, making an automatic retry potentially pay twice. Those
legacy records instead require manual reconciliation, with an explicit
failure message. Existing operation records decode unchanged; a nonempty
transaction-history extension preserves earlier attempts. Older binaries
refuse these new records rather than silently forgetting their history.

Rollback reopens confirmations and reserves their inputs in the same
database transaction that rolls back notes. The worker also reconciles
all retained attempts before selecting inputs for new sends. Rebuilding
from unrelated notes was rejected because a later reorg could mine both
versions: replacement inputs must belong to every retained transaction.
An older version that gets mined becomes the active transaction. A failed
replacement never releases an earlier broadcast's reservations or declares
that payment failed; it remains pending even after the build retry limit.

The worker and rescan RPC share an async lock so witness trees cannot be
rolled back during proof construction. Conditional operation updates make
cancellation and the worker's claim mutually exclusive. Submission failure,
restart, rollback persistence, stale confirmations, and older-attempt
confirmation are covered by regression tests; a real-node test deliberately
loses an acceptance reply and reopens the wallet without creating another
payment.

## 2026-09-23: Automatic desktop storage and wallet onboarding

Ordinary desktop startup creates an OS-standard application data directory
and a TOML `null.conf`, with separate wallet and chain paths per network.
Missing wallets lead to a choice between generating a recovery phrase and
importing one; existing wallets lead to unlock. The backend owns the selected
wallet path, so GUI actions no longer ask the user to manage database files.
Passphrases and seed phrases never enter the configuration.

Saved settings are read without rewriting user comments. Command-line flags
override them for a launch and remain available for advanced recovery and
multiple instances. The first launch writes its initial effective settings.
Existing scaffold wallets in the old working-directory default are adopted
in place and remembered by absolute path; automatically moving a potentially
open database was rejected. New installations use the OS user data location
instead of depending on the directory from which the executable was started.
The native GUI, embedded node, wallet service, and authenticated RPC still
run in one process.

## 2026-09-24: Desktop design system

The desktop GUI moved from one file of ad-hoc egui calls to three layers:
design tokens (`theme`), components built from them (`widgets`), and one
module per screen. Screens return an `Effect` instead of holding the backend
client, so their state and validation are testable without a window and the
shell alone talks to the backend. Colors are checked against WCAG AA in
unit tests. Alternatives considered: a third-party egui theme crate, which
still leaves per-screen layout ad hoc and adds a dependency; and
following the system light/dark preference, which is deferred until a light
palette passes the same contrast tests. Fonts remain egui's bundled defaults
to avoid shipping font files.

## 2026-09-24: One per-user data directory for every binary

`nulld`, `null-wallet-rpc`, and the desktop app resolve storage through
`null_node::paths`: `%LOCALAPPDATA%\Null` on Windows, `~/Library/Application
Support/Null` on macOS, and the XDG data directory elsewhere, with a
directory per network. `nulld run` now defaults to `<network>/chain`, the
desktop's chain directory, instead of an in-memory chain. `--in-memory`
keeps the old behaviour. `null-wallet-rpc` defaults to the desktop wallet and
the default node token. A daemon run without flags used to lose the chain
and print its token to the log; now it keeps the chain and writes the token
to an owner-only file. Alternatives considered: separate directories per
binary, which would sync and store the chain twice; and the `dirs` crate,
which adds a dependency for three environment lookups we already test.
Existing explicit `--datadir` layouts are unchanged.

Daemons now stop gracefully on `SIGTERM` and on Windows console close,
logoff, and shutdown events, not only Ctrl-C. `--blocknotify` runs through
`cmd /C` on Windows. CI runs the full suite on Linux, macOS, and Windows.
Windows file privacy relies on inherited access lists rather than explicit
ACLs; hardening that needs a Windows ACL dependency and is tracked in TODO.

## 2026-09-25: Exact fee quotes and backup verification in the desktop

`estimatefee` prices by recipient count only, but a payment funded by many
small notes needs a larger action class and pays more. The new wallet
method `quotepayment` runs the same note selection as `build_payments`
(both go through one `plan` function), without proving, so the review
screen shows the exact fee for the wallet's current notes. Alternatives
considered: showing `estimatefee` as a minimum, which misleads exactly when
fees are highest; and building and proving at review time, which costs
seconds and would reserve notes the user may not send. A queued payment
still selects notes when it is built. If notes arrive or are reserved in
between, it may use different notes than quoted, and the docs say so.

Recovery phrase backup now asks for three randomly chosen words before
dismissing the phrase. Three words catch a skipped or reordered line
without making users retype all 24. The answers are compared in constant
time and live in zeroizing buffers. Idle auto-lock is a GUI concern
configured in `null.conf`. It never interrupts a running backend request
or the phrase backup.

## 2026-09-28: Saturating fallback in the difficulty rule

`next_target` computes `sum_targets * weighted / denominator`. When that
product overflows `U256`, it divides first. That fallback multiplied
unchecked. With every target at the test network's limit (about 2^255) and
solve times clamped high, it overflowed too, and `uint` panics on
overflow. Slow CI runners mining test blocks hit this. Mainnet's limit
(about 2^243) keeps the fallback under 2^246, so mainnet was not affected.

The fallback now saturates. This does not fork the rule: saturating and
exact multiplication agree whenever the product fits, and when it does not,
the exact value exceeds 2^256 and is clamped to the limit either way.
Only histories that used to crash a node now produce a target, the limit.
A regression test covers the slowest history on both networks, and a
property test over random histories and targets on both networks, which
found the same overflow independently, checks every result is in
`[1, limit]` and survives the compact roundtrip. Alternatives considered:
widening to `U512`, which is exact but adds a type for a case the clamp
already settles; and lowering the test network's limit, which changes its
genesis and every existing test chain.

## 2026-09-28: Per-connection version nonces; never redial ourselves

A seed node finds its own name in the seed list, dialed itself every five
seconds, detected the self-connection, and logged the disconnect each time.
Two changes stop that.

Before a direct dial, the node resolves the name itself and drops any
address equal to its bound listen address, or loopback on its port when it
listens on an unspecified address. A name that resolves only to us is not
dialed at all. Names reached through a proxy are resolved by the proxy and
skip this check.

Other routes back to us (a public address in front of an unspecified
listener, NAT, a proxy) still connect once. The version nonce was
node-wide, and the inbound half detected the match and closed, so the
outbound half could not tell its dial had been ourselves. Each connection
now uses its own random nonce. The node remembers its outbound nonces until
their handshakes finish, and an inbound version carrying one names exactly
which dial came back. That target, and its address, are then never dialed
again, with one log line. This is also a privacy fix: a node-wide nonce let
anyone seeing two of a node's connections, say one over Tor and one over
clearnet, link them. Alternative considered: marking any outbound peer still
handshaking when an inbound self-connection appears, which can blame the
wrong seed when several dials are in flight and would then never retry it.

## 2026-09-29: Coinbase maturity by delaying the note tree

Without maturity a miner could spend a reward in the next block, and a
reorganization that orphaned the block would erase that reward and every
payment built on it, downstream to people who cannot tell, since every
note is shielded. Transparent chains stop this by refusing spends of young
coinbase outputs (100 blocks in Bitcoin and Zcash).

A spend rule does not work here: a shielded spend does not reveal which
note it spends, so the circuit would have to prove the note is not a young
coinbase, which needs a coinbase flag in the note commitment (a
fingerprint) and a circuit change. Instead the coinbase outputs of block
`h` enter the commitment tree only while block `h + M - 1` is applied,
before that block's own outputs. A note is only spendable against a root
that contains it, so it is first spendable in block `h + M`. Nothing about
the note changes and the circuit is untouched; once in the tree a matured
reward is a note like any other. M is 100 on mainnet (about 3 h 20 min)
and 10 on test, so the test network and tests exercise the rule quickly.
Genesis is exempt so the premine and both genesis hashes are unchanged.

One function, `null_protocol::maturity::tree_transactions`, gives the
order for the validator, the miner's template, wallets, and compact
blocks, so they cannot disagree; with `M = 1` it is the old block order.
Whoever applies a block supplies the maturing coinbase: the validator and
miner from the stored main chain (blocks apply in order, so a
reorganization sees its own branch), full-block wallets through a new
`coinbase <height>` control command, and light wallets get compact blocks
already in tree order. Wallets keep no pending state, so rollback is
unchanged, and a mined reward appears in the wallet when it matures.

Alternatives considered: requiring every anchor to be M blocks old, which
enforces maturity without reordering but delays every spend of any fresh
note by M blocks; and a wallet-only policy, which protects honest wallets
but not recipients of a modified one. This is a consensus change: chains
built under the old order are invalid and must be restarted.

