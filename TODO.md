# TODO

Roadmap for the shielded-only privacy coin. Phases are ordered by
dependency. Within a phase, items are ordered by what unblocks the most.
Tick an item only when it has tests and passes clippy.

## Phase 0: Repository and tooling

- [x] Cargo workspace with one crate per layer
- [x] Workspace-level lints (`unsafe_code = forbid`, clippy pedantic, `missing_docs`)
- [x] `CLAUDE.md` with engineering rules
- [x] `rustfmt.toml`, `.gitignore`
- [x] CI workflow: fmt, clippy `-D warnings`, test, doc
- [x] `docs/decisions.md` with the initial design decisions
- [x] `docs/protocol.md` protocol specification, written from the code and to be kept ahead of it from here on

## Phase 1: Cryptographic foundations (`crates/crypto`)

- [x] Domain-separated BLAKE2b helpers (`prf_expand`, `hash_to_base`, `hash_to_scalar`)
- [x] Canonical encoding helpers for Pallas base, scalar and points
- [x] Key hierarchy: spending key -> spend authorizing key, nullifier key,
      commitment randomness key -> full viewing key -> incoming viewing key
- [x] Diversifiers and diversified base / transmission key derivation
- [x] Pedersen value commitments with homomorphism tests
- [x] Note commitment over Poseidon with a base-field trapdoor
- [x] Zeroize and constant-time equality on all secret types
- [x] Outgoing viewing key derivation
- [x] Diversifier index encryption (FF1-AES as in ZIP 32) so wallets can enumerate addresses
- [x] Hierarchical key derivation from a seed (ZIP 32 style), hardened only, `m/32'/1'/account'`
- [x] RedPallas spend authorization signatures with batch verification (via `reddsa`)
- [x] Binding signature over the value commitment sum
- [x] Note encryption: ephemeral key agreement, KDF, AEAD (ChaCha20-Poly1305)
- [x] Outgoing ciphertext so the sender can recover its own outputs
- [x] Poseidon hash for note commitments, Merkle tree, nullifier PRF and ivk commitment (`halo2_poseidon`, distinct input lengths)
- [x] Merkle path, empty roots and a naive full tree in `crypto::merkle`
- [ ] Benchmarks with `criterion` for every primitive

## Phase 2: Protocol types (`crates/protocol`)

- [x] `Amount` with `MAX_MONEY`, checked arithmetic, signed `ValueSum`
- [x] `Address` (diversifier + transmission key), raw and bech32m encoding
- [x] `Note` with `rho`, random seed, commitment and nullifier derivation
- [x] `Nullifier` newtype and encoding
- [x] `Reader`/`Writer` byte cursor helpers for canonical layouts
- [x] Note plaintext layout, `EncryptedNote`, trial decryption with `ivk` and `ovk`
- [x] `Action` (one spend + one output): nullifier, rk, cmx, ephemeral key, ciphertexts, cv_net
- [x] Fixed action-count classes (2, 4, 8, 16), dummy action padding and shuffling in `builder`
- [x] `FEE_PER_ACTION` consensus constant; fee derived from action count, no fee field
- [x] Transaction format: single version byte, anchor, actions, proof, binding signature, no locktime/expiry
- [x] Canonical transaction serialization, `txid` and `sighash` over effecting data only
- [x] Stateless validation rules (version, action class, duplicate nullifiers, batch signature check with computed fee)
- [x] Consensus constants: block interval (120 s), subsidy schedule (10 coins halving every 1,050,000 blocks), max transactions per block. All provisional.
- [x] Coinbase: shielded only, built by `Builder::build_coinbase`, negative value balance = subsidy + fees
- [x] `protocol::transaction` carries the real `Proof`; exact length per action class is a consensus rule, no length prefix
- [x] Builder takes a `MerklePath` per spend, builds circuit witnesses and proves every action in one proof
- [x] Stateless validation verifies the proof (single or batched) after structure and signatures
- [ ] Builder takes `ask` + `fvk` instead of the raw spending key, for hardware wallets
- [x] Memo field: fixed 512 bytes, encrypted, always present

## Phase 3: Circuit (`crates/circuit`)

- [x] Write `docs/circuit.md` first: statement, public inputs, witnesses
- [x] Layer 1 (`gadgets::note`, `gadgets::merkle`): note commitment integrity, membership-or-dummy, nullifier, rho chaining
- [x] Layer 2 (`gadgets::ecc`, `action`): spend authority `pk_d = [ivk] g_d`, `rk = ak + [alpha] G`, `cv_net` balance, non-identity checks, variable-base multiplication with constant bases
- [x] Fixed-base window tables for `G_spend`, `V`, `R` (`circuit::constants`, generated, checked against the generators); frees about 3 000 ECC rows, `K` stays 11 because Poseidon dominates
- [x] Layer 3 (`gadgets::range`): 64-bit range checks on both values via the 10-bit lookup
- [x] `ActionCircuit` with the seven-row public input layout, K = 12 (K = 11 until the depth-48 change of 2026-09-13)
- [x] Poseidon chip configuration (reuse `halo2_gadgets`)
- [x] Merkle tree depth decision (32, raised to 48 on 2026-09-13)
- [x] Merkle path gadget over the Poseidon chip
- [x] `MockProver` tests for every layer 1 and 2 constraint (positive and negative)
- [x] `MockProver` tests for layer 3
- [x] Proving and verifying keys generated deterministically at startup; verifying key hash pinned by test
- [x] One proof per bundle over N actions (`proof::Proof`)
- [x] Batch verifier across transactions (`proof::ProofBatch`)
- [x] Proof size and timing per action class in `docs/perf.md`
- [ ] Membership proof behind a trait so an alternative backend can be added later

## Phase 4: Chain and storage (`crates/chain`, `crates/storage`)

- [x] Block header (`protocol::block`): version, prev hash, height, timestamp, commitment root, tx root, target, nonce, fixed-size PoW solution
- [x] `EquihashPow` in `chain::pow`: header check (solution, padding, target) and mining loop
- [x] Own Equihash verifier and pure Rust Wagner solver with chain personalization, cross-checked against the `equihash` crate
- [x] Benchmark candidate `(n, k)` sets; mainnet is `(144, 5)`, see `docs/perf.md` and `docs/decisions.md`
- [x] Equihash solver in pure Rust (Wagner's algorithm, sort and pair), CPU
- [x] Solver with flat tables, counting sort and parent references (2.1 GB, 15 s single-thread at mainnet parameters)
- [x] Solver tables repacked: 144,5 peaks at 1.80 GB, near the 1.5 GB floor of known solvers for collision width 24
- [x] Solver and verifier cross-tests against the `equihash` crate under Zcash personalization for `(96, 5)`
- [x] Difficulty adjustment (LWMA), compact-normalized, clamped solve times; overflow-free for any history on both networks, property-tested (2026-09-28)
- [x] Storage backend on `redb`: blocks, height index, nullifier set, per-height frontier, tip; atomic apply and revert
- [x] Nullifier set as a `redb` B-tree table (point lookups)
- [x] Nullifier lookups measured at 0.66 us each at one million entries; no bloom filter needed
- [x] Incremental commitment tree (frontier only) using `incrementalmerkletree`, root checked against the naive tree
- [x] Stateful block validation: version, prev/height, median-time and future timestamp, target, PoW, tx root, structure, recent anchors, nullifier freshness, batched signatures and proofs, commitment root
- [x] Coinbase: first transaction, no spends, outputs equal subsidy plus fees, negative public balance
- [x] Proofs and signatures are verified in one batch each per block; Halo2's batch verifier is multi-threaded through its `multicore` feature
- [x] Reorg handling and chain selection by cumulative work, with rollback on an invalid branch
- [x] Checkpoints per network (list empty until launch), reorganizations refused below a checkpoint or deeper than `max_reorg_depth`, frontiers pruned beyond that depth
- [x] Mempool: arrival-order queue, refuses when full, nullifier conflicts against chain and pool, stale-anchor pruning on selection, eviction on applied blocks, readmission after reverts

## Phase 5: Networking (`crates/p2p`)

- [x] Wire protocol: fixed message set with bounded lists, length-prefixed framing, version handshake, Noise NN encrypted transport chunked for large messages
- [x] Address book: bounded, timestamp-sanitized gossip, bans, failure-aware candidates
- [x] Peer state: handshake, keepalive, misbehavior score to ban
- [x] Seed list per network, `--seed`, hostnames resolved at dial time; main network seeds `seed1`–`seed5.nullnet.sh:19000` (2026-09-28)
- [x] Never redial ourselves: skip seed names resolving to our listen address; per-connection version nonces identify other routes back to us (2026-09-28)
- [x] Peer discovery bootstraps: dialed peers enter the address book and are gossiped, so a node reaches peers it was never configured with (self-advertising the listen address is future work)
- [x] Headers-first sync state machine: locator, chained header acceptance, bounded in-flight block requests with timeouts
- [x] Dandelion++ routing state: epochs, stem map, fluff probability, embargo timers
- [x] `--proxy` routes every outbound connection through SOCKS5, which reaches `.onion` peers via Tor; no feature flag needed
- [x] I2P via the SAM v3 bridge: `--i2p <sam addr>` opens one transient session and streams to `.i2p` peers, as `--proxy` reaches `.onion` peers (`node::i2p`)
- [x] Compact block relay: header, coinbase and txids, missing transactions fetched with `GetBlockTxn`
- [x] Property tests over the decoder and framer in `crates/p2p/tests`; `cargo-fuzz` target in `fuzz/`

## Phase 6: Wallet (`crates/wallet`)

- [x] Seed phrase (BIP 39, 24 English words, empty passphrase, account `m/32'/1'/n'`) on top of the existing ZIP 32 derivation; `nulld create` prints or restores it (`wallet::seed`)
- [x] Trial decryption scanner producing owned notes with tree witnesses (`wallet::scan`)
- [x] Scanner does the success path's work on a stand-in note for every action that is not ours, so per-action cost does not reveal ownership (work-equalized, not branch-free)
- [x] Persistent wallet on `redb`: witness tree, owned notes with spent status, scanned heights, reorg rollback, witnesses (`wallet::wallet`)
- [x] Sharded witness tree (`shardtree` over redb, depth 48, shard height 16, one checkpoint per block, 256 retained) instead of storing every leaf (`wallet::tree`)
- [x] Payment builder: largest-first note selection, change, computed fee (`wallet::spend`)
- [x] Light client: node serves compact blocks (`compact <height>`), wallet detects notes from the ciphertext lead and maintains the same witness tree (`wallet::scan_compact`); `nulld balance`/`send --light`. Fuzzy message detection is future work
- [x] Encrypted spending key at rest: Argon2id passphrase derivation, ChaCha20-Poly1305, `nulld create`
- [x] Note records encrypted under the file key; the witness tree and heights stay in the clear as public chain data
- [x] CLI: `nulld keygen`, `address`, `balance`, `send` over the control socket

## Phase 7: Node (`crates/node`)

- [x] Node event loop wiring transport, peers, sync, Dandelion, Chain and Mempool together
- [x] Configuration: network, data directory, listen, connect, mine, rpc
- [x] Line-oriented control socket on localhost: status, block, submit, spent
- [x] Control socket authenticated by a per-node token (`auth <token>` first line, constant-time compare, three refusals close the session; token generated into `rpc.token` or given with `--rpc-token`)
- [x] Metrics endpoint: `--metrics <addr>` serves Prometheus text at `/metrics`; status line and metrics count blocks mined against blocks in the main chain
- [x] Miner task: templates from the loop, coinbase proving and Equihash off the runtime
- [x] Ctrl-C shutdown
- [x] Crash recovery tests: a failed store apply leaves no partial state; a node resumes its chain after a restart

## Phase 8: Hardening and launch

- [x] Threat model document (`docs/threat-model.md`), with three hardening fixes from the review: side-chain blocks checked for proof of work and shape before storage, inbound cap, pending compact block cap
- [x] Internal security review (`docs/audit.md`, 2026-09-12): seven findings, six fixed the same day
  - [x] RC-01: side-chain blocks pass the stateless checks (structure, balances, signatures, proofs) before storage, so a corrupted body cannot be stored under a valid header hash
  - [x] RC-02: Merkle depth 48 at `K = 12` (measured: depth 40 and 48 cost the same, about 1.55× the proving time of depth 32); positions are 64-bit; verifying key and genesis re-pinned
  - [x] RC-03: wallet records sealed under a fresh random nonce with version, tag and position as associated data
  - [x] RC-04: 32 pending-inbound slots held through the handshake and a ten-second handshake deadline
  - [x] RC-05: header requests paced one at a time below a low-water mark, queue capped at 6,000 headers
  - [x] RC-06: `coin` and `tcoin` address prefixes, chosen by chain parameter; wallet commands infer the network from the node's genesis
  - [x] Signature domain bound to the network: each network has its own genesis branch id in every sighash (done by the upgrade mechanism)
- [x] Network upgrade mechanism (`docs/upgrades.md`): per-network upgrade schedule in `ChainParams`, `branch_at(height)` gates rules, branch id bound into the sighash, mempool empties at activation, tests in `crates/chain/tests`
- [x] Second re-review of 2026-09-14 (`docs/audit.md` RC-13, RC-08 remainder): one shared header lookback (`validate::header_lookback`) for validation and templates, fixing the mainnet off-by-one that made validators always expect the easiest target; a store with history but no rules digest is refused
- [x] Re-review of 2026-09-14 (`docs/audit.md` RC-08 to RC-12), all fixed the same day: store refuses a database built under other rules or circuit; mempool tracks the branch it was verified for and empties on any change of the next block's branch; side-chain blocks pass header context (height, timestamp, expected target, proof of work) and block-wide nullifier checks before storage; compact blocks use the pool only on the pool's branch; stale depth and `K` mentions corrected
  - [x] RC-07: `consensus::next_height` refuses height `u32::MAX` instead of saturating
- [ ] External audit of `crates/circuit` and `crates/crypto`
- [x] Premine as a development fund: 5% of `MAX_MONEY` paid by a coinbase embedded in genesis, subsidy lowered to 9.5 so the cap holds; `nulld genesis-coinbase` regenerates it (2026-09-18)
- [ ] Before launch: regenerate the mainnet genesis coinbase with the real development fund address (the committed one pays a discarded key) and re-pin the genesis hash
- [ ] Exchange and mining pool integration (`docs/rpc.md` is the plan)
  - [x] Phase 0: JSON-RPC 2.0 over HTTP on `--rpc-http`, bearer token, same dispatcher as the line protocol; txid to (height, index) table in the store with a layout version; HTTP integration test harness (`crates/node/tests/rpc.rs`)
  - [x] Phase 1: node methods (chain info, blocks at three verbosities, transactions by id and status, submission, mempool, nullifier status, compact blocks, peers, network, uptime, stop, help)
  - [x] Phase 2: `getblocktemplate` with node-built and proved coinbase per payout address (cached 5 s, valid 10 min), `submitblock` by template id or full block, long poll on `longpollid`, `--blocknotify`, `getmininginfo` with a work-per-second estimate; `pow_input` layout documented (`crates/node/tests/mining.rs`)
  - [x] Phase 3: `null-wallet-rpc` daemon (`crates/node/src/walletd.rs`): diversified deposit addresses with labels, watch-only wallets from an exported viewing key (`nulld export-viewing-key`, `nulld create --viewing-key`), `listreceived`/`gettransaction` with per-note txids, asynchronous `sendmany` with persisted operations that lock notes and rebuild on anchor expiry (`crates/node/tests/walletd.rs`)
  - [x] Payment recovery: resume interrupted builds; save transactions and reservations before broadcast; retain pending state on uncertain submission; atomically reopen reorged confirmations; reconcile all retained attempts, including compact scans; serialize rescans and prevent cancellation races (2026-09-22)
  - [x] Integration guides: `docs/guide-exchange.md`, `docs/guide-pool.md`
  - [x] Phase 4: payment disclosure (`getpaymentdisclosure` in the daemon, `verifypaymentdisclosure` in the node) and address ownership by challenge (`createchallenge` in the node, `answerchallenge` in the daemon), `crates/protocol/src/disclosure.rs`
- [x] Local testnet (see README)
- [x] Faucet command, Dockerfile, systemd unit and Tor configuration in `deploy/`
- [ ] Run nulld on the five seed hosts and publish DNS for `seed1`–`seed5.nullnet.sh`
- [ ] Public testnet: run seed nodes and the faucet on public hosts and fill the test seed list
- [x] Reproducible build recipe: pinned toolchain image, `--locked`, fixed `SOURCE_DATE_EPOCH`; compare digests across builders before release
- [x] Supply integrity: exact coinbase credit and single value-creating transaction per block are tested at block level; emission sum tested under the cap;
      document that a fully shielded pool cannot be externally audited

## Desktop wallet (`crates/desktop`)

- [x] Native egui/eframe scaffold embedding node, wallet service, and local authenticated RPC in one process
- [x] Socket-free embedded wallet/node connection alongside the existing remote daemon transport
- [x] Create/restore/unlock/lock, balance, receiving addresses, confirmed send form, activity, node status
- [x] Shared GUI/RPC wallet ownership; drain wallet work before lock/shutdown; own node listener tasks
- [x] Automatic OS-standard data directories and `null.conf`; first-run create/import onboarding and automatic existing-wallet detection (2026-09-23)
- [x] Design system: theme tokens with contrast tests, shared widgets, one module per screen returning effects (2026-09-24)
- [x] Receive QR codes, exact fee quote (`quotepayment`) before confirming, idle auto-lock (`lock_after_minutes`), three-word recovery phrase check, cancel queued payments, received memos (2026-09-25)
- [x] NULL brand: website palette (black and terminal green), vector logo and nav icons, window icon, Linux desktop entry (2026-09-28)
- [x] Desktop mining: switch and thread slider on the Node page, main (index 0) address payout, needs an unlocked wallet, stops on lock, saved in `null.conf`; runtime start/stop in `null_node::miner` (2026-09-28)
- [x] Mining stops within one solve and never blocks the GUI; Linux app installs its own desktop entry so Wayland taskbars show the brand icon (2026-09-28)
- [ ] Transaction detail view (`gettransaction`), file pickers, viewing-key export and rescan from the GUI
- [ ] Pagination, push-driven UI updates, accessibility, native platform tests and signed packages
- [ ] Desktop security review, including toolkit copies of secrets and shared node/wallet process

## Cross-platform

- [x] Shared per-user data directory for `nulld`, `null-wallet-rpc`, and desktop on Linux, macOS, and Windows; `nulld run --in-memory` (2026-09-24)
- [x] Graceful stop on SIGTERM and Windows console events; `--blocknotify` through the platform shell; CI on all three OSes (2026-09-24)
- [ ] Explicit owner-only ACLs for token, config, and wallet files on Windows (currently inherited from the profile directory)
- [ ] Default `--wallet` and node token for the remaining `nulld` wallet subcommands (`create`, `balance`, `send`, `faucet`, ...)
- [ ] Windows service and macOS launchd examples alongside the systemd unit in `deploy/`

## Open questions

- Equihash `(n, k)` parameters: to be chosen by benchmark, see Phase 4. `POW_SOLUTION_LEN` is provisionally sized for `(192, 7)`.
