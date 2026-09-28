# Threat model

What the system protects, against whom, and what it does not protect.
Written after an adversarial read of the circuit statement, the chain
validator, the mempool and the node loop on 2026-09-09. Update it when a
rule changes.

## Assets

1. **Supply integrity.** No value is created except by the subsidy rule.
2. **Ownership.** Only the holder of a spending key can spend a note.
3. **Privacy.** An observer of the chain, the network or a node's disk
   learns nothing about who paid whom how much, beyond what is stated in
   "what leaks" below.
4. **Availability.** A node keeps following the best chain under abuse.

## Adversaries

- A **chain observer** with every block and transaction ever published.
- A **network observer** who sees every packet, or runs many peers.
- A **malicious peer** who sends arbitrary protocol messages.
- A **malicious miner** who chooses block contents and timestamps.
- A **thief with a copy of a wallet file** or a node's data directory.
- **Not considered:** an adversary who breaks the discrete logarithm on
  Pallas, Poseidon, BLAKE2b, ChaCha20-Poly1305 or the Halo2 soundness
  argument; a compromised operating system; side channels on the proving
  machine.

## Supply integrity

Every action proves `cv_net = [v_old - v_new] V + [rcv] R` with both
values below `2^64`, and the binding signature proves the sum of all
`cv_net` in a transaction equals a commitment to the public balance. For a
regular transaction the balance is its fee; for the coinbase it is minus
the subsidy plus the block's fees. The validator recomputes both from the
action count and the height, so a coinbase cannot claim more, or less,
than the rule allows.

Consequences and residual risks:

- Total supply is bounded by the subsidy schedule plus the premine, which
  a test shows sum below `MAX_MONEY`. Amounts inside notes are parsed
  with the same cap. The premine is a coinbase embedded in genesis; its
  binding signature commits to exactly the premine value, and a test
  verifies the embedded transaction for that balance, so the amount the
  genesis block creates is public and provable even though the note
  itself is shielded.
- The circuit's soundness is the whole argument. A bug there means silent
  inflation that no external audit of the chain can detect, because there
  is no transparent pool. Mitigations: the statement is written down in
  `docs/circuit.md`, every constraint has a failing-witness test, the
  verifying key is pinned by hash, and an external audit is a launch
  requirement.
- A real note of value zero may be spent without a membership proof, by
  design, to allow dummy actions. It carries no value and its nullifier
  is recorded, so it cannot be reused.

## Ownership

Spending requires `pk_d_old = [ivk] g_d_old` with `ivk` derived from `ak`,
`nk` and `rivk` inside the circuit, and a RedPallas signature under
`rk = ak + [alpha] G` over the sighash. Negating `ak` keeps `ivk` but the
signer would need `-ask`, which it does not have.

Every signature binds the consensus branch id in force at the block's
height and the branch differs per network, so a transaction is valid
only under the rules it was signed for: neither side of a fork can
replay the other's transactions, and a test network transaction is never
valid on the main network (`docs/upgrades.md`).

Nullifiers are `Poseidon(nk, rho, psi, cm)`. `rho` and `psi` are bound by
the commitment, which is in the tree, so a note has exactly one nullifier.
Uniqueness of `rho` across the chain follows from `rho_new = nf_old` being
enforced in-circuit and every nullifier, dummies included, entering the
nullifier set. That closes the faerie-gold attack of sending a victim two
notes that share a nullifier.

## Privacy

What the chain reveals per transaction: the action count (2, 4, 8 or 16),
hence the fee; the anchor, which places the spend within the last 100
blocks; nothing else. Every field is uniform in size and shape.

What the network reveals: connection metadata. Transactions travel the
Dandelion++ stem before broadcast, sessions are encrypted with ephemeral
keys, and there is no user agent or service field. Tor is supported via
SOCKS5. Timing correlation by an observer of both the sender's and the
receiver's links is not addressed.

What scanning reveals: a wallet that trial-decrypts every action does
the same work for an action that is not its own as for one that is, on
a stand-in note, so the time spent per action does not tell an observer
of the wallet process which actions it owns. The equalization is of
work, not of branches; a recorded note still costs a small allocation.

What the disk reveals: the chain database holds only public data. The
wallet file holds the spending key and the wallet's notes under a
passphrase-derived key; without the passphrase it reveals the tree leaves
and scanned heights, which are public chain data, and nothing else.

Known malleability: the txid and the block's transaction root exclude
proofs and signatures. A relayer can therefore replace a proof with
another valid one without changing any hash. This cannot change what the
transaction does, and it is why txids are stable. It does mean a block
hash does not identify its authorization data, so a block must never be
recorded under its hash until its signatures and proofs have verified;
otherwise a corrupted body would shadow the authentic one (`docs/audit.md`,
RC-01).

## Availability

Rules a malicious peer runs into:

- Every list in a message has a fixed maximum and every frame a maximum
  size; oversized input ends the connection.
- Messages before the handshake, a wrong network, or a repeated handshake
  end the connection with a ban.
- Invalid blocks cost 100 misbehavior points, the ban threshold; invalid
  transactions 20; bad headers 20.
- Side-chain blocks are stored only after their header is checked
  against the block's own ancestry (height, timestamp, the target the
  difficulty rule expects, proof of work), the checkpoint and transaction
  root are verified, and the transactions pass structure, block-wide
  nullifier uniqueness, signatures and proofs, so storage cannot be
  filled with cheaply made blocks that have a known parent, and a
  corrupted body cannot occupy a valid block hash.
- A chain database records the rules it was built under; a binary with
  another upgrade schedule or circuit refuses it rather than trusting
  blocks validated under other rules.
- Reorganizations deeper than 200 blocks or below a checkpoint are refused.
- At most 32 inbound connections may be in the Noise handshake at once,
  each for at most ten seconds, so silent clients cannot hold sockets.
- Header sync requests one message at a time and only while fewer than
  4,000 headers await download, so a peer with a long chain of valid
  looking headers cannot grow the queue past 6,000.
- Inbound connections are capped; compact blocks awaiting transactions
  are capped and expire; the address book is capped and sanitizes
  timestamps; the mempool refuses when full.
- Proof verification of a transaction costs the receiving node a few
  milliseconds; an attacker can spend that at most five times before the
  ban.

Rules a malicious miner runs into:

- Timestamps must exceed the median of the last eleven and may not run
  more than two hours ahead; solve times are clamped in the difficulty
  rule, so one wild timestamp moves the target little.
- Coinbase credit is exact.
- A block conflicting with a checkpoint is rejected before storage.

The control socket, which can submit transactions and read the chain,
demands a per-node token on the first line of each session, compared in
constant time, and closes a session after three refusals. The token is
generated at startup and written owner-readable into the data directory,
or supplied by the operator. The socket still binds to localhost by
default: the token protects against other local users, not against
exposing the socket to the network, and a process that can read the
data directory can read the token as well as the chain.

Not addressed: eclipse attacks by an adversary who controls every peer
of a node; a majority of hashrate; resource exhaustion through many
inbound connections from many addresses beyond the cap.
