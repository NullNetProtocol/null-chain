# Protocol specification

The rules every node enforces and every byte on the wire or on the chain,
written from the code on 2026-09-09. Where this document and the code
disagree, the code is wrong. `docs/circuit.md` holds the zero-knowledge
statement; `docs/decisions.md` holds why things are the way they are.

Notation: `LE32`, `LE64` are little-endian integers; `||` is
concatenation; `BLAKE2b-256[p](x)` and `BLAKE2b-512[p](x)` are BLAKE2b
with the 16-byte personalization `p`; `Poseidon(a, b, ...)` is Poseidon
over the Pallas base field with the `P128Pow5T3` parameters and the
constant-length domain of its input count.

## 1. Curve, fields, encodings

The Pallas curve; `Fp` its base field, `Fq` its scalar field. Points,
base and scalar elements encode as 32 bytes, points compressed. Decoding
rejects any non-canonical encoding.

`ToBase(x)` reduces 64 uniform bytes into `Fp`; `ToScalar(x)` likewise
into `Fq`. `x mod r` maps an `Fp` element to `Fq` by its integer value.

Fixed generators: `V = HashToCurve("null:Generator", "value-commit-v")`;
`R` and `G_spend` are the RedPallas binding and spend authorization
basepoints of Zcash's Orchard, as the `reddsa` crate defines them.

Hash personalizations, each 16 bytes:

| Name | Personalization | Use |
|---|---|---|
| `PRF_EXPAND` | `null_ExpandSeed_` | key and note randomness derivation |
| `OVK` | `null_OvkDerive__` | outgoing viewing key |
| `DK` | `null_DkDerive___` | diversifier key |
| `NOTE_KDF` | `null_NoteEncKDF_` | note encryption key |
| `OCK` | `null_DeriveOck__` | outgoing cipher key |
| `ZIP32_MASTER` | `null_IP32Master_` | master key from seed |
| `TXID` | `null_TxIdHash___` | transaction id |
| `SIGHASH` | `null_TxSigHash__` | signature message |
| `BLOCK_HASH` | `null_BlockHash__` | block id |
| `TX_ROOT` | `null_TxRoot_____` | transaction root |

`PRF_expand(sk, t) = BLAKE2b-512[PRF_EXPAND](sk || t)`.

## 2. Keys

From a 32-byte spending key `sk`:

```
ask  = ToScalar(PRF_expand(sk, [0x06]))     non-zero
nk   = ToBase  (PRF_expand(sk, [0x07]))
rivk = ToBase  (PRF_expand(sk, [0x08]))
ak   = [ask] G_spend
ivk  = Poseidon(ak.x, nk, rivk) mod r         non-zero
ovk  = BLAKE2b-256[OVK](rivk || ak || nk)
dk   = BLAKE2b-256[DK] (rivk || ak || nk)
```

The full viewing key is `(ak, nk, rivk)`. A diversifier `d` is 11 bytes,
`d = FF1-AES256[dk](index)` for an 88-bit index; `g_d = HashToCurve
("null:DiversifiedBase", d)` must not be the identity; `pk_d = [ivk] g_d`.
An address is `d || pk_d` (43 bytes), shown as bech32m with human readable
part `coin` on the main network and `tcoin` on test networks; the bytes
are the same, and a decoder refuses the other network's prefix.

Hierarchical derivation, hardened only: master `I = BLAKE2b-512
[ZIP32_MASTER](seed)`, `sk = I[0..32]`, chain code `c = I[32..64]`; child
`I = PRF_expand(c_parent, [0x81] || sk_parent || LE32(i))`. Seeds are 32
to 252 bytes. Accounts live at `m / 32' / 1' / account'`.

## 3. Notes

A note is `(address, value, rho, rseed)`: value a `u64` no larger than
`MAX_MONEY`; `rho` an `Fp` element; `rseed` 32 bytes. From `rseed`:

```
esk = ToScalar(PRF_expand(rseed, [0x04] || rho))
rcm = ToBase  (PRF_expand(rseed, [0x05] || rho))
psi = ToBase  (PRF_expand(rseed, [0x09] || rho))
```

Commitment and nullifier, with `(x, y)` the affine coordinates of a
point and the identity as `(0, 0)`:

```
cm = Poseidon(g_d.x, g_d.y, pk_d.x, pk_d.y, value, rho, psi, rcm)
nf = Poseidon(nk, rho, psi, cm)
```

The note commitment tree has depth 48, leaves are `cm`, nodes are
`Poseidon(left, right)`, the empty leaf is 0. Its root is the anchor.
`2^48` leaves is over 100,000 years at the maximum block load.

## 4. Amounts and fees

One coin is `10^8` units; `MAX_MONEY` is `21,000,000` coins. The
genesis coinbase pays a premine of `1,050,000` coins (5%) to the
development fund; the block subsidy is 9.5 coins at height 1, halving
every 1,050,000 blocks, so emission plus premine sums to the cap. The
premine is the only value the genesis block creates, and `subsidy(0)`
is zero. A transaction's fee is `10,000` units per action. There is no
fee field: the fee is a function of the action count.

## 5. Value commitments and signatures

`cv = [v] V + [rcv] R` for a signed `v` and random `rcv`. Spend
authorization signatures are RedPallas under `rk = ak + [alpha] G_spend`
with randomizer `alpha`; the binding signature is RedPallas under
`bvk = sum(cv_net) - [balance] V`, whose secret is `sum(rcv)`. `balance`
is the fee for a regular transaction and minus the coinbase credit for a
coinbase (section 8).

## 6. Note encryption

```
epk    = [esk] g_d
shared = [esk] pk_d = [ivk] epk
key    = BLAKE2b-256[NOTE_KDF](shared || epk)
ct     = ChaCha20-Poly1305(key, nonce 0, plaintext)
```

Note plaintext is `0x02 || d || LE64(value) || rseed || memo` (564
bytes, memo 512 bytes); the ciphertext is 580 bytes. The outgoing
ciphertext encrypts `pk_d || esk` (64 bytes, ciphertext 80) under
`ock = BLAKE2b-256[OCK](ovk || cv || cm || epk)`, or under a random key
when the sender keeps no record. A receiver rejects a decrypted note
whose recomputed `cm` or `epk` differ from the action's.

## 7. Actions and transactions

An action carries one spend and one output:

```
nf (32) || rk (32) || cmx (32) || cv_net (32) || epk (32)
|| enc_ciphertext (580) || out_ciphertext (80) || spend_auth_sig (64)
```

884 bytes; the first 820 are the body. `cmx` is the created note's `cm`;
`cv_net` commits to `v_old - v_new`. The created note's `rho` equals the
spent note's `nf`. A dummy spend is a zero-valued note that is not in
the tree; a dummy output is a zero-valued note to a random address.

A transaction:

```
version (1) = 1 || anchor (32) || n_actions (1) || actions || proof || binding_sig (64)
```

`n_actions` is 2, 4, 8 or 16; the proof has the exact length for that
count: 8672, 14432, 25952 or 48992 bytes. A light client may instead
fetch compact blocks, which carry per action the nullifier, the note
commitment, the ephemeral key and the leading 52 bytes of the note
ciphertext, enough to detect notes and rebuild the commitment tree
without the memo. There is no locktime, expiry,
fee, or length prefix on the proof.

```
effecting = version || anchor || n_actions || action bodies
txid      = BLAKE2b-256[TXID](effecting)
sighash   = BLAKE2b-256[SIGHASH](effecting || LE32(branch id))
```

Every spend authorization signature and the binding signature sign the
sighash. Proof and signatures are excluded from the txid. The branch id
names the consensus rules in force at the block's height (see
`docs/upgrades.md`); it is not encoded in the transaction, so a
transaction is valid only under the rules it was signed for, and never
on another network.

The proof is one Halo2 proof over `n_actions` instances of the action
circuit with public inputs `(anchor, nf, rk.x, rk.y, cmx, cv_net.x,
cv_net.y)` per action.

## 8. Transaction validity

Stateless: version 1; an allowed action count; the exact proof length;
no nullifier repeated within the transaction; every spend authorization
signature valid under its `rk`; the binding signature valid under `bvk`
computed with the transaction's balance; the proof valid.

Stateful, against the chain: the anchor equals the commitment root of a
main-chain block at most 100 blocks below the tip; no nullifier already
in the nullifier set, and none repeated within the block.

The first transaction of a block is the coinbase. Its balance is minus
`subsidy(height) + sum of the other transactions' fees`, exactly. Every
other transaction's balance is its fee. The coinbase pays no fee.

## 9. Blocks

Header, 245 bytes:

```
version (1) = 1 || prev_hash (32) || LE32(height) || LE64(timestamp)
|| commitment_root (32) || tx_root (32) || LE32(target) || nonce (32)
|| solution (100)
```

`block_hash = BLAKE2b-256[BLOCK_HASH](header)`; `tx_root =
BLAKE2b-256[TX_ROOT](txid_1 || txid_2 || ...)`; `commitment_root` is the
tree root after appending every `cmx` of the block in order, coinbase
first. A block is the header, `LE32(count)`, then the transactions; at
most 512 transactions.

Genesis has height 0, previous hash zero, the limit target, no proof of
work, and one transaction: the coinbase paying the premine, a coinbase
like any other except that its balance is the premine rather than a
subsidy. Its commitment root is the tree after that transaction's
outputs. It is fixed by hash and not validated at runtime; the embedded
transaction is verified by a test, so every build agrees on it.

## 10. Proof of work

Equihash `(n, k) = (144, 5)` with BLAKE2b personalization
`nullPoW_ || LE32(n) || LE32(k)`, input `header without nonce and
solution`, and the 32-byte nonce. The solution is the minimal encoding of
32 indices of 25 bits each, 100 bytes. Hash generation, the collision
tree rules and the encoding follow Zcash exactly.

The target is Bitcoin's compact form. The block hash read big-endian
must not exceed the target. Work is `2^256 / (target + 1)`; the best
chain has the most summed work.

Difficulty: the target for a block is
`avg_target * sum(i * solve_i) / (T * N * (N + 1) / 2)` over the last
`N = 60` solve times with `T = 120` seconds, each solve time clamped to
`[1, 6T]`, the result rounded to compact form and capped at the limit.
Fewer than `N + 1` headers yield the limit.

## 11. Block validity

Version 1; extends the tip; matches any checkpoint at its height; the
timestamp exceeds the median of the last eleven and is at most two hours
ahead of the validator's clock; the target equals the difficulty rule's
output; valid proof of work; `tx_root` matches; one to 512 transactions;
every transaction valid per section 8 with the coinbase rule; the header's
`commitment_root` equals the tree after the block.

Nodes refuse reorganizations that revert a checkpoint or exceed 200
blocks.

## 12. Network protocol

Transport: TCP, Noise `NN_25519_ChaChaPoly_BLAKE2b` with fresh ephemeral
keys per connection. Handshake messages are prefixed by `LE16(length)`.
After the handshake, the stream is split into Noise frames of at most
65535 bytes, each `LE16(length) || ciphertext`; the decrypted stream
carries messages as `LE32(length) || tag (1) || payload`, at most 40 MiB.

Messages, by tag:

| Tag | Message | Payload |
|---|---|---|
| 1 | Version | `LE32(1) || LE64(nonce) || LE32(best_height) || genesis (32) || LE64(time)` |
| 2 | Verack | empty |
| 3 | Ping | `LE64(nonce)` |
| 4 | Pong | `LE64(nonce)` |
| 5 | GetAddr | empty |
| 6 | Addr | `LE32(n) || n * (ip (16) || LE16(port) || LE64(last_seen))`, n <= 1000 |
| 7 | GetHeaders | `LE32(n) || n * hash || stop (32)`, n <= 64 |
| 8 | Headers | `LE32(n) || n * header`, n <= 2000 |
| 9 | Inv | `LE32(n) || n * (kind (1) || hash)`, kind 0 block, 1 transaction, n <= 50000 |
| 10 | GetData | as Inv |
| 11 | NotFound | as Inv |
| 12 | Block | a block |
| 13 | Tx | a transaction, fluff phase |
| 14 | StemTx | a transaction, stem phase |
| 15 | CompactBlock | `header || coinbase || LE32(n) || n * txid`, n <= 512 |
| 16 | GetBlockTxn | `hash || LE32(n) || n * LE32(index)` |
| 17 | BlockTxn | `hash || LE32(n) || n * transaction` |

Handshake: each side sends Version then Verack; nothing else is accepted
before both. A peer with another protocol version, another genesis, or
our own nonce is dropped. Peers ping after 60 idle seconds and drop after
120 unanswered.

Synchronization: a node behind its peer sends GetHeaders with a locator
(its last ten hashes, then doubling steps, then genesis); the peer answers
from the first locator hash on its main chain, up to 2000 headers; the
node requests the bodies with GetData, sixteen in flight. New blocks are
relayed as CompactBlock; missing transactions are fetched with
GetBlockTxn by index into the block's transaction list.

Transaction relay follows Dandelion++: a node's own transactions and
transactions received as StemTx go to one epoch-fixed successor as StemTx
with probability 0.9, else are announced to all peers as Inv; a stem
transaction not seen announced within 10 to 30 seconds is announced by
the node that holds it. Epochs last 10 minutes.
