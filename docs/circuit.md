# The action circuit

One proof per transaction covers every action. Each action proves the
statement below. Written before the code, per `CLAUDE.md`.

## Hash functions

All in-circuit hashing is Poseidon over the Pallas base field with the
`P128Pow5T3` parameters (width 3, rate 2, 8 full rounds, 56 partial). The
`halo2_poseidon` constant-length domain puts the input length into the
capacity element, so every use below has a distinct input length and is
therefore domain separated without extra inputs. **Input lengths must stay
distinct**; a test enforces it.

| Use | Inputs | Output |
|---|---|---|
| Merkle node | `(left, right)` | node |
| Incoming viewing key | `(ak.x, nk, rivk)` | `ivk` as base, reduced mod `r` |
| Nullifier | `(nk, rho, psi, cm)` | `nf` |
| Note commitment | `(g_d.x, g_d.y, pk_d.x, pk_d.y, value, rho, psi, rcm)` | `cm` |

Both coordinates of each point are hashed. Hashing `x` plus a sign bit
would save one permutation per commitment but proving the sign bit
in-circuit needs a 254-bit range check, which costs far more. The identity
has no affine coordinates and encodes as `(0, 0)`, the same representation
the ECC chip uses; both `g_d` and `pk_d` are rejected as identity outside
the circuit and constrained non-identity inside it.

The note commitment is a field element. `cmx` is the same value; the name
survives from the design where `cm` was a curve point.

## Merkle tree

Depth 48, leaves are note commitments, nodes are `Poseidon(left, right)`.
An empty leaf is the constant 0. Leaf and node hashes have different
input lengths (8 and 2), so a leaf cannot be confused with a node.

## Statement of one action

Public inputs, in this order:

1. `anchor`: the tree root the spent note is a member of
2. `nf_old`: nullifier of the spent note
3. `rk`: randomized spend verification key, as `(x, y)`
4. `cmx_new`: commitment of the created note
5. `cv_net`: commitment to `v_old - v_new`, as `(x, y)`

Private witnesses:

- spent note: `g_d_old, pk_d_old, v_old, rho_old, psi_old, rcm_old`
- its Merkle path: `position` (48 bits of a 64-bit value) and 48 siblings
- spend authority: `ak` (as a point), `nk`, `rivk`, `alpha`
- created note: `g_d_new, pk_d_new, v_new, rho_new, psi_new, rcm_new`
- `rcv`

Constraints:

1. **Old note integrity.** `cm_old = NoteCommit(g_d_old, pk_d_old, v_old, rho_old, psi_old, rcm_old)`.
2. **Membership or dummy.** Compute `root` from `cm_old`, `position` and the
   siblings. Require `root = anchor` **or** `v_old = 0`. A dummy spend is a
   zero-valued note that is not in the tree.
3. **Nullifier.** `nf_old = Poseidon(nk, rho_old, psi_old, cm_old)`.
4. **Spend authority.** `ivk = Poseidon(ak.x, nk, rivk) mod r` and
   `pk_d_old = [ivk] g_d_old`. This ties the spender's `nk` to the note's
   recipient key, so only the owner can derive the nullifier. `ivk != 0`
   follows because `pk_d_old` is constrained non-identity.
5. **Randomized key.** `rk = ak + [alpha] G_spend`.
6. **New note integrity.** `cmx_new = NoteCommit(g_d_new, pk_d_new, v_new, rho_new, psi_new, rcm_new)`.
7. **Uniqueness chaining.** `rho_new = nf_old`.
8. **Ranges.** `v_old < 2^64` and `v_new < 2^64`.
9. **Value commitment.** `cv_net = [v_old - v_new] V + [rcv] R`. The
   difference is witnessed as a magnitude and a sign with a gate
   `v_old - v_new = magnitude * sign`; the fixed-base short multiplication
   range-checks the magnitude to 64 bits and the sign to `1` or `-1`, so no
   negation or signed scalar is needed.
10. **Non-identity.** `g_d_old`, `g_d_new`, `pk_d_old`, `pk_d_new`, `ak` are
    not the identity.

What the circuit does not prove, and where it is enforced instead:

- Nullifier freshness: chain state (Phase 4).
- Anchor validity: chain state.
- Balance across actions: the binding signature over `sum(cv_net)`.
- Spend authorization: the RedPallas signature under `rk`.
- Correct encryption of the new note: nothing. A sender who encrypts
  garbage only burns their own funds.

## Implementation plan

The circuit is built in three layers, each with `MockProver` tests that
include a failing witness per constraint:

1. Poseidon-only layer: constraints 1, 2, 3, 6, 7 and the Merkle gadget.
2. ECC layer: constraints 4, 5, 9, 10 using the `halo2_gadgets` ECC chip.
   `[ivk] g_d` uses the variable-base gadget. `G_spend` and `R` use
   full-width fixed-base window tables and `V` a signed 64-bit one; the
   tables live in `crates/circuit/src/constants` and are checked against
   the generators by `tests/fixed_bases.rs`.
3. Range layer: constraint 8 with the lookup range check.

Public input rows: `anchor, nf_old, rk.x, rk.y, cmx_new, cv_net.x, cv_net.y`.

All three layers are implemented in `crates/circuit`. Keys are generated
deterministically from the circuit at startup (under a second) rather than
shipped; a test pins a hash of the verifying key so a circuit change can
never slip in unnoticed. Proof sizes and timings are in `docs/perf.md`.
