//! The Merkle path gadget: recomputes the root from a leaf, `MERKLE_DEPTH`
//! position bits and as many siblings, level by level, with a conditional
//! swap and one Poseidon hash per level. Matches
//! `null_crypto::merkle::MerklePath::root`.

use halo2_gadgets::utilities::cond_swap::{CondSwapChip, CondSwapConfig, CondSwapInstructions};
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error};
use null_crypto::merkle::MERKLE_DEPTH;

use super::poseidon::{self, PoseidonConfig};
use crate::Fp;

/// Columns and sub-configurations of the Merkle gadget.
#[derive(Clone, Debug)]
pub struct MerkleConfig {
    poseidon: PoseidonConfig,
    cond_swap: CondSwapConfig,
}

impl MerkleConfig {
    /// Configures the gadget. `swap_advices` are five advice columns for
    /// the conditional swap; the Poseidon configuration is shared.
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        poseidon: PoseidonConfig,
        swap_advices: [Column<Advice>; 5],
    ) -> Self {
        for column in swap_advices {
            meta.enable_equality(column);
        }
        let cond_swap = CondSwapChip::configure(meta, swap_advices);
        Self {
            poseidon,
            cond_swap,
        }
    }

    /// The root reached from `leaf` along the path.
    ///
    /// The position bits are witnesses, not public inputs: any path that
    /// reaches the anchor is acceptable, and nothing else depends on the
    /// position.
    ///
    /// # Errors
    /// Propagates layouter errors.
    pub fn root(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf: AssignedCell<Fp, Fp>,
        position_bits: &[Value<bool>; MERKLE_DEPTH],
        siblings: &[Value<Fp>; MERKLE_DEPTH],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let swap_chip = CondSwapChip::<Fp>::construct(self.cond_swap.clone());
        let mut node = leaf;
        for (level, (bit, sibling)) in position_bits.iter().zip(siblings).enumerate() {
            // When the bit is set the node is the right child, so swap so
            // that `left` is the sibling.
            let (left, right) = swap_chip.swap(
                layouter.namespace(|| format!("swap level {level}")),
                (node, *sibling),
                *bit,
            )?;
            node = poseidon::hash::<2>(
                &self.poseidon,
                layouter.namespace(|| format!("hash level {level}")),
                [left, right],
            )?;
        }
        Ok(node)
    }
}

/// The position bits of a leaf index, least significant first.
pub fn position_bits(position: u64) -> [bool; MERKLE_DEPTH] {
    core::array::from_fn(|i| u32::try_from(i).is_ok_and(|s| s < 64 && (position >> s) & 1 == 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_bits_are_little_endian() {
        let bits = position_bits(0b101);
        assert!(bits[0]);
        assert!(!bits[1]);
        assert!(bits[2]);
        assert!(bits[3..].iter().all(|b| !b));
        assert!(position_bits(u64::MAX).iter().all(|b| *b));
        assert!(position_bits(1 << 47)[MERKLE_DEPTH - 1]);
    }
}
