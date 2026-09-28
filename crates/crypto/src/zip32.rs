//! Hierarchical derivation of spending keys from a seed, after ZIP 32.
//!
//! ```text
//! master:  I = BLAKE2b-512_{ZIP32_MASTER}(seed);  sk = I[..32], c = I[32..]
//! child:   I = PRF_expand(c_par, [0x81] || sk_par || LE32(i));  same split
//! account: m / PURPOSE' / COIN_TYPE' / account'
//! ```
//!
//! Only hardened children exist, because a spending key has no public
//! counterpart that could support non-hardened derivation.

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::{blake2b_wide, prf_expand, WIDE_OUTPUT_LEN, ZIP32_MASTER};
use crate::keys::{SpendingKey, SPENDING_KEY_LEN};
use crate::{Error, Result};

/// Shortest allowed seed, in bytes.
pub const MIN_SEED_LEN: usize = 32;
/// Longest allowed seed, in bytes.
pub const MAX_SEED_LEN: usize = 252;
/// Purpose index shared with ZIP 32 derivations.
pub const PURPOSE: u32 = 32;
/// Coin type. Provisional: 1 is the SLIP-44 value reserved for testnets.
pub const COIN_TYPE: u32 = 1;

/// Child derivation tag.
const CHILD_TAG: u8 = 0x81;
/// Bit that marks an index as hardened.
const HARDENED_BIT: u32 = 1 << 31;

/// A hardened child index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildIndex(u32);

impl ChildIndex {
    /// Hardened index `i'`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDerivation`] if `i` already has the hardened
    /// bit set.
    pub fn hardened(i: u32) -> Result<Self> {
        if i & HARDENED_BIT != 0 {
            return Err(Error::InvalidDerivation("index must be below 2^31"));
        }
        Ok(Self(i | HARDENED_BIT))
    }

    /// The raw value with the hardened bit set.
    pub fn raw(self) -> u32 {
        self.0
    }
}

/// The chain code that extends a spending key for child derivation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct ChainCode([u8; 32]);

/// A spending key together with its chain code and depth.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedSpendingKey {
    sk: SpendingKey,
    chain_code: ChainCode,
    depth: u8,
}

impl ExtendedSpendingKey {
    /// The master key of a seed.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDerivation`] for a seed outside
    /// [`MIN_SEED_LEN`]`..=`[`MAX_SEED_LEN`].
    pub fn master(seed: &[u8]) -> Result<Self> {
        if !(MIN_SEED_LEN..=MAX_SEED_LEN).contains(&seed.len()) {
            return Err(Error::InvalidDerivation("seed length out of range"));
        }
        Ok(Self::from_wide(&blake2b_wide(ZIP32_MASTER, &[seed]), 0))
    }

    /// The hardened child at `index`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDerivation`] past depth 255.
    pub fn child(&self, index: ChildIndex) -> Result<Self> {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or(Error::InvalidDerivation("depth exhausted"))?;
        let mut tag = Vec::with_capacity(1 + SPENDING_KEY_LEN + 4);
        tag.push(CHILD_TAG);
        tag.extend_from_slice(&self.sk.to_bytes());
        tag.extend_from_slice(&index.raw().to_le_bytes());
        Ok(Self::from_wide(
            &prf_expand(&self.chain_code.0, &tag),
            depth,
        ))
    }

    /// Derives along `path`, one hardened child at a time.
    ///
    /// # Errors
    /// Propagates [`Self::child`] errors.
    pub fn derive_path(&self, path: &[ChildIndex]) -> Result<Self> {
        path.iter()
            .try_fold(self.clone(), |key, index| key.child(*index))
    }

    /// The key for `account` at `m / PURPOSE' / COIN_TYPE' / account'`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDerivation`] if `account` is not below 2^31.
    pub fn account(seed: &[u8], account: u32) -> Result<Self> {
        let path = [
            ChildIndex::hardened(PURPOSE)?,
            ChildIndex::hardened(COIN_TYPE)?,
            ChildIndex::hardened(account)?,
        ];
        Self::master(seed)?.derive_path(&path)
    }

    /// The spending key at this node.
    pub fn spending_key(&self) -> &SpendingKey {
        &self.sk
    }

    /// Number of derivation steps from the master key.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    fn from_wide(wide: &[u8; WIDE_OUTPUT_LEN], depth: u8) -> Self {
        let (sk, chain_code) = wide.split_at(SPENDING_KEY_LEN);
        let mut sk_bytes = [0u8; SPENDING_KEY_LEN];
        sk_bytes.copy_from_slice(sk);
        let mut cc_bytes = [0u8; 32];
        cc_bytes.copy_from_slice(chain_code);
        Self {
            sk: SpendingKey::from_bytes(sk_bytes),
            chain_code: ChainCode(cc_bytes),
            depth,
        }
    }
}

impl ConstantTimeEq for ExtendedSpendingKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.sk.ct_eq(&other.sk) & self.chain_code.0.ct_eq(&other.chain_code.0)
    }
}

impl core::fmt::Debug for ExtendedSpendingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedSpendingKey")
            .field("depth", &self.depth)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [42; 32];

    fn same(a: &ExtendedSpendingKey, b: &ExtendedSpendingKey) -> bool {
        bool::from(a.ct_eq(b))
    }

    #[test]
    fn master_is_deterministic_and_seed_dependent() {
        let a = ExtendedSpendingKey::master(&SEED).unwrap();
        assert!(same(&a, &ExtendedSpendingKey::master(&SEED).unwrap()));
        assert!(!same(&a, &ExtendedSpendingKey::master(&[43; 32]).unwrap()));
        assert_eq!(a.depth(), 0);
    }

    #[test]
    fn seed_length_is_bounded() {
        assert!(ExtendedSpendingKey::master(&[0; MIN_SEED_LEN - 1]).is_err());
        assert!(ExtendedSpendingKey::master(&[0; MAX_SEED_LEN + 1]).is_err());
        assert!(ExtendedSpendingKey::master(&[0; MAX_SEED_LEN]).is_ok());
    }

    #[test]
    fn hardened_index_rejects_high_bit() {
        assert_eq!(ChildIndex::hardened(5).unwrap().raw(), 5 | HARDENED_BIT);
        assert!(ChildIndex::hardened(HARDENED_BIT).is_err());
    }

    #[test]
    fn children_differ_by_index_and_increase_depth() {
        let m = ExtendedSpendingKey::master(&SEED).unwrap();
        let c0 = m.child(ChildIndex::hardened(0).unwrap()).unwrap();
        let c1 = m.child(ChildIndex::hardened(1).unwrap()).unwrap();
        assert!(!same(&c0, &c1));
        assert!(!same(&c0, &m));
        assert_eq!(c0.depth(), 1);
    }

    #[test]
    fn path_matches_sequential_children() {
        let m = ExtendedSpendingKey::master(&SEED).unwrap();
        let path = [
            ChildIndex::hardened(32).unwrap(),
            ChildIndex::hardened(1).unwrap(),
        ];
        let via_path = m.derive_path(&path).unwrap();
        let sequential = m.child(path[0]).unwrap().child(path[1]).unwrap();
        assert!(same(&via_path, &sequential));
        assert_eq!(via_path.depth(), 2);
    }

    #[test]
    fn accounts_are_distinct_and_at_depth_three() {
        let a0 = ExtendedSpendingKey::account(&SEED, 0).unwrap();
        let a1 = ExtendedSpendingKey::account(&SEED, 1).unwrap();
        assert!(!same(&a0, &a1));
        assert_eq!(a0.depth(), 3);
        assert!(ExtendedSpendingKey::account(&SEED, HARDENED_BIT).is_err());
        assert_ne!(a0.spending_key().to_bytes(), a1.spending_key().to_bytes());
    }

    #[test]
    fn debug_hides_key_material() {
        let m = ExtendedSpendingKey::master(&SEED).unwrap();
        assert_eq!(format!("{m:?}"), "ExtendedSpendingKey { depth: 0, .. }");
    }
}
