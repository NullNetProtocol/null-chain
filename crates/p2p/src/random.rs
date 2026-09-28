//! Small randomness helpers shared by the state machines.

use rand_core::RngCore;

/// A uniform value below `bound`, or zero when `bound` is zero. The bias
/// of the modulo is negligible for the small bounds used here.
#[allow(clippy::arithmetic_side_effects)] // `max(1)` makes the modulo safe
pub fn below(rng: &mut impl RngCore, bound: u64) -> u64 {
    rng.next_u64() % bound.max(1)
}

/// A uniform index into a slice of `len` items, or `None` when empty.
pub fn index(rng: &mut impl RngCore, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    usize::try_from(below(rng, u64::try_from(len).unwrap_or(u64::MAX))).ok()
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn values_stay_in_range() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        assert_eq!(below(&mut rng, 0), 0);
        for _ in 0..100 {
            assert!(below(&mut rng, 7) < 7);
            assert!(index(&mut rng, 3).unwrap() < 3);
        }
        assert_eq!(index(&mut rng, 0), None);
    }
}
