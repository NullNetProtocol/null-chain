//! Difficulty adjustment: a linearly weighted moving average (LWMA) of
//! the last `N` solve times, which tracks hashrate changes within a few
//! blocks and resists timestamp manipulation better than fixed-epoch
//! retargeting.
//!
//! ```text
//! next = avg_target * sum(i * solvetime_i, i = 1..N) / (T * N * (N + 1) / 2)
//! ```
//!
//! Solve times are clamped to `[1, 6T]` so one wild timestamp cannot swing
//! the target far, and the result never exceeds the proof-of-work limit.

// `U256` arithmetic on targets: sums are pre-divided by the window, the
// product is checked and its fallback saturates, and divisors are at least
// one, so nothing here overflows or divides by zero.
#![allow(clippy::arithmetic_side_effects)]

use crate::params::ChainParams;
use crate::target::{Target, U256};

/// A recent header's contribution to the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// Header timestamp.
    pub timestamp: u64,
    /// Header target.
    pub target: Target,
}

/// The target for the block after `history`, which lists the most recent
/// headers oldest first. Fewer than `window + 1` headers yield the limit.
/// The result is always exactly representable in compact form.
pub fn next_target(params: &ChainParams, history: &[Sample]) -> Target {
    let n = params.difficulty_window;
    let Some(window) = history
        .len()
        .checked_sub(n.saturating_add(1))
        .and_then(|start| history.get(start..))
    else {
        return params.pow_limit;
    };
    let t = params.block_interval.max(1);
    let max_solve = t.saturating_mul(6);

    let mut weighted: u64 = 0;
    let mut sum_targets = U256::zero();
    for (i, pair) in window.windows(2).enumerate() {
        let [prev, cur] = pair else { continue };
        let solve = cur
            .timestamp
            .saturating_sub(prev.timestamp)
            .clamp(1, max_solve);
        let weight = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
        weighted = weighted.saturating_add(solve.saturating_mul(weight));
        // Divide before summing so N targets cannot overflow.
        sum_targets = sum_targets.saturating_add(cur.target.as_u256() / U256::from(n.max(1)));
    }
    let n64 = u64::try_from(n).unwrap_or(u64::MAX);
    let denominator = U256::from(t.saturating_mul(n64).saturating_mul(n64.saturating_add(1)) / 2);
    // Exact when the product fits. Otherwise divide first; that can still
    // overflow when the limit is near 2^256 (the test network's is about
    // 2^255), and saturating is exact there because the result is clamped
    // to the limit below. Mainnet's limit (about 2^243) never reaches it.
    let next = sum_targets.checked_mul(U256::from(weighted)).map_or_else(
        || (sum_targets / denominator).saturating_mul(U256::from(weighted)),
        |x| x / denominator,
    );
    normalize(Target::from_u256(
        next.max(U256::one()).min(params.pow_limit.as_u256()),
    ))
}

/// Rounds a target to what its compact form encodes, so the rule's output
/// equals what a header can carry.
fn normalize(target: Target) -> Target {
    Target::from_compact(target.to_compact()).unwrap_or(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ChainParams {
        let mut p = ChainParams::test();
        p.pow_limit = normalize(Target::from_u256(U256::one() << 200));
        p.block_interval = 10;
        p.difficulty_window = 4;
        p
    }

    fn history(interval: u64, target: Target, count: usize) -> Vec<Sample> {
        (0..count)
            .map(|i| Sample {
                timestamp: 1_000 + i as u64 * interval,
                target,
            })
            .collect()
    }

    #[test]
    fn too_little_history_yields_the_limit() {
        let p = params();
        assert_eq!(next_target(&p, &[]), p.pow_limit);
        assert_eq!(
            next_target(&p, &history(10, Target::from_u256(U256::one() << 100), 4)),
            p.pow_limit
        );
    }

    #[test]
    fn on_schedule_blocks_keep_the_target() {
        let p = params();
        let target = Target::from_u256(U256::one() << 150);
        let next = next_target(&p, &history(10, target, 5));
        assert_eq!(next, target);
    }

    #[test]
    fn results_survive_the_compact_roundtrip() {
        let p = params();
        let target = Target::from_u256((U256::one() << 150) + U256::from(12345u64));
        let next = next_target(&p, &history(7, target, 5));
        assert_eq!(Target::from_compact(next.to_compact()).unwrap(), next);
    }

    #[test]
    fn fast_blocks_lower_the_target_and_slow_blocks_raise_it() {
        let p = params();
        let target = Target::from_u256(U256::one() << 150);
        assert!(next_target(&p, &history(5, target, 5)) < target);
        assert!(next_target(&p, &history(20, target, 5)) > target);
    }

    #[test]
    fn result_never_exceeds_the_limit_or_hits_zero() {
        let p = params();
        let huge = history(1_000_000, p.pow_limit, 5);
        assert_eq!(next_target(&p, &huge), p.pow_limit);
        let tiny = history(0, Target::from_u256(U256::one()), 5);
        assert!(next_target(&p, &tiny).as_u256() >= U256::one());
    }

    #[test]
    fn a_single_wild_timestamp_is_clamped() {
        let p = params();
        let target = Target::from_u256(U256::one() << 150);
        let mut samples = history(10, target, 5);
        samples[4].timestamp += 1_000_000;
        let clamped = next_target(&p, &samples);
        let six_times = next_target(&p, &{
            let mut s = history(10, target, 5);
            s[4].timestamp += 50;
            s
        });
        assert_eq!(clamped, six_times, "60 s solve time is the clamp at 6T");
    }

    /// The slowest history the rule accepts: every solve clamped to 6T and
    /// every target at the limit, maximising both factors of the product.
    fn slowest_at_the_limit(p: &ChainParams) -> Vec<Sample> {
        history(
            p.block_interval.saturating_mul(6),
            p.pow_limit,
            p.difficulty_window + 1,
        )
    }

    #[test]
    fn slow_blocks_at_the_limit_stay_at_the_limit_on_every_network() {
        // The test network's limit is near 2^255, so the weighted product
        // overflows even after dividing by the denominator first.
        for p in [ChainParams::test(), ChainParams::mainnet()] {
            let history = slowest_at_the_limit(&p);
            assert_eq!(next_target(&p, &history), p.pow_limit);
        }
    }

    proptest::proptest! {
        /// Any history, on either network, yields a target in `[1, limit]`
        /// that survives the compact roundtrip, and never panics.
        #[test]
        fn any_history_yields_a_valid_target(
            mainnet: bool,
            solves in proptest::collection::vec(0u64..10_000, 0..80),
            targets in proptest::collection::vec(proptest::array::uniform4(proptest::num::u64::ANY), 80),
        ) {
            let p = if mainnet { ChainParams::mainnet() } else { ChainParams::test() };
            let limit = p.pow_limit.as_u256();
            let mut timestamp = 1_000u64;
            let history: Vec<Sample> = solves
                .iter()
                .zip(&targets)
                .map(|(solve, words)| {
                    timestamp = timestamp.saturating_add(*solve);
                    // Real headers carry targets at or below the limit.
                    let target = (U256(*words) % limit).max(U256::one());
                    Sample { timestamp, target: Target::from_u256(target) }
                })
                .collect();
            let next = next_target(&p, &history);
            proptest::prop_assert!(next.as_u256() >= U256::one());
            proptest::prop_assert!(next <= p.pow_limit);
            proptest::prop_assert_eq!(Target::from_compact(next.to_compact()).unwrap(), next);
        }
    }
}
