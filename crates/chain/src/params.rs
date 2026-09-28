//! Chain parameters: everything a network fixes at launch.

use null_protocol::address::AddressPrefix;
use null_protocol::block::BlockHash;
use null_protocol::consensus::BranchId;

use crate::equihash::Params as EquihashParams;
use crate::target::Target;

/// A block every node must agree on: no chain that disagrees with it is
/// accepted, and no reorganization may revert it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Height.
    pub height: u32,
    /// Hash of the block at that height.
    pub hash: BlockHash,
}

/// A scheduled change of consensus rules: from `height` on, blocks are
/// validated under `branch`. Rule changes in code are gated on
/// [`ChainParams::branch_at`]; the new branch id alone already invalidates
/// every transaction signed for the old rules. See `docs/upgrades.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upgrade {
    /// First height validated under the new rules.
    pub height: u32,
    /// The rules' identifier, bound into every sighash from then on.
    pub branch: BranchId,
}

/// The constants of one network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    /// Equihash `(n, k)`.
    pub equihash: EquihashParams,
    /// The easiest allowed target.
    pub pow_limit: Target,
    /// Target seconds between blocks.
    pub block_interval: u64,
    /// Blocks averaged by the difficulty rule.
    pub difficulty_window: usize,
    /// Timestamp of the genesis block.
    pub genesis_timestamp: u64,
    /// Blocks whose commitment roots remain valid anchors.
    pub anchor_max_age: u32,
    /// Seconds a block timestamp may run ahead of local time.
    pub max_future_seconds: u64,
    /// Deepest reorganization a node accepts; older frontiers are pruned.
    pub max_reorg_depth: u32,
    /// Known-good blocks, ascending by height.
    pub checkpoints: &'static [Checkpoint],
    /// How addresses for this network are written.
    pub address_prefix: AddressPrefix,
    /// The consensus branch from genesis until the first upgrade. Differs
    /// per network so a transaction for one is never valid on another.
    pub genesis_branch: BranchId,
    /// Scheduled upgrades, ascending by height, all above genesis.
    pub upgrades: &'static [Upgrade],
    /// The encoded coinbase transaction of the genesis block, paying the
    /// premine, or `None` for a genesis with no transactions. Generated
    /// once with `nulld genesis-coinbase` and committed; see
    /// `docs/params.md`.
    pub genesis_coinbase: Option<&'static [u8]>,
}

impl ChainParams {
    /// The checkpoint at `height`, if any.
    pub fn checkpoint_at(&self, height: u32) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|c| c.height == height)
    }

    /// Height of the highest checkpoint, or zero.
    pub fn last_checkpoint_height(&self) -> u32 {
        self.checkpoints.last().map_or(0, |c| c.height)
    }

    /// The consensus branch in force at `height`: that of the last upgrade
    /// activated at or below it, or the genesis branch.
    pub fn branch_at(&self, height: u32) -> BranchId {
        self.upgrades
            .iter()
            .rev()
            .find(|u| u.height <= height)
            .map_or(self.genesis_branch, |u| u.branch)
    }

    /// Whether the upgrade schedule is well formed: ascending heights,
    /// none at genesis, and every branch distinct from the others and
    /// from the genesis branch.
    pub fn upgrades_are_well_formed(&self) -> bool {
        let ascending = self.upgrades.windows(2).all(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(a, b)| a.height < b.height)
        });
        let above_genesis = self.upgrades.iter().all(|u| u.height > 0);
        let distinct = self.upgrades.iter().enumerate().all(|(i, u)| {
            u.branch != self.genesis_branch
                && !self.upgrades.iter().take(i).any(|o| o.branch == u.branch)
        });
        ascending && above_genesis && distinct
    }
}

impl ChainParams {
    /// Provisional main network parameters. The Equihash set was chosen by
    /// the benchmark in `docs/perf.md`; `docs/decisions.md` has the reasons.
    ///
    /// # Panics
    /// Never: the constants are valid by construction and checked in tests.
    #[allow(clippy::expect_used)]
    pub fn mainnet() -> Self {
        Self {
            equihash: EquihashParams::new(144, 5).expect("valid parameters"),
            pow_limit: Target::from_compact(0x1f07_ffff).expect("valid compact target"),
            block_interval: 120,
            difficulty_window: 60,
            genesis_timestamp: 1_757_000_000,
            anchor_max_age: 100,
            max_future_seconds: 2 * 60 * 60,
            max_reorg_depth: 200,
            checkpoints: &[],
            address_prefix: AddressPrefix::Main,
            genesis_branch: BranchId::new(0x4d41_494e),
            upgrades: &[],
            // Pays the premine to a placeholder whose key was discarded:
            // regenerate with the real development fund address before
            // launch (`nulld genesis-coinbase`), see docs/params.md.
            genesis_coinbase: Some(include_bytes!("genesis/main.tx")),
        }
    }

    /// Parameters for tests: a tiny puzzle, a starting target half of all
    /// hashes meet, and five-second blocks once difficulty adjusts.
    ///
    /// # Panics
    /// Never: the constants are valid by construction.
    #[allow(clippy::expect_used)]
    pub fn test() -> Self {
        Self {
            equihash: EquihashParams::new(48, 5).expect("valid parameters"),
            pow_limit: Target::from_compact(0x207f_ffff).expect("valid compact target"),
            // Long enough that the difficulty rule demands several nonces
            // per block; with a trivial target block finding is deterministic
            // and the miner that started first wins every block.
            block_interval: 5,
            difficulty_window: 6,
            genesis_timestamp: 1_000_000,
            anchor_max_age: 100,
            max_future_seconds: 2 * 60 * 60,
            max_reorg_depth: 200,
            checkpoints: &[],
            address_prefix: AddressPrefix::Test,
            genesis_branch: BranchId::new(0x5445_5354),
            upgrades: &[],
            // Pays the premine to the all-zero seed phrase's account 0, a
            // published key, so anyone can fund a test wallet from it.
            genesis_coinbase: Some(include_bytes!("genesis/test.tx")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use null_protocol::consensus::POW_SOLUTION_LEN;

    #[test]
    fn mainnet_solution_fits_the_header_field() {
        assert_eq!(
            ChainParams::mainnet().equihash.solution_len(),
            POW_SOLUTION_LEN
        );
    }

    const SCHEDULE: [Upgrade; 2] = [
        Upgrade {
            height: 10,
            branch: BranchId::new(1),
        },
        Upgrade {
            height: 20,
            branch: BranchId::new(2),
        },
    ];

    fn with_schedule(upgrades: &'static [Upgrade]) -> ChainParams {
        ChainParams {
            upgrades,
            ..ChainParams::test()
        }
    }

    #[test]
    fn branch_changes_exactly_at_each_activation_height() {
        let params = with_schedule(&SCHEDULE);
        let genesis = params.genesis_branch;
        assert_eq!(params.branch_at(0), genesis);
        assert_eq!(params.branch_at(9), genesis);
        assert_eq!(params.branch_at(10), BranchId::new(1));
        assert_eq!(params.branch_at(19), BranchId::new(1));
        assert_eq!(params.branch_at(20), BranchId::new(2));
        assert_eq!(params.branch_at(u32::MAX), BranchId::new(2));
        assert!(params.upgrades_are_well_formed());
    }

    #[test]
    fn malformed_schedules_are_detected() {
        static UNORDERED: [Upgrade; 2] = [SCHEDULE[1], SCHEDULE[0]];
        static AT_GENESIS: [Upgrade; 1] = [Upgrade {
            height: 0,
            branch: BranchId::new(1),
        }];
        static REUSES_GENESIS_BRANCH: [Upgrade; 1] = [Upgrade {
            height: 5,
            branch: BranchId::new(0x5445_5354),
        }];
        static REPEATED: [Upgrade; 2] = [
            SCHEDULE[0],
            Upgrade {
                height: 30,
                ..SCHEDULE[0]
            },
        ];
        for bad in [
            &UNORDERED[..],
            &AT_GENESIS[..],
            &REUSES_GENESIS_BRANCH[..],
            &REPEATED[..],
        ] {
            assert!(!with_schedule(bad).upgrades_are_well_formed(), "{bad:?}");
        }
    }

    #[test]
    fn networks_have_distinct_branches_and_well_formed_schedules() {
        let networks = [ChainParams::mainnet(), ChainParams::test()];
        let mut all: Vec<BranchId> = networks
            .iter()
            .flat_map(|p| {
                std::iter::once(p.genesis_branch).chain(p.upgrades.iter().map(|u| u.branch))
            })
            .collect();
        let count = all.len();
        all.sort_by_key(|b| b.to_bytes());
        all.dedup();
        assert_eq!(all.len(), count, "a branch id is shared between networks");
        for p in networks {
            assert!(p.upgrades_are_well_formed());
        }
    }

    #[test]
    fn networks_write_addresses_differently() {
        assert_ne!(
            ChainParams::mainnet().address_prefix,
            ChainParams::test().address_prefix
        );
    }

    #[test]
    fn limits_are_exactly_representable_in_compact_form() {
        for p in [ChainParams::mainnet(), ChainParams::test()] {
            assert_eq!(
                Target::from_compact(p.pow_limit.to_compact()).unwrap(),
                p.pow_limit
            );
        }
    }

    #[test]
    fn checkpoint_lookups_work_on_an_empty_and_a_filled_list() {
        static POINTS: [Checkpoint; 2] = [
            Checkpoint {
                height: 5,
                hash: BlockHash::ZERO,
            },
            Checkpoint {
                height: 9,
                hash: BlockHash::ZERO,
            },
        ];
        let params = ChainParams::test();
        assert_eq!(params.checkpoint_at(0), None);
        assert_eq!(params.last_checkpoint_height(), 0);
        let with = ChainParams {
            checkpoints: &POINTS,
            ..params
        };
        assert_eq!(with.checkpoint_at(9).map(|c| c.height), Some(9));
        assert_eq!(with.last_checkpoint_height(), 9);
    }

    #[test]
    fn test_parameters_are_easier_than_mainnet() {
        assert!(ChainParams::test().pow_limit > ChainParams::mainnet().pow_limit);
        assert!(ChainParams::test().equihash.solution_len() <= POW_SOLUTION_LEN);
    }
}
