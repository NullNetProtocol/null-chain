//! Dandelion++ routing: a transaction first travels a random stem, one
//! peer at a time, then fluffs to everyone. This hides which node created
//! it from observers who watch where a broadcast starts.
//!
//! Each epoch every inbound peer is mapped to one outbound successor and
//! our own transactions get a successor too. A stem transaction is
//! forwarded to the mapped successor with probability `1 - q`, else it
//! fluffs. An embargo timer fluffs anything we have not seen come back.

use std::collections::HashMap;
use std::hash::Hash;

use null_protocol::transaction::TxId;
use rand_core::RngCore;

/// Seconds per epoch, before re-randomizing the stem map.
pub const EPOCH_SECONDS: u64 = 10 * 60;
/// Percent chance a stem transaction fluffs at each hop.
pub const FLUFF_PERCENT: u64 = 10;
/// Minimum seconds a stem transaction stays under embargo.
pub const EMBARGO_MIN: u64 = 10;
/// Extra random seconds of embargo.
pub const EMBARGO_JITTER: u64 = 20;

/// Where to send a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route<P> {
    /// Forward as a stem transaction to this peer only.
    Stem(P),
    /// Announce to every peer.
    Fluff,
}

/// The routing state.
#[derive(Debug)]
pub struct Dandelion<P: Copy + Eq + Hash> {
    epoch_start: u64,
    successors: HashMap<P, P>,
    own_successor: Option<P>,
    embargo: HashMap<TxId, u64>,
}

impl<P: Copy + Eq + Hash> Dandelion<P> {
    /// A router with an empty epoch; call [`Self::new_epoch`] with peers.
    pub fn new(now: u64) -> Self {
        Self {
            epoch_start: now,
            successors: HashMap::new(),
            own_successor: None,
            embargo: HashMap::new(),
        }
    }

    /// Whether the epoch has expired.
    pub fn epoch_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.epoch_start) >= EPOCH_SECONDS
    }

    /// Starts an epoch: maps every peer in `inbound` and ourselves to a
    /// random member of `outbound`. With no outbound peers everything
    /// fluffs.
    pub fn new_epoch(&mut self, now: u64, inbound: &[P], outbound: &[P], rng: &mut impl RngCore) {
        self.epoch_start = now;
        self.successors.clear();
        self.own_successor = pick(outbound, rng);
        for peer in inbound {
            if let Some(successor) = pick(outbound, rng) {
                self.successors.insert(*peer, successor);
            }
        }
    }

    /// Drops a peer that disconnected from the stem map.
    pub fn remove_peer(&mut self, peer: &P) {
        self.successors
            .retain(|from, to| from != peer && to != peer);
        if self.own_successor == Some(*peer) {
            self.own_successor = None;
        }
    }

    /// Routes a transaction we created.
    pub fn route_own(&mut self, txid: TxId, now: u64, rng: &mut impl RngCore) -> Route<P> {
        match self.own_successor {
            Some(peer) => {
                self.embargo(txid, now, rng);
                Route::Stem(peer)
            }
            None => Route::Fluff,
        }
    }

    /// Routes a stem transaction received from `from`.
    pub fn route_stem(
        &mut self,
        from: P,
        txid: TxId,
        now: u64,
        rng: &mut impl RngCore,
    ) -> Route<P> {
        let successor = self.successors.get(&from).copied().or(self.own_successor);
        match successor {
            Some(peer) if rng.next_u64() % 100 >= FLUFF_PERCENT => {
                self.embargo(txid, now, rng);
                Route::Stem(peer)
            }
            _ => Route::Fluff,
        }
    }

    fn embargo(&mut self, txid: TxId, now: u64, rng: &mut impl RngCore) {
        let deadline = now
            .saturating_add(EMBARGO_MIN)
            .saturating_add(crate::random::below(rng, EMBARGO_JITTER));
        self.embargo.insert(txid, deadline);
    }

    /// Records that a transaction was seen fluffed, lifting its embargo.
    pub fn seen_fluffed(&mut self, txid: &TxId) {
        self.embargo.remove(txid);
    }

    /// Transactions whose embargo expired; we must fluff them ourselves.
    pub fn expired_embargoes(&mut self, now: u64) -> Vec<TxId> {
        let expired: Vec<TxId> = self
            .embargo
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.embargo.remove(id);
        }
        expired
    }

    /// Transactions currently under embargo.
    pub fn embargoed(&self) -> usize {
        self.embargo.len()
    }
}

fn pick<P: Copy>(peers: &[P], rng: &mut impl RngCore) -> Option<P> {
    crate::random::index(rng, peers.len())
        .and_then(|i| peers.get(i))
        .copied()
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn txid(b: u8) -> TxId {
        TxId::from_bytes([b; 32])
    }

    #[test]
    fn without_outbound_peers_everything_fluffs() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut d: Dandelion<u8> = Dandelion::new(0);
        d.new_epoch(0, &[1, 2], &[], &mut rng);
        assert_eq!(d.route_own(txid(1), 0, &mut rng), Route::Fluff);
        assert_eq!(d.route_stem(1, txid(2), 0, &mut rng), Route::Fluff);
        assert_eq!(d.embargoed(), 0);
    }

    #[test]
    fn own_transactions_stem_to_the_epoch_successor_under_embargo() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut d: Dandelion<u8> = Dandelion::new(0);
        d.new_epoch(0, &[1], &[10, 11], &mut rng);
        let route = d.route_own(txid(1), 0, &mut rng);
        assert!(matches!(route, Route::Stem(10 | 11)));
        assert_eq!(d.embargoed(), 1);
        assert!(d.expired_embargoes(EMBARGO_MIN - 1).is_empty());
        assert_eq!(
            d.expired_embargoes(EMBARGO_MIN + EMBARGO_JITTER),
            vec![txid(1)]
        );
        assert_eq!(d.embargoed(), 0);
    }

    #[test]
    fn stem_relays_mostly_continue_and_sometimes_fluff() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut d: Dandelion<u8> = Dandelion::new(0);
        d.new_epoch(0, &[1], &[10], &mut rng);
        let mut stems = 0;
        for i in 0..200u8 {
            match d.route_stem(1, txid(i), 0, &mut rng) {
                Route::Stem(10) => stems += 1,
                Route::Stem(_) => panic!("unexpected successor"),
                Route::Fluff => {}
            }
        }
        assert!(
            stems > 150 && stems < 200,
            "about 90 percent stem, got {stems}"
        );
    }

    #[test]
    fn seen_fluffed_lifts_the_embargo_and_removed_peers_fluff() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let mut d: Dandelion<u8> = Dandelion::new(0);
        d.new_epoch(0, &[1], &[10], &mut rng);
        d.route_own(txid(1), 0, &mut rng);
        d.seen_fluffed(&txid(1));
        assert!(d.expired_embargoes(1_000).is_empty());
        d.remove_peer(&10);
        assert_eq!(d.route_own(txid(2), 0, &mut rng), Route::Fluff);
        assert_eq!(d.route_stem(1, txid(3), 0, &mut rng), Route::Fluff);
    }

    #[test]
    fn epochs_expire() {
        let d: Dandelion<u8> = Dandelion::new(100);
        assert!(!d.epoch_expired(100 + EPOCH_SECONDS - 1));
        assert!(d.epoch_expired(100 + EPOCH_SECONDS));
    }
}
