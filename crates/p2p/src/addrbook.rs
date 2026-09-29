//! Known peer addresses, bans, and candidates for outbound connections.

use std::collections::HashMap;

use rand_core::RngCore;

use crate::message::{PeerAddr, MAX_ADDRESSES};

/// Addresses the book keeps at most.
pub const MAX_KNOWN: usize = 10_000;
/// Seconds an address timestamp may be in the future before it is ignored.
pub const MAX_FUTURE: u64 = 10 * 60;
/// Seconds after which an unseen address is forgotten.
pub const MAX_AGE: u64 = 30 * 24 * 60 * 60;
/// Default ban length in seconds.
pub const BAN_SECONDS: u64 = 24 * 60 * 60;
/// Banned IP addresses the book remembers at most.
pub const MAX_BANS: usize = 10_000;

/// An IP address as the book stores it: IPv4 as IPv4-mapped IPv6.
pub type Ip = [u8; 16];

#[derive(Clone, Copy, Debug)]
struct Entry {
    addr: PeerAddr,
    failures: u32,
}

/// The address book.
#[derive(Debug, Default)]
pub struct AddressBook {
    entries: HashMap<(Ip, u16), Entry>,
    /// Ban expiry per IP. Bans are per IP, not per address: an inbound
    /// peer connects from a new ephemeral port every time, so a ban on
    /// its port would never match again.
    bans: HashMap<Ip, u64>,
}

impl AddressBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of known addresses.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the book is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records an address, keeping the newest timestamp. Addresses from
    /// the future or too old are ignored, and the book stays bounded.
    pub fn add(&mut self, addr: PeerAddr, now: u64) -> bool {
        if addr.last_seen > now.saturating_add(MAX_FUTURE)
            || now.saturating_sub(addr.last_seen) > MAX_AGE
        {
            return false;
        }
        if let Some(entry) = self.entries.get_mut(&addr.key()) {
            entry.addr.last_seen = entry.addr.last_seen.max(addr.last_seen);
            return false;
        }
        if self.entries.len() >= MAX_KNOWN {
            return false;
        }
        self.entries.insert(addr.key(), Entry { addr, failures: 0 });
        true
    }

    /// Records addresses received in an `Addr` message, at most the
    /// protocol limit.
    pub fn add_many(&mut self, addrs: &[PeerAddr], now: u64) -> usize {
        addrs
            .iter()
            .take(MAX_ADDRESSES)
            .filter(|a| self.add(**a, now))
            .count()
    }

    /// Bans every port of `ip` until `now + BAN_SECONDS`. When the ban
    /// list is full, expired bans go first, then the one ending soonest.
    pub fn ban(&mut self, ip: Ip, now: u64) {
        if !self.bans.contains_key(&ip) && self.bans.len() >= MAX_BANS {
            self.bans.retain(|_, until| *until > now);
            let soonest = self
                .bans
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(ip, _)| *ip);
            if let (true, Some(soonest)) = (self.bans.len() >= MAX_BANS, soonest) {
                self.bans.remove(&soonest);
            }
        }
        self.bans.insert(ip, now.saturating_add(BAN_SECONDS));
    }

    /// Whether `ip` is banned at `now`.
    pub fn is_banned(&self, ip: &Ip, now: u64) -> bool {
        self.bans.get(ip).is_some_and(|until| *until > now)
    }

    /// Records a failed connection attempt.
    pub fn failed(&mut self, key: ([u8; 16], u16)) {
        if let Some(e) = self.entries.get_mut(&key) {
            e.failures = e.failures.saturating_add(1);
        }
    }

    /// Records a successful connection at `now`.
    pub fn connected(&mut self, key: ([u8; 16], u16), now: u64) {
        if let Some(e) = self.entries.get_mut(&key) {
            e.failures = 0;
            e.addr.last_seen = now;
        }
    }

    /// A random unbanned address not in `exclude`, preferring those that
    /// have failed less.
    pub fn candidate(
        &self,
        exclude: &[([u8; 16], u16)],
        now: u64,
        rng: &mut impl RngCore,
    ) -> Option<PeerAddr> {
        let mut pool: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| !self.is_banned(&e.addr.ip, now) && !exclude.contains(&e.addr.key()))
            .collect();
        if pool.is_empty() {
            return None;
        }
        pool.sort_by_key(|e| e.failures);
        let best = pool.first().map_or(0, |e| e.failures);
        let good: Vec<&Entry> = pool
            .iter()
            .copied()
            .filter(|e| e.failures == best)
            .collect();
        crate::random::index(rng, good.len())
            .and_then(|i| good.get(i))
            .map(|e| e.addr)
    }

    /// A random sample of unbanned addresses to share with a peer.
    pub fn sample(&self, count: usize, now: u64, rng: &mut impl RngCore) -> Vec<PeerAddr> {
        let mut pool: Vec<PeerAddr> = self
            .entries
            .values()
            .filter(|e| !self.is_banned(&e.addr.ip, now))
            .map(|e| e.addr)
            .collect();
        for i in (1..pool.len()).rev() {
            let j = crate::random::index(rng, i.saturating_add(1)).unwrap_or(0);
            pool.swap(i, j);
        }
        pool.truncate(count.min(MAX_ADDRESSES));
        pool
    }

    /// Forgets addresses unseen for longer than [`MAX_AGE`] and expired bans.
    pub fn prune(&mut self, now: u64) {
        self.entries
            .retain(|_, e| now.saturating_sub(e.addr.last_seen) <= MAX_AGE);
        self.bans.retain(|_, until| *until > now);
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn addr(last: u8, seen: u64) -> PeerAddr {
        PeerAddr::v4([10, 0, 0, last], 1234, seen)
    }

    #[test]
    fn adds_deduplicates_and_keeps_the_newest_timestamp() {
        let mut book = AddressBook::new();
        assert!(book.add(addr(1, 100), 100));
        assert!(!book.add(addr(1, 150), 200));
        assert_eq!(book.len(), 1);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        assert_eq!(book.candidate(&[], 200, &mut rng).unwrap().last_seen, 150);
    }

    #[test]
    fn future_and_ancient_addresses_are_ignored() {
        let mut book = AddressBook::new();
        assert!(!book.add(addr(1, 10_000), 100));
        assert!(!book.add(addr(2, 0), MAX_AGE + 100));
        assert!(book.is_empty());
    }

    #[test]
    fn bans_exclude_candidates_and_samples_until_they_expire() {
        let mut book = AddressBook::new();
        book.add(addr(1, 100), 100);
        book.ban(addr(1, 0).ip, 100);
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        assert!(book.is_banned(&addr(1, 0).ip, 100));
        assert!(book.candidate(&[], 100, &mut rng).is_none());
        assert!(book.sample(5, 100, &mut rng).is_empty());
        assert!(book.candidate(&[], 100 + BAN_SECONDS, &mut rng).is_some());
        book.prune(100 + BAN_SECONDS);
        assert!(!book.is_banned(&addr(1, 0).ip, 100 + BAN_SECONDS));
    }

    #[test]
    fn a_ban_covers_every_port_of_the_ip_and_adds_no_address() {
        let mut book = AddressBook::new();
        let inbound = PeerAddr::v4([10, 0, 0, 9], 51_234, 100);
        book.ban(inbound.ip, 100);
        let reconnect = PeerAddr::v4([10, 0, 0, 9], 51_999, 100);
        assert!(book.is_banned(&reconnect.ip, 100), "a new ephemeral port");
        assert!(!book.is_banned(&addr(1, 0).ip, 100), "other IPs are fine");
        assert!(
            book.is_empty(),
            "a banned inbound port is not a dial candidate"
        );
    }

    #[test]
    fn the_ban_list_is_bounded_and_evicts_the_ban_ending_soonest() {
        let mut book = AddressBook::new();
        let ip = |i: usize| {
            let mut ip = [0u8; 16];
            ip[..8].copy_from_slice(&(i as u64).to_le_bytes());
            ip
        };
        for i in 0..MAX_BANS {
            book.ban(ip(i), i as u64);
        }
        book.ban(ip(MAX_BANS), MAX_BANS as u64);
        assert_eq!(book.bans.len(), MAX_BANS);
        assert!(!book.is_banned(&ip(0), 0), "the earliest ban made room");
        assert!(book.is_banned(&ip(MAX_BANS), MAX_BANS as u64));
    }

    #[test]
    fn candidates_skip_excluded_and_prefer_fewer_failures() {
        let mut book = AddressBook::new();
        book.add(addr(1, 100), 100);
        book.add(addr(2, 100), 100);
        book.failed(addr(1, 0).key());
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        for _ in 0..10 {
            assert_eq!(
                book.candidate(&[], 100, &mut rng).unwrap().ip,
                addr(2, 0).ip
            );
        }
        assert_eq!(
            book.candidate(&[addr(2, 0).key()], 100, &mut rng)
                .unwrap()
                .ip,
            addr(1, 0).ip
        );
        book.connected(addr(1, 0).key(), 300);
        assert_eq!(book.add_many(&[addr(3, 300)], 300), 1);
    }

    #[test]
    fn sample_is_bounded_and_prune_forgets_old_entries() {
        let mut book = AddressBook::new();
        for i in 1..=20u8 {
            book.add(addr(i, 100), 100);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        assert_eq!(book.sample(5, 100, &mut rng).len(), 5);
        book.prune(100 + MAX_AGE + 1);
        assert!(book.is_empty());
    }
}
