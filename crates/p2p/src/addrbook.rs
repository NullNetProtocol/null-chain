//! Known peer addresses, bans, and candidates for outbound connections.

use std::collections::HashMap;

use null_protocol::bytes::{Reader, Writer};
use rand_core::RngCore;

use crate::message::{put_count, take_count, PeerAddr, MAX_ADDRESSES};
use crate::{Error, Result};

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
/// Seconds a successful outbound handshake vouches for an address.
pub const VERIFIED_SECONDS: u64 = 24 * 60 * 60;
/// Minimum time between attempts, doubling after each failure up to
/// [`MAX_RETRY_SECONDS`].
pub const RETRY_SECONDS: u64 = 60;
/// Longest delay between attempts at an address that keeps failing.
pub const MAX_RETRY_SECONDS: u64 = 60 * 60;
/// Failures after which the retry delay stops doubling; bounds the shift.
const MAX_BACKOFF_DOUBLINGS: u32 = 6;
/// Granularity of the timestamp on shared addresses. Every address in a
/// sample carries the same rounded time, so a peer cannot tell from it
/// when, or in which order, this node connected to each one.
pub const SHARED_TIME_GRANULARITY: u64 = 60 * 60;

/// An IP address as the book stores it: IPv4 as IPv4-mapped IPv6.
pub type Ip = [u8; 16];
/// Version byte of the [`Snapshot`] layout.
pub const SNAPSHOT_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug)]
struct Entry {
    addr: PeerAddr,
    failures: u32,
    verified_at: Option<u64>,
    retry_at: u64,
}

impl Entry {
    /// Whether a recent outbound handshake verified this address.
    fn is_verified(&self, now: u64) -> bool {
        self.verified_at
            .is_some_and(|at| now.saturating_sub(at) < VERIFIED_SECONDS)
    }
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

    /// Records a new address. Addresses from the future or too old are
    /// ignored, and the book stays bounded. Gossip never refreshes a known
    /// entry, only [`AddressBook::connected`] does, so a peer re-sending an
    /// address cannot keep it alive past [`MAX_AGE`]. A slightly future
    /// timestamp is stored as `now` for the same reason.
    pub fn add(&mut self, addr: PeerAddr, now: u64) -> bool {
        if addr.last_seen > now.saturating_add(MAX_FUTURE)
            || now.saturating_sub(addr.last_seen) > MAX_AGE
            || self.entries.contains_key(&addr.key())
            || self.entries.len() >= MAX_KNOWN
        {
            return false;
        }
        self.entries.insert(
            addr.key(),
            Entry {
                addr: PeerAddr {
                    last_seen: addr.last_seen.min(now),
                    ..addr
                },
                failures: 0,
                verified_at: None,
                retry_at: 0,
            },
        );
        true
    }

    /// Records addresses received in an `Addr` message, at most the
    /// protocol limit, and returns how many were new.
    pub fn add_many(&mut self, addrs: impl IntoIterator<Item = PeerAddr>, now: u64) -> usize {
        addrs
            .into_iter()
            .take(MAX_ADDRESSES)
            .filter(|a| self.add(*a, now))
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
            e.verified_at = None;
        }
    }

    /// Reserves an address while dialing and applies a bounded retry delay.
    pub fn attempted(&mut self, key: (Ip, u16), now: u64) {
        if let Some(e) = self.entries.get_mut(&key) {
            let delay = RETRY_SECONDS
                .saturating_mul(1u64 << e.failures.min(MAX_BACKOFF_DOUBLINGS))
                .min(MAX_RETRY_SECONDS);
            e.retry_at = now.saturating_add(delay);
        }
    }

    /// Records a successful connection at `now`.
    pub fn connected(&mut self, key: ([u8; 16], u16), now: u64) {
        if let Some(e) = self.entries.get_mut(&key) {
            e.failures = 0;
            e.addr.last_seen = now;
            e.verified_at = Some(now);
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
        self.select_candidate(exclude, now, rng, false)
    }

    /// An unverified candidate for a bounded reachability probe.
    pub fn unverified_candidate(
        &self,
        exclude: &[(Ip, u16)],
        now: u64,
        rng: &mut impl RngCore,
    ) -> Option<PeerAddr> {
        self.select_candidate(exclude, now, rng, true)
    }

    fn select_candidate(
        &self,
        exclude: &[(Ip, u16)],
        now: u64,
        rng: &mut impl RngCore,
        unverified_only: bool,
    ) -> Option<PeerAddr> {
        let mut pool: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| {
                e.retry_at <= now
                    && (!unverified_only || !e.is_verified(now))
                    && now.saturating_sub(e.addr.last_seen) <= MAX_AGE
                    && !self.is_banned(&e.addr.ip, now)
                    && !exclude.contains(&e.addr.key())
            })
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

    /// Whether a recent outbound handshake verified this address.
    pub fn verified(&self, key: (Ip, u16), now: u64) -> bool {
        self.entries.get(&key).is_some_and(|e| e.is_verified(now))
    }

    /// A random sample of recently verified, unbanned addresses to share.
    /// Gossip cannot extend the lifetime of our own reachability checks.
    /// Every address carries `now` rounded down to
    /// [`SHARED_TIME_GRANULARITY`] rather than its verification time, which
    /// would single out the peers this node is connected to right now.
    pub fn sample(&self, count: usize, now: u64, rng: &mut impl RngCore) -> Vec<PeerAddr> {
        let shared_time = now.saturating_sub(now % SHARED_TIME_GRANULARITY);
        let mut pool: Vec<PeerAddr> = self
            .entries
            .values()
            .filter(|e| e.is_verified(now) && !self.is_banned(&e.addr.ip, now))
            .map(|e| PeerAddr {
                last_seen: shared_time,
                ..e.addr
            })
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

    /// The addresses worth keeping across a restart, in canonical order.
    pub fn snapshot(&self) -> Snapshot {
        let mut entries: Vec<SavedAddr> = self
            .entries
            .values()
            .map(|e| SavedAddr {
                addr: e.addr,
                verified_at: e.verified_at,
            })
            .collect();
        entries.sort_by_key(|e| e.addr.key());
        Snapshot(entries)
    }

    /// Loads saved addresses under the same rules as gossip: `keep` applies
    /// the caller's network policy, [`AddressBook::add`] the timestamp
    /// checks and the size bound, and known addresses stay as they are. A
    /// verification time in the future is dropped, not trusted, since the
    /// file may have been written by anyone. Returns how many were added.
    pub fn restore(
        &mut self,
        snapshot: Snapshot,
        now: u64,
        keep: impl Fn(&PeerAddr) -> bool,
    ) -> usize {
        let mut added: usize = 0;
        for saved in snapshot.0.into_iter().filter(|s| keep(&s.addr)) {
            if !self.add(saved.addr, now) {
                continue;
            }
            if let Some(e) = self.entries.get_mut(&saved.addr.key()) {
                e.verified_at = saved.verified_at.filter(|at| *at <= now);
            }
            added = added.saturating_add(1);
        }
        added
    }
}

/// One saved address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedAddr {
    /// The address and when it was last seen alive.
    pub addr: PeerAddr,
    /// When an outbound handshake last verified it, if one did.
    pub verified_at: Option<u64>,
}

/// The part of an [`AddressBook`] that survives a restart: addresses and
/// their verification times. Failure counts, retry delays and bans are not
/// kept, so a restart still gives every address a fresh start.
///
/// Layout: [`SNAPSHOT_VERSION`], a `u32` LE count of at most [`MAX_KNOWN`],
/// then per entry, in strictly ascending `(ip, port)` order,
/// `ip (16) | port (u16 LE) | last_seen (u64 LE) | verified (0 or 1)`
/// followed by `verified_at (u64 LE)` when the flag is 1.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot(Vec<SavedAddr>);

impl Snapshot {
    /// The saved addresses, in ascending `(ip, port)` order.
    pub fn entries(&self) -> &[SavedAddr] {
        &self.0
    }

    /// The canonical encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.put_u8(SNAPSHOT_VERSION);
        put_count(&mut w, self.0.len());
        for saved in &self.0 {
            saved.addr.write(&mut w);
            match saved.verified_at {
                Some(at) => w.put_u8(1).put_u64_le(at),
                None => w.put_u8(0),
            };
        }
        w.into_bytes()
    }

    /// Decodes [`Snapshot::to_bytes`].
    ///
    /// # Errors
    /// Fails on another version, more than [`MAX_KNOWN`] entries, entries
    /// out of order or repeated, a flag other than 0 or 1, truncation or
    /// trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take_u8()? != SNAPSHOT_VERSION {
            return Err(Error::BadSnapshot("unknown version"));
        }
        let count = take_count(&mut r, MAX_KNOWN, "saved addresses")?;
        let mut entries: Vec<SavedAddr> = Vec::with_capacity(count);
        for _ in 0..count {
            let saved = read_saved(&mut r)?;
            if entries
                .last()
                .is_some_and(|prev| prev.addr.key() >= saved.addr.key())
            {
                return Err(Error::BadSnapshot("addresses not strictly ascending"));
            }
            entries.push(saved);
        }
        r.finish()?;
        Ok(Self(entries))
    }
}

fn read_saved(r: &mut Reader<'_>) -> Result<SavedAddr> {
    let addr = PeerAddr::read(r)?;
    let verified_at = match r.take_u8()? {
        0 => None,
        1 => Some(r.take_u64_le()?),
        _ => return Err(Error::BadSnapshot("verified flag is not 0 or 1")),
    };
    Ok(SavedAddr { addr, verified_at })
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
    fn adds_deduplicates_and_gossip_does_not_refresh_known_entries() {
        let mut book = AddressBook::new();
        assert!(book.add(addr(1, 100), 100));
        assert!(!book.add(addr(1, 150), 200));
        assert_eq!(book.len(), 1);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        assert_eq!(book.candidate(&[], 200, &mut rng).unwrap().last_seen, 100);
    }

    #[test]
    fn re_gossiped_addresses_still_expire_but_handshakes_keep_them() {
        let mut book = AddressBook::new();
        book.add(addr(1, 100), 100);
        book.add(addr(2, 100), 100);
        let later = 100 + MAX_AGE;
        book.add(addr(1, later), later);
        book.connected(addr(2, 0).key(), later);
        book.prune(later + 1);
        assert_eq!(book.len(), 1);
        assert!(book.verified(addr(2, 0).key(), later + 1));
    }

    #[test]
    fn future_timestamps_are_stored_as_now() {
        let mut book = AddressBook::new();
        assert!(book.add(addr(1, 100 + MAX_FUTURE), 100));
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        assert_eq!(book.candidate(&[], 100, &mut rng).unwrap().last_seen, 100);
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
        assert_eq!(book.sample(5, 100, &mut rng).len(), 0);
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
        assert_eq!(book.add_many([addr(3, 300), addr(3, 300)], 300), 1);
    }

    #[test]
    fn sample_is_bounded_and_prune_forgets_old_entries() {
        let mut book = AddressBook::new();
        for i in 1..=20u8 {
            book.add(addr(i, 100), 100);
            book.connected(addr(i, 100).key(), 100);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        assert_eq!(book.sample(5, 100, &mut rng).len(), 5);
        book.prune(100 + MAX_AGE + 1);
        assert!(book.is_empty());
    }

    #[test]
    fn gossip_is_shared_only_after_verification_and_cannot_renew_it() {
        let mut book = AddressBook::new();
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        book.add(addr(1, 100), 100);
        assert_eq!(book.sample(100, 100, &mut rng).len(), 0);
        book.connected(addr(1, 100).key(), 100);
        assert!(book.unverified_candidate(&[], 100, &mut rng).is_none());
        book.add(addr(1, 200), 200);
        assert_eq!(book.sample(100, 200, &mut rng), vec![addr(1, 0)]);
        assert_eq!(book.sample(100, 100 + VERIFIED_SECONDS, &mut rng).len(), 0);
        assert!(book
            .unverified_candidate(&[], 100 + VERIFIED_SECONDS, &mut rng)
            .is_some());
        book.connected(addr(1, 100).key(), 300);
        book.failed(addr(1, 100).key());
        assert_eq!(book.sample(100, 300, &mut rng).len(), 0);
    }

    #[test]
    fn shared_timestamps_are_rounded_and_identical() {
        let mut book = AddressBook::new();
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let now = 5 * SHARED_TIME_GRANULARITY + 17;
        for (i, seen) in [(1, now - 1_000), (2, now - 1)] {
            book.add(addr(i, seen), seen);
            book.connected(addr(i, 0).key(), seen);
        }
        let sample = book.sample(100, now, &mut rng);
        assert_eq!(sample.len(), 2);
        assert!(sample
            .iter()
            .all(|a| a.last_seen == 5 * SHARED_TIME_GRANULARITY));
    }

    #[test]
    fn retry_delay_doubles_and_is_capped() {
        let mut book = AddressBook::new();
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        book.add(addr(1, 100), 100);
        for _ in 0..=MAX_BACKOFF_DOUBLINGS {
            book.failed(addr(1, 0).key());
        }
        book.attempted(addr(1, 0).key(), 100);
        let retry = 100 + MAX_RETRY_SECONDS;
        assert!(book.candidate(&[], retry - 1, &mut rng).is_none());
        assert!(book.candidate(&[], retry, &mut rng).is_some());
    }

    #[test]
    fn failed_candidates_back_off_even_when_announced_again() {
        let mut book = AddressBook::new();
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let a = addr(1, 100);
        book.add(a, 100);
        book.attempted(a.key(), 100);
        book.failed(a.key());
        book.add(addr(1, 110), 110);
        assert!(book.candidate(&[], 159, &mut rng).is_none());
        assert!(book.candidate(&[], 160, &mut rng).is_some());
        book.attempted(a.key(), 160);
        assert!(book.candidate(&[], 279, &mut rng).is_none());
        assert!(book.candidate(&[], 280, &mut rng).is_some());
    }

    fn saved_book() -> AddressBook {
        let mut book = AddressBook::new();
        book.add(addr(3, 100), 100);
        book.add(addr(1, 100), 100);
        book.add(addr(2, 100), 100);
        book.connected(addr(2, 0).key(), 150);
        book
    }

    #[test]
    fn snapshots_roundtrip_in_canonical_order() {
        let snapshot = saved_book().snapshot();
        let keys: Vec<_> = snapshot.entries().iter().map(|s| s.addr.key()).collect();
        assert_eq!(
            keys,
            vec![addr(1, 0).key(), addr(2, 0).key(), addr(3, 0).key()]
        );
        assert_eq!(snapshot.entries()[1].verified_at, Some(150));
        let bytes = snapshot.to_bytes();
        assert_eq!(Snapshot::from_bytes(&bytes).unwrap(), snapshot);
        assert_eq!(bytes, saved_book().snapshot().to_bytes(), "deterministic");
        assert_eq!(bytes.len(), 1 + 4 + 3 * (16 + 2 + 8 + 1) + 8);
    }

    #[test]
    fn snapshots_reject_garbage() {
        let good = saved_book().snapshot().to_bytes();
        let mut bad_version = good.clone();
        bad_version[0] = 2;
        let mut bad_flag = good.clone();
        bad_flag[1 + 4 + 26] = 2;
        let mut too_many = good.clone();
        too_many[1..5].copy_from_slice(&u32::try_from(MAX_KNOWN + 1).unwrap().to_le_bytes());
        let mut repeated = AddressBook::new();
        repeated.add(addr(1, 100), 100);
        let one = repeated.snapshot().to_bytes();
        let mut twice = one.clone();
        twice[1..5].copy_from_slice(&2u32.to_le_bytes());
        twice.extend_from_slice(&one[5..]);
        let mut reversed = good[..5].to_vec();
        let entries = &good[5..];
        reversed.extend_from_slice(&entries[27..54]);
        reversed.extend_from_slice(&entries[..27]);
        reversed.extend_from_slice(&entries[54..]);
        let trailing = [good.as_slice(), &[0]].concat();
        for (name, bytes) in [
            ("empty", Vec::new()),
            ("version", bad_version),
            ("flag", bad_flag),
            ("count", too_many),
            ("duplicate", twice),
            ("order", reversed),
            ("truncated", good[..good.len() - 1].to_vec()),
            ("trailing", trailing),
        ] {
            assert!(Snapshot::from_bytes(&bytes).is_err(), "{name} accepted");
        }
    }

    #[test]
    fn restored_books_keep_verification_under_gossip_rules() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let mut book = AddressBook::new();
        let added = book.restore(saved_book().snapshot(), 200, |a| a.ip != addr(3, 0).ip);
        assert_eq!(added, 2, "the policy filter drops one");
        assert!(book.verified(addr(2, 0).key(), 200));
        assert!(!book.verified(addr(1, 0).key(), 200));
        assert_eq!(book.sample(10, 200, &mut rng).len(), 1);
        assert_eq!(
            book.restore(saved_book().snapshot(), 200, |_| true),
            1,
            "known stay"
        );
        assert_eq!(
            AddressBook::new().restore(saved_book().snapshot(), 150 + MAX_AGE + 1, |_| true),
            0
        );
    }

    #[test]
    fn restored_future_verification_is_not_trusted() {
        let mut book = AddressBook::new();
        book.restore(saved_book().snapshot(), 120, |_| true);
        assert_eq!(book.len(), 3);
        assert!(
            !book.verified(addr(2, 0).key(), 120),
            "verified at 150, now is 120"
        );
    }
}
