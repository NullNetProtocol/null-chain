//! Headers-first synchronization: build a locator, accept a chained run
//! of headers, then download the bodies in order with bounded in-flight
//! requests and timeouts.
//!
//! Headers are requested one message at a time and only while the queue
//! of headers awaiting download is below a low-water mark, so the queue
//! never exceeds [`MAX_QUEUED_HEADERS`] however long the peer's chain is.

use std::collections::{HashMap, VecDeque};

use null_protocol::block::{BlockHash, BlockHeader};

use crate::message::{MAX_HEADERS, MAX_LOCATOR};
use crate::{Error, Result};

/// Block requests kept in flight at once.
pub const MAX_IN_FLIGHT: usize = 16;
/// Seconds before an unanswered block request is retried.
pub const REQUEST_TIMEOUT: u64 = 60;
/// More headers are requested only while fewer than this are queued.
pub const HEADERS_LOW_WATER: usize = 2 * MAX_HEADERS;
/// Most headers queued for download at once: the low-water mark plus one
/// full message. A peer that sends more misbehaves.
pub const MAX_QUEUED_HEADERS: usize = HEADERS_LOW_WATER + MAX_HEADERS;

/// Hashes from the tip backwards: the last ten densely, then doubling
/// steps, ending with genesis, so a peer on any fork finds a common point.
pub fn locator(tip_height: u32, hash_at: impl Fn(u32) -> Option<BlockHash>) -> Vec<BlockHash> {
    let mut hashes = Vec::new();
    let mut height = tip_height;
    let mut step = 1u32;
    loop {
        if let Some(hash) = hash_at(height) {
            hashes.push(hash);
        }
        if height == 0 || hashes.len() >= MAX_LOCATOR.saturating_sub(1) {
            break;
        }
        if hashes.len() >= 10 {
            step = step.saturating_mul(2);
        }
        height = height.saturating_sub(step);
    }
    if height != 0 {
        if let Some(genesis) = hash_at(0) {
            hashes.push(genesis);
        }
    }
    hashes
}

/// Progress reported after a headers message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Headers queued for download.
    pub queued: usize,
    /// Whether the peer sent fewer than the maximum, meaning it has no more.
    pub exhausted: bool,
}

/// Download state.
#[derive(Debug)]
pub struct BlockSync {
    queue: VecDeque<BlockHeader>,
    in_flight: HashMap<BlockHash, u64>,
    last_header: Option<BlockHeader>,
    /// A headers request has been sent and not yet answered.
    headers_outstanding: bool,
    /// The peer has sent a short headers message: it has no more.
    exhausted: bool,
}

impl Default for BlockSync {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockSync {
    /// A syncer whose first headers request, built from a locator by the
    /// caller, has just been sent.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            in_flight: HashMap::new(),
            last_header: None,
            headers_outstanding: true,
            exhausted: false,
        }
    }

    /// Whether the peer has sent everything it has.
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Whether nothing is queued or in flight.
    pub fn is_idle(&self) -> bool {
        self.queue.is_empty() && self.in_flight.is_empty()
    }

    /// Headers queued but not yet requested.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Requests in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// The last header accepted, the point to build the next locator from.
    pub fn last_header(&self) -> Option<&BlockHeader> {
        self.last_header.as_ref()
    }

    /// Accepts a headers message. `known` says whether we already have
    /// the block, so those are skipped; the rest must chain, from a known
    /// parent or from the last accepted header.
    ///
    /// # Errors
    /// Returns [`Error::BadHeaders`] on a gap, an out-of-order header, or
    /// more headers than the queue may hold.
    pub fn on_headers(
        &mut self,
        headers: &[BlockHeader],
        known: impl Fn(&BlockHash) -> bool,
    ) -> Result<Progress> {
        self.headers_outstanding = false;
        self.exhausted = headers.len() < MAX_HEADERS;
        if self.queue.len().saturating_add(headers.len()) > MAX_QUEUED_HEADERS {
            return Err(Error::BadHeaders("queue full"));
        }
        let mut queued: usize = 0;
        for header in headers {
            let hash = header.hash();
            let chains = known(&header.prev_hash)
                || self.last_header.as_ref().is_some_and(|last| {
                    last.hash() == header.prev_hash
                        && last.height.saturating_add(1) == header.height
                });
            if !chains {
                return Err(Error::BadHeaders("gap"));
            }
            self.last_header = Some(header.clone());
            if known(&hash) {
                continue;
            }
            self.queue.push_back(header.clone());
            queued = queued.saturating_add(1);
        }
        Ok(Progress {
            queued,
            exhausted: self.exhausted,
        })
    }

    /// The header to continue from if more headers should be requested
    /// now: the peer has more, no request is outstanding, and the queue
    /// is below the low-water mark. Marks the request as sent.
    pub fn next_headers_request(&mut self) -> Option<BlockHash> {
        if self.exhausted || self.headers_outstanding || self.queue.len() >= HEADERS_LOW_WATER {
            return None;
        }
        let from = self.last_header.as_ref()?.hash();
        self.headers_outstanding = true;
        Some(from)
    }

    /// Block hashes to request now, filling the in-flight window.
    pub fn next_requests(&mut self, now: u64) -> Vec<BlockHash> {
        let mut requests = Vec::new();
        while self.in_flight.len() < MAX_IN_FLIGHT {
            let Some(header) = self.queue.pop_front() else {
                break;
            };
            let hash = header.hash();
            self.in_flight.insert(hash, now);
            requests.push(hash);
        }
        requests
    }

    /// Records a received block; returns whether it was expected.
    pub fn on_block(&mut self, hash: &BlockHash) -> bool {
        self.in_flight.remove(hash).is_some()
    }

    /// Requests that have timed out, re-queued for another peer.
    pub fn timeouts(&mut self, now: u64) -> Vec<BlockHash> {
        let expired: Vec<BlockHash> = self
            .in_flight
            .iter()
            .filter(|(_, sent)| now.saturating_sub(**sent) >= REQUEST_TIMEOUT)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &expired {
            self.in_flight.remove(hash);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use null_crypto::pallas;
    use null_protocol::block::empty_header;
    use null_protocol::transaction::Anchor;

    use super::*;

    fn chain(len: u32) -> Vec<BlockHeader> {
        let mut out: Vec<BlockHeader> = Vec::new();
        for height in 0..len {
            let prev = out.last().map_or(BlockHash::ZERO, BlockHeader::hash);
            out.push(empty_header(
                height,
                prev,
                Anchor::from_base(pallas::Base::from(u64::from(height))),
            ));
        }
        out
    }

    #[test]
    fn locator_is_dense_then_sparse_and_ends_at_genesis() {
        let headers = chain(100);
        let hashes: Vec<BlockHash> = headers.iter().map(BlockHeader::hash).collect();
        let loc = locator(99, |h| hashes.get(h as usize).copied());
        assert_eq!(loc[0], hashes[99]);
        assert_eq!(loc[9], hashes[90]);
        assert_eq!(loc[10], hashes[88]);
        assert_eq!(loc[11], hashes[84]);
        assert_eq!(*loc.last().unwrap(), hashes[0]);
        assert!(loc.len() <= MAX_LOCATOR);
        assert_eq!(
            locator(0, |h| hashes.get(h as usize).copied()),
            vec![hashes[0]]
        );
    }

    #[test]
    fn headers_chain_are_queued_and_downloaded_in_order() {
        let headers = chain(5);
        let genesis = headers[0].hash();
        let mut sync = BlockSync::new();
        let progress = sync.on_headers(&headers[1..], |h| *h == genesis).unwrap();
        assert_eq!(
            progress,
            Progress {
                queued: 4,
                exhausted: true
            }
        );
        assert_eq!(sync.last_header().unwrap().height, 4);
        let requests = sync.next_requests(0);
        assert_eq!(
            requests,
            headers[1..]
                .iter()
                .map(BlockHeader::hash)
                .collect::<Vec<_>>()
        );
        assert!(!sync.on_block(&BlockHash::ZERO));
        for hash in &requests {
            assert!(sync.on_block(hash));
        }
        assert!(sync.is_idle());
    }

    #[test]
    fn known_headers_are_skipped_and_gaps_are_rejected() {
        let headers = chain(5);
        let known = [headers[0].hash(), headers[1].hash()];
        let mut sync = BlockSync::new();
        let progress = sync
            .on_headers(&headers[1..], |h| known.contains(h))
            .unwrap();
        assert_eq!(progress.queued, 3);
        let mut bad = BlockSync::new();
        assert!(matches!(
            bad.on_headers(&headers[2..], |h| *h == headers[0].hash()),
            Err(Error::BadHeaders(_))
        ));
        let mut continued = BlockSync::new();
        continued
            .on_headers(&headers[1..3], |h| *h == headers[0].hash())
            .unwrap();
        assert_eq!(
            continued
                .on_headers(&headers[3..], |_| false)
                .unwrap()
                .queued,
            2
        );
    }

    /// Feeds `headers` in full-size messages and returns the queue length
    /// after each.
    fn feed_full_messages(sync: &mut BlockSync, headers: &[BlockHeader]) -> Vec<usize> {
        headers
            .chunks(MAX_HEADERS)
            .map(|chunk| {
                sync.on_headers(chunk, |_| false).unwrap();
                sync.queued()
            })
            .collect()
    }

    #[test]
    fn header_requests_pause_at_the_low_water_mark_and_resume_as_blocks_arrive() {
        let headers = chain(u32::try_from(HEADERS_LOW_WATER + 1).unwrap());
        let mut sync = BlockSync::new();
        assert_eq!(
            sync.next_headers_request(),
            None,
            "the first request is outstanding"
        );
        sync.on_headers(&headers[1..=MAX_HEADERS], |h| *h == headers[0].hash())
            .unwrap();
        assert!(!sync.exhausted());
        let from = sync.next_headers_request().unwrap();
        assert_eq!(from, headers[MAX_HEADERS].hash());
        assert_eq!(sync.next_headers_request(), None, "one at a time");

        feed_full_messages(&mut sync, &headers[MAX_HEADERS + 1..]);
        assert_eq!(sync.queued(), HEADERS_LOW_WATER);
        assert_eq!(sync.next_headers_request(), None, "queue at the mark");

        let requested = sync.next_requests(0);
        for hash in &requested {
            sync.on_block(hash);
        }
        assert!(sync.next_headers_request().is_some(), "queue drained");
    }

    #[test]
    fn a_full_queue_rejects_further_headers_and_exhaustion_stops_requests() {
        let headers = chain(u32::try_from(MAX_QUEUED_HEADERS + 2).unwrap());
        let mut sync = BlockSync::new();
        sync.on_headers(&headers[1..=MAX_HEADERS], |h| *h == headers[0].hash())
            .unwrap();
        let lengths = feed_full_messages(&mut sync, &headers[MAX_HEADERS + 1..=MAX_QUEUED_HEADERS]);
        assert_eq!(lengths.last(), Some(&MAX_QUEUED_HEADERS));
        assert!(matches!(
            sync.on_headers(&headers[MAX_QUEUED_HEADERS + 1..], |_| false),
            Err(Error::BadHeaders("queue full"))
        ));

        let mut short = BlockSync::new();
        short
            .on_headers(&headers[1..3], |h| *h == headers[0].hash())
            .unwrap();
        assert!(short.exhausted());
        assert_eq!(short.next_headers_request(), None);
    }

    #[test]
    fn in_flight_is_bounded_and_timeouts_requeue() {
        let headers = chain(40);
        let mut sync = BlockSync::new();
        sync.on_headers(&headers[1..], |h| *h == headers[0].hash())
            .unwrap();
        let first = sync.next_requests(0);
        assert_eq!(first.len(), MAX_IN_FLIGHT);
        assert_eq!(sync.queued(), 39 - MAX_IN_FLIGHT);
        assert!(sync.next_requests(1).is_empty());
        assert!(sync.timeouts(REQUEST_TIMEOUT - 1).is_empty());
        let expired = sync.timeouts(REQUEST_TIMEOUT);
        assert_eq!(expired.len(), MAX_IN_FLIGHT);
        assert_eq!(sync.in_flight(), 0);
    }
}
