//! One peer's connection state: handshake, keepalive, misbehavior.

use std::collections::HashSet;

use null_protocol::block::BlockHash;

use crate::message::{Inventory, Message, VersionInfo, PROTOCOL_VERSION};

/// Misbehavior score at which a peer is dropped and banned.
pub const BAN_THRESHOLD: u32 = 100;
/// Seconds between pings.
pub const PING_INTERVAL: u64 = 60;
/// Seconds without a pong before disconnecting.
pub const PING_TIMEOUT: u64 = 120;
/// Inventory items remembered per peer, to avoid re-announcing.
pub const KNOWN_INVENTORY_CAP: usize = 50_000;
/// Disconnect reason when the remote side is this node: its version
/// carries our own nonce.
pub const SELF_CONNECTION: &str = "connected to self";

/// Who opened the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// We connected to them.
    Outbound,
    /// They connected to us.
    Inbound,
}

/// Handshake progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Start,
    VersionSent,
    Ready,
}

/// What the caller must do after feeding a message or the clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Send this message to the peer.
    Send(Message),
    /// The handshake finished; the peer announced this.
    Ready(VersionInfo),
    /// Drop the connection for this reason, banning if `ban` is set.
    Disconnect {
        /// Why.
        reason: &'static str,
        /// Whether to ban the address.
        ban: bool,
    },
}

/// The state of one peer.
#[derive(Debug)]
pub struct Peer {
    direction: Direction,
    stage: Stage,
    ours: VersionInfo,
    theirs: Option<VersionInfo>,
    verack_received: bool,
    score: u32,
    last_ping_sent: Option<(u64, u64)>,
    last_activity: u64,
    known: HashSet<Inventory>,
}

impl Peer {
    /// A new peer. Outbound peers send their version immediately.
    pub fn new(direction: Direction, ours: VersionInfo, now: u64) -> (Self, Vec<Event>) {
        let peer = Self {
            direction,
            stage: Stage::Start,
            ours,
            theirs: None,
            verack_received: false,
            score: 0,
            last_ping_sent: None,
            last_activity: now,
            known: HashSet::new(),
        };
        let mut peer = peer;
        let events = match direction {
            Direction::Outbound => vec![peer.send_version()],
            Direction::Inbound => Vec::new(),
        };
        (peer, events)
    }

    /// Whether the handshake is complete.
    pub fn is_ready(&self) -> bool {
        self.stage == Stage::Ready
    }

    /// The direction.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// What the peer announced, once known.
    pub fn version(&self) -> Option<&VersionInfo> {
        self.theirs.as_ref()
    }

    /// Current misbehavior score.
    pub fn score(&self) -> u32 {
        self.score
    }

    fn send_version(&mut self) -> Event {
        self.stage = Stage::VersionSent;
        Event::Send(Message::Version(self.ours.clone()))
    }

    /// Adds misbehavior points; at the threshold the peer is dropped.
    pub fn misbehave(&mut self, points: u32, reason: &'static str) -> Option<Event> {
        self.score = self.score.saturating_add(points);
        (self.score >= BAN_THRESHOLD).then_some(Event::Disconnect { reason, ban: true })
    }

    /// Handles a message from the peer.
    pub fn handle(&mut self, message: &Message, now: u64) -> Vec<Event> {
        self.last_activity = now;
        match (self.stage, message) {
            (Stage::Start | Stage::VersionSent, Message::Version(theirs)) => {
                self.on_version(theirs.clone())
            }
            (Stage::VersionSent, Message::Verack) => {
                self.verack_received = true;
                self.maybe_ready()
            }
            (Stage::Ready, Message::Ping(n)) => vec![Event::Send(Message::Pong(*n))],
            (Stage::Ready, Message::Pong(n)) => {
                if self.last_ping_sent.is_some_and(|(nonce, _)| nonce == *n) {
                    self.last_ping_sent = None;
                }
                Vec::new()
            }
            (Stage::Ready, Message::Version(_) | Message::Verack) => {
                vec![Event::Disconnect {
                    reason: "duplicate handshake",
                    ban: true,
                }]
            }
            (Stage::Ready, _) => Vec::new(),
            (_, _) => vec![Event::Disconnect {
                reason: "message before handshake",
                ban: true,
            }],
        }
    }

    fn on_version(&mut self, theirs: VersionInfo) -> Vec<Event> {
        if theirs.version != PROTOCOL_VERSION {
            return vec![Event::Disconnect {
                reason: "protocol version mismatch",
                ban: false,
            }];
        }
        if theirs.genesis != self.ours.genesis {
            return vec![Event::Disconnect {
                reason: "different network",
                ban: true,
            }];
        }
        if theirs.nonce == self.ours.nonce {
            return vec![Event::Disconnect {
                reason: SELF_CONNECTION,
                ban: false,
            }];
        }
        self.theirs = Some(theirs);
        let mut events = Vec::new();
        if self.stage == Stage::Start {
            events.push(self.send_version());
        }
        events.push(Event::Send(Message::Verack));
        events.extend(self.maybe_ready());
        events
    }

    fn maybe_ready(&mut self) -> Vec<Event> {
        match (&self.theirs, self.verack_received, self.stage) {
            (Some(theirs), true, Stage::VersionSent) => {
                self.stage = Stage::Ready;
                vec![Event::Ready(theirs.clone())]
            }
            _ => Vec::new(),
        }
    }

    /// Drives keepalives: pings when idle, disconnects when unanswered.
    pub fn tick(&mut self, now: u64, nonce: u64) -> Vec<Event> {
        if !self.is_ready() {
            return Vec::new();
        }
        match self.last_ping_sent {
            Some((_, sent)) if now.saturating_sub(sent) >= PING_TIMEOUT => {
                vec![Event::Disconnect {
                    reason: "ping timeout",
                    ban: false,
                }]
            }
            None if now.saturating_sub(self.last_activity) >= PING_INTERVAL => {
                self.last_ping_sent = Some((nonce, now));
                vec![Event::Send(Message::Ping(nonce))]
            }
            _ => Vec::new(),
        }
    }

    /// Records that the peer knows `item`; returns whether it was new.
    pub fn mark_known(&mut self, item: Inventory) -> bool {
        if self.known.len() >= KNOWN_INVENTORY_CAP {
            self.known.clear();
        }
        self.known.insert(item)
    }

    /// Whether the peer is known to have `item`.
    pub fn knows(&self, item: &Inventory) -> bool {
        self.known.contains(item)
    }
}

/// Our version announcement for a given tip.
pub fn version_info(nonce: u64, best_height: u32, genesis: BlockHash, now: u64) -> VersionInfo {
    VersionInfo {
        version: PROTOCOL_VERSION,
        nonce,
        best_height,
        genesis,
        timestamp: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(nonce: u64) -> VersionInfo {
        version_info(nonce, 5, BlockHash::from_bytes([1; 32]), 100)
    }

    /// Runs a full handshake between an outbound and an inbound peer.
    fn handshake() -> (Peer, Peer) {
        let (mut out, events) = Peer::new(Direction::Outbound, info(1), 0);
        let (mut inb, none) = Peer::new(Direction::Inbound, info(2), 0);
        assert!(none.is_empty());
        let Event::Send(version) = &events[0] else {
            panic!("outbound sends version")
        };
        let replies = inb.handle(version, 1);
        // Inbound answers with its own version and a verack.
        assert!(matches!(replies[0], Event::Send(Message::Version(_))));
        assert_eq!(replies[1], Event::Send(Message::Verack));
        for reply in &replies {
            if let Event::Send(m) = reply {
                let back = out.handle(m, 2);
                for b in back {
                    if let Event::Send(m) = b {
                        inb.handle(&m, 3);
                    }
                }
            }
        }
        (out, inb)
    }

    #[test]
    fn handshake_reaches_ready_on_both_sides() {
        let (out, inb) = handshake();
        assert!(out.is_ready() && inb.is_ready());
        assert_eq!(out.version().unwrap().nonce, 2);
        assert_eq!(inb.version().unwrap().nonce, 1);
    }

    #[test]
    fn wrong_network_and_self_connection_are_refused() {
        let (mut inb, _) = Peer::new(Direction::Inbound, info(2), 0);
        let mut other = info(9);
        other.genesis = BlockHash::ZERO;
        assert_eq!(
            inb.handle(&Message::Version(other), 1),
            vec![Event::Disconnect {
                reason: "different network",
                ban: true
            }]
        );
        let (mut inb, _) = Peer::new(Direction::Inbound, info(2), 0);
        assert_eq!(
            inb.handle(&Message::Version(info(2)), 1),
            vec![Event::Disconnect {
                reason: SELF_CONNECTION,
                ban: false
            }]
        );
        let (mut inb, _) = Peer::new(Direction::Inbound, info(2), 0);
        let mut old = info(3);
        old.version = 0;
        assert!(matches!(
            inb.handle(&Message::Version(old), 1)[0],
            Event::Disconnect { ban: false, .. }
        ));
    }

    #[test]
    fn messages_before_the_handshake_are_banned() {
        let (mut inb, _) = Peer::new(Direction::Inbound, info(2), 0);
        assert_eq!(
            inb.handle(&Message::Ping(1), 1),
            vec![Event::Disconnect {
                reason: "message before handshake",
                ban: true
            }]
        );
    }

    #[test]
    fn pings_are_answered_and_timeouts_disconnect() {
        let (mut out, _) = handshake();
        assert_eq!(
            out.handle(&Message::Ping(9), 10),
            vec![Event::Send(Message::Pong(9))]
        );
        assert!(out.tick(10, 1).is_empty());
        assert_eq!(
            out.tick(10 + PING_INTERVAL, 42),
            vec![Event::Send(Message::Ping(42))]
        );
        assert!(out.tick(10 + PING_INTERVAL + 1, 43).is_empty());
        assert_eq!(
            out.tick(10 + PING_INTERVAL + PING_TIMEOUT, 44),
            vec![Event::Disconnect {
                reason: "ping timeout",
                ban: false
            }]
        );
        let (mut out, _) = handshake();
        out.tick(PING_INTERVAL, 7);
        out.handle(&Message::Pong(7), PING_INTERVAL + 1);
        // The answered ping does not disconnect; idleness starts a new one.
        assert_eq!(
            out.tick(PING_INTERVAL + PING_TIMEOUT, 8),
            vec![Event::Send(Message::Ping(8))]
        );
    }

    #[test]
    fn misbehavior_accumulates_to_a_ban() {
        let (mut out, _) = handshake();
        assert_eq!(out.misbehave(50, "bad"), None);
        assert_eq!(
            out.misbehave(50, "bad"),
            Some(Event::Disconnect {
                reason: "bad",
                ban: true
            })
        );
        assert_eq!(out.score(), 100);
    }

    #[test]
    fn known_inventory_is_tracked_and_bounded() {
        let (mut out, _) = handshake();
        let item = Inventory::Block(BlockHash::ZERO);
        assert!(out.mark_known(item));
        assert!(!out.mark_known(item));
        assert!(out.knows(&item));
        assert_eq!(out.direction(), Direction::Outbound);
    }
}
