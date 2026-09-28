//! The message set. Every message is `tag || payload` with the canonical
//! encodings of the protocol crate; lists carry a `u32` count bounded by
//! a per-list limit. There is no user agent and no optional field: every
//! node speaks exactly the same bytes.

use null_protocol::block::{Block, BlockHash, BlockHeader};
use null_protocol::bytes::{Encodable, Reader, Writer};
use null_protocol::consensus::MAX_BLOCK_TRANSACTIONS;
use null_protocol::transaction::{Transaction, TxId};

use crate::{Error, Result};

/// The only protocol version.
pub const PROTOCOL_VERSION: u32 = 1;
/// Upper bound on one encoded message, comfortably above a full block.
pub const MAX_MESSAGE_LEN: usize = 40 * 1024 * 1024;
/// Most inventory items in one message.
pub const MAX_INVENTORY: usize = 50_000;
/// Most headers in one message.
pub const MAX_HEADERS: usize = 2_000;
/// Most locator hashes in one message.
pub const MAX_LOCATOR: usize = 64;
/// Most addresses in one message.
pub const MAX_ADDRESSES: usize = 1_000;

/// What a node announces about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    /// Protocol version.
    pub version: u32,
    /// Random nonce to detect connecting to ourselves.
    pub nonce: u64,
    /// Height of the sender's tip.
    pub best_height: u32,
    /// Genesis hash, which identifies the network.
    pub genesis: BlockHash,
    /// Sender's clock, seconds since the epoch.
    pub timestamp: u64,
}

/// A network address: IPv6, with IPv4 mapped into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerAddr {
    /// The address bytes.
    pub ip: [u8; 16],
    /// The port.
    pub port: u16,
    /// When the address was last seen alive, seconds since the epoch.
    pub last_seen: u64,
}

impl PeerAddr {
    /// An IPv4 address, mapped.
    pub fn v4(octets: [u8; 4], port: u16, last_seen: u64) -> Self {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..].copy_from_slice(&octets);
        Self {
            ip,
            port,
            last_seen,
        }
    }

    /// The address without its timestamp, for use as a key.
    pub fn key(&self) -> ([u8; 16], u16) {
        (self.ip, self.port)
    }
}

/// A block or transaction reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Inventory {
    /// A block by hash.
    Block(BlockHash),
    /// A transaction by id.
    Tx(TxId),
}

/// A protocol message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Handshake: who we are.
    Version(VersionInfo),
    /// Handshake: version accepted.
    Verack,
    /// Keepalive request.
    Ping(u64),
    /// Keepalive reply.
    Pong(u64),
    /// Ask for known addresses.
    GetAddr,
    /// Known addresses.
    Addr(Vec<PeerAddr>),
    /// Ask for headers after the first locator hash we recognize.
    GetHeaders {
        /// Hashes from our tip backwards, dense then sparse.
        locator: Vec<BlockHash>,
        /// Stop at this hash, or zero for as many as allowed.
        stop: BlockHash,
    },
    /// Headers in chain order.
    Headers(Vec<BlockHeader>),
    /// Announce items we have.
    Inv(Vec<Inventory>),
    /// Request items.
    GetData(Vec<Inventory>),
    /// Items we do not have.
    NotFound(Vec<Inventory>),
    /// A full block.
    Block(Box<Block>),
    /// A transaction in the fluff phase, to be relayed to everyone.
    Tx(Box<Transaction>),
    /// A transaction in the stem phase, to be relayed to one peer.
    StemTx(Box<Transaction>),
    /// A new block as its header, its coinbase, and the ids of the other
    /// transactions, which the receiver usually already has.
    CompactBlock(Box<CompactBlock>),
    /// Request the transactions at these indices of a compact block.
    GetBlockTxn {
        /// The block.
        hash: BlockHash,
        /// Indices into the block's transaction list, ascending.
        indices: Vec<u32>,
    },
    /// The requested transactions of a block, in index order.
    BlockTxn {
        /// The block.
        hash: BlockHash,
        /// The transactions.
        transactions: Vec<Transaction>,
    },
}

/// A block with the transactions the receiver likely has left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactBlock {
    /// The header.
    pub header: BlockHeader,
    /// The coinbase, which no mempool holds.
    pub coinbase: Transaction,
    /// Ids of the remaining transactions, in block order.
    pub txids: Vec<TxId>,
}

impl CompactBlock {
    /// The compact form of `block`.
    ///
    /// # Errors
    /// Fails if the block has no transactions.
    pub fn from_block(block: &Block) -> Result<Self> {
        let (coinbase, rest) = block.transactions().split_first().ok_or(Error::Protocol(
            null_protocol::Error::InvalidBlock("no coinbase"),
        ))?;
        Ok(Self {
            header: block.header().clone(),
            coinbase: coinbase.clone(),
            txids: rest.iter().map(Transaction::txid).collect(),
        })
    }

    /// The block hash.
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }
}

mod tag {
    pub const VERSION: u8 = 1;
    pub const VERACK: u8 = 2;
    pub const PING: u8 = 3;
    pub const PONG: u8 = 4;
    pub const GET_ADDR: u8 = 5;
    pub const ADDR: u8 = 6;
    pub const GET_HEADERS: u8 = 7;
    pub const HEADERS: u8 = 8;
    pub const INV: u8 = 9;
    pub const GET_DATA: u8 = 10;
    pub const NOT_FOUND: u8 = 11;
    pub const BLOCK: u8 = 12;
    pub const TX: u8 = 13;
    pub const STEM_TX: u8 = 14;
    pub const COMPACT_BLOCK: u8 = 15;
    pub const GET_BLOCK_TXN: u8 = 16;
    pub const BLOCK_TXN: u8 = 17;
}

impl Message {
    /// The type tag.
    pub fn tag(&self) -> u8 {
        match self {
            Self::Version(_) => tag::VERSION,
            Self::Verack => tag::VERACK,
            Self::Ping(_) => tag::PING,
            Self::Pong(_) => tag::PONG,
            Self::GetAddr => tag::GET_ADDR,
            Self::Addr(_) => tag::ADDR,
            Self::GetHeaders { .. } => tag::GET_HEADERS,
            Self::Headers(_) => tag::HEADERS,
            Self::Inv(_) => tag::INV,
            Self::GetData(_) => tag::GET_DATA,
            Self::NotFound(_) => tag::NOT_FOUND,
            Self::Block(_) => tag::BLOCK,
            Self::Tx(_) => tag::TX,
            Self::StemTx(_) => tag::STEM_TX,
            Self::CompactBlock(_) => tag::COMPACT_BLOCK,
            Self::GetBlockTxn { .. } => tag::GET_BLOCK_TXN,
            Self::BlockTxn { .. } => tag::BLOCK_TXN,
        }
    }

    /// Encodes to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.put_u8(self.tag());
        match self {
            Self::Version(v) => {
                w.put(&v.version.to_le_bytes())
                    .put_u64_le(v.nonce)
                    .put(&v.best_height.to_le_bytes())
                    .put(v.genesis.as_bytes())
                    .put_u64_le(v.timestamp);
            }
            Self::Verack | Self::GetAddr => {}
            Self::Ping(n) | Self::Pong(n) => {
                w.put_u64_le(*n);
            }
            Self::Addr(addrs) => {
                put_count(&mut w, addrs.len());
                for a in addrs {
                    w.put(&a.ip)
                        .put(&a.port.to_le_bytes())
                        .put_u64_le(a.last_seen);
                }
            }
            Self::GetHeaders { locator, stop } => {
                put_count(&mut w, locator.len());
                for h in locator {
                    w.put(h.as_bytes());
                }
                w.put(stop.as_bytes());
            }
            Self::Headers(headers) => {
                put_count(&mut w, headers.len());
                for h in headers {
                    h.write(&mut w);
                }
            }
            Self::Inv(items) | Self::GetData(items) | Self::NotFound(items) => {
                put_count(&mut w, items.len());
                for item in items {
                    match item {
                        Inventory::Block(h) => {
                            w.put_u8(0).put(h.as_bytes());
                        }
                        Inventory::Tx(id) => {
                            w.put_u8(1).put(id.as_bytes());
                        }
                    }
                }
            }
            Self::Block(b) => b.write(&mut w),
            Self::Tx(t) | Self::StemTx(t) => t.write(&mut w),
            Self::CompactBlock(c) => {
                c.header.write(&mut w);
                c.coinbase.write(&mut w);
                put_count(&mut w, c.txids.len());
                for id in &c.txids {
                    w.put(id.as_bytes());
                }
            }
            Self::GetBlockTxn { hash, indices } => {
                w.put(hash.as_bytes());
                put_count(&mut w, indices.len());
                for i in indices {
                    w.put(&i.to_le_bytes());
                }
            }
            Self::BlockTxn { hash, transactions } => {
                w.put(hash.as_bytes());
                put_count(&mut w, transactions.len());
                for t in transactions {
                    t.write(&mut w);
                }
            }
        }
        w.into_bytes()
    }

    /// Decodes a complete message.
    ///
    /// # Errors
    /// Fails on an unknown tag, an over-long list, or malformed payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let tag = r.take_u8()?;
        let message = match tag {
            tag::VERSION => Self::Version(VersionInfo {
                version: u32::from_le_bytes(r.take_array()?),
                nonce: r.take_u64_le()?,
                best_height: u32::from_le_bytes(r.take_array()?),
                genesis: BlockHash::from_bytes(r.take_array()?),
                timestamp: r.take_u64_le()?,
            }),
            tag::VERACK => Self::Verack,
            tag::PING => Self::Ping(r.take_u64_le()?),
            tag::PONG => Self::Pong(r.take_u64_le()?),
            tag::GET_ADDR => Self::GetAddr,
            tag::ADDR => {
                let count = take_count(&mut r, MAX_ADDRESSES, "addresses")?;
                let addrs = (0..count)
                    .map(|_| {
                        Ok(PeerAddr {
                            ip: r.take_array()?,
                            port: u16::from_le_bytes(r.take_array()?),
                            last_seen: r.take_u64_le()?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Self::Addr(addrs)
            }
            tag::GET_HEADERS => {
                let count = take_count(&mut r, MAX_LOCATOR, "locator")?;
                let locator = (0..count)
                    .map(|_| Ok(BlockHash::from_bytes(r.take_array()?)))
                    .collect::<Result<Vec<_>>>()?;
                Self::GetHeaders {
                    locator,
                    stop: BlockHash::from_bytes(r.take_array()?),
                }
            }
            tag::HEADERS => {
                let count = take_count(&mut r, MAX_HEADERS, "headers")?;
                let headers = (0..count)
                    .map(|_| Ok(BlockHeader::read(&mut r)?))
                    .collect::<Result<Vec<_>>>()?;
                Self::Headers(headers)
            }
            tag::INV | tag::GET_DATA | tag::NOT_FOUND => {
                let count = take_count(&mut r, MAX_INVENTORY, "inventory")?;
                let items = (0..count)
                    .map(|_| read_inventory(&mut r))
                    .collect::<Result<Vec<_>>>()?;
                match tag {
                    tag::INV => Self::Inv(items),
                    tag::GET_DATA => Self::GetData(items),
                    _ => Self::NotFound(items),
                }
            }
            tag::BLOCK => Self::Block(Box::new(Block::read(&mut r)?)),
            tag::TX => Self::Tx(Box::new(Transaction::read(&mut r)?)),
            tag::STEM_TX => Self::StemTx(Box::new(Transaction::read(&mut r)?)),
            tag::COMPACT_BLOCK => {
                let header = BlockHeader::read(&mut r)?;
                let coinbase = Transaction::read(&mut r)?;
                let count = take_count(&mut r, MAX_BLOCK_TRANSACTIONS, "txids")?;
                let txids = (0..count)
                    .map(|_| Ok(TxId::from_bytes(r.take_array()?)))
                    .collect::<Result<Vec<_>>>()?;
                Self::CompactBlock(Box::new(CompactBlock {
                    header,
                    coinbase,
                    txids,
                }))
            }
            tag::GET_BLOCK_TXN => {
                let hash = BlockHash::from_bytes(r.take_array()?);
                let count = take_count(&mut r, MAX_BLOCK_TRANSACTIONS, "indices")?;
                let indices = (0..count)
                    .map(|_| Ok(u32::from_le_bytes(r.take_array()?)))
                    .collect::<Result<Vec<_>>>()?;
                Self::GetBlockTxn { hash, indices }
            }
            tag::BLOCK_TXN => {
                let hash = BlockHash::from_bytes(r.take_array()?);
                let count = take_count(&mut r, MAX_BLOCK_TRANSACTIONS, "transactions")?;
                let transactions = (0..count)
                    .map(|_| Ok(Transaction::read(&mut r)?))
                    .collect::<Result<Vec<_>>>()?;
                Self::BlockTxn { hash, transactions }
            }
            other => return Err(Error::UnknownTag(other)),
        };
        r.finish()?;
        Ok(message)
    }
}

fn put_count(w: &mut Writer, count: usize) {
    // Every list is bounded by a limit far below u32::MAX.
    w.put(&u32::try_from(count).unwrap_or(u32::MAX).to_le_bytes());
}

fn take_count(r: &mut Reader<'_>, max: usize, what: &'static str) -> Result<usize> {
    let count = usize::try_from(u32::from_le_bytes(r.take_array()?))
        .map_err(|_| Error::ListTooLong(what))?;
    if count > max {
        return Err(Error::ListTooLong(what));
    }
    Ok(count)
}

fn read_inventory(r: &mut Reader<'_>) -> Result<Inventory> {
    match r.take_u8()? {
        0 => Ok(Inventory::Block(BlockHash::from_bytes(r.take_array()?))),
        1 => Ok(Inventory::Tx(TxId::from_bytes(r.take_array()?))),
        _ => Err(Error::Protocol(null_protocol::Error::Malformed(
            "inventory kind",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use null_crypto::pallas;
    use null_protocol::block::empty_header;
    use null_protocol::transaction::Anchor;

    use super::*;

    fn samples() -> Vec<Message> {
        let header = empty_header(
            3,
            BlockHash::from_bytes([1; 32]),
            Anchor::from_base(pallas::Base::from(2u64)),
        );
        vec![
            Message::Version(VersionInfo {
                version: PROTOCOL_VERSION,
                nonce: 7,
                best_height: 9,
                genesis: BlockHash::from_bytes([4; 32]),
                timestamp: 1_000,
            }),
            Message::Verack,
            Message::Ping(1),
            Message::Pong(2),
            Message::GetAddr,
            Message::Addr(vec![PeerAddr::v4([127, 0, 0, 1], 8333, 5)]),
            Message::GetHeaders {
                locator: vec![BlockHash::from_bytes([3; 32])],
                stop: BlockHash::ZERO,
            },
            Message::Headers(vec![header.clone(), header.clone()]),
            Message::Inv(vec![
                Inventory::Block(BlockHash::ZERO),
                Inventory::Tx(TxId::from_bytes([8; 32])),
            ]),
            Message::GetData(vec![Inventory::Tx(TxId::from_bytes([8; 32]))]),
            Message::NotFound(vec![]),
            Message::Block(Box::new(Block::new(header.clone(), Vec::new()))),
            Message::GetBlockTxn {
                hash: BlockHash::ZERO,
                indices: vec![1, 3],
            },
            Message::BlockTxn {
                hash: BlockHash::ZERO,
                transactions: vec![],
            },
        ]
    }

    #[test]
    fn every_message_roundtrips() {
        for message in samples() {
            let bytes = message.encode();
            assert_eq!(
                Message::decode(&bytes).unwrap(),
                message,
                "{}",
                message.tag()
            );
        }
    }

    #[test]
    fn tags_are_distinct() {
        let mut tags: Vec<u8> = samples().iter().map(Message::tag).collect();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), samples().len());
    }

    #[test]
    fn unknown_tags_trailing_bytes_and_long_lists_are_rejected() {
        assert!(matches!(
            Message::decode(&[200]),
            Err(Error::UnknownTag(200))
        ));
        let mut bytes = Message::Verack.encode();
        bytes.push(0);
        assert!(Message::decode(&bytes).is_err());
        let mut long = vec![tag::INV];
        long.extend_from_slice(&(u32::MAX).to_le_bytes());
        assert!(matches!(
            Message::decode(&long),
            Err(Error::ListTooLong("inventory"))
        ));
        assert!(Message::decode(&[tag::PING, 1, 2]).is_err(), "truncated");
    }

    #[test]
    fn compact_block_needs_a_coinbase() {
        let header = empty_header(
            0,
            BlockHash::ZERO,
            Anchor::from_base(pallas::Base::from(1u64)),
        );
        assert!(CompactBlock::from_block(&Block::new(header, Vec::new())).is_err());
    }

    #[test]
    fn mapped_v4_addresses_have_the_standard_prefix() {
        let a = PeerAddr::v4([10, 0, 0, 1], 1, 0);
        assert_eq!(&a.ip[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(a.key(), (a.ip, 1));
    }
}
