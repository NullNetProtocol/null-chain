//! Property tests: the decoder and framer never panic on any input, and
//! mutated valid messages either decode or fail cleanly.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use null_p2p::codec::{frame, Framer};
use null_p2p::message::{Inventory, Message, PeerAddr, VersionInfo};
use null_protocol::block::BlockHash;
use null_protocol::transaction::TxId;
use proptest::prelude::*;

fn samples() -> Vec<Message> {
    vec![
        Message::Version(VersionInfo {
            version: 1,
            nonce: 2,
            best_height: 3,
            genesis: BlockHash::ZERO,
            timestamp: 4,
        }),
        Message::Ping(9),
        Message::Addr(vec![PeerAddr::v4([1, 2, 3, 4], 5, 6)]),
        Message::GetHeaders {
            locator: vec![BlockHash::from_bytes([7; 32])],
            stop: BlockHash::ZERO,
        },
        Message::Inv(vec![Inventory::Tx(TxId::from_bytes([8; 32]))]),
        Message::GetBlockTxn {
            hash: BlockHash::ZERO,
            indices: vec![1],
        },
    ]
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_the_decoder(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Message::decode(&bytes);
        let mut framer = Framer::new();
        framer.push(&bytes);
        while let Ok(Some(_)) = framer.next_message() {}
    }

    #[test]
    fn mutated_messages_decode_or_fail_cleanly(
        which in 0usize..6,
        position in 0usize..200,
        flip in any::<u8>(),
        truncate in 0usize..64,
    ) {
        let mut bytes = samples()[which].encode();
        if position < bytes.len() {
            bytes[position] ^= flip;
        }
        let keep = bytes.len().saturating_sub(truncate);
        bytes.truncate(keep);
        if let Ok(message) = Message::decode(&bytes) {
            prop_assert_eq!(message.encode(), bytes, "a decoded message re-encodes to the same bytes");
        }
        let mut framer = Framer::new();
        framer.push(&frame(&samples()[which]));
        prop_assert_eq!(framer.next_message().unwrap(), Some(samples()[which].clone()));
    }
}
