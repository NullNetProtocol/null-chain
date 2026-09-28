//! `cargo +nightly fuzz run decode` from the repository root.
#![no_main]

use null_p2p::codec::Framer;
use null_p2p::message::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::decode(data) {
        assert_eq!(message.encode(), data);
    }
    let mut framer = Framer::new();
    framer.push(data);
    while let Ok(Some(_)) = framer.next_message() {}
});
