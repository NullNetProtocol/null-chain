//! Reading backend JSON and turning values into display text.

use null_node::config::Network;
use null_protocol::address::Address;
use null_protocol::amount::{COIN, MAX_MONEY};
use serde_json::{json, Value};

/// Shown in place of a value the backend did not report.
pub const MISSING: &str = "—";

/// Characters kept at each end when shortening a hash.
const HASH_EDGE: usize = 10;

/// A field of a JSON object, or `null`.
pub fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

/// A string field, or [`MISSING`].
pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or(MISSING)
}

/// A number field as display text, or [`MISSING`].
pub fn number(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map_or_else(|| MISSING.into(), |n| n.to_string())
}

/// An amount field, sent as a decimal string of smallest units, in NULL
/// with all eight decimal places so no precision is hidden.
pub fn coins(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|v| v.parse::<u64>().ok())
        .map_or_else(
            || MISSING.into(),
            |n| format!("{}.{:08}", n / COIN, n % COIN),
        )
}

/// Middle-elided form of a long identifier, such as a transaction id.
pub fn short_hash(hash: &str) -> String {
    let chars: Vec<char> = hash.chars().collect();
    if chars.len() <= HASH_EDGE.saturating_mul(2) {
        return hash.to_owned();
    }
    let head: String = chars.iter().take(HASH_EDGE).collect();
    let tail: String = chars
        .iter()
        .skip(chars.len().saturating_sub(HASH_EDGE))
        .collect();
    format!("{head}…{tail}")
}

/// Parses a user-entered NULL amount into smallest units, exactly.
pub fn parse_amount(text: &str) -> Result<u64, String> {
    let (whole, fraction) = text.trim().split_once('.').unwrap_or((text.trim(), ""));
    if whole.is_empty()
        || !whole.bytes().all(|c| c.is_ascii_digit())
        || fraction.len() > 8
        || !fraction.bytes().all(|c| c.is_ascii_digit())
    {
        return Err("Enter a positive amount with at most 8 decimal places".into());
    }
    let base = whole.parse::<u64>().ok().and_then(|n| n.checked_mul(COIN));
    let fraction = format!("{fraction:0<8}").parse::<u64>().ok();
    base.zip(fraction)
        .and_then(|(a, b)| a.checked_add(b))
        .filter(|n| *n > 0 && *n <= MAX_MONEY)
        .ok_or_else(|| "Amount is outside the supported range".into())
}

/// Validates a payment form and returns a `sendmany` recipient.
pub fn payment(address: &str, amount: &str, memo: &str, node: &Value) -> Result<Value, String> {
    let network: Network = text(node, "network").parse()?;
    Address::decode(address.trim(), network.address_prefix()).map_err(|e| e.to_string())?;
    null_protocol::memo::Memo::from_text(memo).map_err(|e| e.to_string())?;
    Ok(
        json!({ "address": address.trim(), "amount": parse_amount(amount)?.to_string(), "memo": memo }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_input_is_exact_and_rejects_excess_precision_or_overflow() {
        assert_eq!(parse_amount("0.00000001"), Ok(1));
        assert_eq!(parse_amount("12.34"), Ok(1_234_000_000));
        for value in [
            "0",
            "-1",
            "NaN",
            "1e3",
            "1.000000001",
            "21000001",
            "18446744073709551615",
            "1..2",
        ] {
            assert!(parse_amount(value).is_err(), "{value}");
        }
    }

    #[test]
    fn coins_show_all_eight_decimals_and_mark_missing_values() {
        let value = json!({ "a": "1234000000", "b": "1", "c": 5, "d": "x" });
        assert_eq!(coins(&value, "a"), "12.34000000");
        assert_eq!(coins(&value, "b"), "0.00000001");
        for key in ["c", "d", "absent"] {
            assert_eq!(coins(&value, key), MISSING);
        }
    }

    #[test]
    fn short_hash_keeps_both_ends_and_leaves_short_text_alone() {
        let hash = "0123456789abcdef0123456789abcdef";
        assert_eq!(short_hash(hash), "0123456789…6789abcdef");
        assert_eq!(short_hash("abc"), "abc");
        assert_eq!(short_hash("é".repeat(30).as_str()).chars().count(), 21);
    }

    #[test]
    fn number_and_text_fall_back_to_missing() {
        let value = json!({ "n": 7, "s": "hi" });
        assert_eq!(number(&value, "n"), "7");
        assert_eq!(number(&value, "s"), MISSING);
        assert_eq!(text(&value, "s"), "hi");
        assert_eq!(text(&value, "n"), MISSING);
    }
}
