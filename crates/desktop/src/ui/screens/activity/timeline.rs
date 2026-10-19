//! Sent payments and received notes as one list: kinds, ordering,
//! filtering, search, and pages. No drawing.

use std::collections::HashSet;
use std::ops::Range;

use serde_json::Value;

/// Entries on one page of the list.
pub const PER_PAGE: usize = 20;

/// What an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A payment this wallet sent.
    Sent,
    /// A note someone else paid to this wallet.
    Received,
    /// A block reward the wallet's miner earned.
    Mined,
    /// The part of a sent payment's inputs that came back to the wallet.
    Change,
}

/// Which kinds the list shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Filter {
    /// Everything except change, unless change is asked for.
    #[default]
    All,
    /// Sent payments only.
    Sent,
    /// Received notes, with change if asked for.
    Received,
    /// Mining rewards only.
    Mined,
}

impl Filter {
    /// Every filter in display order, with its label.
    pub const ALL: [(Self, &'static str); 4] = [
        (Self::All, "All"),
        (Self::Sent, "Sent"),
        (Self::Received, "Received"),
        (Self::Mined, "Mined"),
    ];

    /// Whether this filter shows entries of `kind`.
    pub fn shows(self, kind: Kind, with_change: bool) -> bool {
        match (self, kind) {
            (_, Kind::Change) => with_change && matches!(self, Self::All | Self::Received),
            (Self::All, _) => true,
            (Self::Sent, kind) => kind == Kind::Sent,
            (Self::Received, kind) => kind == Kind::Received,
            (Self::Mined, kind) => kind == Kind::Mined,
        }
    }
}

/// One row of the list.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Entry<'a> {
    /// What it is.
    pub kind: Kind,
    /// The operation or note as the wallet reported it.
    pub item: &'a Value,
    /// When it happened: a payment's creation, a note's block. `None`
    /// while a note's block time is still being looked up.
    pub time: Option<u64>,
}

/// Every entry, newest first. Notes whose transaction is one this wallet
/// sent are change; entries without a time yet come last.
pub fn entries<'a>(operations: &'a Value, received: &'a Value) -> Vec<Entry<'a>> {
    let operations = items(operations);
    let sent: HashSet<&str> = operations.iter().filter_map(txid).collect();
    let mut all: Vec<Entry<'a>> = operations
        .iter()
        .map(|op| Entry {
            kind: Kind::Sent,
            item: op,
            time: op.get("created_at").and_then(Value::as_u64),
        })
        .chain(items(received).iter().map(|note| Entry {
            kind: note_kind(note, &sent),
            item: note,
            time: note.get("time").and_then(Value::as_u64),
        }))
        .collect();
    // The wallet lists both oldest first, so reversing before a stable sort
    // keeps entries with equal times newest first too.
    all.reverse();
    all.sort_by_key(|entry| std::cmp::Reverse(entry.time.map_or(0, |t| t.saturating_add(1))));
    all
}

fn note_kind(note: &Value, sent: &HashSet<&str>) -> Kind {
    if txid(note).is_some_and(|id| sent.contains(id)) {
        Kind::Change
    } else if note.get("mined").and_then(Value::as_bool) == Some(true) {
        Kind::Mined
    } else {
        Kind::Received
    }
}

/// Whether `entry` contains `query`, ignoring case, in its transaction id,
/// addresses, labels, memos, or payment number. An empty query matches.
pub fn matches(entry: &Entry<'_>, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    query.is_empty()
        || searchable(entry.item)
            .iter()
            .any(|text| text.to_lowercase().contains(&query))
}

/// The texts of an operation or note that search looks at.
fn searchable(item: &Value) -> Vec<String> {
    let mut texts: Vec<String> = ["txid", "address", "label", "memo"]
        .iter()
        .filter_map(|key| item.get(key).and_then(Value::as_str).map(str::to_owned))
        .collect();
    if let Some(id) = item.get("operation_id").and_then(Value::as_u64) {
        texts.push(format!("#{id}"));
    }
    for recipient in items(item.get("recipients").unwrap_or(&Value::Null)) {
        texts.extend(searchable(recipient));
    }
    texts
}

/// Which slice of a filtered list one page shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageView {
    /// The page shown, from zero; a too-large request shows the last page.
    pub index: usize,
    /// How many pages there are; at least one, even when empty.
    pub count: usize,
    /// The positions of the entries on it.
    pub range: Range<usize>,
}

/// Page `requested` of a list of `len` entries, `per_page` at a time.
pub fn page(len: usize, requested: usize, per_page: usize) -> PageView {
    let per_page = per_page.max(1);
    let count = len.div_ceil(per_page).max(1);
    let index = requested.min(count.saturating_sub(1));
    let start = index.saturating_mul(per_page).min(len);
    PageView {
        index,
        count,
        range: start..start.saturating_add(per_page).min(len),
    }
}

fn items(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

fn txid(item: &Value) -> Option<&str> {
    item.get("txid").and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn kinds_and_times(entries: &[Entry<'_>]) -> Vec<(Kind, Option<u64>)> {
        entries.iter().map(|e| (e.kind, e.time)).collect()
    }

    #[test]
    fn entries_merge_newest_first_and_tell_change_and_rewards_apart() {
        let operations = json!([
            { "operation_id": 1, "created_at": 100, "txid": "spend" },
            { "operation_id": 2, "created_at": 300, "txid": null },
        ]);
        let received = json!([
            { "time": 50, "txid": "reward", "mined": true },
            { "time": 200, "txid": "spend" },
            { "time": 300, "txid": "gift" },
            { "txid": "pending" },
        ]);
        assert_eq!(
            kinds_and_times(&entries(&operations, &received)),
            vec![
                (Kind::Received, Some(300)),
                (Kind::Sent, Some(300)),
                (Kind::Change, Some(200)),
                (Kind::Sent, Some(100)),
                (Kind::Mined, Some(50)),
                (Kind::Received, None),
            ]
        );
    }

    #[test]
    fn a_time_of_zero_still_sorts_above_an_unknown_time() {
        let received = json!([{ "txid": "a" }, { "time": 0, "txid": "b" }]);
        let order = entries(&Value::Null, &received);
        assert_eq!(order[0].item["txid"], "b");
        assert_eq!(order[1].item["txid"], "a");
    }

    #[test]
    fn missing_lists_give_no_entries() {
        assert_eq!(entries(&Value::Null, &json!({})), Vec::new());
    }

    #[test]
    fn filters_show_their_kinds_and_change_only_when_asked() {
        use Kind::{Change, Mined, Received, Sent};
        let cases = [
            (Filter::All, false, vec![Sent, Received, Mined]),
            (Filter::All, true, vec![Sent, Received, Mined, Change]),
            (Filter::Sent, true, vec![Sent]),
            (Filter::Received, false, vec![Received]),
            (Filter::Received, true, vec![Received, Change]),
            (Filter::Mined, true, vec![Mined]),
        ];
        for (filter, with_change, expected) in cases {
            let shown: Vec<Kind> = [Sent, Received, Mined, Change]
                .into_iter()
                .filter(|kind| filter.shows(*kind, with_change))
                .collect();
            assert_eq!(shown, expected, "{filter:?} with change {with_change}");
        }
    }

    #[test]
    fn search_looks_at_ids_addresses_labels_memos_and_payment_numbers() {
        let op = json!({
            "operation_id": 42,
            "txid": "ABCdef",
            "recipients": [{ "address": "null1shop", "memo": "Invoice 7" }],
        });
        let note =
            json!({ "txid": "f00d", "address": "null1me", "label": "Savings", "memo": null });
        let op = Entry {
            kind: Kind::Sent,
            item: &op,
            time: None,
        };
        let note = Entry {
            kind: Kind::Received,
            item: &note,
            time: None,
        };
        for query in ["", "  ", "abcDEF", "#42", "null1shop", "invoice"] {
            assert!(matches(&op, query), "{query}");
        }
        for query in ["savings", "F00D", "null1me"] {
            assert!(matches(&note, query), "{query}");
        }
        assert!(!matches(&op, "savings"));
        assert!(!matches(&note, "#42"));
    }

    #[test]
    fn pages_cover_the_list_and_clamp_out_of_range_requests() {
        let cases = [
            (
                0,
                0,
                PageView {
                    index: 0,
                    count: 1,
                    range: 0..0,
                },
            ),
            (
                5,
                0,
                PageView {
                    index: 0,
                    count: 1,
                    range: 0..5,
                },
            ),
            (
                20,
                0,
                PageView {
                    index: 0,
                    count: 1,
                    range: 0..20,
                },
            ),
            (
                21,
                1,
                PageView {
                    index: 1,
                    count: 2,
                    range: 20..21,
                },
            ),
            (
                45,
                9,
                PageView {
                    index: 2,
                    count: 3,
                    range: 40..45,
                },
            ),
        ];
        for (len, requested, expected) in cases {
            assert_eq!(
                page(len, requested, PER_PAGE),
                expected,
                "{len} {requested}"
            );
        }
        assert_eq!(page(3, 0, 0).count, 3);
    }
}
