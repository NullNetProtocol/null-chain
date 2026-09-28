//! Persisted send operations: what a wallet was asked to pay, how far it
//! got, and which notes it has set aside for it. An operation survives a
//! restart and is rebuilt if its transaction fails to be mined.

use null_protocol::address::Address;
use null_protocol::amount::Amount;
use null_protocol::bytes::{Encodable, Reader, Writer};
use null_protocol::memo::Memo;
use null_protocol::transaction::TxId;

use crate::spend::Payment;

/// How far an operation has got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationStatus {
    /// Waiting for a prover.
    Queued,
    /// Legacy proving state. Older writers could broadcast before saving the
    /// transaction, so an interrupted record requires manual reconciliation.
    Proving,
    /// Being built and proved, with no new transaction broadcast yet.
    /// Uses a distinct disk tag so recovery cannot retry an ambiguous legacy send.
    Building,
    /// Durably recorded for broadcast; not yet seen in a block. Node acceptance
    /// may be unknown, including when a submission reply was lost.
    Submitted {
        /// The transaction's id.
        txid: TxId,
        /// A conservative height bound for scheduling an anchor-expiry rebuild.
        /// Initially the build height; recovery may delay a rebuild using a
        /// later confirmation or retry height.
        built_at: u32,
    },
    /// Seen in a block.
    Confirmed {
        /// The transaction's id.
        txid: TxId,
        /// The block that holds it.
        height: u32,
    },
    /// Given up, with the reason.
    Failed(String),
    /// Withdrawn by the operator before any transaction was recorded for broadcast.
    Cancelled,
}

impl OperationStatus {
    /// Whether the operation still holds its notes and may still be mined.
    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Proving | Self::Building | Self::Submitted { .. }
        )
    }

    /// The transaction id, once one exists.
    pub fn txid(&self) -> Option<TxId> {
        match self {
            Self::Submitted { txid, .. } | Self::Confirmed { txid, .. } => Some(*txid),
            _ => None,
        }
    }

    /// The name shown to operators.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Proving | Self::Building => "proving",
            Self::Submitted { .. } => "submitted",
            Self::Confirmed { .. } => "confirmed",
            Self::Failed(_) => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// One send, as persisted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    /// Its id, assigned by the wallet.
    pub id: u64,
    /// Seconds since the epoch when it was created.
    pub created_at: u64,
    /// Who gets what.
    pub recipients: Vec<Payment>,
    /// Notes with fewer confirmations than this are not spent.
    pub min_confirmations: u32,
    /// Where it is.
    pub status: OperationStatus,
    /// Positions of the notes set aside for it while pending.
    pub locked: Vec<u64>,
    /// The built transaction, kept for resubmission.
    pub transaction: Option<Vec<u8>>,
    /// How many times it was built.
    pub attempts: u32,
    /// Earlier versions of this payment. Kept so a reorganization that mines
    /// an older attempt is recognized instead of triggering another payment.
    pub previous_transactions: Vec<Vec<u8>>,
}

impl Operation {
    /// A fresh, queued operation.
    pub fn new(id: u64, created_at: u64, recipients: Vec<Payment>, min_confirmations: u32) -> Self {
        Self {
            id,
            created_at,
            recipients,
            min_confirmations,
            status: OperationStatus::Queued,
            locked: Vec::new(),
            transaction: None,
            attempts: 0,
            previous_transactions: Vec::new(),
        }
    }

    /// Makes `bytes` the active transaction without forgetting earlier attempts.
    /// Selecting a previously mined attempt moves it out of the history.
    pub fn record_transaction(&mut self, bytes: Vec<u8>) {
        self.previous_transactions
            .retain(|previous| previous != &bytes);
        if let Some(previous) = self.transaction.replace(bytes) {
            if self.transaction.as_ref() != Some(&previous)
                && !self.previous_transactions.contains(&previous)
            {
                self.previous_transactions.push(previous);
            }
        }
    }

    /// Every retained transaction, active first.
    pub fn transactions(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.transaction.iter().chain(&self.previous_transactions)
    }

    /// The sum of the recipients' amounts.
    pub fn total(&self) -> u64 {
        self.recipients
            .iter()
            .map(|p| p.amount.raw())
            .fold(0u64, u64::saturating_add)
    }
}

fn write_string(w: &mut Writer, text: &str) {
    w.put_u64_le(text.len() as u64).put(text.as_bytes());
}

fn read_string(r: &mut Reader<'_>) -> null_protocol::Result<String> {
    let len = usize::try_from(r.take_u64_le()?)
        .map_err(|_| null_protocol::Error::Malformed("string length"))?;
    String::from_utf8(r.take(len)?.to_vec()).map_err(|_| null_protocol::Error::Malformed("string"))
}

fn write_txid(w: &mut Writer, txid: &TxId) {
    w.put(txid.as_bytes());
}

fn read_txid(r: &mut Reader<'_>) -> null_protocol::Result<TxId> {
    Ok(TxId::from_bytes(r.take_array()?))
}

impl Encodable for Payment {
    fn write(&self, w: &mut Writer) {
        self.recipient.write(w);
        w.put_u64_le(self.amount.raw());
        self.memo.write(w);
    }

    fn read(r: &mut Reader<'_>) -> null_protocol::Result<Self> {
        Ok(Self {
            recipient: Address::read(r)?,
            amount: Amount::from_raw(r.take_u64_le()?)?,
            memo: Memo::read(r)?,
        })
    }
}

impl Encodable for OperationStatus {
    fn write(&self, w: &mut Writer) {
        match self {
            Self::Queued => {
                w.put_u8(0);
            }
            Self::Proving => {
                w.put_u8(1);
            }
            Self::Submitted { txid, built_at } => {
                w.put_u8(2);
                write_txid(w, txid);
                w.put(&built_at.to_le_bytes());
            }
            Self::Confirmed { txid, height } => {
                w.put_u8(3);
                write_txid(w, txid);
                w.put(&height.to_le_bytes());
            }
            Self::Failed(reason) => {
                w.put_u8(4);
                write_string(w, reason);
            }
            Self::Cancelled => {
                w.put_u8(5);
            }
            Self::Building => {
                w.put_u8(6);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> null_protocol::Result<Self> {
        Ok(match r.take_u8()? {
            0 => Self::Queued,
            1 => Self::Proving,
            2 => Self::Submitted {
                txid: read_txid(r)?,
                built_at: u32::from_le_bytes(r.take_array()?),
            },
            3 => Self::Confirmed {
                txid: read_txid(r)?,
                height: u32::from_le_bytes(r.take_array()?),
            },
            4 => Self::Failed(read_string(r)?),
            5 => Self::Cancelled,
            6 => Self::Building,
            _ => return Err(null_protocol::Error::Malformed("operation status")),
        })
    }
}

impl Encodable for Operation {
    fn write(&self, w: &mut Writer) {
        w.put_u64_le(self.id).put_u64_le(self.created_at);
        w.put_u64_le(self.recipients.len() as u64);
        for payment in &self.recipients {
            payment.write(w);
        }
        w.put(&self.min_confirmations.to_le_bytes());
        self.status.write(w);
        w.put_u64_le(self.locked.len() as u64);
        for position in &self.locked {
            w.put_u64_le(*position);
        }
        match &self.transaction {
            Some(bytes) => {
                w.put_u8(1).put_u64_le(bytes.len() as u64).put(bytes);
            }
            None => {
                w.put_u8(0);
            }
        }
        w.put(&self.attempts.to_le_bytes());
        // Empty history retains the original disk layout. A nonempty extension
        // is readable by new wallets and refused by old ones, never ignored.
        if !self.previous_transactions.is_empty() {
            w.put_u64_le(self.previous_transactions.len() as u64);
            for bytes in &self.previous_transactions {
                w.put_u64_le(bytes.len() as u64).put(bytes);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> null_protocol::Result<Self> {
        let id = r.take_u64_le()?;
        let created_at = r.take_u64_le()?;
        let count = r.take_u64_le()?;
        let recipients = (0..count)
            .map(|_| Payment::read(r))
            .collect::<null_protocol::Result<Vec<_>>>()?;
        let min_confirmations = u32::from_le_bytes(r.take_array()?);
        let status = OperationStatus::read(r)?;
        let locked_count = r.take_u64_le()?;
        let locked = (0..locked_count)
            .map(|_| r.take_u64_le())
            .collect::<null_protocol::Result<Vec<_>>>()?;
        let transaction = match r.take_u8()? {
            0 => None,
            1 => {
                let len = usize::try_from(r.take_u64_le()?)
                    .map_err(|_| null_protocol::Error::Malformed("transaction length"))?;
                Some(r.take(len)?.to_vec())
            }
            _ => return Err(null_protocol::Error::Malformed("transaction flag")),
        };
        let attempts = u32::from_le_bytes(r.take_array()?);
        let mut previous_transactions = Vec::new();
        if r.remaining() > 0 {
            let count = r.take_u64_le()?;
            if count == 0 {
                return Err(null_protocol::Error::Malformed(
                    "empty transaction history extension",
                ));
            }
            for _ in 0..count {
                let len = usize::try_from(r.take_u64_le()?)
                    .map_err(|_| null_protocol::Error::Malformed("transaction length"))?;
                previous_transactions.push(r.take(len)?.to_vec());
            }
        }
        Ok(Self {
            id,
            created_at,
            recipients,
            min_confirmations,
            status,
            locked,
            transaction,
            attempts,
            previous_transactions,
        })
    }
}

#[cfg(test)]
mod tests {
    use null_crypto::keys::SpendingKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::keys::WalletKeys;

    fn sample(status: OperationStatus) -> Operation {
        let keys =
            WalletKeys::from_spending_key(SpendingKey::random(&mut ChaCha20Rng::seed_from_u64(1)))
                .unwrap();
        let mut op = Operation::new(
            9,
            1_700_000_000,
            vec![
                Payment {
                    recipient: keys.default_address().unwrap(),
                    amount: Amount::from_raw(1_000).unwrap(),
                    memo: Memo::from_text("rent").unwrap(),
                },
                Payment {
                    recipient: keys.address(7u64.into()).unwrap(),
                    amount: Amount::from_raw(2_000).unwrap(),
                    memo: Memo::empty(),
                },
            ],
            6,
        );
        op.status = status;
        op.locked = vec![3, 5];
        op.transaction = Some(vec![1, 2, 3]);
        op.attempts = 2;
        op
    }

    #[test]
    fn operations_round_trip_in_every_status() {
        let txid = TxId::from_bytes([7; 32]);
        for status in [
            OperationStatus::Queued,
            OperationStatus::Proving,
            OperationStatus::Building,
            OperationStatus::Submitted { txid, built_at: 4 },
            OperationStatus::Confirmed { txid, height: 9 },
            OperationStatus::Failed("no funds".into()),
            OperationStatus::Cancelled,
        ] {
            let op = sample(status);
            let again = Operation::from_slice(&op.to_vec()).unwrap();
            assert_eq!(again, op);
            assert_eq!(again.total(), 3_000);
        }
        assert!(Operation::from_slice(&[0; 8]).is_err());
        let mut bytes = sample(OperationStatus::Queued).to_vec();
        bytes.push(0);
        assert!(Operation::from_slice(&bytes).is_err(), "trailing byte");
    }

    #[test]
    fn pending_means_notes_stay_locked() {
        let txid = TxId::from_bytes([1; 32]);
        assert!(OperationStatus::Queued.is_pending());
        assert!(OperationStatus::Proving.is_pending());
        assert!(OperationStatus::Building.is_pending());
        assert!(OperationStatus::Submitted { txid, built_at: 0 }.is_pending());
        assert!(!OperationStatus::Confirmed { txid, height: 1 }.is_pending());
        assert!(!OperationStatus::Failed("x".into()).is_pending());
        assert!(!OperationStatus::Cancelled.is_pending());
        assert_eq!(
            OperationStatus::Submitted { txid, built_at: 0 }.txid(),
            Some(txid)
        );
        assert_eq!(OperationStatus::Queued.txid(), None);
        assert_eq!(OperationStatus::Cancelled.name(), "cancelled");
    }

    #[test]
    fn transaction_history_survives_reopening_and_can_select_an_older_attempt() {
        let mut op = sample(OperationStatus::Building);
        assert!(Operation::from_slice(&op.to_vec())
            .unwrap()
            .previous_transactions
            .is_empty());
        let original = op.transaction.clone().unwrap();
        op.record_transaction(vec![4, 5]);
        op.record_transaction(vec![6, 7]);
        let mut op = Operation::from_slice(&op.to_vec()).unwrap();
        op.record_transaction(original.clone());
        op.record_transaction(original.clone());
        assert_eq!(op.transaction, Some(original));
        assert_eq!(op.previous_transactions, vec![vec![4, 5], vec![6, 7]]);
        assert_eq!(Operation::from_slice(&op.to_vec()).unwrap(), op);
        let mut malformed = sample(OperationStatus::Queued).to_vec();
        malformed.extend_from_slice(&0u64.to_le_bytes());
        assert!(Operation::from_slice(&malformed).is_err());
        let mut truncated = op.to_vec();
        truncated.pop();
        assert!(Operation::from_slice(&truncated).is_err());
    }
}
