use super::constants::LEDGER_I64_MAX_U64;
use super::error::LedgerError;
use super::hash::LedgerHash;
use super::ids::LedgerSequenceNo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerChainHead {
    last_sequence_no: u64,
    last_entry_hash: LedgerHash,
}

impl LedgerChainHead {
    pub fn genesis() -> Self {
        Self {
            last_sequence_no: 0,
            last_entry_hash: LedgerHash::genesis(),
        }
    }

    pub fn new(last_sequence_no: u64, last_entry_hash: LedgerHash) -> Result<Self, LedgerError> {
        if last_sequence_no > LEDGER_I64_MAX_U64 {
            return Err(LedgerError::InvalidNonNegativeInteger {
                field: "last_sequence_no",
            });
        }

        Ok(Self {
            last_sequence_no,
            last_entry_hash,
        })
    }

    pub fn from_i64(
        last_sequence_no: i64,
        last_entry_hash: LedgerHash,
    ) -> Result<Self, LedgerError> {
        let converted = u64::try_from(last_sequence_no).map_err(|_| {
            LedgerError::InvalidNonNegativeInteger {
                field: "last_sequence_no",
            }
        })?;

        Self::new(converted, last_entry_hash)
    }

    pub fn last_sequence_no(self) -> u64 {
        self.last_sequence_no
    }

    pub fn last_entry_hash(self) -> LedgerHash {
        self.last_entry_hash
    }

    pub fn next_sequence_no(self) -> Result<LedgerSequenceNo, LedgerError> {
        let next = self
            .last_sequence_no
            .checked_add(1)
            .ok_or(LedgerError::SequenceOverflow)?;

        LedgerSequenceNo::new(next)
    }
}
