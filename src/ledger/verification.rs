use super::chain::LedgerChainHead;
use super::entry::SignedLedgerEntry;
use super::error::LedgerError;
use super::signature::{LedgerSignatureKeyVersion, LedgerVerifyingKey};

pub fn verify_ledger_chain(
    entries: &[SignedLedgerEntry],
    initial_head: LedgerChainHead,
    verification_keys: &[LedgerVerifyingKey],
) -> Result<LedgerChainHead, LedgerError> {
    let mut previous_sequence_no = initial_head.last_sequence_no();
    let mut previous_hash = initial_head.last_entry_hash();

    for entry in entries {
        let expected_sequence_no = previous_sequence_no
            .checked_add(1)
            .ok_or(LedgerError::SequenceOverflow)?;
        let actual_sequence_no = entry.sequence_no().get();

        if actual_sequence_no != expected_sequence_no {
            return Err(LedgerError::SequenceGap {
                expected: expected_sequence_no,
                actual: actual_sequence_no,
            });
        }

        if entry.previous_entry_hash() != previous_hash {
            return Err(LedgerError::PreviousHashMismatch {
                sequence_no: actual_sequence_no,
            });
        }

        if entry.recompute_entry_hash() != entry.entry_hash() {
            return Err(LedgerError::HashMismatch {
                sequence_no: actual_sequence_no,
            });
        }

        let verification_key = find_verification_key_with_seq(
            verification_keys,
            entry.signature_key_version(),
            actual_sequence_no,
        )?;
        entry
            .verify_signature(verification_key)
            .map_err(|_| LedgerError::SignatureInvalid {
                sequence_no: actual_sequence_no,
            })?;

        previous_sequence_no = actual_sequence_no;
        previous_hash = entry.entry_hash();
    }

    LedgerChainHead::new(previous_sequence_no, previous_hash)
}

fn find_verification_key_with_seq(
    verification_keys: &[LedgerVerifyingKey],
    key_version: LedgerSignatureKeyVersion,
    sequence_no: u64,
) -> Result<&LedgerVerifyingKey, LedgerError> {
    verification_keys
        .iter()
        .find(|key| key.key_version() == key_version)
        .ok_or_else(|| LedgerError::UnknownSignatureKey {
            key_version: key_version.get(),
            sequence_no,
        })
}
