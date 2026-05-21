#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_auditor_env
require_state_dir

secret_id="$(read_state "secret_id")"
ledger_response="$(
    request_json \
        "GET" \
        "${MIPSORCU_BASE_URL}/audit/v1/ledger-entries?limit=100&offset=0" \
        "${MIPSORCU_AUDITOR_JWT}"
)"

assert_no_forbidden_response_material "ledger response" "${ledger_response}"

for entry_type in secret_created secret_version_created secret_decrypted; do
    printf '%s' "${ledger_response}" \
        | jq -e \
            --arg secret_id "${secret_id}" \
            --arg entry_type "${entry_type}" \
            '.items | any(
                .target_secret_id == $secret_id
                and .entry_type == $entry_type
                and .result == "success"
                and (.signature | type == "string" and length > 0)
                and .signature_algorithm == "ed25519"
                and (.signature_key_version | type == "number" and . > 0)
            )' \
        >/dev/null \
        || fail "missing signed ledger entry: ${entry_type}"
    log_info "signed ledger entry found: ${entry_type}"
done

integrity_status_response="$(
    request_json \
        "GET" \
        "${MIPSORCU_BASE_URL}/audit/v1/integrity-status" \
        "${MIPSORCU_AUDITOR_JWT}"
)"
last_sequence_no="$(
    printf '%s' "${integrity_status_response}" \
        | jq -er 'map(.last_sequence_no) | max'
)"

[[ "${last_sequence_no}" =~ ^[1-9][0-9]*$ ]] \
    || fail "invalid last_sequence_no returned by integrity-status"

write_state "last_sequence_no" "${last_sequence_no}"

log_info "ledger verification passed"
