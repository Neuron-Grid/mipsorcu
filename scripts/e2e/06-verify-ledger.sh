#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_common_env
require_state_dir

secret_id="$(read_state "secret_id")"
ledger_response="$(
    request_json \
        "GET" \
        "${MIPSORCU_BASE_URL}/audit/v1/ledger-entries?limit=100&offset=0" \
        "${MIPSORCU_AUDITOR_JWT}"
)"

for entry_type in secret_created secret_version_created secret_decrypted; do
    printf '%s' "${ledger_response}" \
        | jq -e \
            --arg secret_id "${secret_id}" \
            --arg entry_type "${entry_type}" \
            '.items | any(.target_secret_id == $secret_id and .entry_type == $entry_type and .result == "success")' \
        >/dev/null \
        || fail "missing ledger entry: ${entry_type}"
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

