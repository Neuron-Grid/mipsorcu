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

entry_count="$(printf '%s' "${ledger_response}" | jq -er '.items | length')"
[[ "${entry_count}" =~ ^[1-9][0-9]*$ ]] \
    || fail "ledger response contains no entries"

unsigned_count="$(
    printf '%s' "${ledger_response}" \
        | jq -er '[.items[] | select(
            (.signature | type != "string" or length == 0)
            or .signature_algorithm != "ed25519"
            or (.signature_key_version | type != "number" or . <= 0)
        )] | length'
)"
[[ "${unsigned_count}" == "0" ]] \
    || fail "ledger response contains unsigned or invalid signature entries: ${unsigned_count}"

sequence_check="$(
    printf '%s' "${ledger_response}" \
        | jq -er '
            [.items[].sequence_no] | sort
            | if length == 0 then
                {ok: false, first: null, last: null}
              else
                . as $seqs
                | {
                    ok: all(range(1; length); $seqs[.] == ($seqs[0] + .)),
                    first: $seqs[0],
                    last: $seqs[-1]
                  }
              end
        '
)"

sequence_ok="$(printf '%s' "${sequence_check}" | jq -er '.ok')"
[[ "${sequence_ok}" == "true" ]] \
    || fail "ledger sequence numbers are not contiguous"

first_sequence="$(printf '%s' "${sequence_check}" | jq -er '.first')"
last_sequence="$(printf '%s' "${sequence_check}" | jq -er '.last')"
[[ "${first_sequence}" =~ ^[1-9][0-9]*$ ]] \
    || fail "invalid first ledger sequence"
[[ "${last_sequence}" =~ ^[1-9][0-9]*$ ]] \
    || fail "invalid last ledger sequence"

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

write_state "ledger_first_sequence" "${first_sequence}"
write_state "ledger_last_sequence" "${last_sequence}"

log_info "ledger verification passed (count=${entry_count}, sequence ${first_sequence}..${last_sequence})"
