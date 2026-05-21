#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_auditor_env
require_state_dir

secret_id="$(read_state "secret_id")"
audit_response="$(
    request_json \
        "GET" \
        "${MIPSORCU_BASE_URL}/audit/v1/audit-events?limit=100&offset=0" \
        "${MIPSORCU_AUDITOR_JWT}"
)"

assert_no_forbidden_response_material "audit response" "${audit_response}"

for action_name in encrypt_create secret_alias_create encrypt_rotate decrypt; do
    printf '%s' "${audit_response}" \
        | jq -e \
            --arg secret_id "${secret_id}" \
            --arg action_name "${action_name}" \
            '.items | any(.target_secret_id == $secret_id and .action == $action_name and .result == "success")' \
        >/dev/null \
        || fail "missing audit event: ${action_name}"
    log_info "audit event found: ${action_name}"
done

latest_occurred_at="$(
    printf '%s' "${audit_response}" \
        | jq -er '[.items[].occurred_at] | max'
)"
write_state "latest_occurred_at" "${latest_occurred_at}"

log_info "audit event verification passed"
