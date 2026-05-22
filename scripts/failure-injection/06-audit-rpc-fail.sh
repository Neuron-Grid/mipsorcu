#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "curl"
require_command "docker"
require_command "jq"
require_command "psql"
require_failure_injection_allowed
require_local_base_url
require_local_test_db_url

readonly INVALID_JWT="eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAifQ.invalid_signature"

log_info "Scenario 6: audit RPC failure writes local fallback"

initial_lines="$(fallback_line_count)"
log_info "initial fallback line count: ${initial_lines}"

restore_grant() {
    log_info "restoring rpc_append_audit_event EXECUTE grant"
    grant_rpc_execute "${RPC_APPEND_AUDIT_EVENT_SIGNATURE}" || true
}
trap restore_grant EXIT

log_info "revoking rpc_append_audit_event EXECUTE from service_role"
revoke_rpc_execute "${RPC_APPEND_AUDIT_EVENT_SIGNATURE}"

result="$(
    http_request \
        --max-time 30 \
        -X POST \
        -H "Authorization: Bearer ${INVALID_JWT}" \
        -H "Content-Type: application/json" \
        --data "$(valid_create_body "66692d30362d61756469742d7270632d6661696c")" \
        "${MIPSORCU_BASE_URL}/v1/secrets"
)"
status="${result%%|*}"
body="${result#*|}"

assert_status_exact "401" "${status}"
assert_no_forbidden_material "invalid-jwt response body" "${body}"

sleep 3
final_lines="$(fallback_line_count)"
log_info "final fallback line count: ${final_lines}"

if [[ "${final_lines}" -le "${initial_lines}" ]]; then
    fail "fallback file did not receive a pending audit record"
fi
log_ok "fallback pending line was appended (${initial_lines} -> ${final_lines})"

assert_fallback_no_forbidden_material

restore_grant
trap - EXIT

log_ok "Scenario 6 passed"
