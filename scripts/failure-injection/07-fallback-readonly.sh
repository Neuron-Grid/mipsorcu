#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "curl"
require_command "docker"
require_command "jq"
require_command "psql"
require_env "MIPSORCU_JWT"
require_failure_injection_allowed
require_local_base_url
require_local_test_db_url

log_info "Scenario 7: fallback write failure fails closed"

log_info "creating baseline secret for decrypt fail-close check"
baseline_response="$(
    create_test_secret_with_token \
        "${MIPSORCU_JWT}" \
        "66692d30372d646563727970742d626173656c696e65"
)"
baseline_secret_id="$(printf '%s' "${baseline_response}" | jq -er '.secret_id')"
log_ok "baseline secret created for decrypt fail-close check"

restore_all() {
    log_info "restoring fallback file permissions and RPC grants"
    docker compose exec -T "mipsorcu" sh -c \
        'path="$1"; chmod 0755 /var/lib/mipsorcu || true; if [ -f "$path" ]; then chmod 0644 "$path" || true; fi' \
        sh "${FALLBACK_PATH}" >/dev/null 2>&1 || true
    grant_rpc_execute "${RPC_APPEND_AUDIT_EVENT_SIGNATURE}" || true
    grant_rpc_execute "${RPC_WRITE_SECRET_VERSION_SIGNATURE}" || true
}
trap restore_all EXIT

log_info "making audit fallback file and directory read-only"
docker compose exec -T "mipsorcu" sh -c \
    'path="$1"; touch "$path"; chmod 0444 "$path"; chmod 0555 /var/lib/mipsorcu' \
    sh "${FALLBACK_PATH}"

log_info "revoking write and audit RPC EXECUTE grants"
revoke_rpc_execute "${RPC_APPEND_AUDIT_EVENT_SIGNATURE}"
revoke_rpc_execute "${RPC_WRITE_SECRET_VERSION_SIGNATURE}"

result="$(
    http_request \
        --max-time 30 \
        -X POST \
        -H "Authorization: Bearer ${MIPSORCU_JWT}" \
        -H "Content-Type: application/json" \
        --data "$(valid_create_body "66692d30372d6661696c2d636c6f7365")" \
        "${MIPSORCU_BASE_URL}/v1/secrets"
)"
status="${result%%|*}"
body="${result#*|}"

assert_not_success_status "${status}"
assert_no_forbidden_material "fail-close response body" "${body}"
assert_fallback_no_forbidden_material

log_info "checking decrypt also fails closed while audit append and fallback are unavailable"
decrypt_result="$(
    http_request \
        --max-time 30 \
        -X POST \
        -H "Authorization: Bearer ${MIPSORCU_JWT}" \
        -H "Content-Type: application/json" \
        --data '{}' \
        "${MIPSORCU_BASE_URL}/v1/secrets/${baseline_secret_id}/decrypt"
)"
decrypt_status="${decrypt_result%%|*}"
decrypt_body="${decrypt_result#*|}"

assert_not_success_status "${decrypt_status}"
assert_no_forbidden_material "decrypt fail-close response body" "${decrypt_body}"
assert_fallback_no_forbidden_material

restore_all
trap - EXIT

log_info "checking recovery after permissions and grants are restored"
recovery_response="$(
    create_test_secret_with_token \
        "${MIPSORCU_JWT}" \
        "66692d30372d7265636f76657279"
)"
printf '%s' "${recovery_response}" | jq -e '.secret_id | type == "string"' >/dev/null
log_ok "secret creation recovered"

log_ok "Scenario 7 passed"
