#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "curl"
require_command "jq"
require_env "MIPSORCU_JWT"
require_env "MIPSORCU_AUDITOR_JWT"

log_info "Scenario 4: non-auditor user attempts to read /audit/v1 endpoints"

start_time="$(utc_now)"

result="$(
    http_request \
        -X GET \
        -H "Authorization: Bearer ${MIPSORCU_JWT}" \
        "${MIPSORCU_BASE_URL}/audit/v1/audit-events?limit=100&offset=0"
)"
status="${result%%|*}"
body="${result#*|}"

assert_status_exact "403" "${status}"
assert_no_forbidden_material "audit-events non-auditor response body" "${body}"

result="$(
    http_request \
        -X GET \
        -H "Authorization: Bearer ${MIPSORCU_JWT}" \
        "${MIPSORCU_BASE_URL}/audit/v1/ledger-entries?limit=100&offset=0"
)"
status="${result%%|*}"
body="${result#*|}"

assert_status_exact "403" "${status}"
assert_no_forbidden_material "ledger-entries non-auditor response body" "${body}"

sleep 2
assert_audit_ui_read_failure_recorded_since "${start_time}"

log_ok "Scenario 4 passed"
