#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "curl"
require_command "jq"
require_env "MIPSORCU_AUDITOR_JWT"

log_info "Scenario 1: POST /v1/secrets without Authorization"

start_time="$(utc_now)"
result="$(
    http_request \
        -X POST \
        -H "Content-Type: application/json" \
        --data "$(valid_create_body "66692d30312d6e6f2d61757468")" \
        "${MIPSORCU_BASE_URL}/v1/secrets"
)"
status="${result%%|*}"
body="${result#*|}"

assert_status_exact "401" "${status}"
assert_no_forbidden_material "no-auth response body" "${body}"

sleep 2
assert_auth_failure_audit_recorded_since "${start_time}"

log_ok "Scenario 1 passed"
