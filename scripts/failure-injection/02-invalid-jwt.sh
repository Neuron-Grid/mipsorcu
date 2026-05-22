#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "curl"
require_command "jq"
require_env "MIPSORCU_AUDITOR_JWT"

readonly INVALID_JWT="eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAifQ.invalid_signature"

log_info "Scenario 2: POST /v1/secrets with invalid JWT"

start_time="$(utc_now)"
result="$(
    http_request \
        -X POST \
        -H "Authorization: Bearer ${INVALID_JWT}" \
        -H "Content-Type: application/json" \
        --data "$(valid_create_body "66692d30322d696e76616c69642d6a7774")" \
        "${MIPSORCU_BASE_URL}/v1/secrets"
)"
status="${result%%|*}"
body="${result#*|}"

assert_status_exact "401" "${status}"
assert_no_forbidden_material "invalid-jwt response body" "${body}"

sleep 2
assert_auth_failure_audit_recorded_since "${start_time}"

log_ok "Scenario 2 passed"
