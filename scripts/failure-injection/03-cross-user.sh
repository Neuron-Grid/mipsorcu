#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "curl"
require_command "jq"
require_env "MIPSORCU_JWT"
require_env "MIPSORCU_OTHER_USER_JWT"

log_info "Scenario 3: other user attempts to decrypt an owned secret"

create_response="$(
    create_test_secret_with_token \
        "${MIPSORCU_JWT}" \
        "66692d30332d63726f73732d757365722d736563726574"
)"
secret_id="$(printf '%s' "${create_response}" | jq -er '.secret_id')"
log_ok "created owner secret ${secret_id}"

result="$(
    http_request \
        -X POST \
        -H "Authorization: Bearer ${MIPSORCU_OTHER_USER_JWT}" \
        -H "Content-Type: application/json" \
        --data '{}' \
        "${MIPSORCU_BASE_URL}/v1/secrets/${secret_id}/decrypt"
)"
status="${result%%|*}"
body="${result#*|}"

assert_status_in "${status}" "403" "404"
assert_no_forbidden_material "cross-user response body" "${body}"

if printf '%s' "${body}" | grep -qiE 'owner|exists|created by|belongs to|cross-user'; then
    fail "cross-user response body may reveal ownership or existence details"
fi
log_ok "cross-user response does not reveal ownership or existence details"

log_ok "Scenario 3 passed"
