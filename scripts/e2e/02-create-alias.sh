#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_secret_env
require_state_dir

secret_id="$(read_state "secret_id")"
alias_name="e2e-secret-$(printf '%s' "${secret_id}" | tr -d '-' | cut -c1-12)"

alias_response="$(
    request_json \
        "POST" \
        "${MIPSORCU_BASE_URL}/v1/secrets/${secret_id}/aliases" \
        "${MIPSORCU_JWT}" \
        '{"alias":"'"${alias_name}"'"}'
)"

returned_secret_id="$(printf '%s' "${alias_response}" | jq -er '.secret_id')"
secret_alias_id="$(printf '%s' "${alias_response}" | jq -er '.secret_alias_id')"

[[ "${returned_secret_id}" == "${secret_id}" ]] \
    || fail "alias create returned non-canonical secret_id"
[[ "${secret_alias_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
    || fail "alias create returned invalid secret_alias_id"

write_state "alias" "${alias_name}"
write_state "alias_id" "${secret_alias_id}"

log_info "alias create passed"
