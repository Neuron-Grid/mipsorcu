#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_common_env
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
returned_alias="$(printf '%s' "${alias_response}" | jq -er '.alias')"
returned_alias_normalized="$(printf '%s' "${alias_response}" | jq -er '.alias_normalized')"

[[ "${returned_secret_id}" == "${secret_id}" ]] \
    || fail "alias create returned non-canonical secret_id"
[[ "${returned_alias}" == "${alias_name}" ]] \
    || fail "alias create returned unexpected alias"
[[ "${returned_alias_normalized}" == "${alias_name}" ]] \
    || fail "alias create returned unexpected alias_normalized"

write_state "alias" "${alias_name}"

log_info "alias create passed"

