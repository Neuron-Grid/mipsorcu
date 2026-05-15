#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_common_env
require_state_dir

readonly rotated_plaintext_hex="76302e312e302d6532652d726f7461746564"

secret_id="$(read_state "secret_id")"
alias_name="$(read_state "alias")"

rotate_response="$(
    request_json \
        "POST" \
        "${MIPSORCU_BASE_URL}/v1/secrets/${alias_name}/versions" \
        "${MIPSORCU_JWT}" \
        '{"device_id":"e2e-sbc","plaintext_hex":"'"${rotated_plaintext_hex}"'"}'
)"

returned_secret_id="$(printf '%s' "${rotate_response}" | jq -er '.secret_id')"
version="$(printf '%s' "${rotate_response}" | jq -er '.version')"

[[ "${returned_secret_id}" == "${secret_id}" ]] \
    || fail "alias rotation returned non-canonical secret_id"
[[ "${version}" == "2" ]] \
    || fail "alias rotation returned unexpected version: ${version}"

log_info "alias rotation passed"

