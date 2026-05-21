#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_secret_env
require_state_dir

readonly initial_plaintext_hex="76302e312e302d6532652d696e697469616c"
readonly rotated_plaintext_hex="76302e312e302d6532652d726f7461746564"

create_response="$(
    request_json \
        "POST" \
        "${MIPSORCU_BASE_URL}/v1/secrets" \
        "${MIPSORCU_JWT}" \
        '{"classification":"e2e-confidential","device_id":"e2e-sbc","plaintext_hex":"'"${initial_plaintext_hex}"'"}'
)"

secret_id="$(printf '%s' "${create_response}" | jq -er '.secret_id')"
version="$(printf '%s' "${create_response}" | jq -er '.version')"
secret_version_id="$(printf '%s' "${create_response}" | jq -er '.secret_version_id')"

[[ "${version}" == "1" ]] || fail "create returned unexpected version: ${version}"
[[ "${secret_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
    || fail "create returned invalid secret_id"
[[ "${secret_version_id}" =~ ^[0-9a-f-]+$ ]] \
    || fail "create returned invalid secret_version_id"

write_state "secret_id" "${secret_id}"
write_state "expected_plaintext_sha256" "$(sha256_hex_bytes "${rotated_plaintext_hex}")"

log_info "secret create passed"
