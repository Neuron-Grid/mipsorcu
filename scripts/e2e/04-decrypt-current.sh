#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_common_env
require_state_dir

secret_id="$(read_state "secret_id")"
alias_name="$(read_state "alias")"
expected_hash="$(read_state "expected_plaintext_sha256")"

decrypt_response="$(
    request_json \
        "POST" \
        "${MIPSORCU_BASE_URL}/v1/secrets/${alias_name}/decrypt" \
        "${MIPSORCU_JWT}"
)"

returned_secret_id="$(printf '%s' "${decrypt_response}" | jq -er '.secret_id')"
version="$(printf '%s' "${decrypt_response}" | jq -er '.version')"
encoding="$(printf '%s' "${decrypt_response}" | jq -er '.encoding')"
plaintext_hex="$(printf '%s' "${decrypt_response}" | jq -er '.plaintext_hex')"
actual_hash="$(sha256_hex_bytes "${plaintext_hex}")"

[[ "${returned_secret_id}" == "${secret_id}" ]] \
    || fail "decrypt returned non-canonical secret_id"
[[ "${version}" == "2" ]] \
    || fail "decrypt returned unexpected version: ${version}"
[[ "${encoding}" == "hex" ]] \
    || fail "decrypt returned unexpected encoding"
[[ "${actual_hash}" == "${expected_hash}" ]] \
    || fail "decrypt plaintext hash mismatch"

log_info "alias decrypt hash verification passed"

