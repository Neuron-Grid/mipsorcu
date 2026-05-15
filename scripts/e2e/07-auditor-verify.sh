#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_common_env
require_state_dir

last_sequence_no="$(read_state "last_sequence_no")"
verify_response="$(
    run_mipsorcu_cli auditor verify \
        --from-sequence "1" \
        --to-sequence "${last_sequence_no}" \
        --format json
)"

printf '%s' "${verify_response}" | jq -e '.valid == true' >/dev/null

log_info "auditor verification passed"

