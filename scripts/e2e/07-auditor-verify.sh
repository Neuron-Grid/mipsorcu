#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_common_env
require_state_dir
require_command "jq"

if [[ "${E2E_MODE}" == "container" ]]; then
    require_command "docker"
else
    require_command "mipsorcu"
fi

first_sequence="$(read_state "ledger_first_sequence")"
last_sequence="$(read_state "ledger_last_sequence")"
verify_response="$(
    run_mipsorcu_cli auditor verify \
        --from-sequence "${first_sequence}" \
        --to-sequence "${last_sequence}" \
        --format json
)"

printf '%s' "${verify_response}" | jq -e '.valid == true' >/dev/null
printf '%s' "${verify_response}" | jq -e '.checked_count > 0' >/dev/null

log_info "auditor verification passed for sequence ${first_sequence}..${last_sequence}"
