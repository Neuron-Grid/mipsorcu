#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

validate_common_env

for command_name in bash curl jq xxd shasum; do
    require_command "${command_name}"
done

if [[ "${E2E_MODE}" == "container" ]]; then
    require_command "docker"
fi

health_response="$(curl -fsS "${MIPSORCU_BASE_URL}/health")"
printf '%s' "${health_response}" | jq -e '.status == "up"' >/dev/null
log_info "health check passed"

ready_response="$(curl -fsS "${MIPSORCU_BASE_URL}/ready")"
printf '%s' "${ready_response}" | jq -e '.status == "ready"' >/dev/null
log_info "readiness check passed"

status_response="$(
    run_mipsorcu_cli signature-key status \
        --key-version "${SIGNATURE_KEY_VERSION}" \
        --format json
)"
printf '%s' "${status_response}" | jq -e '.status == "active"' >/dev/null
log_info "signature key is active"

if [[ "${E2E_MODE}" == "container" ]]; then
    if [[ -n "${MIPSORCU_AUDIT_UI_BASE_URL:-}" ]]; then
        curl -fsS "${MIPSORCU_AUDIT_UI_BASE_URL}" >/dev/null
        log_info "audit-ui endpoint is reachable: ${MIPSORCU_AUDIT_UI_BASE_URL}"
    fi
fi

reset_state_dir
log_info "state directory initialized: ${MIPSORCU_E2E_STATE_DIR}"
