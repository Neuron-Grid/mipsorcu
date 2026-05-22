#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "curl"
require_command "docker"
require_safe_mutating_environment

log_info "Scenario 5: Supabase connectivity loss"

pre_status="$(http_status --max-time 5 "${MIPSORCU_BASE_URL}/ready")"
assert_status_exact "200" "${pre_status}"

container_id="$(compose_container_id)"
network_name="$(compose_container_network "${container_id}")"
network_disconnected="0"

restore_network() {
    if [[ "${network_disconnected}" == "1" ]]; then
        log_info "restoring compose network ${network_name}"
        docker network connect "${network_name}" "${container_id}" >/dev/null 2>&1 || true
    fi
}
trap restore_network EXIT

log_info "disconnecting mipsorcu container from ${network_name}"
docker network disconnect "${network_name}" "${container_id}" >/dev/null
network_disconnected="1"

down_status="200"
for _ in $(seq 1 24); do
    down_status="$(http_status --max-time 5 "${MIPSORCU_BASE_URL}/ready")"
    case "${down_status}" in
        503 | 500 | 502 | 000)
            log_ok "/ready failed while Supabase connectivity was unavailable (${down_status})"
            break
            ;;
    esac
    sleep 5
done

case "${down_status}" in
    503 | 500 | 502 | 000) ;;
    *) fail "/ready stayed healthy during Supabase connectivity loss: ${down_status}" ;;
esac

if [[ -n "${MIPSORCU_JWT:-}" && -n "${TEST_SECRET_ID:-}" ]]; then
    log_info "checking decrypt path while Supabase connectivity is unavailable"
    result="$(
        http_request \
            --max-time 10 \
            -X POST \
            -H "Authorization: Bearer ${MIPSORCU_JWT}" \
            -H "Content-Type: application/json" \
            --data '{}' \
            "${MIPSORCU_BASE_URL}/v1/secrets/${TEST_SECRET_ID}/decrypt"
    )"
    status="${result%%|*}"
    body="${result#*|}"

    assert_not_success_status "${status}"
    assert_no_forbidden_material "decrypt failure response body" "${body}"
else
    log_info "MIPSORCU_JWT or TEST_SECRET_ID is not set; skipping decrypt-path check"
fi

restore_network
network_disconnected="0"
trap - EXIT

wait_for_http_status "${MIPSORCU_BASE_URL}/ready" "200" "18" "5"

log_ok "Scenario 5 passed"
