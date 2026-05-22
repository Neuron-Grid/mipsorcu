#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "docker"
require_failure_injection_allowed
require_local_base_url

readonly UNREGISTERED_SIGNATURE_KEY_VERSION="2147483647"

run_name="mipsorcu-fi-ledger-key-inactive-$$"

cleanup_container() {
    docker rm -f "${run_name}" >/dev/null 2>&1 || true
}
trap cleanup_container EXIT

log_info "Scenario 8: configured ledger signing public key is not active"
log_info "starting one-off mipsorcu container with key version ${UNREGISTERED_SIGNATURE_KEY_VERSION}"

docker compose run \
    -d \
    --no-deps \
    --name "${run_name}" \
    -e "MIPSORCU_LEDGER_SIGNATURE_KEY_VERSION=${UNREGISTERED_SIGNATURE_KEY_VERSION}" \
    "mipsorcu" \
    >/dev/null

running="true"
for _ in $(seq 1 30); do
    running="$(docker inspect -f '{{.State.Running}}' "${run_name}" 2>/dev/null || echo "unknown")"
    [[ "${running}" != "true" ]] && break
    sleep 2
done

if [[ "${running}" == "true" ]]; then
    docker logs "${run_name}" >&2 || true
    fail "one-off container kept running with an unregistered ledger signature key version"
fi

exit_code="$(docker inspect -f '{{.State.ExitCode}}' "${run_name}")"
if [[ "${exit_code}" == "0" ]]; then
    docker logs "${run_name}" >&2 || true
    fail "one-off container exited successfully despite inactive ledger signing public key"
fi
log_ok "one-off container failed closed with exit code ${exit_code}"

logs="$(docker logs "${run_name}" 2>&1 || true)"
assert_no_forbidden_material "scenario 8 logs" "${logs}"

if printf '%s' "${logs}" | grep -qiE 'ledger_signing_public_key_not_active|ledger signing public key is not active|configured ledger signing public key is not active'; then
    log_ok "ledger signing public key inactive error was logged"
else
    printf '%s\n' "${logs}" >&2
    fail "ledger signing public key inactive error was not found in logs"
fi

cleanup_container
trap - EXIT

log_ok "Scenario 8 passed"
