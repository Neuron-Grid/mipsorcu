#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "bun"
require_failure_injection_allowed

readonly TAINT_FILE="${FAILURE_REPO_ROOT}/audit-ui/src/__tainted_for_guard_test__.ts"

restore_audit_ui() {
    rm -f "${TAINT_FILE}" || true
}
trap restore_audit_ui EXIT

log_info "Scenario 10: audit-ui readonly guard detects a write path"

cat >"${TAINT_FILE}" <<'TAINT'
export async function taintedWritePathForGuardTest() {
    return fetch("/v1/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plaintext: "tainted" }),
    });
}
TAINT

guard_exit=0
(
    cd "${FAILURE_REPO_ROOT}/audit-ui"
    bun run test:guards
) >/dev/null 2>&1 || guard_exit=$?

if [[ "${guard_exit}" == "0" ]]; then
    fail "audit-ui test:guards did not detect the tainted write path"
fi
log_ok "audit-ui test:guards failed as expected with exit ${guard_exit}"

restore_audit_ui
trap - EXIT

(
    cd "${FAILURE_REPO_ROOT}/audit-ui"
    bun run test:guards
)
log_ok "audit-ui test:guards passes after cleanup"

log_ok "Scenario 10 passed"
