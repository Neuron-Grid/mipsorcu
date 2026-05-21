#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export MIPSORCU_BASE_URL="${MIPSORCU_BASE_URL:-http://127.0.0.1:3000}"
export MIPSORCU_E2E_MODE="${MIPSORCU_E2E_MODE:-container}"

if [[ -z "${MIPSORCU_E2E_STATE_DIR:-}" ]]; then
    export MIPSORCU_E2E_STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mipsorcu-e2e-state.XXXXXX")"
    cleanup_state_dir="true"
else
    mkdir -p "${MIPSORCU_E2E_STATE_DIR}"
    cleanup_state_dir="false"
fi

cleanup() {
    if [[ "${cleanup_state_dir}" == "true" ]]; then
        rm -rf "${MIPSORCU_E2E_STATE_DIR}"
    fi
}

trap cleanup EXIT

printf '[e2e] base_url=%s\n' "${MIPSORCU_BASE_URL}" >&2
printf '[e2e] mode=%s\n' "${MIPSORCU_E2E_MODE}" >&2
printf '[e2e] state_dir=%s\n' "${MIPSORCU_E2E_STATE_DIR}" >&2

for step in \
    "00-precheck.sh" \
    "01-create-secret.sh" \
    "02-create-alias.sh" \
    "03-rotate-by-alias.sh" \
    "04-decrypt-current.sh" \
    "05-verify-audit.sh" \
    "06-verify-ledger.sh" \
    "07-auditor-verify.sh"
do
    bash "${SCRIPT_DIR}/${step}"
done

printf '[e2e] representative flow passed\n' >&2
