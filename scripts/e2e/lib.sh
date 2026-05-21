#!/usr/bin/env bash

set -euo pipefail

readonly E2E_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly E2E_REPO_ROOT="$(cd "${E2E_LIB_DIR}/../.." && pwd)"
readonly DEFAULT_E2E_STATE_DIR="/tmp/mipsorcu-e2e-state"
readonly MIPSORCU_BASE_URL="${MIPSORCU_BASE_URL:-http://127.0.0.1:3000}"
readonly MIPSORCU_E2E_STATE_DIR="${MIPSORCU_E2E_STATE_DIR:-${STATE_DIR:-${DEFAULT_E2E_STATE_DIR}}}"
readonly E2E_MODE="${MIPSORCU_E2E_MODE:-container}"
readonly SIGNATURE_KEY_VERSION="${MIPSORCU_SIGNATURE_KEY_VERSION:-1}"
readonly FORBIDDEN_RESPONSE_PATTERN='plaintext|secret_body|service_role|master_key'

log_info() {
    printf '[e2e] %s\n' "$*" >&2
}

log_error() {
    printf '[e2e] ERROR: %s\n' "$*" >&2
}

fail() {
    log_error "$*"
    exit 1
}

require_command() {
    local command_name="$1"

    command -v "${command_name}" >/dev/null 2>&1 \
        || fail "required command not found: ${command_name}"
}

require_env() {
    local variable_name="$1"

    [[ -n "${!variable_name:-}" ]] \
        || fail "required environment variable is empty: ${variable_name}"
}

validate_mode() {
    case "${E2E_MODE}" in
        container | host) ;;
        *) fail "MIPSORCU_E2E_MODE must be 'container' or 'host'" ;;
    esac
}

validate_secret_env() {
    validate_mode
    require_env "MIPSORCU_JWT"
}

validate_auditor_env() {
    validate_mode
    require_env "MIPSORCU_AUDITOR_JWT"
}

validate_common_env() {
    validate_mode
}

require_state_dir() {
    [[ -d "${MIPSORCU_E2E_STATE_DIR}" ]] \
        || fail "state directory does not exist: ${MIPSORCU_E2E_STATE_DIR}"
}

reset_state_dir() {
    case "${MIPSORCU_E2E_STATE_DIR}" in
        "" | "/" | ".")
            fail "refusing to reset unsafe state directory: ${MIPSORCU_E2E_STATE_DIR}"
            ;;
    esac

    rm -rf "${MIPSORCU_E2E_STATE_DIR}"
    mkdir -p "${MIPSORCU_E2E_STATE_DIR}"
}

state_path() {
    local name="$1"

    printf '%s/%s\n' "${MIPSORCU_E2E_STATE_DIR}" "${name}"
}

write_state() {
    local name="$1"
    local value="$2"

    printf '%s\n' "${value}" >"$(state_path "${name}")"
}

read_state() {
    local name="$1"
    local path

    path="$(state_path "${name}")"
    [[ -f "${path}" ]] || fail "missing E2E state file: ${name}"
    cat "${path}"
}

request_json() {
    local method="$1"
    local url="$2"
    local bearer_token="$3"
    local data="${4:-}"
    local response_file
    local status

    response_file="$(mktemp "${TMPDIR:-/tmp}/mipsorcu-e2e-response.XXXXXX")"

    if [[ -n "${data}" ]]; then
        status="$(
            curl -sS \
                -o "${response_file}" \
                -w '%{http_code}' \
                -X "${method}" \
                -H "Authorization: Bearer ${bearer_token}" \
                -H "Content-Type: application/json" \
                --data "${data}" \
                "${url}"
        )"
    else
        status="$(
            curl -sS \
                -o "${response_file}" \
                -w '%{http_code}' \
                -X "${method}" \
                -H "Authorization: Bearer ${bearer_token}" \
                "${url}"
        )"
    fi

    if [[ "${status}" -lt 200 || "${status}" -ge 300 ]]; then
        rm -f "${response_file}"
        fail "HTTP ${method} ${url} returned status ${status}"
    fi

    cat "${response_file}"
    rm -f "${response_file}"
}

run_mipsorcu_cli() {
    case "${E2E_MODE}" in
        container)
            (
                cd "${E2E_REPO_ROOT}"
                docker compose exec -T "mipsorcu" mipsorcu "$@"
            )
            ;;
        host)
            mipsorcu "$@"
            ;;
    esac
}

sha256_hex_bytes() {
    local hex_value="$1"

    printf '%s' "${hex_value}" \
        | xxd -r -p \
        | shasum -a 256 \
        | awk '{print $1}'
}

assert_no_forbidden_response_material() {
    local label="$1"
    local value="$2"

    if printf '%s' "${value}" | grep -qiE "${FORBIDDEN_RESPONSE_PATTERN}"; then
        fail "${label} contains forbidden plaintext or secret key markers"
    fi
}
