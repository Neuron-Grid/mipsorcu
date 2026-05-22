#!/usr/bin/env bash

set -euo pipefail

readonly FAILURE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly FAILURE_REPO_ROOT="$(cd "${FAILURE_LIB_DIR}/../../.." && pwd)"
readonly MIPSORCU_BASE_URL="${MIPSORCU_BASE_URL:-http://127.0.0.1:3000}"
readonly FALLBACK_PATH="${MIPSORCU_AUDIT_FALLBACK_PATH:-/var/lib/mipsorcu/audit-fallback-current.jsonl}"
readonly FORBIDDEN_FAILURE_PATTERN='plaintext|secret_body|service_role|master_key|ledger_signing_key|alias_encryption_key|alias_fingerprint_key|encrypted_data_key|nonce_or_iv|aad_context|Authorization|jwt'
readonly RPC_APPEND_AUDIT_EVENT_SIGNATURE='public.rpc_append_audit_event(uuid, uuid, uuid, text, text, uuid, text, integer, jsonb)'
readonly RPC_WRITE_SECRET_VERSION_SIGNATURE='public.rpc_write_secret_version(uuid, text, uuid, uuid, text, text, timestamptz, integer, bytea, bytea, integer, text, bytea, jsonb, uuid, jsonb)'

log_info() {
    printf '[failure-injection] %s\n' "$*" >&2
}

log_ok() {
    printf '[failure-injection] OK: %s\n' "$*" >&2
}

log_error() {
    printf '[failure-injection] ERROR: %s\n' "$*" >&2
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

utc_now() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

valid_create_body() {
    local plaintext_hex="${1:-6661696c7572652d696e6a656374696f6e}"

    printf '{"classification":"failure-injection","device_id":"failure-injection-sbc","plaintext_hex":"%s"}' \
        "${plaintext_hex}"
}

require_failure_injection_allowed() {
    [[ "${MIPSORCU_FAILURE_INJECTION_ALLOWED:-}" == "1" ]] \
        || fail "set MIPSORCU_FAILURE_INJECTION_ALLOWED=1 for mutating failure-injection scenarios"
}

require_local_base_url() {
    case "${MIPSORCU_BASE_URL}" in
        http://127.0.0.1:* | http://localhost:*) ;;
        *) fail "MIPSORCU_BASE_URL must be local for failure injection: ${MIPSORCU_BASE_URL}" ;;
    esac
}

require_local_test_db_url() {
    require_env "MIPSORCU_TEST_DB_URL"

    case "${MIPSORCU_TEST_DB_URL}" in
        *supabase.co* | *amazonaws.com* | *azure.com* | *googleapis.com* | *neon.tech* | *railway.app* | *render.com* | *prod* | *production*)
            fail "refusing non-local MIPSORCU_TEST_DB_URL"
            ;;
    esac

    case "${MIPSORCU_TEST_DB_URL}" in
        postgres://*@127.0.0.1:*/* | postgresql://*@127.0.0.1:*/* | postgres://*@localhost:*/* | postgresql://*@localhost:*/*)
            ;;
        *) fail "MIPSORCU_TEST_DB_URL must point to localhost or 127.0.0.1" ;;
    esac
}

require_safe_mutating_environment() {
    require_failure_injection_allowed
    require_local_base_url
    if [[ -n "${MIPSORCU_TEST_DB_URL:-}" ]]; then
        require_local_test_db_url
    fi
}

http_status() {
    local status

    status="$(curl -sS -o /dev/null -w '%{http_code}' "$@" 2>/dev/null)" \
        || {
            printf '000\n'
            return 0
        }
    printf '%s\n' "${status}"
}

http_request() {
    local response_file
    local status
    local body

    response_file="$(mktemp "${TMPDIR:-/tmp}/mipsorcu-fi-response.XXXXXX")"
    status="$(curl -sS -o "${response_file}" -w '%{http_code}' "$@" 2>/dev/null)" \
        || status="000"
    body="$(cat "${response_file}")"
    rm -f "${response_file}"
    printf '%s|%s\n' "${status}" "${body}"
}

api_json_with_bearer() {
    local method="$1"
    local url="$2"
    local bearer_token="$3"
    local data="${4:-}"
    local result
    local status
    local body

    if [[ -n "${data}" ]]; then
        result="$(
            http_request \
                -X "${method}" \
                -H "Authorization: Bearer ${bearer_token}" \
                -H "Content-Type: application/json" \
                --data "${data}" \
                "${url}"
        )"
    else
        result="$(
            http_request \
                -X "${method}" \
                -H "Authorization: Bearer ${bearer_token}" \
                "${url}"
        )"
    fi
    status="${result%%|*}"
    body="${result#*|}"

    if [[ "${status}" -lt 200 || "${status}" -ge 300 ]]; then
        fail "HTTP ${method} ${url} returned status ${status}: ${body}"
    fi

    assert_no_forbidden_material "HTTP ${method} response" "${body}"
    printf '%s' "${body}"
}

create_test_secret_with_token() {
    local bearer_token="$1"
    local plaintext_hex="${2:-6661696c7572652d696e6a656374696f6e}"

    api_json_with_bearer \
        "POST" \
        "${MIPSORCU_BASE_URL}/v1/secrets" \
        "${bearer_token}" \
        "$(valid_create_body "${plaintext_hex}")"
}

assert_status_exact() {
    local expected="$1"
    local actual="$2"

    [[ "${actual}" == "${expected}" ]] \
        || fail "expected HTTP ${expected}, got ${actual}"
    log_ok "HTTP status ${actual}"
}

assert_status_in() {
    local actual="$1"
    shift

    local expected
    for expected in "$@"; do
        if [[ "${actual}" == "${expected}" ]]; then
            log_ok "HTTP status ${actual}"
            return 0
        fi
    done

    fail "unexpected HTTP status ${actual}; expected one of: $*"
}

assert_not_success_status() {
    local actual="$1"

    if [[ "${actual}" =~ ^2[0-9][0-9]$ ]]; then
        fail "expected failure status, got ${actual}"
    fi
    log_ok "request failed closed with HTTP ${actual}"
}

sanitize_allowed_auth_error_codes() {
    sed -E \
        -e 's/authorization_header_missing/safe_auth_error_code/g' \
        -e 's/authorization_header_invalid/safe_auth_error_code/g' \
        -e 's/authorization_scheme_invalid/safe_auth_error_code/g' \
        -e 's/raw_jwt_malformed/safe_auth_error_code/g' \
        -e 's/jwt_verification_failed/safe_auth_error_code/g'
}

assert_no_forbidden_material() {
    local label="$1"
    local value="$2"
    local sanitized

    sanitized="$(printf '%s' "${value}" | sanitize_allowed_auth_error_codes)"
    if printf '%s' "${sanitized}" | grep -qiE "${FORBIDDEN_FAILURE_PATTERN}"; then
        log_error "${label} contains forbidden secret-bearing marker"
        printf '%s\n' "${value}" >&2
        return 1
    fi

    log_ok "${label} contains no forbidden secret-bearing marker"
}

fetch_audit_events() {
    local action="$1"
    local result="$2"
    local url="${MIPSORCU_BASE_URL}/audit/v1/audit-events?limit=500&offset=0"

    require_env "MIPSORCU_AUDITOR_JWT"

    if [[ -n "${action}" ]]; then
        url="${url}&action=${action}"
    fi
    if [[ -n "${result}" ]]; then
        url="${url}&result=${result}"
    fi

    curl -fsS \
        -H "Authorization: Bearer ${MIPSORCU_AUDITOR_JWT}" \
        "${url}"
}

assert_auth_failure_audit_recorded_since() {
    local _start_time="$1"
    local events

    events="$(fetch_audit_events "auth_failure" "failure")"
    assert_no_forbidden_material "auth_failure audit response" "${events}"
    printf '%s' "${events}" \
        | jq -e \
            '.items | any(
                .action == "auth_failure"
                and .result == "failure"
                and .actor_user_id == null
                and .actor_device_id == null
                and .target_secret_id == null
                and .key_version == null
                and (.metadata_json | type == "object")
                and (.metadata_json.source_event_at | type == "string")
                and (.metadata_json.error_code | type == "string")
            )' \
        >/dev/null \
        || fail "auth_failure audit event was not recorded with minimum information"

    log_ok "auth_failure audit event recorded with minimum information"
}

assert_audit_ui_read_failure_recorded_since() {
    local _start_time="$1"
    local events

    events="$(fetch_audit_events "audit_ui_read" "failure")"
    assert_no_forbidden_material "audit_ui_read failure audit response" "${events}"
    printf '%s' "${events}" \
        | jq -e \
            '.items | any(
                .action == "audit_ui_read"
                and .result == "failure"
                and (.metadata_json | type == "object")
                and .metadata_json.error_code == "auditor_role_required"
            )' \
        >/dev/null \
        || fail "audit_ui_read failure audit event was not recorded"

    log_ok "audit_ui_read failure audit event recorded"
}

psql_scalar() {
    local sql="$1"

    psql "${MIPSORCU_TEST_DB_URL}" -v ON_ERROR_STOP=1 -tAc "${sql}" \
        | tr -d '\r'
}

psql_exec() {
    local sql="$1"

    psql "${MIPSORCU_TEST_DB_URL}" -v ON_ERROR_STOP=1 -c "${sql}" >/dev/null
}

revoke_rpc_execute() {
    local signature="$1"

    psql_exec "REVOKE EXECUTE ON FUNCTION ${signature} FROM service_role;"
}

grant_rpc_execute() {
    local signature="$1"

    psql_exec "GRANT EXECUTE ON FUNCTION ${signature} TO service_role;"
}

compose_container_id() {
    local container_id

    container_id="$(docker compose ps -q "mipsorcu")"
    [[ -n "${container_id}" ]] || fail "mipsorcu compose service is not running"
    printf '%s\n' "${container_id}"
}

compose_container_network() {
    local container_id="$1"
    local network_name

    network_name="$(
        docker inspect \
            -f '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
            "${container_id}" \
            | head -n 1
    )"
    [[ -n "${network_name}" ]] || fail "could not determine compose network for ${container_id}"
    printf '%s\n' "${network_name}"
}

run_mipsorcu_cli() {
    (
        cd "${FAILURE_REPO_ROOT}"
        docker compose exec -T "mipsorcu" mipsorcu "$@"
    )
}

wait_for_http_status() {
    local url="$1"
    local expected="$2"
    local attempts="$3"
    local delay_seconds="$4"
    local status="000"
    local i

    for i in $(seq 1 "${attempts}"); do
        status="$(http_status --max-time 5 "${url}")"
        if [[ "${status}" == "${expected}" ]]; then
            log_ok "${url} returned ${expected}"
            return 0
        fi
        sleep "${delay_seconds}"
    done

    fail "${url} did not return ${expected}; last status was ${status}"
}

fallback_line_count() {
    docker compose exec -T "mipsorcu" sh -c \
        'path="$1"; if [ -f "$path" ]; then wc -l < "$path"; else echo 0; fi' \
        sh "${FALLBACK_PATH}" \
        | tr -d '[:space:]'
}

fallback_contents() {
    docker compose exec -T "mipsorcu" sh -c \
        'path="$1"; if [ -f "$path" ]; then cat "$path"; fi' \
        sh "${FALLBACK_PATH}"
}

assert_fallback_no_forbidden_material() {
    local contents

    contents="$(fallback_contents)"
    assert_no_forbidden_material "audit fallback file" "${contents}"
}
