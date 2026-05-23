#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly DEFAULT_AUDIT_UI_REPO_DIR="${REPO_ROOT}/../mipsorcu-audit-ui"
readonly AUDIT_UI_REPO_DIR="${MIPSORCU_AUDIT_UI_REPO_DIR:-${DEFAULT_AUDIT_UI_REPO_DIR}}"

log_ok() {
    printf '[audit-ui-boundary] OK: %s\n' "$*" >&2
}

fail() {
    printf '[audit-ui-boundary] ERROR: %s\n' "$*" >&2
    exit 1
}

require_path() {
    local relative_path="$1"
    local path="${AUDIT_UI_REPO_DIR}/${relative_path}"

    [[ -e "${path}" ]] || fail "required audit-ui artifact is missing: ${path}"
}

require_dir() {
    local relative_path="$1"
    local path="${AUDIT_UI_REPO_DIR}/${relative_path}"

    [[ -d "${path}" ]] || fail "required audit-ui directory is missing: ${path}"
}

require_command() {
    local command_name="$1"

    command -v "${command_name}" >/dev/null 2>&1 \
        || fail "required command not found: ${command_name}"
}

scan_for_pattern() {
    local label="$1"
    local pattern="$2"
    shift 2

    local matches
    matches="$(
        grep -RInE \
            --exclude-dir ".git" \
            --exclude-dir "dist" \
            --exclude-dir "node_modules" \
            --exclude-dir "test-results" \
            --exclude "bun.lock" \
            "${pattern}" \
            "$@" \
            2>/dev/null || true
    )"

    if [[ -n "${matches}" ]]; then
        printf '%s\n' "${matches}" >&2
        fail "${label}"
    fi
}

[[ -d "${AUDIT_UI_REPO_DIR}" ]] || fail "audit-ui repository not found: ${AUDIT_UI_REPO_DIR}"

require_command "grep"
require_command "find"

require_path "package.json"
require_path "bun.lock"
require_path "Dockerfile"
require_path "nginx.conf"
require_path "README.md"
require_dir "src"
require_dir "tests"
log_ok "required standalone artifacts exist"

symlinks="$(
    find "${AUDIT_UI_REPO_DIR}" \
        -path "${AUDIT_UI_REPO_DIR}/.git" -prune -o \
        -path "${AUDIT_UI_REPO_DIR}/node_modules" -prune -o \
        -path "${AUDIT_UI_REPO_DIR}/dist" -prune -o \
        -path "${AUDIT_UI_REPO_DIR}/test-results" -prune -o \
        -type l -print
)"
if [[ -n "${symlinks}" ]]; then
    printf '%s\n' "${symlinks}" >&2
    fail "audit-ui repository must not contain symlinks in release artifacts"
fi
log_ok "no symlinks in release artifacts"

scan_for_pattern \
    "audit-ui must not depend on parent repository paths or Rust sources" \
    '(\.\./(src|supabase|scripts|Cargo\.toml|Cargo\.lock|compose\.yaml)|mipsorcu/(src|supabase)|path[[:space:]]*=[[:space:]]*["'\'']\.\./)' \
    "${AUDIT_UI_REPO_DIR}"
log_ok "no direct dependency on parent Rust repository"

scan_for_pattern \
    "audit-ui implementation must not reference server-only environment variables" \
    '(MIPSORCU_SUPABASE_SERVICE_ROLE_KEY|MIPSORCU_MASTER_KEY|MIPSORCU_MASTER_KEY_DIR|MIPSORCU_LEDGER_SIGNING_KEY|MIPSORCU_ALIAS_ENCRYPTION_KEY|MIPSORCU_ALIAS_FINGERPRINT_KEY)' \
    "${AUDIT_UI_REPO_DIR}/src" \
    "${AUDIT_UI_REPO_DIR}/scripts"
log_ok "no server-only environment variables in implementation code"

scan_for_pattern \
    "audit-ui runtime config must only use VITE_MIPSORCU_* public variables" \
    'import\.meta\.env\.MIPSORCU_' \
    "${AUDIT_UI_REPO_DIR}/src"
log_ok "runtime config is limited to public VITE variables"

printf '[audit-ui-boundary] repository: %s\n' "${AUDIT_UI_REPO_DIR}" >&2
