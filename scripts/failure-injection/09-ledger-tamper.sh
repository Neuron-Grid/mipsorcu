#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

require_command "docker"
require_command "jq"
require_command "psql"
require_failure_injection_allowed
require_local_base_url
require_local_test_db_url

target_sequence=""
original_signature_hex=""
max_sequence=""

restore_ledger_entry() {
    log_info "restoring ledger entry and immutable trigger"
    if [[ -n "${target_sequence}" && -n "${original_signature_hex}" ]]; then
        psql_exec "ALTER TABLE public.ledger_entries DISABLE TRIGGER ledger_entries_no_update_delete;" || true
        psql_exec "UPDATE public.ledger_entries SET signature = decode('${original_signature_hex}', 'hex') WHERE sequence_no = ${target_sequence};" || true
    fi
    psql_exec "ALTER TABLE public.ledger_entries ENABLE TRIGGER ledger_entries_no_update_delete;" || true
}
trap restore_ledger_entry EXIT

log_info "Scenario 9: auditor verify detects ledger signature tampering"

max_sequence="$(psql_scalar "SELECT COALESCE(MAX(sequence_no), 0) FROM public.ledger_entries;")"
if [[ -z "${max_sequence}" || "${max_sequence}" == "0" ]]; then
    fail "public.ledger_entries has no rows to tamper"
fi

target_sequence="$(psql_scalar "SELECT sequence_no FROM public.ledger_entries ORDER BY sequence_no LIMIT 1;")"
original_signature_hex="$(psql_scalar "SELECT encode(signature, 'hex') FROM public.ledger_entries WHERE sequence_no = ${target_sequence};")"

[[ "${target_sequence}" =~ ^[1-9][0-9]*$ ]] || fail "invalid target sequence: ${target_sequence}"
[[ "${max_sequence}" =~ ^[1-9][0-9]*$ ]] || fail "invalid max sequence: ${max_sequence}"
[[ "${original_signature_hex}" =~ ^[0-9a-f]{128}$ ]] || fail "invalid original signature hex"

log_info "precondition: auditor verify is valid for sequence 1..${max_sequence}"
pre_stderr="$(mktemp "${TMPDIR:-/tmp}/mipsorcu-fi-verify-pre.XXXXXX")"
pre_exit=0
pre_output="$(run_mipsorcu_cli auditor verify --from-sequence "1" --to-sequence "${max_sequence}" --format json 2>"${pre_stderr}")" \
    || pre_exit=$?
if [[ "${pre_exit}" != "0" ]]; then
    printf '%s\n' "${pre_output}" >&2
    cat "${pre_stderr}" >&2
    rm -f "${pre_stderr}"
    fail "precondition failed: ledger chain was invalid before tampering"
fi
rm -f "${pre_stderr}"
printf '%s' "${pre_output}" | jq -e '.valid == true' >/dev/null \
    || fail "precondition failed: auditor verify returned valid=false before tampering"

log_info "tampering ledger entry signature at sequence ${target_sequence}"
psql_exec "ALTER TABLE public.ledger_entries DISABLE TRIGGER ledger_entries_no_update_delete;"
psql_exec "UPDATE public.ledger_entries SET signature = decode(repeat('00', 64), 'hex') WHERE sequence_no = ${target_sequence};"
psql_exec "ALTER TABLE public.ledger_entries ENABLE TRIGGER ledger_entries_no_update_delete;"

verify_stderr="$(mktemp "${TMPDIR:-/tmp}/mipsorcu-fi-verify-tampered.XXXXXX")"
verify_exit=0
verify_output="$(run_mipsorcu_cli auditor verify --from-sequence "1" --to-sequence "${max_sequence}" --format json 2>"${verify_stderr}")" \
    || verify_exit=$?

if [[ "${verify_exit}" == "0" ]]; then
    printf '%s\n' "${verify_output}" >&2
    cat "${verify_stderr}" >&2
    rm -f "${verify_stderr}"
    fail "auditor verify exited 0 after ledger tampering"
fi

assert_no_forbidden_material "auditor verify stdout" "${verify_output}"
assert_no_forbidden_material "auditor verify stderr" "$(cat "${verify_stderr}")"
rm -f "${verify_stderr}"

printf '%s' "${verify_output}" | jq -e '.valid == false' >/dev/null \
    || fail "auditor verify did not return valid=false"
printf '%s' "${verify_output}" | jq -e --argjson target "${target_sequence}" '.first_error.sequence_no == $target' >/dev/null \
    || fail "auditor verify did not identify the tampered sequence"
printf '%s' "${verify_output}" | jq -e '.first_error.code == "signature_invalid"' >/dev/null \
    || fail "auditor verify did not classify the tamper as signature_invalid"
log_ok "auditor verify detected signature tampering at sequence ${target_sequence}"

restore_ledger_entry
trap - EXIT

log_info "checking auditor verify after restore"
post_stderr="$(mktemp "${TMPDIR:-/tmp}/mipsorcu-fi-verify-post.XXXXXX")"
post_exit=0
post_output="$(run_mipsorcu_cli auditor verify --from-sequence "1" --to-sequence "${max_sequence}" --format json 2>"${post_stderr}")" \
    || post_exit=$?
if [[ "${post_exit}" != "0" ]]; then
    printf '%s\n' "${post_output}" >&2
    cat "${post_stderr}" >&2
    rm -f "${post_stderr}"
    fail "auditor verify failed after ledger entry restore"
fi
rm -f "${post_stderr}"
printf '%s' "${post_output}" | jq -e '.valid == true' >/dev/null \
    || fail "auditor verify returned valid=false after restore"
log_ok "auditor verify is valid after restore"

log_ok "Scenario 9 passed"
