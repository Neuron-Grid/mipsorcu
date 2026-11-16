#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

readonly MOCK_BIN="${TEMP_DIR}/bin"
mkdir -p "${MOCK_BIN}"

for command_name in curl docker; do
    cat >"${MOCK_BIN}/${command_name}" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$0 $*" >>"${MOCK_CALLS}"
exit 99
SH
    chmod +x "${MOCK_BIN}/${command_name}"
done

for missing_env in MIPSORCU_JWT TEST_SECRET_ID; do
    calls="${TEMP_DIR}/missing-${missing_env}.calls"
    output="${TEMP_DIR}/missing-${missing_env}.out"
    status=0
    if [[ "${missing_env}" == "MIPSORCU_JWT" ]]; then
        env -u MIPSORCU_JWT -u TEST_SECRET_ID \
            PATH="${MOCK_BIN}:${PATH}" MOCK_CALLS="${calls}" \
            MIPSORCU_FAILURE_INJECTION_ALLOWED=1 MIPSORCU_BASE_URL=http://127.0.0.1:3000 \
            bash "${REPO_ROOT}/scripts/failure-injection/05-supabase-down.sh" >"${output}" 2>&1 || status=$?
    else
        env -u TEST_SECRET_ID \
            PATH="${MOCK_BIN}:${PATH}" MOCK_CALLS="${calls}" \
            MIPSORCU_FAILURE_INJECTION_ALLOWED=1 MIPSORCU_BASE_URL=http://127.0.0.1:3000 MIPSORCU_JWT=test-jwt \
            bash "${REPO_ROOT}/scripts/failure-injection/05-supabase-down.sh" >"${output}" 2>&1 || status=$?
    fi
    [[ "${status}" != "0" ]]
    [[ ! -e "${calls}" ]]
    grep -Fq "required environment variable is empty: ${missing_env}" "${output}"
done

cat >"${MOCK_BIN}/curl" <<'SH'
#!/usr/bin/env bash
args="$*"
if [[ "${args}" == *"/ready"* ]]; then
    count=0
    [[ -f "${CURL_CALLS}" ]] && count="$(cat "${CURL_CALLS}")"
    count=$((count + 1))
    printf '%s' "${count}" >"${CURL_CALLS}"
    if [[ "${count}" == "1" ]]; then printf '200'; else printf '503'; fi
elif [[ "${args}" == *"/decrypt"* ]]; then
    for arg in "$@"; do
        if [[ "${previous_arg:-}" == "-o" ]]; then printf '{}' >"${arg}"; fi
        previous_arg="${arg}"
    done
    printf '503'
else
    exit 99
fi
SH

cat >"${MOCK_BIN}/docker" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${DOCKER_LOG}"
case "$*" in
    'compose ps -q mipsorcu') printf 'container-id\n' ;;
    'inspect '*) printf 'compose-network\n' ;;
    'network disconnect '*) ;;
    'network connect '*)
        count=0
        [[ -f "${CONNECT_CALLS}" ]] && count="$(cat "${CONNECT_CALLS}")"
        count=$((count + 1))
        printf '%s' "${count}" >"${CONNECT_CALLS}"
        [[ "${count}" != "1" ]]
        ;;
    *) exit 99 ;;
esac
SH
chmod +x "${MOCK_BIN}/curl" "${MOCK_BIN}/docker"

status=0
PATH="${MOCK_BIN}:${PATH}" \
CURL_CALLS="${TEMP_DIR}/curl.calls" \
DOCKER_LOG="${TEMP_DIR}/network-docker.log" \
CONNECT_CALLS="${TEMP_DIR}/connect.calls" \
MIPSORCU_FAILURE_INJECTION_ALLOWED=1 \
MIPSORCU_BASE_URL=http://127.0.0.1:3000 \
MIPSORCU_JWT=test-jwt \
TEST_SECRET_ID=00000000-0000-0000-0000-000000000001 \
bash "${REPO_ROOT}/scripts/failure-injection/05-supabase-down.sh" >"${TEMP_DIR}/network-restore.out" 2>&1 || status=$?
[[ "${status}" != "0" ]]
[[ "$(cat "${TEMP_DIR}/connect.calls")" == "2" ]]
[[ "$(grep -c '^network connect ' "${TEMP_DIR}/network-docker.log")" == "2" ]]
grep -Fq 'failed to restore compose network compose-network' "${TEMP_DIR}/network-restore.out"

cat >"${MOCK_BIN}/docker" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == *"compose exec"* ]]; then
    count=0
    [[ -f "${DOCKER_CALLS}" ]] && count="$(cat "${DOCKER_CALLS}")"
    count=$((count + 1))
    printf '%s' "${count}" >"${DOCKER_CALLS}"
    if [[ "${count}" == "1" && "${FAIL_PRECONDITION:-0}" == "1" ]]; then
        printf '{"valid":false}\n'
    elif [[ "${count}" == "1" ]]; then
        printf '{"valid":true}\n'
    else
        printf '{"valid":false,"first_error":{"sequence_no":1,"code":"signature_invalid"}}\n'
    fi
    exit 0
fi
exit 0
SH

cat >"${MOCK_BIN}/jq" <<'SH'
#!/usr/bin/env bash
cat >/dev/null
if [[ "${FAIL_PRECONDITION:-0}" == "1" && "$*" == *'.valid == true'* ]]; then
    exit 1
fi
exit 0
SH

cat >"${MOCK_BIN}/psql" <<'SH'
#!/usr/bin/env bash
query="${*: -1}"
if [[ "${query}" == SELECT* ]]; then
    case "${query}" in
        *MAX\(sequence_no\)*) printf '1\n' ;;
        *ORDER\ BY\ sequence_no*) printf '1\n' ;;
        *encode\(signature*) printf '%0128d\n' 0 | tr '0' 'a' ;;
        *) exit 1 ;;
    esac
    exit 0
fi
printf '%s\n' "${query}" >>"${PSQL_CALLS}"
if [[ "${query}" == *"decode('$(printf '%0128d' 0 | tr '0' 'a')', 'hex')"* ]]; then
    exit 1
fi
exit 0
SH
chmod +x "${MOCK_BIN}/docker" "${MOCK_BIN}/jq" "${MOCK_BIN}/psql"

status=0
PATH="${MOCK_BIN}:${PATH}" \
DOCKER_CALLS="${TEMP_DIR}/precondition-docker.calls" \
PSQL_CALLS="${TEMP_DIR}/precondition-psql.calls" \
FAIL_PRECONDITION=1 \
MIPSORCU_FAILURE_INJECTION_ALLOWED=1 \
MIPSORCU_BASE_URL=http://127.0.0.1:3000 \
MIPSORCU_TEST_DB_URL=postgres://test@localhost:54322/test \
bash "${REPO_ROOT}/scripts/failure-injection/09-ledger-tamper.sh" >"${TEMP_DIR}/precondition.out" 2>&1 || status=$?
[[ "${status}" != "0" ]]
grep -Fq 'precondition failed: auditor verify returned valid=false' "${TEMP_DIR}/precondition.out"
[[ ! -e "${TEMP_DIR}/precondition-psql.calls" ]]

status=0
PATH="${MOCK_BIN}:${PATH}" \
DOCKER_CALLS="${TEMP_DIR}/docker.calls" \
PSQL_CALLS="${TEMP_DIR}/psql.calls" \
MIPSORCU_FAILURE_INJECTION_ALLOWED=1 \
MIPSORCU_BASE_URL=http://127.0.0.1:3000 \
MIPSORCU_TEST_DB_URL=postgres://test@localhost:54322/test \
bash "${REPO_ROOT}/scripts/failure-injection/09-ledger-tamper.sh" >"${TEMP_DIR}/restore.out" 2>&1 || status=$?

[[ "${status}" != "0" ]]
grep -Fq 'ledger restore failed' "${TEMP_DIR}/restore.out"
grep -Fq 'ENABLE TRIGGER ledger_entries_no_update_delete' "${TEMP_DIR}/psql.calls"
printf 'failure injection contract checks passed\n'
