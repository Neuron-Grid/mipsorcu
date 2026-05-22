#!/usr/bin/env bash
set -euo pipefail

echo "[1/5] audit-ui/ ディレクトリ存在確認"
if [[ ! -d "audit-ui" ]]; then
    echo "NG: audit-ui/ が存在しない"
    exit 1
fi
echo "OK"

echo "[2/5] 親参照禁止"
if grep -RnE "(from|import)[[:space:]]+['\"]\\.\\./\\.\\.|\\.\\./\\.\\./" "audit-ui/src" "audit-ui/tests" 2>/dev/null; then
    echo "NG: audit-ui から親ディレクトリへの参照を検出"
    exit 1
fi
echo "OK: 親参照なし"

echo "[3/5] server-only env 参照禁止"
for path in "audit-ui/src" "audit-ui/tests"; do
    [[ -d "${path}" ]] || continue
    while IFS= read -r -d '' file; do
        case "${file}" in
            "audit-ui/src/redaction.ts" | "audit-ui/tests/e2e/audit-ui.spec.ts")
                continue
                ;;
        esac

        if grep -nE "MIPSORCU_SUPABASE_SERVICE_ROLE_KEY|MIPSORCU_MASTER_KEY|MIPSORCU_LEDGER_SIGNING_KEY|MIPSORCU_ALIAS_ENCRYPTION_KEY|MIPSORCU_ALIAS_FINGERPRINT_KEY|service_role|master_key|ledger_signing_key|alias_encryption_key|alias_fingerprint_key" "${file}"; then
            echo "NG: audit-ui に server-only env または key marker を検出: ${file}"
            exit 1
        fi
    done < <(find "${path}" -type f \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' \) -print0)
done
echo "OK: server-only env 参照なし"

echo "[4/5] audit-ui/ 単独 build context 必須ファイル"
required_files=(
    "audit-ui/package.json"
    "audit-ui/bun.lock"
    "audit-ui/tsconfig.json"
    "audit-ui/vite.config.ts"
    "audit-ui/Dockerfile"
    "audit-ui/.dockerignore"
    "audit-ui/nginx.conf"
    "audit-ui/README.md"
)

for file in "${required_files[@]}"; do
    if [[ ! -f "${file}" ]]; then
        echo "NG: 必須ファイル ${file} が存在しない"
        exit 1
    fi
done
echo "OK: 必須ファイルが揃っている"

echo "[5/5] .env ファイル混入禁止"
if find "audit-ui" \
    -path "audit-ui/node_modules" -prune -o \
    -type f \
    \( -name ".env" -o -name ".env.*" \) \
    ! -name ".env.example" \
    -print | grep -q .; then
    echo "NG: audit-ui 配下に .env ファイル (例外: .env.example) を検出"
    exit 1
fi
echo "OK: .env コミットなし"

echo ""
echo "============================="
echo "OK: audit-ui 境界チェック通過"
echo "============================="
