# E2E scripts

mipsorcu v0.1.0 の seed なし代表 E2E シナリオを実行する bash スクリプト群です。

## 依存ツール

- `bash`
- `curl`
- `jq`
- `xxd`
- `shasum`
- `docker compose` (`MIPSORCU_E2E_MODE=container` の場合)
- `mipsorcu` binary (`MIPSORCU_E2E_MODE=host` の場合)

`shellcheck` は必須依存ではありません。現行スクリプトは `openssl` を使いません。

## 環境変数

- `MIPSORCU_BASE_URL`: 任意。既定値は `http://127.0.0.1:3000`
- `MIPSORCU_JWT`: 必須。secret create / alias / rotate / decrypt 用の owner JWT
- `MIPSORCU_AUDITOR_JWT`: 必須。`/audit/v1` 読み取り用の auditor JWT
- `MIPSORCU_E2E_MODE`: 任意。`container` または `host`。既定値は `container`
- `MIPSORCU_E2E_STATE_DIR`: 任意。既定値は `/tmp/mipsorcu-e2e-state`
- `STATE_DIR`: 任意。`MIPSORCU_E2E_STATE_DIR` 未指定時の互換 alias
- `MIPSORCU_SIGNATURE_KEY_VERSION`: 任意。既定値は `1`

JWT、service role key、Master Key、ledger signing key、plaintext、`plaintext_hex` は `.env`、ドキュメント、ログ、チケットへ保存しないでください。

## 一括実行

リポジトリルート `/Users/neurongrid/Filen/Git/Individual_Projects/mipsorcu` で実行します。

```sh
cd "/Users/neurongrid/Filen/Git/Individual_Projects/mipsorcu"

export MIPSORCU_BASE_URL="http://127.0.0.1:3000"
export MIPSORCU_JWT="<owner_jwt>"
export MIPSORCU_AUDITOR_JWT="<auditor_jwt>"
export MIPSORCU_E2E_STATE_DIR="/tmp/mipsorcu-e2e-state"

bash "scripts/e2e/run-all.sh"
```

期待:

- exit code 0
- `===== E2E PASSED =====`
- state が `/tmp/mipsorcu-e2e-state` に残る
- `plaintext` ファイルは残らない

## 個別実行順

`00-precheck.sh` が state directory を初期化します。個別実行時も必ず 00 から順に実行します。

```sh
cd "/Users/neurongrid/Filen/Git/Individual_Projects/mipsorcu"

bash "scripts/e2e/00-precheck.sh"
bash "scripts/e2e/01-create-secret.sh"
bash "scripts/e2e/02-create-alias.sh"
bash "scripts/e2e/03-rotate-by-alias.sh"
bash "scripts/e2e/04-decrypt-current.sh"
bash "scripts/e2e/05-verify-audit.sh"
bash "scripts/e2e/06-verify-ledger.sh"
bash "scripts/e2e/07-auditor-verify.sh"
```

## Container 実行

```sh
cd "/Users/neurongrid/Filen/Git/Individual_Projects/mipsorcu"

docker compose build
docker compose up -d

MIPSORCU_BASE_URL="http://127.0.0.1:3000" \
MIPSORCU_JWT="<owner_jwt>" \
MIPSORCU_AUDITOR_JWT="<auditor_jwt>" \
bash "scripts/e2e/run-all.sh"
```

## Bare Metal 実行

server が別プロセスで起動済みで、`mipsorcu` binary が `PATH` 上にあることを前提にします。

```sh
MIPSORCU_E2E_MODE="host" \
MIPSORCU_BASE_URL="http://127.0.0.1:3000" \
MIPSORCU_JWT="<owner_jwt>" \
MIPSORCU_AUDITOR_JWT="<auditor_jwt>" \
bash "scripts/e2e/run-all.sh"
```

## 確認内容

- `/health` と `/ready`
- signature key が `active`
- secret create / alias create / alias rotate / alias decrypt
- decrypt 結果の hash 一致
- audit event: `encrypt_create`, `secret_alias_create`, `encrypt_rotate`, `decrypt`
- ledger entry: `secret_created`, `secret_version_created`, `secret_decrypted`
- ledger response 全体の sequence 連続性
- ledger response 全体の Ed25519 署名と `signature_key_version > 0`
- `mipsorcu auditor verify` の `valid: true` と `checked_count > 0`

詳細は `docs/e2e-v0.1.0.md` を参照してください。
