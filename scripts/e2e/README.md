# E2E scripts

mipsorcu v0.1.0 の seed なし代表 E2E シナリオを実行する bash スクリプト群です。

## 依存ツール

- `bash`
- `curl`
- `jq`
- `xxd`
- `shasum`
- `docker compose` (`MIPSORCU_E2E_MODE=container` の場合)

`shellcheck` は必須依存ではありません。

## 環境変数

- `MIPSORCU_BASE_URL`: 任意。既定値は `http://127.0.0.1:3000`
- `MIPSORCU_JWT`: secret create / alias / rotate / decrypt 用の owner JWT
- `MIPSORCU_AUDITOR_JWT`: `/audit/v1` 読み取り用の auditor JWT
- `MIPSORCU_E2E_MODE`: 任意。`container` または `host`。既定値は `container`
- `MIPSORCU_E2E_STATE_DIR`: 任意。未指定時は `run-all.sh` が一時ディレクトリを作成し、終了時に削除します。
- `MIPSORCU_SIGNATURE_KEY_VERSION`: 任意。既定値は `1`

JWT、service role key、Master Key、ledger signing key、plaintext、`plaintext_hex` は `.env`、ドキュメント、ログ、チケットへ保存しないでください。

## Container 実行

リポジトリルート `/Users/neurongrid/Filen/Git/Individual_Projects/mipsorcu` で実行します。

```sh
docker compose build
docker compose up -d

MIPSORCU_BASE_URL="http://127.0.0.1:3000" \
MIPSORCU_JWT="<owner_jwt>" \
MIPSORCU_AUDITOR_JWT="<auditor_jwt>" \
bash "scripts/e2e/run-all.sh"
```

## Bare Metal 実行

`mipsorcu` binary が `PATH` 上にあり、server が別プロセスで起動済みであることを前提にします。

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
- ledger entry の Ed25519 署名
- `mipsorcu auditor verify` の `valid: true`

詳細は `docs/e2e-v0.1.0.md` を参照してください。
