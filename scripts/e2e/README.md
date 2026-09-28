# E2E scripts

起動済みの mipsorcu server に対して、seed なしの代表シナリオを実行する bash スクリプトです。secret 作成 → alias 作成 → alias 経由の rotation → alias 経由の復号 → 監査・台帳の確認 → `auditor verify` の順に確認します。

## 前提

- server が起動し、`/health` が `up`、`/ready` が `ready` であること
- 台帳の署名鍵（`MIPSORCU_SIGNATURE_KEY_VERSION`、既定 `1`）が `active` であること
- 通常の利用者の JWT と、`mipsorcu_roles` に `auditor` を含む利用者の JWT を用意していること
- コマンド: `bash`, `curl`, `jq`, `xxd`, `shasum`。container モードでは `docker`、host モードでは `PATH` 上の `mipsorcu`

## 環境変数

| 変数 | 必須 | 既定値 | 内容 |
|---|---|---|---|
| `MIPSORCU_JWT` | 必須 | なし | secret と alias の操作に使う利用者の JWT |
| `MIPSORCU_AUDITOR_JWT` | 必須 | なし | `/audit/v1` の読み取りに使う auditor の JWT |
| `MIPSORCU_BASE_URL` | 任意 | `http://127.0.0.1:3000` | server の URL |
| `MIPSORCU_E2E_MODE` | 任意 | `container` | `container`（`docker compose exec -T mipsorcu mipsorcu ...` で CLI を実行）または `host`（`mipsorcu ...`） |
| `MIPSORCU_E2E_STATE_DIR` | 任意 | `/tmp/mipsorcu-e2e-state` | 手順間で ID などを受け渡すディレクトリ（`STATE_DIR` も互換名として読む） |
| `MIPSORCU_SIGNATURE_KEY_VERSION` | 任意 | `1` | 確認する署名鍵の version |
| `MIPSORCU_AUDIT_UI_BASE_URL` | 任意 | なし | 設定すると container モードで audit-ui への疎通も確認する |

JWT はファイル・ログ・チケットに保存しないでください。スクリプトは固定のテスト用平文を使い、復号結果はハッシュで照合します。

## 実行

source repo のルートで実行します。

```sh
export MIPSORCU_JWT="<owner_jwt>"
export MIPSORCU_AUDITOR_JWT="<auditor_jwt>"
bash "scripts/e2e/run-all.sh"
```

成功すると終了コード 0 で `===== E2E PASSED =====` を出力します。state ディレクトリは残ります。

個別に実行する場合も、`00-precheck.sh` から順に実行してください（`00` が state ディレクトリを初期化します）。

| スクリプト | 内容 |
|---|---|
| `00-precheck.sh` | 依存コマンド、`/health`・`/ready`、署名鍵の状態を確認し、state を初期化する |
| `01-create-secret.sh` | `POST /v1/secrets` で secret を作成する |
| `02-create-alias.sh` | alias を作成する |
| `03-rotate-by-alias.sh` | alias を指定して rotation する |
| `04-decrypt-current.sh` | alias を指定して復号し、平文のハッシュを照合する |
| `05-verify-audit.sh` | `/audit/v1/audit-events` で `encrypt_create`・`secret_alias_create`・`encrypt_rotate`・`decrypt` を確認する |
| `06-verify-ledger.sh` | `/audit/v1/ledger-entries` で `secret_created`・`secret_version_created`・`secret_decrypted` と、sequence の連続性・署名の形式を確認する |
| `07-auditor-verify.sh` | `mipsorcu auditor verify` が `valid: true` かつ `checked_count > 0` を返すことを確認する |

API と CLI の仕様は docs repo の `reference/http-api.md` と `reference/cli.md`、テスト全体は `development/testing.md` を参照してください。
