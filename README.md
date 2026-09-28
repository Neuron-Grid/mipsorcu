# mipsorcu

秘密情報を SBC（Single Board Computer）上で暗号化してから外部データベースへ保存する、自己ホスト型の秘密情報管理システムです。鍵・平文・認可判断・台帳署名を SBC に閉じ込め、データベース側が侵害されても平文を復元できない構成を採ります。操作は監査イベントとして記録し、SHA3-256 と Ed25519 による署名付き台帳で改ざんを検出できます。

- **Status**: 最新リリースは v0.1.0（ベータ）。`develop` では v0.2.0 を開発中です（[リリースの位置付け](docs/release/scope.md)）
- **License**: Apache License 2.0

## 特徴

- **信頼境界の集約**: Master Key（KEK）、DEK、alias 鍵、台帳の署名鍵、認可判断は SBC 内だけで扱います。
- **エンベロープ暗号化**: secret の version ごとに DEK を生成して XChaCha20-Poly1305 で暗号化し、DEK を KEK で wrap して保存します。
- **書き込み経路の限定**: DB への書き込みは SBC が呼ぶ用途別の RPC だけです。RLS と権限設定でクライアントの直接書き込みを拒否します。
- **監査と台帳**: `audit_events` を監査の正本とし、署名付きの hash chain で改ざんを検出します。月次 digest を外部 archive（S3 Object Lock）と RFC 3161 timestamping で保全できます。
- **fail-close**: 認可・暗号・監査・必須の台帳記録の失敗を成功として扱いません。SIEM などの副次連携の失敗は主要な操作へ伝播させません。
- **read-only の監査コンソール**: 外部 repo `mipsorcu-audit-ui` で提供します。書き込み・復号・修復の導線は持ちません。

## 構成

```text
Client ──(Bearer JWT)──▶ mipsorcu（SBC） ─┬─ RLS 付き SELECT / 用途別 RPC ──▶ Supabase（PostgreSQL + Auth）
                                            └─ SIEM / webhook / S3 / TSA（任意）
Auditor ──▶ mipsorcu-audit-ui ──▶ mipsorcu /audit/v1（read-only）
```

| 技術 | 内容 |
|---|---|
| server | Rust（axum、RustCrypto） |
| DB・認証 | Supabase（PostgreSQL 17、Auth、RLS、RPC） |
| 監査 UI | Vite + Preact + TypeScript（外部 repo） |
| 実行環境 | Docker Compose、Raspberry Pi 4 相当の SBC、Tailscale などの private network |

```text
mipsorcu/
├── src/                  # Rust server と CLI
├── supabase/
│   ├── migrations/       # スキーマ・RLS・RPC（0100〜1460）
│   └── tests/            # pgTAP
├── tests/                # Rust の integration / unit テスト
├── scripts/              # E2E、障害注入、security check
├── compose.yaml
├── Dockerfile
├── .env.example
└── docs/                 # 文書（独立した Git repo）
```

## クイックスタート（ローカル開発）

前提: Docker / Docker Compose、Supabase CLI、事前に生成した鍵（Master Key、alias 鍵 2 本、台帳の署名鍵。いずれも 32 byte の hex）。

```sh
# 1. ローカルの Supabase を起動し、migration を適用する（ローカル DB のデータは消えます）
supabase start
supabase db reset

# 2. 環境変数を用意する
cp ".env.example" ".env"
# .env の値を実値に置き換える

# 3. server を起動する
docker compose build
docker compose up -d
curl -fsS "http://127.0.0.1:3000/ready"
```

- server は起動時に、設定した台帳の署名鍵が DB 上で `active` であることを確認し、満たさなければ終了します。
- `.env` の Supabase URL と JWKS URL には、container 内から到達できる値を設定してください（container 内の `127.0.0.1` はホストではありません）。
- `.env` と `./mipsorcu-data`（永続化ディレクトリ）には秘密値が含まれます。version 管理に含めないでください。

詳細は [デプロイ](docs/operations/deployment.md) と [環境変数](docs/reference/configuration.md) を参照してください。

## テスト

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
supabase test db
```

E2E は [scripts/e2e/README.md](scripts/e2e/README.md)、その他のテストは [テスト](docs/development/testing.md) を参照してください。

## ドキュメント

`docs/` は独立した Git repository です。source repo の clone には含まれません。

| 文書 | 内容 |
|---|---|
| [docs/README.md](docs/README.md) | 索引と文書の規約 |
| [docs/overview.md](docs/overview.md) | システム概要 |
| [docs/reference/http-api.md](docs/reference/http-api.md) | HTTP API |
| [docs/reference/cli.md](docs/reference/cli.md) | CLI |
| [docs/operations/runbook.md](docs/operations/runbook.md) | 運用手順 |
| [docs/release/known-limitations.md](docs/release/known-limitations.md) | 既知の制約 |

## 貢献

設計上の契約を変える変更は ADR で決定してから実装します。コミットは Conventional Commits 形式です（[変更管理](docs/development/change-management.md)）。

## ライセンス

Apache License 2.0
