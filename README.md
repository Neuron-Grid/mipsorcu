# mipsorcu

機密情報を保存前に暗号化し、平文を外部ストレージへ保管しない秘密情報管理システム。

鍵管理・暗号操作・認可判断をプライベートネットワーク内部に設置した SBC（Single Board Computer）に集約することで、データベース側が侵害された場合でも平文を復元できない設計を採用しています。

- **Status**: v0.1.0 リリース準備中
- **License**: Apache License 2.0

---

## 1. 特徴

- **信頼境界の集約**: 鍵の保持・暗号操作・認可判断を SBC 内部に閉じ込め、外部に露出しない構成。
- **平文を外部へ保存しない**: Supabase には暗号文、保護された Data Key、非秘密メタデータ、監査記録を保存。鍵の平文は保存しない。
- **エンベロープ暗号化**: Master Key で各 secret 専用の Data Key を保護し、Data Key で平文を AEAD 暗号化する 2 段構成。
- **監査台帳**: 操作イベントを正本として記録し、Ed25519 署名付き台帳によって改ざん検出を可能にする。
- **fail-close 設計**: 認可・暗号・監査正本・必須の台帳記録・整合性確認の失敗を成功として扱わない。SIEM など副次連携の失敗は別に扱う。
- **読み取り専用の監査コンソール**: 外部 companion repository `mipsorcu-audit-ui` で提供。書き込み・復号・修復系の導線は持たない。

---

## 2. アーキテクチャ概要

### 2.1 信頼境界

本システムの信頼境界は SBC（Single Board Computer）です。以下の操作は SBC 内部でのみ実行されます。

- Master Key の保持と使用
- Data Key の生成・unwrap / rewrap
- 平文の暗号化・復号
- JWT の検証
- 認可判断
- 署名秘密鍵の保持と署名生成

外部データベースおよび UI コンテナは信頼境界の外側に位置し、復号能力・認可判断・鍵の平文を持ちません。

### 2.2 リクエストフロー

```
Client
  │
  │ (1) 認証基盤に公開可能キーでログイン → JWT 取得
  ▼
Client
  │
  │ (2) SBC API に Bearer JWT を付けてアクセス
  ▼
SBC（mipsorcu server）
  │ (3) JWT をオフライン検証
  │ (4) 暗号化 / 復号 / 認可判断を実施
  │ (5) 高権限キーで外部 DB の RPC を呼び出し
  ▼
External Database
        (6) 暗号文・メタデータ・監査イベントを保存
```

### 2.3 コンテナ構成

```
Client ──┬──→ mipsorcu-audit-ui container（外部 companion repo、read-only console）
         │             │
         │             │ read-only audit API
         │             ▼
         └──→ mipsorcu container（SBC trust boundary）
                       │
                       ├──→ persistent volume
                       └──→ External Database / Auth
```

`mipsorcu-audit-ui` は外部必須成果物として `../mipsorcu-audit-ui` で管理する静的ファイル配信コンテナです。高権限キー・Master Key・署名秘密鍵は runtime env、build args、image、静的 bundle のいずれにも渡しません。

---

## 3. 技術スタック

| レイヤ | 採用技術 |
|---|---|
| SBC ハードウェア | Raspberry Pi 4（8GB）相当 |
| プライベートネットワーク | Tailscale 等の overlay network |
| サーバー実装 | Rust |
| データベース・認証基盤 | Supabase（PostgreSQL + Auth + RPC + RLS） |
| 監査 UI | Vite + Preact + TypeScript（Bun） |
| Web サーバー | nginx（静的配信） |
| コンテナ | Docker / Docker Compose |
| 暗号方式 | エンベロープ暗号化（AEAD + AAD） |
| 監査台帳の署名 | Ed25519 |

依存先は設計上の選択であり、同等機能を持つ代替に置換可能な構造としています。

---

## 4. リポジトリ構成

```
mipsorcu/
├── README.md
├── Cargo.toml
├── src/                    # Rust サーバー実装
├── supabase/
│   └── migrations/         # スキーマ / RLS / RPC 定義
├── compose.yaml
├── .env.example
├── docs/                   # source repo に含まれる v0.1.0 release 文書
│   ├── release-scope.md
│   └── known-limitations.md
└── scripts/                # E2E・失敗系など

../mipsorcu-audit-ui/       # 隣接配置した場合の外部 companion repo（read-only UI）
├── Dockerfile
├── nginx.conf
├── src/
└── tests/
```

---

## 5. クイックスタート

### 5.1 前提

- Docker および Docker Compose が利用可能であること
- Supabase CLI でローカル開発用 DB を起動できること（外部 project を使う場合は migration 適用済みであること）
- 監査 UI を使う場合は、外部 companion repo `../mipsorcu-audit-ui` が用意済みであること
- JWT issuer / audience / JWKS URL が確定していること
- Master Key、台帳署名鍵などの秘密値が生成済みであること

### 5.2 起動

```sh
# 1. ローカル開発用 Supabase を起動し、migration を適用
supabase start
supabase db reset

# 2. 環境変数を準備
cp ".env.example" ".env"
# .env を編集し、必要な値を実値に置換する

# 3. server container の build と起動
docker compose build
docker compose up -d

# 4. ヘルスチェック
curl http://127.0.0.1:3000/health
curl http://127.0.0.1:3000/ready

# 5. 監査 UI を外部 repo で build / run する場合
# 公開用 VITE_* の build 設定は外部 repo の README を確認する
(
  cd "../mipsorcu-audit-ui"
  docker build -t "mipsorcu-audit-ui:local" "."
  docker run --rm -d --name "mipsorcu-audit-ui-local" -p "127.0.0.1:8080:8080" "mipsorcu-audit-ui:local"
  curl -fsS "http://127.0.0.1:8080/healthz"
  docker rm -f "mipsorcu-audit-ui-local"
)
```

この例はローカル開発用 DB を前提とします。`supabase db reset` はローカル DB のデータを消去します。外部 project を使う場合は、接続先を確認してからその project に migration を適用してください。`.env` の Supabase / JWKS URL は server container から到達できる値を設定します（container 内の `127.0.0.1` はホストではありません）。監査 UI の例は静的配信の疎通確認です。ログイン・閲覧には外部 repo の README に従い、公開可能な `VITE_*` 値を build 時に指定してください。

`.env` および永続化ボリュームには秘密値が含まれます。バージョン管理から除外し、アクセス制御・バックアップ対象として運用してください。

### 5.3 開発時のテスト

以下は source repository のルートから実行します。Supabase のテストにはローカル開発用 DB を使用します。

```sh
# Rust サーバー
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test

# データベース（ローカル開発用 DB のみ。reset はデータを消去します）
supabase start
supabase db reset
supabase test db

# 監査 UI（外部 repo）
cd "../mipsorcu-audit-ui"
bun install --frozen-lockfile
bun run check
bun run test:guards
bun run build
bun run test:e2e
```

---

## 6. 機能

| 機能 | 内容 |
|---|---|
| secret の作成・更新 | UUID v4 単位でのエンベロープ暗号化保存と、最新バージョンへの更新（rotation） |
| secret alias | 入力補助用の人間向け識別子。canonical な UUID 識別子の置換ではなく、入力解決のみに使用 |
| 復号 | 最新バージョンの復号 |
| 監査イベント | 成功・失敗・認証失敗を記録。永続化失敗時は SBC 内部の fallback にバッファし、後で再送 |
| 署名付き台帳 | Ed25519 署名により改ざんを検出可能にする |
| Master Key rotation | 既存の Data Key を新しい Master Key で rewrap（本文は再暗号化しない） |
| 整合性確認 / 復元テスト | 暗号文と平文の対応関係を確認する運用機能 |
| 監査コンソール | read-only の閲覧 UI。書き込み・復号・修復系の導線は持たない |

v0.1.0 の core scope と限定範囲は [release scope](docs/release-scope.md)、運用上の注意点は [known limitations](docs/known-limitations.md) を参照してください。scheduler、SIEM、archive、timestamping、incident notification、monthly digest / report は本番完成版として扱いません。

---

## 7. 設計上の制約

以下は実装・運用において維持する制約です。

- 平文を外部データベースに保存しない
- Master Key および Data Key を SBC 外へ持ち出さない
- 暗号プリミティブを自作せず、検証済みライブラリを使用する
- 監査の正本をアプリケーションログで代替しない
- ログ・エラー出力に秘密情報を含めない
- クライアントから直接データベースへ書き込まない（書き込みは SBC 経由の RPC のみ）
- 監査 UI から write・decrypt・台帳修正の操作を提供しない

---

## 8. 開発ステータス

v0.1.0 は、single SBC / single replica の限定環境で secret 管理・監査・復旧・検証の基本運用を反復するための最初の安定版です。production-ready の完成版ではなく、本番 SLA や HA / multi-replica は対象外です。

本 README のリリース範囲は v0.1.0 を対象とします。開発中の追加機能を v0.1.0 の提供範囲や将来バージョンの確定した計画として扱いません。

---

## 9. 貢献

設計変更を伴う変更は、Architecture Decision Record（ADR）として記録した上で議論します。コミットメッセージは Conventional Commits 形式を採用しています。

---

## 10. ライセンス

Apache License 2.0
