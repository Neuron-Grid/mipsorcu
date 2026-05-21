# mipsorcu

機密情報を保存前に暗号化し、暗号文のみを外部ストレージへ保管する秘密情報管理システム。

鍵管理・暗号操作・認可判断をプライベートネットワーク内部に設置した SBC（Single Board Computer）に集約することで、データベース側が侵害された場合でも平文を復元できない設計を採用しています。

- **Status**: v0.1.0 リリース準備中
- **License**: TBD

---

## 1. 特徴

- **信頼境界の集約**: 鍵の保持・暗号操作・認可判断を SBC 内部に閉じ込め、外部に露出しない構成。
- **暗号文のみを永続化**: データベースには暗号文と関連メタデータのみを保存。Master Key を持たない限り平文を復元できない。
- **エンベロープ暗号化**: Master Key で各 secret 専用の Data Key を保護し、Data Key で平文を AEAD 暗号化する 2 段構成。
- **監査台帳**: 操作イベントを正本として記録し、Ed25519 署名付き台帳によって改ざん検出を可能にする。
- **fail-close 設計**: 認可・暗号・監査・整合性確認のいずれかが失敗した処理を成功として扱わない。
- **読み取り専用の監査コンソール**: 監査担当者向けの UI を独立コンテナとして提供。書き込み・復号・修復系の導線は持たない。

---

## 2. アーキテクチャ概要

### 2.1 信頼境界

本システムの信頼境界は SBC（Single Board Computer）です。以下の操作は SBC 内部でのみ実行されます。

- Master Key の保持と使用
- Data Key の生成・復号・再利用判断
- 平文の暗号化・復号
- JWT の検証
- 認可判断
- 署名秘密鍵の保持と署名生成

外部データベースおよび UI コンテナは信頼境界の外側に位置し、復号能力・認可判断・鍵素材を持ちません。

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
Client ──┬──→ audit-ui container（静的配信、read-only console）
         │             │
         │             │ read-only audit API
         │             ▼
         └──→ mipsorcu container（SBC trust boundary）
                       │
                       ├──→ persistent volume
                       └──→ External Database / Auth
```

`audit-ui` は静的ファイル配信コンテナです。高権限キー・Master Key・署名秘密鍵は runtime env、build args、image、静的 bundle のいずれにも渡しません。

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
├── audit-ui/               # 監査担当者向け read-only UI
│   ├── Dockerfile
│   ├── nginx.conf
│   └── ...
├── compose.yaml
├── .env.example
└── scripts/
```

---

## 5. クイックスタート

### 5.1 前提

- Docker および Docker Compose が利用可能であること
- 外部データベース（Supabase project）が用意済み、または Supabase CLI でローカル起動できること
- JWT issuer / audience / JWKS URL が確定していること
- Master Key、台帳署名鍵などの秘密値が生成済みであること

### 5.2 起動

```sh
# 1. 環境変数を準備
cp .env.example .env
# .env を編集し、必要な値を実値に置換する

# 2. データベース migration を適用
supabase db push

# 3. コンテナの build と起動
docker compose build
docker compose up -d

# 4. ヘルスチェック
curl http://127.0.0.1:3000/health
curl http://127.0.0.1:3000/ready

# 5. 監査 UI を確認
open http://127.0.0.1:8080
```

`.env` および永続化ボリュームには秘密値が含まれます。バージョン管理から除外し、アクセス制御・バックアップ対象として運用してください。

### 5.3 開発時のテスト

```sh
# Rust サーバー
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test

# データベース
supabase db reset
supabase test db

# 監査 UI
cd audit-ui
bun run check
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
| Master Key rotation | バージョン管理されたキーリングによる再暗号化 |
| 整合性確認 / 復元テスト | 暗号文と平文の対応関係を確認する運用機能 |
| 監査コンソール | read-only の閲覧 UI。書き込み・復号・修復系の導線は持たない |

v0.1.0 で保証する範囲、限定的に扱う範囲、対象外の範囲については、リリース時のリリースノートで明示します。

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

本プロジェクトは v0.1.0 のリリース準備フェーズにあります。v0.1.0 は、限定環境で secret 管理・監査・復旧・検証の基本運用を反復するための最初の安定版として位置づけられており、全機能が本番完成した版ではありません。

詳細なリリース範囲・既知の制限事項・運用前提は、リリース時に公開予定のリリースノートおよびドキュメントを参照してください。

---

## 9. 貢献

設計変更を伴う変更は、Architecture Decision Record（ADR）として記録した上で議論します。コミットメッセージは Conventional Commits 形式を採用しています。

---

## 10. ライセンス

TBD