# mipsorcu audit-ui

`mipsorcu-audit-ui` は mipsorcu の read-only 監査コンソールです。Vite + Preact + Bun でビルドし、静的ファイルとして配信します。

このディレクトリは親ディレクトリの Rust コードを参照せず、将来単独リポジトリへ分離できる前提で管理します。

## 必要なもの

- Bun 1.3 以降
- Docker 互換のコンテナランタイム
- mipsorcu の `/audit/v1` read-only API
- Supabase Auth の公開 URL と publishable key

## ローカルビルド

単独リポジトリ化後も、この README があるディレクトリをプロジェクトルートとして扱います。

```sh
bun install --frozen-lockfile
bun run check
bun run test:guards
bun run build
```

`bun run test:e2e` は Playwright を使い、テスト用の Vite dev server と API mock を起動します。

```sh
bun run test:e2e
```

## 設定

Vite の `VITE_*` 環境変数は build-time に JavaScript bundle へ埋め込まれます。秘密値ではなく、ブラウザへ公開してよい値だけを指定してください。

使用する公開設定は以下です。

```sh
VITE_MIPSORCU_SUPABASE_URL="http://127.0.0.1:54321"
VITE_MIPSORCU_SUPABASE_PUBLISHABLE_KEY="your-publishable-key"
VITE_MIPSORCU_AUDIT_API_BASE_URL="http://127.0.0.1:3000"
```

以下の値は audit-ui の build arg、環境変数、Docker image、静的ファイルへ絶対に渡さないでください。

```sh
MIPSORCU_SUPABASE_SERVICE_ROLE_KEY
MIPSORCU_MASTER_KEY
MIPSORCU_LEDGER_SIGNING_KEY
```

audit-ui は `/audit/v1` の read-only API だけを参照します。secret の作成、更新、削除、復号の導線は持ちません。

## Docker

`audit-ui/` を build context として使います。mipsorcu 本体の Rust コードは Docker build context に含めません。

```sh
docker build -t "mipsorcu-audit-ui:local" "."
```

公開設定を指定して build する場合は、build arg として渡します。

```sh
docker build \
  --build-arg VITE_MIPSORCU_SUPABASE_URL="https://example.supabase.co" \
  --build-arg VITE_MIPSORCU_SUPABASE_PUBLISHABLE_KEY="your-publishable-key" \
  --build-arg VITE_MIPSORCU_AUDIT_API_BASE_URL="https://mipsorcu.example.com" \
  -t "mipsorcu-audit-ui:local" \
  "."
```

runtime image は `nginxinc/nginx-unprivileged` を使い、コンテナ内部では非 root で `8080` を listen します。

```sh
docker run --rm \
  -p "127.0.0.1:8080:8080" \
  "mipsorcu-audit-ui:local"
```

起動後に静的配信を確認します。

```sh
curl -fsS "http://127.0.0.1:8080/"
```

`nginx.conf` には SPA fallback、静的 asset cache、read-only method 制限、最低限のセキュリティヘッダを設定しています。`/audit/v1` への `proxy_pass` は設定していません。API の到達先は `VITE_MIPSORCU_AUDIT_API_BASE_URL` で build-time に指定します。

## 分離

mipsorcu 本体のリポジトリから audit-ui だけを切り出す場合は、履歴操作の前に作業ツリーを clean にしてください。

```sh
git filter-repo --path "audit-ui/" --path-rename "audit-ui/:"
```

分離後も、このディレクトリ内の `package.json`、`bun.lock`、`Dockerfile`、`.dockerignore`、`nginx.conf` だけで install、build、Docker build が完結します。
