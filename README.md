# mipsorcu

mipsorcu は、Supabase と SBC (Single Board Computer) を組み合わせた秘密情報管理システムです。SBC を唯一の信頼境界とし、鍵管理、平文の暗号化・復号、JWT 検証、認可判断を SBC 内部に閉じます。Supabase には暗号文、非秘密メタデータ、監査証跡のみを保存します。

## v0.1.0 release documents

v0.1.0 は、実験フェーズを閉じ、限定環境で安全に運用練習できる最初の安定版です。全機能が本番完成したことを意味しません。

- [v0.1.0 release scope](docs/release-scope.md): v0.1.0 で中核として保証する機能、限定扱いの機能、対象外を定義します。
- [v0.1.0 known limitations](docs/known-limitations.md): scheduler、SIEM、archive、timestamping、audit-ui などの既知の制限をまとめます。

`audit-ui` は read-only 監査コンソールです。secret の作成・更新・削除、復号、ledger 修正、自動修復、署名再生成の導線は持ちません。

## Security boundary

- Master Key、Data Key、平文、復号結果、JWT 全文、service_role key を Supabase、ログ、監視基盤、audit-ui へ出しません。
- secret 作成、rotation、current version decrypt、alias 解決は、SBC 側の認証・認可と Supabase RPC / RLS の境界内で扱います。
- 監査証跡、signed ledger、local audit fallback は v0.1.0 の core security property です。
- scheduler、SIEM forwarding、archive / S3 archive、timestamping、incident notification、monthly digest / audit report は v0.1.0 では限定扱いまたは運用補助機能です。
