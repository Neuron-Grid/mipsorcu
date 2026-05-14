# v0.1.0 Release Scope

## Positioning

mipsorcu v0.1.0 は、実験フェーズを閉じ、限定環境で安全に運用練習できる最初の安定版です。

この release は「全機能が本番完成した版」ではありません。SBC を唯一の信頼境界とし、鍵・平文・認可判断を SBC 内部に閉じる中核設計を維持しながら、限定された環境で secret 管理、監査、復旧、検証の基本運用を反復できる状態を到達目標とします。

監査証跡、signed ledger、local audit fallback は v0.1.0 の core security property です。これらは補助機能ではなく、保存・復号・検証の安全性を説明するための中核要素として扱います。

## Core Scope

| Area | v0.1.0 で保証する範囲 | Notes |
|---|---|---|
| secret lifecycle | secret 作成、rotation、current version decrypt、owner scope alias | 復号対象は current version のみ。alias は `secret_id` の入力補助であり、AAD、暗号、監査、ledger の正本 ID ではありません。 |
| Supabase boundary | Supabase RPC、RLS、JWT 認証認可 | 書き込みは SBC 経由の RPC に限定します。RLS と GRANT / REVOKE により client の直接書き込みを拒否します。 |
| AAD / crypto metadata | AAD canonicalization、`aad_context` 再構成、created_at の SBC 決定 | JSONB 保存値をそのまま AAD として使わず、アプリケーション側で正規化再構成します。 |
| audit | audit event、成功監査、失敗監査、local audit fallback | `audit_events` を監査の正本とし、監査追記失敗時は SBC ローカルの fallback に残して再送します。 |
| restore / integrity | restore test、integrity check | 限定環境で復元手順と整合性確認を運用練習できることを目標にします。 |
| signed ledger | signed ledger、auditor verify、signature-key lifecycle | Ed25519 署名付き ledger と公開鍵 lifecycle により、監査対象の検証材料を保持します。署名秘密鍵は SBC 内に閉じます。 |
| audit read path | read-only audit API、`audit-ui` | `audit-ui` は read-only 監査コンソールです。write / decrypt / repair 系の導線は持ちません。 |

## Limited Scope

| Area | v0.1.0 での扱い | Limitation |
|---|---|---|
| scheduler | 既定無効または限定運用 | single SBC process / single replica 前提です。multi replica 実行、分散 lock、DB-backed lease は保証しません。 |
| SIEM forwarding | 抽象化、dummy / local buffer、非秘密 DTO を中心とする限定扱い | Splunk、Elastic、Datadog など具体的な実 SIEM 製品連携は未保証です。SIEM 失敗は主要 secret 操作へ伝播させません。 |
| archive / S3 archive | 実験的または限定運用 | 外部耐久性、WORM 保証、組織の保管要件への適合は v0.1.0 の保証外です。 |
| timestamping | 実サービス未接続なら実験的 | RFC 3161 互換 TSA などの実サービス選定、法的時刻保証、token 長期保全は保証しません。 |
| incident notification | Dummy / local 中心 | 本番通知経路、オンコール連携、通知到達 SLA は保証しません。 |
| monthly digest / audit report | 運用補助機能 | 公式監査報告書の完成版ではありません。digest と report は監査確認を補助しますが、監査証跡の正本を置き換えません。 |

## Out of Scope

| Area | v0.1.0 で対象外とするもの | Reason |
|---|---|---|
| 本番 SLA | 可用性 SLA、復旧時間保証、監視運用の完成保証 | v0.1.0 は限定環境での運用練習を目的とします。 |
| HA / multi replica | 複数 SBC、複数 runtime、分散 scheduler、DB lease | single replica 前提を越えるため、別設計と ADR が必要です。 |
| write / decrypt 可能な audit-ui | secret write、decrypt、ledger 修正、自動修復、署名再生成 | `audit-ui` は read-only 監査コンソールに限定します。 |
| 具体 SIEM 製品連携 | Splunk HEC、Elastic、Datadog、Sumo Logic、OTLP exporter などの完成保証 | v0.1.0 では backend 抽象化と非秘密 DTO 境界を中心に扱います。 |
| 外部 timestamping の法的保証 | 商用 TSA 選定、法的証跡性、token 保管ポリシーの完成 | 実サービス接続と法務・運用要件は release 後の判断事項です。 |
| 過去 version decrypt | current version 以外の復号 | v0.1.0 の認可モデルは current version decrypt のみです。 |
| sharing / advanced authorization | 他ユーザー共有、classification に基づく高度な権限制御、段階的 decrypt 認可 | MVP 後の拡張候補として扱います。 |
| deletion model | secret の物理削除、論理削除、tombstone | 削除ポリシー変更は監査・ledger・復旧に影響するため別 ADR が必要です。 |
| secret material outside SBC | Master Key、Data Key、平文、復号結果を Supabase や UI に出すこと | 信頼境界に違反するため対象外ではなく禁止事項です。 |

## Related Documents

- [known limitations](known-limitations.md)
- [requirements](requirements.md)
- [coding rules](coding-rules.md)
- [v0.1.0 release task overview](v0.1.0-release-tasks/task-00-overview.md)
