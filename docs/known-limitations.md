# v0.1.0 Known Limitations

## Summary

この文書は、mipsorcu v0.1.0 の known limitations を定義します。

v0.1.0 は、限定環境で secret 管理、監査、復旧、検証を安全に運用練習するための release です。全機能が本番完成した状態、または任意の運用環境で同じ保証を提供する状態ではありません。

監査証跡、signed ledger、local audit fallback は core security property です。これらは v0.1.0 の保証範囲に含めますが、SIEM、archive、timestamping、scheduler、incident notification、monthly digest / audit report は以下の制限を持ちます。

## Not Guaranteed in v0.1.0

| Area | v0.1.0 で保証しない範囲 |
|---|---|
| Production readiness | 本番 SLA、可用性保証、オンコール体制、監視運用完成、障害復旧時間保証 |
| Multi replica | 複数 SBC、複数 process、複数 container replica での同時 scheduler 実行 |
| Distributed coordination | 分散 lock、DB-backed lease、cross-instance job deduplication |
| External integrations | 具体的な SIEM 製品、商用 TSA、組織標準の archive backend との完成済み接続 |
| Legal / compliance proof | 外部 timestamping の法的時刻保証、監査報告書の正式証跡性、WORM 保管証明 |
| Advanced secret workflows | 過去 version decrypt、secret 共有、classification による権限制御、secret 削除 |
| UI operations | `audit-ui` からの secret write、decrypt、ledger 修正、自動修復、署名再生成 |

## Scheduler

scheduler を有効化する場合、v0.1.0 では single SBC process / single replica 前提で運用します。

- in-process lock による同一 job の重複抑止は、単一 runtime 内だけを対象とします。
- multi replica、複数 container、複数 SBC で同じ scheduler を同時に動かす構成は保証しません。
- 分散 lock、DB-backed lease、leader election、cross-instance deduplication は未実装または保証外です。
- scheduler failure は secret 作成、rotation、current version decrypt の主要 path へ伝播させません。
- 異常検出時の自動修復は行いません。監査、ledger、incident の非秘密記録をもとに運用者が判断します。

## SIEM Forwarding

SIEM forwarding は、非秘密 DTO、backend abstraction、dummy / local buffer を中心とする限定扱いです。

- Splunk、Elastic、Datadog、Sumo Logic、OTLP exporter などの実 SIEM 製品連携は v0.1.0 では保証しません。
- SIEM 送信先の可用性、到達保証、再送 SLA、長期保管要件への適合は保証しません。
- SIEM 失敗は secret 保存・復号・rotation の成功条件に含めません。
- SIEM へ送る情報は非秘密メタデータに限定します。平文、Master Key、Data Key、JWT 全文、service_role key、request / response body 全文は送信対象外です。

## Archive / S3 Archive

archive / S3 archive は実験的または限定運用です。

- local / in-memory / experimental backend は、本番の耐久性や WORM 保証を提供しません。
- S3 archive を使う場合でも、bucket policy、object lock、retention、監査証跡、復旧演習の運用完成は v0.1.0 の保証外です。
- archive は signed monthly digest などの非秘密検証材料を保全するための経路です。secret plaintext、Master Key、Data Key を保存する経路ではありません。
- archive export 失敗は主要 secret 操作へ伝播させません。

## Timestamping

timestamping は、実サービス未接続または dummy backend の場合は実験的です。

- RFC 3161 互換 TSA や商用 timestamping provider の選定は v0.1.0 の保証外です。
- 外部 timestamp token の法的効力、長期検証性、保管方式、provider SLA は保証しません。
- ledger には token raw bytes ではなく hash などの非秘密検証材料を記録します。
- timestamping failure は主要 secret 操作へ伝播させません。

## Incident Notification

incident notification は Dummy / local 中心の限定扱いです。

- Slack、メール、PagerDuty、Teams などの本番通知経路は保証しません。
- 通知到達 SLA、重複通知制御、オンコール escalations は v0.1.0 の保証外です。
- 通知 payload は非秘密情報に限定します。

## Monthly Digest / Audit Report

monthly digest / audit report は運用補助機能です。

- 公式監査報告書の完成版ではありません。
- `audit_events`、signed ledger、verification materials の正本性を置き換えません。
- report 生成失敗は、secret 保存・復号・rotation の成功条件に含めません。
- LLM による report 生成は v0.1.0 の対象外です。

## Audit UI

`audit-ui` は read-only 監査コンソールです。

- read-only audit API の閲覧だけを目的とします。
- secret 作成、更新、削除、rotation、decrypt の導線を持ちません。
- ledger 修正、自動修復、署名再生成、署名鍵 lifecycle mutation の導線を持ちません。
- Master Key、Data Key、平文、復号結果、JWT 全文、service_role key、request / response body 全文を表示しません。
- 認可判断は UI ではなく SBC backend に依存します。

## Related Documents

- [release scope](release-scope.md)
- [requirements](requirements.md)
- [coding rules](coding-rules.md)
