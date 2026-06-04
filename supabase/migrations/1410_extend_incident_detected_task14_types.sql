-- Task 14 / ADR-0043 keeps the existing incident_detected metadata shape
-- and extends only the non-secret incident_type vocabulary.

create or replace function public.incident_type_allowed(p_incident_type text)
returns boolean
language sql
immutable
set search_path = public
as $$
    select p_incident_type in (
        'hash_chain_mismatch',
        'signature_mismatch',
        'monthly_digest_mismatch',
        'digest_timestamping_mismatch',
        'archive_export_mismatch',
        'sequence_gap',
        'unknown_signature_key',
        'non_auditor_ledger_read',
        'ledger_secret_leak_suspected',
        'siem_long_failure',
        'audit_ui_forbidden_operation',
        'scheduler_failure',
        'ledger_anomaly',
        'archive_failure_persistent',
        'timestamping_failure_persistent',
        'siem_buffer_threshold',
        'envelope_migration_failure_burst',
        'auth_failure_burst',
        'key_rotation_failure'
    );
$$;

comment on function public.incident_type_allowed(text) is
    'Returns true for non-secret incident type vocabulary accepted by incident audit and ledger records. Task 14 extends ADR-0043 production incident notification categories while preserving the existing incident_detected schema.';

revoke execute on function public.incident_type_allowed(text) from public, anon, authenticated;
