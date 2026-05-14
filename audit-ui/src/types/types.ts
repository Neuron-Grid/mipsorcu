export type PageResponse<T> = {
    readonly items: readonly T[];
    readonly limit: number;
    readonly offset: number;
    readonly has_more: boolean;
};

export type AuditSecret = {
    readonly secret_id: string;
    readonly owner_user_id: string;
    readonly classification: string;
    readonly current_version_id: string | null;
    readonly secret_created_at: string;
    readonly secret_updated_at: string;
};

export type AuditEventRow = {
    readonly audit_event_id: string;
    readonly request_id: string;
    readonly actor_user_id: string | null;
    readonly actor_device_id: string | null;
    readonly action: string;
    readonly target_secret_id: string | null;
    readonly result: string;
    readonly key_version: number | null;
    readonly metadata_json: unknown;
    readonly occurred_at: string;
};

export type LedgerEntryRow = {
    readonly ledger_entry_id: string;
    readonly sequence_no: number;
    readonly entry_type: string;
    readonly source_event_at: string;
    readonly request_id: string;
    readonly source_event_id: string | null;
    readonly target_secret_id: string | null;
    readonly target_secret_version_id: string | null;
    readonly actor_user_id: string | null;
    readonly actor_device_id: string | null;
    readonly result: string;
    readonly error_code: string | null;
    readonly payload: unknown;
    readonly canonicalization_version: number;
    readonly previous_entry_hash: string;
    readonly entry_hash: string;
    readonly hash_algorithm: string;
    readonly signature: string;
    readonly signature_algorithm: string;
    readonly signature_key_version: number;
    readonly created_at: string;
};

export type IntegrityStatusRow = {
    readonly chain_id: string;
    readonly last_sequence_no: number;
    readonly last_entry_hash: string;
    readonly chain_state_updated_at: string;
};

export type HashChainVerification = {
    readonly chain_valid: boolean;
    readonly entries_checked: number;
    readonly first_gap_sequence_no: number | null;
    readonly first_gap_detail: string | null;
    readonly first_hash_mismatch_sequence_no: number | null;
    readonly first_hash_mismatch_detail: string | null;
    readonly chain_head_sequence_no: number | null;
    readonly chain_head_entry_hash: string | null;
};

export type SignatureVerification = {
    readonly valid: boolean;
    readonly checked_count: number;
    readonly start_sequence_no: number | null;
    readonly end_sequence_no: number | null;
    readonly error_code: string | null;
};

export type MonthlyDigestVerification = {
    readonly valid: boolean;
    readonly target_year_month: string;
    readonly start_sequence_no: number | null;
    readonly end_sequence_no: number | null;
    readonly entry_count: number | null;
    readonly error_code: string | null;
};

export type VerificationFailureRow = {
    readonly code: string;
    readonly occurred_at: string;
    readonly sequence_no: number | null;
    readonly source: string;
};

export type HashChainVerificationSummary = {
    readonly checked_count: number;
    readonly detail: string | null;
    readonly valid: boolean;
};

export type IntegrityCheckReportItem = {
    readonly checked_audit_event_count: number;
    readonly checked_secret_count: number;
    readonly checked_secret_version_count: number;
    readonly duration_ms: number;
    readonly occurred_at: string;
    readonly result: string;
    readonly trigger: string | null;
    readonly violation_count: number;
};

export type MonthlyDigestReportItem = {
    readonly digest_hash: string;
    readonly end_sequence_no: number;
    readonly entry_count: number;
    readonly sequence_no: number;
    readonly start_sequence_no: number;
    readonly target_year_month: string;
};

export type RestoreTestReportItem = {
    readonly duration_ms: number;
    readonly occurred_at: string;
    readonly result: string;
    readonly sample_count: number;
    readonly trigger: string | null;
};

export type SignatureKeyVersionReportItem = {
    readonly key_version: number;
    readonly status: string;
};

export type VerificationFailureReportItem = {
    readonly code: string;
    readonly occurred_at: string;
    readonly sequence_no: number | null;
    readonly source: string;
};

export type AuditReportSummary = {
    readonly audit_event_count: number;
    readonly hash_chain_verification: HashChainVerificationSummary;
    readonly integrity_checks: readonly IntegrityCheckReportItem[];
    readonly ledger_entry_count: number;
    readonly monthly_digests: readonly MonthlyDigestReportItem[];
    readonly period_end: string;
    readonly period_start: string;
    readonly restore_tests: readonly RestoreTestReportItem[];
    readonly secret_count: number;
    readonly sequence_end: number | null;
    readonly sequence_start: number | null;
    readonly signature_key_versions: readonly SignatureKeyVersionReportItem[];
    readonly verification_failures: readonly VerificationFailureReportItem[];
};

export type SummaryResponse = {
    readonly summary: AuditReportSummary;
    readonly signature_verification: SignatureVerification;
};
