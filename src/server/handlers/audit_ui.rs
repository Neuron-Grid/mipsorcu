use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult, AuditUiReadMetadata,
    FORBIDDEN_AUDIT_METADATA_KEYS,
};
use crate::authorization::authorize_audit_ui_read;
use crate::incident::ledger_payload_contains_forbidden_key;
use crate::ledger::{
    LedgerChainHead, LedgerError, LedgerSequenceNo, LedgerVerifyingKey, MonthlyDigestPeriod,
    SignedLedgerEntry, verify_ledger_chain,
};
use crate::server::errors::{ApiError, RequestAwareApiError, ServerResult};
use crate::server::middleware::{AuthenticatedUser, RequestContext};
use crate::server::state::AppState;
use crate::server::supabase::{
    AuditReportSummary, AuditUiAuditEventRow, AuditUiAuditEventsParams,
    AuditUiHashChainVerification, AuditUiIntegrityStatusRow, AuditUiLedgerEntriesParams,
    AuditUiLedgerEntryRow, AuditUiSecretInventoryRow, AuditUiVerificationFailureRow,
    AuditUiVerificationFailuresParams, SupabaseRpcError,
};
use crate::server::use_cases::verify_monthly_digest::{
    VerifyMonthlyDigestInput, record_monthly_digest_verify_failure_audit, verify_monthly_digest,
};
use crate::types::{OwnerUserId, SourceEventAt};

const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 500;

pub fn build_audit_read_router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/secrets", axum::routing::get(list_secrets))
        .route("/audit-events", axum::routing::get(list_audit_events))
        .route("/ledger-entries", axum::routing::get(list_ledger_entries))
        .route("/integrity-status", axum::routing::get(integrity_status))
        .route(
            "/verification/hash-chain",
            axum::routing::get(verify_hash_chain),
        )
        .route(
            "/verification/signatures",
            axum::routing::get(verify_signatures),
        )
        .route(
            "/verification/monthly-digest",
            axum::routing::get(verify_monthly_digest_endpoint),
        )
        .route(
            "/verification/failures",
            axum::routing::get(list_verification_failures),
        )
        .route(
            "/verification/summary",
            axum::routing::get(verification_summary),
        )
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct AuditEventsQuery {
    limit: Option<u32>,
    offset: Option<u32>,
    period_start: Option<String>,
    period_end: Option<String>,
    action: Option<String>,
    result: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LedgerEntriesQuery {
    limit: Option<u32>,
    offset: Option<u32>,
    start_sequence_no: Option<u64>,
    end_sequence_no: Option<u64>,
    entry_type: Option<String>,
    result: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SequenceRangeQuery {
    start_sequence_no: Option<u64>,
    end_sequence_no: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct MonthlyDigestQuery {
    year_month: String,
}

#[derive(Debug, Deserialize)]
pub struct PeriodPageQuery {
    period_start: String,
    period_end: String,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct PeriodQuery {
    period_start: String,
    period_end: String,
}

#[derive(Debug, Serialize)]
struct PageResponse<T> {
    items: Vec<T>,
    limit: u32,
    offset: u32,
    has_more: bool,
}

#[derive(Debug, Clone, Copy)]
struct Page {
    limit: u32,
    offset: u32,
}

#[derive(Debug, Serialize)]
struct SignatureVerificationResponse {
    valid: bool,
    checked_count: u64,
    start_sequence_no: Option<u64>,
    end_sequence_no: Option<u64>,
    error_code: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct MonthlyDigestVerificationResponse {
    valid: bool,
    target_year_month: String,
    start_sequence_no: Option<u64>,
    end_sequence_no: Option<u64>,
    entry_count: Option<u64>,
    error_code: Option<String>,
}

#[derive(Debug, Serialize)]
struct SummaryResponse {
    summary: AuditReportSummary,
    signature_verification: SignatureVerificationResponse,
}

#[derive(Debug, Clone)]
struct AuditUiReadAuditInput {
    endpoint: &'static str,
    resource: &'static str,
    result_count: Option<u64>,
    period: Option<(SourceEventAt, SourceEventAt)>,
    sequence_range: Option<(u64, u64)>,
    target_year_month: Option<MonthlyDigestPeriod>,
    error_code: Option<&'static str>,
}

async fn list_secrets(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    Query(query): Query<PageQuery>,
) -> ServerResult<Json<PageResponse<AuditUiSecretInventoryRow>>> {
    let request_id = request_context.into_request_id();
    let audit = AuditUiReadAuditInput::new("/audit/v1/secrets", "secrets");
    ensure_auditor(&state, &request_id, &auth, &audit).await?;
    let page = parse_page(query.limit, query.offset)
        .map_err(|error| error.with_request_id(&request_id))?;

    let rows = match state
        .supabase_client
        .fetch_audit_ui_secret_inventory(page.rpc_limit(), page.offset)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return Err(upstream_failure(&state, &request_id, &auth.claims, audit, error).await);
        }
    };
    let response = page_response(rows, page);
    record_audit_ui_success(
        &state,
        &request_id,
        auth.claims.subject_user_id(),
        audit.with_result_count(len_to_u64(response.items.len())),
    )
    .await
    .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(response))
}

async fn list_audit_events(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    Query(query): Query<AuditEventsQuery>,
) -> ServerResult<Json<PageResponse<AuditUiAuditEventRow>>> {
    let request_id = request_context.into_request_id();
    let mut audit = AuditUiReadAuditInput::new("/audit/v1/audit-events", "audit_events");
    ensure_auditor(&state, &request_id, &auth, &audit).await?;
    let page = parse_page(query.limit, query.offset)
        .map_err(|error| error.with_request_id(&request_id))?;
    let period = parse_optional_period(query.period_start, query.period_end)
        .map_err(|error| error.with_request_id(&request_id))?;
    if let Some((start, end)) = period.clone() {
        audit = audit.with_period(start, end);
    }
    validate_optional_audit_action(query.action.as_deref())
        .map_err(|error| error.with_request_id(&request_id))?;
    validate_optional_result(query.result.as_deref())
        .map_err(|error| error.with_request_id(&request_id))?;

    let params = AuditUiAuditEventsParams {
        p_limit: page.rpc_limit(),
        p_offset: page.offset,
        p_period_start: period.as_ref().map(|(start, _)| start.as_str().to_owned()),
        p_period_end: period.as_ref().map(|(_, end)| end.as_str().to_owned()),
        p_action: query.action,
        p_result: query.result,
    };
    let mut rows = match state
        .supabase_client
        .fetch_audit_ui_audit_events(params)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return Err(upstream_failure(&state, &request_id, &auth.claims, audit, error).await);
        }
    };
    for row in &mut rows {
        row.metadata_json = sanitize_audit_metadata(row.metadata_json.clone());
    }
    let response = page_response(rows, page);
    record_audit_ui_success(
        &state,
        &request_id,
        auth.claims.subject_user_id(),
        audit.with_result_count(len_to_u64(response.items.len())),
    )
    .await
    .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(response))
}

async fn list_ledger_entries(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    Query(query): Query<LedgerEntriesQuery>,
) -> ServerResult<Json<PageResponse<AuditUiLedgerEntryRow>>> {
    let request_id = request_context.into_request_id();
    let mut audit = AuditUiReadAuditInput::new("/audit/v1/ledger-entries", "ledger_entries");
    ensure_auditor(&state, &request_id, &auth, &audit).await?;
    let page = parse_page(query.limit, query.offset)
        .map_err(|error| error.with_request_id(&request_id))?;
    let range = parse_optional_sequence_range(query.start_sequence_no, query.end_sequence_no)
        .map_err(|error| error.with_request_id(&request_id))?;
    if let Some((start, end)) = range {
        audit = audit.with_sequence_range(start.get(), end.get());
    }
    validate_optional_result(query.result.as_deref())
        .map_err(|error| error.with_request_id(&request_id))?;

    let params = AuditUiLedgerEntriesParams {
        p_limit: page.rpc_limit(),
        p_offset: page.offset,
        p_start_sequence_no: range
            .map(|(start, _)| start.as_i64())
            .transpose()
            .map_err(|_| ApiError::BadRequest("invalid sequence range".to_owned()))
            .map_err(|error| error.with_request_id(&request_id))?,
        p_end_sequence_no: range
            .map(|(_, end)| end.as_i64())
            .transpose()
            .map_err(|_| ApiError::BadRequest("invalid sequence range".to_owned()))
            .map_err(|error| error.with_request_id(&request_id))?,
        p_entry_type: query.entry_type,
        p_result: query.result,
    };
    let mut rows = match state
        .supabase_client
        .fetch_audit_ui_ledger_entries(params)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return Err(upstream_failure(&state, &request_id, &auth.claims, audit, error).await);
        }
    };
    for row in &mut rows {
        row.payload = sanitize_ledger_payload(row.payload.clone());
    }
    let response = page_response(rows, page);
    record_audit_ui_success(
        &state,
        &request_id,
        auth.claims.subject_user_id(),
        audit.with_result_count(len_to_u64(response.items.len())),
    )
    .await
    .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(response))
}

async fn integrity_status(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
) -> ServerResult<Json<Vec<AuditUiIntegrityStatusRow>>> {
    let request_id = request_context.into_request_id();
    let audit = AuditUiReadAuditInput::new("/audit/v1/integrity-status", "integrity_status");
    ensure_auditor(&state, &request_id, &auth, &audit).await?;
    let rows = match state
        .supabase_client
        .fetch_audit_ui_integrity_status()
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return Err(upstream_failure(&state, &request_id, &auth.claims, audit, error).await);
        }
    };
    record_audit_ui_success(
        &state,
        &request_id,
        auth.claims.subject_user_id(),
        audit.with_result_count(len_to_u64(rows.len())),
    )
    .await
    .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(rows))
}

async fn verify_hash_chain(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    Query(query): Query<SequenceRangeQuery>,
) -> ServerResult<Json<AuditUiHashChainVerification>> {
    let request_id = request_context.into_request_id();
    let mut audit = AuditUiReadAuditInput::new("/audit/v1/verification/hash-chain", "hash_chain");
    ensure_auditor(&state, &request_id, &auth, &audit).await?;
    let range = parse_optional_sequence_range(query.start_sequence_no, query.end_sequence_no)
        .map_err(|error| error.with_request_id(&request_id))?;
    if let Some((start, end)) = range {
        audit = audit.with_sequence_range(start.get(), end.get());
    }

    let response = match state
        .supabase_client
        .verify_audit_ui_ledger_hash_chain(range.map(|(start, _)| start), range.map(|(_, end)| end))
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return Err(upstream_failure(&state, &request_id, &auth.claims, audit, error).await);
        }
    };
    record_audit_ui_success(
        &state,
        &request_id,
        auth.claims.subject_user_id(),
        audit.with_result_count(response.entries_checked),
    )
    .await
    .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(response))
}

async fn verify_signatures(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    Query(query): Query<SequenceRangeQuery>,
) -> ServerResult<Json<SignatureVerificationResponse>> {
    let request_id = request_context.into_request_id();
    let mut audit = AuditUiReadAuditInput::new("/audit/v1/verification/signatures", "signatures");
    ensure_auditor(&state, &request_id, &auth, &audit).await?;
    let (start, end) = resolve_signature_range(&state, query)
        .await
        .map_err(|error| error.with_request_id(&request_id))?;
    if let (Some(start), Some(end)) = (start, end) {
        audit = audit.with_sequence_range(start.get(), end.get());
    }
    let response = match verify_signature_range(&state, start, end).await {
        Ok(response) => response,
        Err(error) => {
            return Err(upstream_failure(&state, &request_id, &auth.claims, audit, error).await);
        }
    };
    record_audit_ui_success(
        &state,
        &request_id,
        auth.claims.subject_user_id(),
        audit.with_result_count(response.checked_count),
    )
    .await
    .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(response))
}

async fn verify_monthly_digest_endpoint(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    Query(query): Query<MonthlyDigestQuery>,
) -> ServerResult<Json<MonthlyDigestVerificationResponse>> {
    let request_id = request_context.into_request_id();
    let period = MonthlyDigestPeriod::parse(&query.year_month)
        .map_err(|_| ApiError::BadRequest("invalid year_month".to_owned()))
        .map_err(|error| error.with_request_id(&request_id))?;
    let audit =
        AuditUiReadAuditInput::new("/audit/v1/verification/monthly-digest", "monthly_digest")
            .with_target_year_month(period.clone());
    ensure_auditor(&state, &request_id, &auth, &audit).await?;

    let verified_at = SourceEventAt::now_utc()
        .map_err(|error| ApiError::InternalError(error.to_string()))
        .map_err(|error| error.with_request_id(&request_id))?;
    let input = VerifyMonthlyDigestInput {
        period: period.clone(),
        request_id: request_id.clone(),
    };
    let response = match verify_monthly_digest(&state.supabase_client, &input).await {
        Ok(info) => MonthlyDigestVerificationResponse {
            valid: true,
            target_year_month: period.as_str().to_owned(),
            start_sequence_no: Some(info.start_sequence_no.get()),
            end_sequence_no: Some(info.end_sequence_no.get()),
            entry_count: Some(info.entry_count),
            error_code: None,
        },
        Err(error) => {
            record_monthly_digest_verify_failure_audit(
                &state.audit_recorder,
                &request_id,
                &period,
                &error,
                &verified_at,
            )
            .await;
            MonthlyDigestVerificationResponse {
                valid: false,
                target_year_month: period.as_str().to_owned(),
                start_sequence_no: None,
                end_sequence_no: None,
                entry_count: None,
                error_code: Some(error.as_error_code().to_owned()),
            }
        }
    };
    record_audit_ui_success(&state, &request_id, auth.claims.subject_user_id(), audit)
        .await
        .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(response))
}

async fn list_verification_failures(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    Query(query): Query<PeriodPageQuery>,
) -> ServerResult<Json<PageResponse<AuditUiVerificationFailureRow>>> {
    let request_id = request_context.into_request_id();
    let page = parse_page(query.limit, query.offset)
        .map_err(|error| error.with_request_id(&request_id))?;
    let (period_start, period_end) = parse_required_period(&query.period_start, &query.period_end)
        .map_err(|error| error.with_request_id(&request_id))?;
    let audit =
        AuditUiReadAuditInput::new("/audit/v1/verification/failures", "verification_failures")
            .with_period(period_start.clone(), period_end.clone());
    ensure_auditor(&state, &request_id, &auth, &audit).await?;

    let rows = match state
        .supabase_client
        .fetch_audit_ui_verification_failures(AuditUiVerificationFailuresParams {
            p_limit: page.rpc_limit(),
            p_offset: page.offset,
            p_period_start: period_start.as_str().to_owned(),
            p_period_end: period_end.as_str().to_owned(),
        })
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return Err(upstream_failure(&state, &request_id, &auth.claims, audit, error).await);
        }
    };
    let response = page_response(rows, page);
    record_audit_ui_success(
        &state,
        &request_id,
        auth.claims.subject_user_id(),
        audit.with_result_count(len_to_u64(response.items.len())),
    )
    .await
    .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(response))
}

async fn verification_summary(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    Query(query): Query<PeriodQuery>,
) -> ServerResult<Json<SummaryResponse>> {
    let request_id = request_context.into_request_id();
    let (period_start, period_end) = parse_required_period(&query.period_start, &query.period_end)
        .map_err(|error| error.with_request_id(&request_id))?;
    let audit = AuditUiReadAuditInput::new("/audit/v1/verification/summary", "summary")
        .with_period(period_start.clone(), period_end.clone());
    ensure_auditor(&state, &request_id, &auth, &audit).await?;
    let summary = match state
        .supabase_client
        .fetch_audit_report_summary(period_start.as_str(), period_end.as_str())
        .await
    {
        Ok(summary) => summary,
        Err(error) => {
            return Err(upstream_failure(&state, &request_id, &auth.claims, audit, error).await);
        }
    };
    let signature_verification = match (summary.sequence_start, summary.sequence_end) {
        (Some(start), Some(end)) => {
            let start = LedgerSequenceNo::new(start).map_err(|_| {
                ApiError::InternalInvariantViolation(
                    "audit summary returned invalid sequence_start".to_owned(),
                )
                .with_request_id(&request_id)
            })?;
            let end = LedgerSequenceNo::new(end).map_err(|_| {
                ApiError::InternalInvariantViolation(
                    "audit summary returned invalid sequence_end".to_owned(),
                )
                .with_request_id(&request_id)
            })?;
            match verify_signature_range(&state, Some(start), Some(end)).await {
                Ok(response) => response,
                Err(error) => {
                    return Err(
                        upstream_failure(&state, &request_id, &auth.claims, audit, error).await,
                    );
                }
            }
        }
        _ => SignatureVerificationResponse {
            valid: true,
            checked_count: 0,
            start_sequence_no: None,
            end_sequence_no: None,
            error_code: None,
        },
    };
    record_audit_ui_success(&state, &request_id, auth.claims.subject_user_id(), audit)
        .await
        .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(SummaryResponse {
        summary,
        signature_verification,
    }))
}

impl AuditUiReadAuditInput {
    fn new(endpoint: &'static str, resource: &'static str) -> Self {
        Self {
            endpoint,
            resource,
            result_count: None,
            period: None,
            sequence_range: None,
            target_year_month: None,
            error_code: None,
        }
    }

    fn with_result_count(mut self, result_count: u64) -> Self {
        self.result_count = Some(result_count);
        self
    }

    fn with_period(mut self, period_start: SourceEventAt, period_end: SourceEventAt) -> Self {
        self.period = Some((period_start, period_end));
        self
    }

    fn with_sequence_range(mut self, start_sequence_no: u64, end_sequence_no: u64) -> Self {
        self.sequence_range = Some((start_sequence_no, end_sequence_no));
        self
    }

    fn with_target_year_month(mut self, target_year_month: MonthlyDigestPeriod) -> Self {
        self.target_year_month = Some(target_year_month);
        self
    }

    fn with_error_code(mut self, error_code: &'static str) -> Self {
        self.error_code = Some(error_code);
        self
    }
}

async fn ensure_auditor(
    state: &AppState,
    request_id: &crate::RequestId,
    auth: &AuthenticatedUser,
    audit: &AuditUiReadAuditInput,
) -> ServerResult<()> {
    if let Err(error) = authorize_audit_ui_read(&auth.claims) {
        tracing::warn!(
            request_id = %request_id.as_canonical_string(),
            actor_user_id = %auth.claims.subject_user_id().as_canonical_string(),
            action = AuditAction::AuditUiRead.as_str(),
            result = "failure",
            error = %error,
            "non-auditor attempted to read auditor UI endpoint"
        );
        record_audit_ui_failure(
            state,
            request_id,
            auth.claims.subject_user_id(),
            audit.clone().with_error_code("auditor_role_required"),
        )
        .await;
        return Err(ApiError::Forbidden("forbidden".to_owned()).with_request_id(request_id));
    }

    Ok(())
}

async fn upstream_failure(
    state: &AppState,
    request_id: &crate::RequestId,
    claims: &crate::VerifiedJwtClaims,
    audit: AuditUiReadAuditInput,
    error: SupabaseRpcError,
) -> RequestAwareApiError {
    tracing::error!(
        request_id = %request_id.as_canonical_string(),
        actor_user_id = %claims.subject_user_id().as_canonical_string(),
        action = AuditAction::AuditUiRead.as_str(),
        result = "failure",
        error = %error,
        error_code = "upstream_dependency_failed",
        "auditor UI read upstream call failed"
    );
    record_audit_ui_failure(
        state,
        request_id,
        claims.subject_user_id(),
        audit.with_error_code("upstream_dependency_failed"),
    )
    .await;
    ApiError::from(error).with_request_id(request_id)
}

async fn record_audit_ui_success(
    state: &AppState,
    request_id: &crate::RequestId,
    actor_user_id: &OwnerUserId,
    input: AuditUiReadAuditInput,
) -> Result<(), ApiError> {
    record_audit_ui_read(
        state,
        request_id,
        actor_user_id,
        AuditResult::Success,
        input,
    )
    .await
    .map(|_| ())
}

async fn record_audit_ui_failure(
    state: &AppState,
    request_id: &crate::RequestId,
    actor_user_id: &OwnerUserId,
    input: AuditUiReadAuditInput,
) {
    if let Err(error) = record_audit_ui_read(
        state,
        request_id,
        actor_user_id,
        AuditResult::Failure,
        input,
    )
    .await
    {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            actor_user_id = %actor_user_id.as_canonical_string(),
            error = %error,
            action = AuditAction::AuditUiRead.as_str(),
            result = "failure",
            error_code = "audit_ui_read_audit_record_failed",
            "failed to record audit_ui_read failure audit"
        );
    }
}

async fn record_audit_ui_read(
    state: &AppState,
    request_id: &crate::RequestId,
    actor_user_id: &OwnerUserId,
    result: AuditResult,
    input: AuditUiReadAuditInput,
) -> Result<crate::AuditRecordOutcome, ApiError> {
    let source_event_at =
        SourceEventAt::now_utc().map_err(|error| ApiError::InternalError(error.to_string()))?;
    let mut metadata_builder =
        AuditUiReadMetadata::new(input.endpoint, input.resource, source_event_at);
    if let Some(result_count) = input.result_count {
        metadata_builder = metadata_builder.with_result_count(result_count);
    }
    if let Some((period_start, period_end)) = input.period {
        metadata_builder = metadata_builder.with_period(period_start, period_end);
    }
    if let Some((start_sequence_no, end_sequence_no)) = input.sequence_range {
        metadata_builder = metadata_builder.with_sequence_range(start_sequence_no, end_sequence_no);
    }
    if let Some(target_year_month) = input.target_year_month {
        metadata_builder = metadata_builder.with_target_year_month(target_year_month);
    }
    if let Some(error_code) = input.error_code {
        metadata_builder = metadata_builder.with_error_code(error_code);
    }

    let metadata = metadata_builder
        .build()
        .map_err(|error| ApiError::InternalError(error.to_string()))?;
    let audit_event_id =
        AuditEventId::generate().map_err(|error| ApiError::InternalError(error.to_string()))?;
    let event = AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: Some(actor_user_id.clone()),
        actor_device_id: None,
        action: AuditAction::AuditUiRead,
        target_secret_id: None,
        result,
        key_version: None,
        metadata_json: metadata,
    })
    .map_err(|error| ApiError::InternalError(error.to_string()))?;

    state
        .audit_recorder
        .record(&event)
        .await
        .map_err(|_| ApiError::AuditRecordFailed)
}

fn parse_page(limit: Option<u32>, offset: Option<u32>) -> Result<Page, ApiError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    let offset = offset.unwrap_or(0);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(ApiError::BadRequest("invalid limit".to_owned()));
    }

    Ok(Page { limit, offset })
}

impl Page {
    fn rpc_limit(self) -> u32 {
        self.limit.saturating_add(1)
    }
}

fn page_response<T>(mut rows: Vec<T>, page: Page) -> PageResponse<T> {
    let has_more = rows.len() > page.limit as usize;
    if has_more {
        rows.truncate(page.limit as usize);
    }

    PageResponse {
        items: rows,
        limit: page.limit,
        offset: page.offset,
        has_more,
    }
}

fn parse_optional_period(
    period_start: Option<String>,
    period_end: Option<String>,
) -> Result<Option<(SourceEventAt, SourceEventAt)>, ApiError> {
    match (period_start, period_end) {
        (Some(start), Some(end)) => parse_required_period(&start, &end).map(Some),
        (None, None) => Ok(None),
        _ => Err(ApiError::BadRequest(
            "period_start and period_end must be provided together".to_owned(),
        )),
    }
}

fn parse_required_period(
    period_start: &str,
    period_end: &str,
) -> Result<(SourceEventAt, SourceEventAt), ApiError> {
    let start = SourceEventAt::parse(period_start)
        .map_err(|_| ApiError::BadRequest("invalid period_start".to_owned()))?;
    let end = SourceEventAt::parse(period_end)
        .map_err(|_| ApiError::BadRequest("invalid period_end".to_owned()))?;
    if start.as_str() >= end.as_str() {
        return Err(ApiError::BadRequest(
            "period_start must be before period_end".to_owned(),
        ));
    }

    Ok((start, end))
}

fn parse_optional_sequence_range(
    start_sequence_no: Option<u64>,
    end_sequence_no: Option<u64>,
) -> Result<Option<(LedgerSequenceNo, LedgerSequenceNo)>, ApiError> {
    match (start_sequence_no, end_sequence_no) {
        (Some(start), Some(end)) => {
            let start = LedgerSequenceNo::new(start)
                .map_err(|_| ApiError::BadRequest("invalid start_sequence_no".to_owned()))?;
            let end = LedgerSequenceNo::new(end)
                .map_err(|_| ApiError::BadRequest("invalid end_sequence_no".to_owned()))?;
            if start.get() > end.get() {
                return Err(ApiError::BadRequest(
                    "start_sequence_no must be <= end_sequence_no".to_owned(),
                ));
            }
            Ok(Some((start, end)))
        }
        (None, None) => Ok(None),
        _ => Err(ApiError::BadRequest(
            "start_sequence_no and end_sequence_no must be provided together".to_owned(),
        )),
    }
}

fn validate_optional_audit_action(value: Option<&str>) -> Result<(), ApiError> {
    if let Some(value) = value {
        AuditAction::parse(value).map_err(|_| ApiError::BadRequest("invalid action".to_owned()))?;
    }

    Ok(())
}

fn validate_optional_result(value: Option<&str>) -> Result<(), ApiError> {
    if let Some(value) = value
        && !matches!(value, "success" | "failure")
    {
        return Err(ApiError::BadRequest("invalid result".to_owned()));
    }

    Ok(())
}

async fn resolve_signature_range(
    state: &AppState,
    query: SequenceRangeQuery,
) -> Result<(Option<LedgerSequenceNo>, Option<LedgerSequenceNo>), ApiError> {
    if let Some(range) =
        parse_optional_sequence_range(query.start_sequence_no, query.end_sequence_no)?
    {
        return Ok((Some(range.0), Some(range.1)));
    }

    let chain_head = state
        .supabase_client
        .fetch_ledger_chain_head()
        .await
        .map_err(ApiError::from)?;
    if chain_head.last_sequence_no() == 0 {
        return Ok((None, None));
    }
    let start = LedgerSequenceNo::new(1)
        .map_err(|_| ApiError::InternalInvariantViolation("invalid sequence start".to_owned()))?;
    let end = LedgerSequenceNo::new(chain_head.last_sequence_no()).map_err(|_| {
        ApiError::InternalInvariantViolation("invalid chain head sequence".to_owned())
    })?;

    Ok((Some(start), Some(end)))
}

async fn verify_signature_range(
    state: &AppState,
    start: Option<LedgerSequenceNo>,
    end: Option<LedgerSequenceNo>,
) -> Result<SignatureVerificationResponse, SupabaseRpcError> {
    let (Some(start), Some(end)) = (start, end) else {
        return Ok(SignatureVerificationResponse {
            valid: true,
            checked_count: 0,
            start_sequence_no: None,
            end_sequence_no: None,
            error_code: None,
        });
    };
    let rows = state
        .supabase_client
        .export_ledger_verification_materials(start, end)
        .await?;
    if rows.is_empty() {
        return Ok(SignatureVerificationResponse {
            valid: false,
            checked_count: 0,
            start_sequence_no: Some(start.get()),
            end_sequence_no: Some(end.get()),
            error_code: Some("ledger_range_empty"),
        });
    }

    let verification =
        tokio::task::spawn_blocking(move || verify_signature_material_rows(start, end, rows))
            .await
            .map_err(|_| {
                SupabaseRpcError::InvalidResponse("signature verification join failed".to_owned())
            })?;

    Ok(verification)
}

fn verify_signature_material_rows(
    start: LedgerSequenceNo,
    end: LedgerSequenceNo,
    rows: Vec<crate::server::supabase::LedgerVerificationMaterialRow>,
) -> SignatureVerificationResponse {
    let mut entries: Vec<SignedLedgerEntry> = Vec::with_capacity(rows.len());
    let mut verification_keys: Vec<LedgerVerifyingKey> = Vec::new();

    for row in &rows {
        if ledger_payload_contains_forbidden_key(&row.payload) {
            return signature_failure(start, end, entries.len(), "ledger_payload_forbidden_key");
        }
        let entry = match row.try_restore_signed_ledger_entry() {
            Ok(entry) => entry,
            Err(_) => {
                return signature_failure(start, end, entries.len(), "ledger_entry_restore_failed");
            }
        };
        if !verification_keys
            .iter()
            .any(|key| key.key_version() == entry.signature_key_version())
        {
            match row.try_restore_verifying_key() {
                Ok(Some(key)) => verification_keys.push(key),
                Ok(None) => {
                    return signature_failure(
                        start,
                        end,
                        entries.len(),
                        "ledger_signature_key_missing",
                    );
                }
                Err(_) => {
                    return signature_failure(
                        start,
                        end,
                        entries.len(),
                        "ledger_key_restore_failed",
                    );
                }
            }
        }
        entries.push(entry);
    }

    let initial_head = match initial_chain_head(start, &rows) {
        Ok(head) => head,
        Err(_) => {
            return signature_failure(start, end, entries.len(), "ledger_chain_head_build_failed");
        }
    };
    match verify_ledger_chain(&entries, initial_head, &verification_keys) {
        Ok(_) => SignatureVerificationResponse {
            valid: true,
            checked_count: len_to_u64(entries.len()),
            start_sequence_no: Some(start.get()),
            end_sequence_no: Some(end.get()),
            error_code: None,
        },
        Err(error) => signature_failure(start, end, entries.len(), ledger_error_code(&error)),
    }
}

fn initial_chain_head(
    start: LedgerSequenceNo,
    rows: &[crate::server::supabase::LedgerVerificationMaterialRow],
) -> Result<LedgerChainHead, LedgerError> {
    if start.get() == 1 {
        return Ok(LedgerChainHead::genesis());
    }
    let first_previous_hash = rows.first().map(|row| row.previous_entry_hash).ok_or(
        LedgerError::InvalidPositiveInteger {
            field: "sequence_no",
        },
    )?;
    LedgerChainHead::new(start.get() - 1, first_previous_hash)
}

fn signature_failure(
    start: LedgerSequenceNo,
    end: LedgerSequenceNo,
    checked_count: usize,
    error_code: &'static str,
) -> SignatureVerificationResponse {
    SignatureVerificationResponse {
        valid: false,
        checked_count: len_to_u64(checked_count),
        start_sequence_no: Some(start.get()),
        end_sequence_no: Some(end.get()),
        error_code: Some(error_code),
    }
}

fn ledger_error_code(error: &LedgerError) -> &'static str {
    match error {
        LedgerError::SequenceGap { .. } => "ledger_sequence_gap",
        LedgerError::PreviousHashMismatch { .. } => "ledger_previous_hash_mismatch",
        LedgerError::HashMismatch { .. } => "ledger_entry_hash_mismatch",
        LedgerError::UnknownSignatureKey { .. } => "ledger_signature_key_missing",
        LedgerError::SignatureInvalid { .. } => "ledger_signature_invalid",
        LedgerError::SequenceOverflow => "ledger_sequence_overflow",
        _ => "ledger_signature_verification_failed",
    }
}

fn sanitize_audit_metadata(value: Value) -> Value {
    if contains_forbidden_key(&value, FORBIDDEN_AUDIT_METADATA_KEYS) {
        json!({ "redacted": true })
    } else {
        value
    }
}

fn sanitize_ledger_payload(value: Value) -> Value {
    if ledger_payload_contains_forbidden_key(&value) {
        json!({ "redacted": true })
    } else {
        value
    }
}

fn contains_forbidden_key(value: &Value, forbidden_keys: &[&str]) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            let normalized = key.trim().to_ascii_lowercase();
            forbidden_keys
                .iter()
                .any(|forbidden| normalized == *forbidden)
                || contains_forbidden_key(nested, forbidden_keys)
        }),
        Value::Array(values) => values
            .iter()
            .any(|nested| contains_forbidden_key(nested, forbidden_keys)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}
