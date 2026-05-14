import type { AppConfig } from "../config";
import type {
    AuditEventRow,
    AuditSecret,
    HashChainVerification,
    IntegrityStatusRow,
    LedgerEntryRow,
    MonthlyDigestVerification,
    PageResponse,
    SignatureVerification,
    SummaryResponse,
    VerificationFailureRow,
} from "../types/types";
import { appendQuery, fetchReadOnlyJson } from "./http";

export type AuditApiClient = {
    readonly listSecrets: () => Promise<PageResponse<AuditSecret>>;
    readonly listAuditEvents: () => Promise<PageResponse<AuditEventRow>>;
    readonly listLedgerEntries: () => Promise<PageResponse<LedgerEntryRow>>;
    readonly integrityStatus: () => Promise<readonly IntegrityStatusRow[]>;
    readonly verifyHashChain: () => Promise<HashChainVerification>;
    readonly verifySignatures: () => Promise<SignatureVerification>;
    readonly verifyMonthlyDigest: (yearMonth: string) => Promise<MonthlyDigestVerification>;
    readonly listVerificationFailures: (
        periodStart: string,
        periodEnd: string,
    ) => Promise<PageResponse<VerificationFailureRow>>;
    readonly verificationSummary: (
        periodStart: string,
        periodEnd: string,
    ) => Promise<SummaryResponse>;
};

const DEFAULT_LIMIT = "50";

export const createAuditApiClient = (config: AppConfig, accessToken: string): AuditApiClient => ({
    listSecrets: () =>
        fetchReadOnlyJson<PageResponse<AuditSecret>>(
            config,
            accessToken,
            appendQuery("/audit/v1/secrets", { limit: DEFAULT_LIMIT, offset: "0" }),
        ),
    listAuditEvents: () =>
        fetchReadOnlyJson<PageResponse<AuditEventRow>>(
            config,
            accessToken,
            appendQuery("/audit/v1/audit-events", { limit: DEFAULT_LIMIT, offset: "0" }),
        ),
    listLedgerEntries: () =>
        fetchReadOnlyJson<PageResponse<LedgerEntryRow>>(
            config,
            accessToken,
            appendQuery("/audit/v1/ledger-entries", { limit: DEFAULT_LIMIT, offset: "0" }),
        ),
    integrityStatus: () =>
        fetchReadOnlyJson<readonly IntegrityStatusRow[]>(
            config,
            accessToken,
            "/audit/v1/integrity-status",
        ),
    verifyHashChain: () =>
        fetchReadOnlyJson<HashChainVerification>(
            config,
            accessToken,
            "/audit/v1/verification/hash-chain",
        ),
    verifySignatures: () =>
        fetchReadOnlyJson<SignatureVerification>(
            config,
            accessToken,
            "/audit/v1/verification/signatures",
        ),
    verifyMonthlyDigest: (yearMonth: string) =>
        fetchReadOnlyJson<MonthlyDigestVerification>(
            config,
            accessToken,
            appendQuery("/audit/v1/verification/monthly-digest", { year_month: yearMonth }),
        ),
    listVerificationFailures: (periodStart: string, periodEnd: string) =>
        fetchReadOnlyJson<PageResponse<VerificationFailureRow>>(
            config,
            accessToken,
            appendQuery("/audit/v1/verification/failures", {
                period_start: periodStart,
                period_end: periodEnd,
                limit: DEFAULT_LIMIT,
                offset: "0",
            }),
        ),
    verificationSummary: (periodStart: string, periodEnd: string) =>
        fetchReadOnlyJson<SummaryResponse>(
            config,
            accessToken,
            appendQuery("/audit/v1/verification/summary", {
                period_start: periodStart,
                period_end: periodEnd,
            }),
        ),
});
