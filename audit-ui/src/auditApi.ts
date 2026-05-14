import type { AppConfig } from "./config";
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
} from "./types/types";

export class AuditApiError extends Error {
    readonly code: string;
    readonly requestId: string | null;

    constructor(code: string, requestId: string | null) {
        super(code);
        this.name = "AuditApiError";
        this.code = code;
        this.requestId = requestId;
    }
}

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

const appendQuery = (path: string, params: Record<string, string | null>): string => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
        if (value !== null && value !== "") {
            query.set(key, value);
        }
    }

    const queryText = query.toString();
    return queryText === "" ? path : `${path}?${queryText}`;
};

const errorCodeFromResponse = async (
    response: Response,
): Promise<{ code: string; requestId: string | null }> => {
    const fallbackCode = response.status === 401 ? "unauthorized" : `http_${response.status}`;
    try {
        const value = (await response.json()) as { code?: unknown; request_id?: unknown };
        return {
            code: typeof value.code === "string" ? value.code : fallbackCode,
            requestId: typeof value.request_id === "string" ? value.request_id : null,
        };
    } catch {
        return { code: fallbackCode, requestId: null };
    }
};

const fetchReadOnlyJson = async <T>(
    config: AppConfig,
    accessToken: string,
    path: string,
): Promise<T> => {
    const response = await fetch(`${config.auditApiBaseUrl}${path}`, {
        headers: {
            Accept: "application/json",
            Authorization: `Bearer ${accessToken}`,
        },
        cache: "no-store",
    });

    if (!response.ok) {
        const error = await errorCodeFromResponse(response);
        throw new AuditApiError(error.code, error.requestId);
    }

    return (await response.json()) as T;
};

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
