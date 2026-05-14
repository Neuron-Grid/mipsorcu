import type { ComponentChildren } from "preact";
import type { Credentials } from "../auth";
import type {
    AuditEventRow,
    AuditSecret,
    HashChainVerification,
    IntegrityCheckReportItem,
    IntegrityStatusRow,
    LedgerEntryRow,
    MonthlyDigestReportItem,
    MonthlyDigestVerification,
    PageResponse,
    RestoreTestReportItem,
    SignatureVerification,
    SummaryResponse,
    VerificationFailureRow,
} from "./types";

export type LoadState = "idle" | "loading" | "loaded" | "failed";

export type DashboardData = {
    readonly secrets: PageResponse<AuditSecret>;
    readonly auditEvents: PageResponse<AuditEventRow>;
    readonly ledgerEntries: PageResponse<LedgerEntryRow>;
    readonly integrityStatus: readonly IntegrityStatusRow[];
    readonly hashChain: HashChainVerification;
    readonly signatures: SignatureVerification;
    readonly monthlyDigest: MonthlyDigestVerification;
    readonly failures: PageResponse<VerificationFailureRow>;
    readonly summary: SummaryResponse;
};

export type SignInPanelProps = {
    readonly isLoading: boolean;
    readonly errorMessage: string | null;
    readonly onSignIn: (credentials: Credentials) => Promise<void>;
};

export type DashboardProps = {
    readonly data: DashboardData;
};

export type VerificationCardsProps = {
    readonly hashChain: HashChainVerification;
    readonly signatures: SignatureVerification;
    readonly monthlyDigest: MonthlyDigestVerification;
    readonly summary: SummaryResponse;
};

export type StatusCardProps = {
    readonly title: string;
    readonly ok: boolean;
    readonly details: readonly string[];
    readonly errorCode: string | null;
};

export type SectionProps = {
    readonly title: string;
    readonly badge: string;
    readonly children: ComponentChildren;
};

export type SecretsTableProps = {
    readonly rows: readonly AuditSecret[];
};

export type AuditEventsTableProps = {
    readonly rows: readonly AuditEventRow[];
};

export type LedgerEntriesTableProps = {
    readonly rows: readonly LedgerEntryRow[];
};

export type IntegrityTableProps = {
    readonly rows: readonly IntegrityStatusRow[];
};

export type MonthlyDigestsTableProps = {
    readonly rows: readonly MonthlyDigestReportItem[];
};

export type RestoreTestsTableProps = {
    readonly rows: readonly RestoreTestReportItem[];
};

export type IntegrityChecksTableProps = {
    readonly rows: readonly IntegrityCheckReportItem[];
};

export type FailuresTableProps = {
    readonly rows: readonly VerificationFailureRow[];
};
