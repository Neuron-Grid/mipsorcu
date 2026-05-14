import type { SummaryResponse } from "@/types/types";

export const isReportVerificationValid = (summary: SummaryResponse): boolean =>
    summary.summary.verification_failures.length === 0 &&
    summary.summary.restore_tests.every((row) => row.result === "success") &&
    summary.summary.integrity_checks.every(
        (row) => row.result === "success" && row.violation_count === 0,
    ) &&
    summary.signature_verification.valid;

export const nullableDetail = (label: string, value: number | null): string =>
    `${label}=${value ?? "-"}`;

export const rangeDetail = (start: number | null, end: number | null): string =>
    `range=${start ?? "-"}..${end ?? "-"}`;
