import { StatusCard } from "@/components/StatusCard";
import { isReportVerificationValid, nullableDetail, rangeDetail } from "@/lib/verification";
import type { VerificationCardsProps } from "@/types/ui";

export const VerificationCards = ({
    hashChain,
    signatures,
    monthlyDigest,
    summary,
}: VerificationCardsProps) => (
    <section class="cards" aria-label="検証結果">
        <StatusCard
            title="hash chain"
            ok={hashChain.chain_valid}
            details={[
                `checked=${hashChain.entries_checked}`,
                nullableDetail("head", hashChain.chain_head_sequence_no),
            ]}
            errorCode={hashChain.first_gap_detail ?? hashChain.first_hash_mismatch_detail}
        />
        <StatusCard
            title="signature"
            ok={signatures.valid}
            details={[
                `checked=${signatures.checked_count}`,
                rangeDetail(signatures.start_sequence_no, signatures.end_sequence_no),
            ]}
            errorCode={signatures.error_code}
        />
        <StatusCard
            title="monthly digest"
            ok={monthlyDigest.valid}
            details={[
                `period=${monthlyDigest.target_year_month}`,
                `entries=${monthlyDigest.entry_count ?? 0}`,
                rangeDetail(monthlyDigest.start_sequence_no, monthlyDigest.end_sequence_no),
            ]}
            errorCode={monthlyDigest.error_code}
        />
        <StatusCard
            title="restore / integrity"
            ok={isReportVerificationValid(summary)}
            details={[
                `audit_events=${summary.summary.audit_event_count}`,
                `ledger_entries=${summary.summary.ledger_entry_count}`,
                `verification_failures=${summary.summary.verification_failures.length}`,
                `restore_tests=${summary.summary.restore_tests.length}`,
                `integrity_checks=${summary.summary.integrity_checks.length}`,
            ]}
            errorCode={
                summary.signature_verification.error_code ??
                summary.summary.verification_failures[0]?.code ??
                null
            }
        />
    </section>
);
