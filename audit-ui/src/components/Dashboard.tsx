import type { DashboardProps } from "../types/ui";
import { Section } from "./Section";
import { AuditEventsTable } from "./tables/AuditEventsTable";
import { FailuresTable } from "./tables/FailuresTable";
import { IntegrityChecksTable } from "./tables/IntegrityChecksTable";
import { IntegrityTable } from "./tables/IntegrityTable";
import { LedgerEntriesTable } from "./tables/LedgerEntriesTable";
import { MonthlyDigestsTable } from "./tables/MonthlyDigestsTable";
import { RestoreTestsTable } from "./tables/RestoreTestsTable";
import { SecretsTable } from "./tables/SecretsTable";
import { VerificationCards } from "./VerificationCards";

export const Dashboard = ({ data }: DashboardProps) => (
    <div class="dashboard" data-testid="audit-dashboard">
        <VerificationCards
            hashChain={data.hashChain}
            signatures={data.signatures}
            monthlyDigest={data.monthlyDigest}
            summary={data.summary}
        />
        <Section title="secret 非秘密メタデータ" badge={`${data.secrets.items.length} 件`}>
            <SecretsTable rows={data.secrets.items} />
        </Section>
        <Section title="audit_events" badge={`${data.auditEvents.items.length} 件`}>
            <AuditEventsTable rows={data.auditEvents.items} />
        </Section>
        <Section title="ledger_entries" badge={`${data.ledgerEntries.items.length} 件`}>
            <LedgerEntriesTable rows={data.ledgerEntries.items} />
        </Section>
        <Section title="integrity status" badge={`${data.integrityStatus.length} 件`}>
            <IntegrityTable rows={data.integrityStatus} />
        </Section>
        <Section
            title="monthly digests"
            badge={`${data.summary.summary.monthly_digests.length} 件`}
        >
            <MonthlyDigestsTable rows={data.summary.summary.monthly_digests} />
        </Section>
        <Section title="restore tests" badge={`${data.summary.summary.restore_tests.length} 件`}>
            <RestoreTestsTable rows={data.summary.summary.restore_tests} />
        </Section>
        <Section
            title="integrity checks"
            badge={`${data.summary.summary.integrity_checks.length} 件`}
        >
            <IntegrityChecksTable rows={data.summary.summary.integrity_checks} />
        </Section>
        <Section title="検証失敗箇所" badge={`${data.failures.items.length} 件`}>
            <FailuresTable rows={data.failures.items} />
        </Section>
    </div>
);
