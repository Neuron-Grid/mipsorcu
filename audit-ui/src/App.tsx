import type { Session, SupabaseClient } from "@supabase/supabase-js";
import type { ComponentChildren } from "preact";
import { useMemo, useState } from "preact/hooks";

import { type AuditApiClient, AuditApiError, createAuditApiClient } from "./auditApi";
import { type Credentials, createSupabaseAuthClient, signIn, signOut } from "./auth";
import { loadConfig } from "./config";
import { safeJsonText } from "./redaction";
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

type LoadState = "idle" | "loading" | "loaded" | "failed";

type DashboardData = {
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

const config = loadConfig();

const nowIso = (): string => new Date().toISOString();

const daysAgoIso = (days: number): string => {
    const date = new Date();
    date.setUTCDate(date.getUTCDate() - days);
    return date.toISOString();
};

const currentYearMonth = (): string => new Date().toISOString().slice(0, 7);

const safeErrorMessage = (error: unknown): string => {
    if (error instanceof AuditApiError) {
        return error.requestId === null
            ? `監査 API の読み取りに失敗しました: ${error.code}`
            : `監査 API の読み取りに失敗しました: ${error.code} / request_id=${error.requestId}`;
    }

    return "処理に失敗しました。設定または接続状態を確認してください。";
};

export const App = () => {
    const [session, setSession] = useState<Session | null>(null);
    const [authError, setAuthError] = useState<string | null>(null);
    const [authLoading, setAuthLoading] = useState(false);
    const [loadState, setLoadState] = useState<LoadState>("idle");
    const [loadError, setLoadError] = useState<string | null>(null);
    const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
    const [periodStart, setPeriodStart] = useState(daysAgoIso(30));
    const [periodEnd, setPeriodEnd] = useState(nowIso());
    const [yearMonth, setYearMonth] = useState(currentYearMonth());

    const supabase = useMemo<SupabaseClient>(() => createSupabaseAuthClient(config), []);
    const auditApi = useMemo<AuditApiClient | null>(() => {
        if (session === null) {
            return null;
        }

        return createAuditApiClient(config, session.access_token);
    }, [session]);

    const handleSignIn = async (credentials: Credentials): Promise<void> => {
        setAuthLoading(true);
        setAuthError(null);
        try {
            const nextSession = await signIn(supabase, credentials);
            setSession(nextSession);
        } catch {
            setAuthError("認証に失敗しました。入力または設定を確認してください。");
        } finally {
            setAuthLoading(false);
        }
    };

    const handleSignOut = async (): Promise<void> => {
        await signOut(supabase);
        setSession(null);
        setDashboardData(null);
        setLoadState("idle");
        setLoadError(null);
    };

    const loadDashboard = async (): Promise<void> => {
        if (auditApi === null) {
            return;
        }

        setLoadState("loading");
        setLoadError(null);
        try {
            const [
                secrets,
                auditEvents,
                ledgerEntries,
                integrityStatus,
                hashChain,
                signatures,
                monthlyDigest,
                failures,
                summary,
            ] = await Promise.all([
                auditApi.listSecrets(),
                auditApi.listAuditEvents(),
                auditApi.listLedgerEntries(),
                auditApi.integrityStatus(),
                auditApi.verifyHashChain(),
                auditApi.verifySignatures(),
                auditApi.verifyMonthlyDigest(yearMonth),
                auditApi.listVerificationFailures(periodStart, periodEnd),
                auditApi.verificationSummary(periodStart, periodEnd),
            ]);
            setDashboardData({
                secrets,
                auditEvents,
                ledgerEntries,
                integrityStatus,
                hashChain,
                signatures,
                monthlyDigest,
                failures,
                summary,
            });
            setLoadState("loaded");
        } catch (error) {
            setLoadError(safeErrorMessage(error));
            setLoadState("failed");
        }
    };

    if (session === null) {
        return (
            <SignInPanel isLoading={authLoading} errorMessage={authError} onSignIn={handleSignIn} />
        );
    }

    return (
        <main class="shell">
            <header class="hero">
                <div>
                    <p class="eyebrow">mipsorcu auditor console</p>
                    <h1>監査担当者向け台帳ビュー</h1>
                    <p class="hero__description">
                        SBC の read-only 監査 API から、非秘密メタデータと検証結果だけを表示します。
                    </p>
                </div>
                <button type="button" class="secondary-button" onClick={handleSignOut}>
                    サインアウト
                </button>
            </header>

            <section class="controls" aria-label="照会条件">
                <label>
                    対象期間開始
                    <input
                        value={periodStart}
                        onInput={(event) => setPeriodStart(event.currentTarget.value)}
                    />
                </label>
                <label>
                    対象期間終了
                    <input
                        value={periodEnd}
                        onInput={(event) => setPeriodEnd(event.currentTarget.value)}
                    />
                </label>
                <label>
                    digest 対象年月
                    <input
                        value={yearMonth}
                        onInput={(event) => setYearMonth(event.currentTarget.value)}
                    />
                </label>
                <button
                    type="button"
                    class="primary-button"
                    onClick={loadDashboard}
                    disabled={loadState === "loading"}
                >
                    {loadState === "loading" ? "読み取り中…" : "監査データを読み取る"}
                </button>
            </section>

            {loadError !== null && (
                <div class="notice notice--failure" role="alert">
                    {loadError}
                </div>
            )}

            {dashboardData === null ? (
                <section class="empty-state">
                    <h2>認証済みです</h2>
                    <p>照会条件を確認し、監査データを読み取ってください。</p>
                </section>
            ) : (
                <Dashboard data={dashboardData} />
            )}
        </main>
    );
};

type SignInPanelProps = {
    readonly isLoading: boolean;
    readonly errorMessage: string | null;
    readonly onSignIn: (credentials: Credentials) => Promise<void>;
};

const SignInPanel = ({ isLoading, errorMessage, onSignIn }: SignInPanelProps) => {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");

    return (
        <main class="signin-shell">
            <section class="signin-card" aria-label="監査 UI 認証">
                <p class="eyebrow">mipsorcu auditor console</p>
                <h1>監査担当者サインイン</h1>
                <p>Supabase Auth の監査担当者アカウントでサインインしてください。</p>
                <form
                    onSubmit={(event) => {
                        event.preventDefault();
                        void onSignIn({ email, password });
                    }}
                >
                    <label>
                        メールアドレス
                        <input
                            autocomplete="email"
                            inputMode="email"
                            type="email"
                            value={email}
                            onInput={(event) => setEmail(event.currentTarget.value)}
                            required
                        />
                    </label>
                    <label>
                        パスワード
                        <input
                            autocomplete="current-password"
                            type="password"
                            value={password}
                            onInput={(event) => setPassword(event.currentTarget.value)}
                            required
                        />
                    </label>
                    <button type="submit" class="primary-button" disabled={isLoading}>
                        {isLoading ? "確認中…" : "サインイン"}
                    </button>
                </form>
                {errorMessage !== null && (
                    <div class="notice notice--failure" role="alert">
                        {errorMessage}
                    </div>
                )}
            </section>
        </main>
    );
};

const Dashboard = ({ data }: { readonly data: DashboardData }) => (
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
        <Section title="検証失敗箇所" badge={`${data.failures.items.length} 件`}>
            <FailuresTable rows={data.failures.items} />
        </Section>
    </div>
);

type VerificationCardsProps = {
    readonly hashChain: HashChainVerification;
    readonly signatures: SignatureVerification;
    readonly monthlyDigest: MonthlyDigestVerification;
    readonly summary: SummaryResponse;
};

const VerificationCards = ({
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
            ok={summary.summary.failure_count === 0 && summary.signature_verification.valid}
            details={[
                `audit_events=${summary.summary.audit_event_count}`,
                `ledger_entries=${summary.summary.ledger_entry_count}`,
                `failures=${summary.summary.failure_count}`,
            ]}
            errorCode={summary.signature_verification.error_code}
        />
    </section>
);

type StatusCardProps = {
    readonly title: string;
    readonly ok: boolean;
    readonly details: readonly string[];
    readonly errorCode: string | null;
};

const StatusCard = ({ title, ok, details, errorCode }: StatusCardProps) => (
    <article class={ok ? "status-card status-card--ok" : "status-card status-card--failure"}>
        <div class="status-card__header">
            <h2>{title}</h2>
            <span>{ok ? "valid" : "failure"}</span>
        </div>
        <ul>
            {details.map((detail) => (
                <li key={detail}>{detail}</li>
            ))}
        </ul>
        {errorCode !== null && <p class="error-code">error_code={errorCode}</p>}
    </article>
);

type SectionProps = {
    readonly title: string;
    readonly badge: string;
    readonly children: ComponentChildren;
};

const Section = ({ title, badge, children }: SectionProps) => (
    <section class="panel">
        <div class="panel__header">
            <h2>{title}</h2>
            <span class="badge">{badge}</span>
        </div>
        {children}
    </section>
);

const SecretsTable = ({ rows }: { readonly rows: readonly AuditSecret[] }) => (
    <table>
        <thead>
            <tr>
                <th>secret_id</th>
                <th>owner_user_id</th>
                <th>classification</th>
                <th>current_version_id</th>
                <th>created_at</th>
                <th>updated_at</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr key={row.secret_id}>
                    <td>{row.secret_id}</td>
                    <td>{row.owner_user_id}</td>
                    <td>{row.classification}</td>
                    <td>{row.current_version_id ?? "-"}</td>
                    <td>{row.secret_created_at}</td>
                    <td>{row.secret_updated_at}</td>
                </tr>
            ))}
        </tbody>
    </table>
);

const AuditEventsTable = ({ rows }: { readonly rows: readonly AuditEventRow[] }) => (
    <table>
        <thead>
            <tr>
                <th>occurred_at</th>
                <th>action</th>
                <th>result</th>
                <th>actor_user_id</th>
                <th>target_secret_id</th>
                <th>metadata</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr
                    key={row.audit_event_id}
                    class={row.result === "failure" ? "row--failure" : undefined}
                >
                    <td>{row.occurred_at}</td>
                    <td>{row.action}</td>
                    <td>{row.result}</td>
                    <td>{row.actor_user_id ?? "-"}</td>
                    <td>{row.target_secret_id ?? "-"}</td>
                    <td>
                        <pre>{safeJsonText(row.metadata_json)}</pre>
                    </td>
                </tr>
            ))}
        </tbody>
    </table>
);

const LedgerEntriesTable = ({ rows }: { readonly rows: readonly LedgerEntryRow[] }) => (
    <table>
        <thead>
            <tr>
                <th>sequence_no</th>
                <th>entry_type</th>
                <th>result</th>
                <th>error_code</th>
                <th>entry_hash</th>
                <th>signature_key_version</th>
                <th>payload</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr
                    key={row.ledger_entry_id}
                    class={
                        row.result === "failure" || row.error_code !== null
                            ? "row--failure"
                            : undefined
                    }
                >
                    <td>{row.sequence_no}</td>
                    <td>{row.entry_type}</td>
                    <td>{row.result}</td>
                    <td>{row.error_code ?? "-"}</td>
                    <td>{row.entry_hash}</td>
                    <td>{row.signature_key_version}</td>
                    <td>
                        <pre>{safeJsonText(row.payload)}</pre>
                    </td>
                </tr>
            ))}
        </tbody>
    </table>
);

const IntegrityTable = ({ rows }: { readonly rows: readonly IntegrityStatusRow[] }) => (
    <table>
        <thead>
            <tr>
                <th>chain_id</th>
                <th>last_sequence_no</th>
                <th>last_entry_hash</th>
                <th>updated_at</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr key={row.chain_id}>
                    <td>{row.chain_id}</td>
                    <td>{row.last_sequence_no}</td>
                    <td>{row.last_entry_hash}</td>
                    <td>{row.chain_state_updated_at}</td>
                </tr>
            ))}
        </tbody>
    </table>
);

const FailuresTable = ({ rows }: { readonly rows: readonly VerificationFailureRow[] }) => (
    <table>
        <thead>
            <tr>
                <th>occurred_at</th>
                <th>source</th>
                <th>code</th>
                <th>sequence_no</th>
            </tr>
        </thead>
        <tbody>
            {rows.map((row) => (
                <tr key={`${row.source}-${row.code}-${row.occurred_at}`} class="row--failure">
                    <td>{row.occurred_at}</td>
                    <td>{row.source}</td>
                    <td>{row.code}</td>
                    <td>{row.sequence_no ?? "-"}</td>
                </tr>
            ))}
        </tbody>
    </table>
);

const nullableDetail = (label: string, value: number | null): string => `${label}=${value ?? "-"}`;

const rangeDetail = (start: number | null, end: number | null): string =>
    `range=${start ?? "-"}..${end ?? "-"}`;
