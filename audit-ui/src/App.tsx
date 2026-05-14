import type { Session, SupabaseClient } from "@supabase/supabase-js";
import { useMemo, useState } from "preact/hooks";
import { type AuditApiClient, createAuditApiClient } from "@/api/client";
import { type Credentials, createSupabaseAuthClient, signIn, signOut } from "@/auth";
import { Dashboard } from "@/components/Dashboard";
import { SignInPanel } from "@/components/SignInPanel";
import { loadConfig } from "@/config";
import { currentYearMonth, daysAgoIso, nowIso } from "@/lib/datetime";
import { AUTH_ERROR_MESSAGE, safeErrorMessage } from "@/lib/errors";
import type { DashboardData, LoadState } from "@/types/ui";

const config = loadConfig();

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
            setAuthError(AUTH_ERROR_MESSAGE);
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
