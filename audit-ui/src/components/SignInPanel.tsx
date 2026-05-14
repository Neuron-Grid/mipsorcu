import { useState } from "preact/hooks";
import type { SignInPanelProps } from "@/types/ui";

export const SignInPanel = ({ isLoading, errorMessage, onSignIn }: SignInPanelProps) => {
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
