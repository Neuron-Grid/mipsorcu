import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'on-first-retry',
  },
  webServer: {
    command: 'bun run dev -- --host 127.0.0.1 --port 4173',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
    env: {
      VITE_MIPSORCU_SUPABASE_URL: 'http://127.0.0.1:4173/mock-supabase',
      VITE_MIPSORCU_SUPABASE_PUBLISHABLE_KEY: 'test-publishable-key',
      VITE_MIPSORCU_AUDIT_API_BASE_URL: 'http://127.0.0.1:4173',
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
