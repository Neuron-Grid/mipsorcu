import { expect, test, type Page } from '@playwright/test';

const forbiddenOperationPattern = /作成|更新|削除|復号|修復|再生成|decrypt|create|update|delete|repair|regenerate/i;

const forbiddenSecretValues = [
  'DO_NOT_SHOW_PLAINTEXT',
  'DO_NOT_SHOW_MASTER_KEY',
  'DO_NOT_SHOW_DATA_KEY',
  'DO_NOT_SHOW_SERVICE_ROLE_KEY',
  'DO_NOT_SHOW_REQUEST_BODY',
  'DO_NOT_SHOW_RESPONSE_BODY',
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdWRpdG9yIn0.signaturevalue'
];

const installApiMocks = async (page: Page): Promise<void> => {
  await page.route('**/mock-supabase/auth/v1/token?grant_type=password', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        access_token: 'mock-auditor-access-token',
        token_type: 'bearer',
        expires_in: 900,
        refresh_token: 'mock-refresh-token',
        user: {
          id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          aud: 'authenticated',
          role: 'authenticated',
          email: 'auditor@example.test',
          app_metadata: { roles: ['auditor'] },
          user_metadata: {},
          created_at: '2026-05-14T00:00:00Z'
        }
      })
    });
  });

  await page.route('**/mock-supabase/auth/v1/logout*', async (route) => {
    await route.fulfill({ status: 204, body: '' });
  });

  await page.route('**/audit/v1/secrets*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          {
            secret_id: '550e8400-e29b-41d4-a716-446655440000',
            owner_user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            classification: 'confidential',
            current_version_id: '660e8400-e29b-41d4-a716-446655440001',
            secret_created_at: '2026-05-01T00:00:00Z',
            secret_updated_at: '2026-05-02T00:00:00Z'
          }
        ],
        limit: 50,
        offset: 0,
        has_more: false
      })
    });
  });

  await page.route('**/audit/v1/audit-events*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          {
            audit_event_id: '770e8400-e29b-41d4-a716-446655440000',
            request_id: '880e8400-e29b-41d4-a716-446655440000',
            actor_user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            actor_device_id: null,
            action: 'audit_ui_read',
            target_secret_id: null,
            result: 'failure',
            key_version: null,
            metadata_json: {
              endpoint: '/audit/v1/audit-events',
              resource: 'audit_events',
              plaintext: 'DO_NOT_SHOW_PLAINTEXT',
              master_key: 'DO_NOT_SHOW_MASTER_KEY',
              data_key: 'DO_NOT_SHOW_DATA_KEY',
              service_role_key: 'DO_NOT_SHOW_SERVICE_ROLE_KEY',
              jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdWRpdG9yIn0.signaturevalue',
              request_body: 'DO_NOT_SHOW_REQUEST_BODY',
              response_body: 'DO_NOT_SHOW_RESPONSE_BODY'
            },
            occurred_at: '2026-05-14T00:00:00Z'
          }
        ],
        limit: 50,
        offset: 0,
        has_more: false
      })
    });
  });

  await page.route('**/audit/v1/ledger-entries*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          {
            ledger_entry_id: '990e8400-e29b-41d4-a716-446655440000',
            sequence_no: 42,
            entry_type: 'integrity_check',
            source_event_at: '2026-05-14T00:00:00Z',
            request_id: '880e8400-e29b-41d4-a716-446655440000',
            source_event_id: '770e8400-e29b-41d4-a716-446655440000',
            target_secret_id: null,
            target_secret_version_id: null,
            actor_user_id: null,
            actor_device_id: null,
            result: 'failure',
            error_code: 'ledger_hash_mismatch',
            payload: { check: 'hash_chain', plaintext: 'DO_NOT_SHOW_PLAINTEXT' },
            canonicalization_version: 1,
            previous_entry_hash: '00'.repeat(32),
            entry_hash: '11'.repeat(32),
            hash_algorithm: 'sha-256',
            signature: '22'.repeat(64),
            signature_algorithm: 'ed25519',
            signature_key_version: 1,
            created_at: '2026-05-14T00:00:01Z'
          }
        ],
        limit: 50,
        offset: 0,
        has_more: false
      })
    });
  });

  await page.route('**/audit/v1/integrity-status*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([
        {
          chain_id: 'global',
          last_sequence_no: 42,
          last_entry_hash: '11'.repeat(32),
          chain_state_updated_at: '2026-05-14T00:00:01Z'
        }
      ])
    });
  });

  await page.route('**/audit/v1/verification/hash-chain*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        chain_valid: false,
        entries_checked: 42,
        first_gap_sequence_no: null,
        first_gap_detail: null,
        first_hash_mismatch_sequence_no: 42,
        first_hash_mismatch_detail: 'ledger_hash_mismatch',
        chain_head_sequence_no: 41,
        chain_head_entry_hash: '00'.repeat(32)
      })
    });
  });

  await page.route('**/audit/v1/verification/signatures*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        valid: true,
        checked_count: 42,
        start_sequence_no: 1,
        end_sequence_no: 42,
        error_code: null
      })
    });
  });

  await page.route('**/audit/v1/verification/monthly-digest*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        valid: false,
        target_year_month: '2026-05',
        start_sequence_no: null,
        end_sequence_no: null,
        entry_count: null,
        error_code: 'monthly_digest_mismatch'
      })
    });
  });

  await page.route('**/audit/v1/verification/failures*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: [
          {
            code: 'ledger_hash_mismatch',
            occurred_at: '2026-05-14T00:00:00Z',
            sequence_no: 42,
            source: 'hash_chain'
          }
        ],
        limit: 50,
        offset: 0,
        has_more: false
      })
    });
  });

  await page.route('**/audit/v1/verification/summary*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        summary: {
          audit_event_count: 3,
          ledger_entry_count: 42,
          secret_count: 1,
          failure_count: 1,
          sequence_start: 1,
          sequence_end: 42,
          period_start: '2026-05-01T00:00:00Z',
          period_end: '2026-05-31T23:59:59Z',
          hash_chain: {},
          signatures: {},
          restore_tests: [],
          integrity_checks: [],
          monthly_digests: [],
          verification_failures: [],
          signature_key_versions: []
        },
        signature_verification: {
          valid: true,
          checked_count: 42,
          start_sequence_no: 1,
          end_sequence_no: 42,
          error_code: null
        }
      })
    });
  });
};

test('認証なしでは監査ダッシュボードにアクセスできない', async ({ page }) => {
  const auditCalls: string[] = [];
  await page.route('**/audit/v1/**', async (route) => {
    auditCalls.push(route.request().url());
    await route.abort();
  });

  await page.goto('/');

  await expect(page.getByRole('heading', { name: '監査担当者サインイン' })).toBeVisible();
  await expect(page.getByTestId('audit-dashboard')).toHaveCount(0);
  expect(auditCalls).toHaveLength(0);
});

test('read-only 監査データを表示し、検証失敗をハイライトし、禁止情報を表示しない', async ({ page }) => {
  await installApiMocks(page);
  const methods: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/audit/v1/')) {
      methods.push(request.method());
    }
  });

  await page.goto('/');
  await page.getByLabel('メールアドレス').fill('auditor@example.test');
  await page.getByLabel('パスワード').fill('dummy-password');
  await page.getByRole('button', { name: 'サインイン' }).click();
  await page.getByRole('button', { name: '監査データを読み取る' }).click();

  await expect(page.getByTestId('audit-dashboard')).toBeVisible();
  await expect(page.getByText('ledger_hash_mismatch').first()).toBeVisible();
  await expect(page.locator('.status-card--failure')).toHaveCount(3);
  await expect(page.locator('.row--failure')).not.toHaveCount(0);
  expect(methods.every((method) => method === 'GET')).toBe(true);

  for (const value of forbiddenSecretValues) {
    await expect(page.getByText(value)).toHaveCount(0);
  }

  await expect(page.getByRole('button', { name: forbiddenOperationPattern })).toHaveCount(0);
  await expect(page.getByRole('link', { name: forbiddenOperationPattern })).toHaveCount(0);
});

test('認可されていない閲覧では安全なエラーのみを表示する', async ({ page }) => {
  await installApiMocks(page);
  await page.route('**/audit/v1/secrets*', async (route) => {
    await route.fulfill({
      status: 403,
      contentType: 'application/json',
      body: JSON.stringify({ code: 'forbidden', request_id: '123e4567-e89b-42d3-a456-426614174000' })
    });
  });

  await page.goto('/');
  await page.getByLabel('メールアドレス').fill('viewer@example.test');
  await page.getByLabel('パスワード').fill('dummy-password');
  await page.getByRole('button', { name: 'サインイン' }).click();
  await page.getByRole('button', { name: '監査データを読み取る' }).click();

  await expect(page.getByRole('alert')).toContainText('forbidden');
  await expect(page.getByRole('alert')).toContainText('request_id=123e4567-e89b-42d3-a456-426614174000');
  for (const value of forbiddenSecretValues) {
    await expect(page.getByText(value)).toHaveCount(0);
  }
});