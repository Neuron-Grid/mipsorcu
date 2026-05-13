const REDACTED = '[redacted]';

const FORBIDDEN_KEY_MARKERS = [
  'plaintext',
  'plain_text',
  'decrypted',
  'decryption_result',
  'master_key',
  'masterkey',
  'data_key',
  'datakey',
  'service_role',
  'secret_key',
  'authorization',
  'jwt',
  'access_token',
  'refresh_token',
  'request_body',
  'response_body'
] as const;

const JWT_PATTERN = /^[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}$/;

const normalizeKey = (key: string): string => key.trim().toLowerCase().replace(/[-\s]+/g, '_');

export const isForbiddenDisplayKey = (key: string): boolean => {
  const normalized = normalizeKey(key);
  return FORBIDDEN_KEY_MARKERS.some((marker) => normalized.includes(marker));
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export const redactValue = (value: unknown): unknown => {
  if (typeof value === 'string') {
    return JWT_PATTERN.test(value) ? REDACTED : value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item));
  }

  if (isRecord(value)) {
    const safeEntries: Array<[string, unknown]> = [];
    let redactedKeyCount = 0;

    for (const [key, nestedValue] of Object.entries(value)) {
      if (isForbiddenDisplayKey(key)) {
        redactedKeyCount += 1;
        safeEntries.push([`redacted_field_${redactedKeyCount}`, REDACTED]);
      } else {
        safeEntries.push([key, redactValue(nestedValue)]);
      }
    }

    return Object.fromEntries(safeEntries);
  }

  return value;
};

export const safeJsonText = (value: unknown): string => JSON.stringify(redactValue(value), null, 2);