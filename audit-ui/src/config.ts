export type AppConfig = {
  readonly supabaseUrl: string;
  readonly supabasePublishableKey: string;
  readonly auditApiBaseUrl: string;
};

type AppConfigEnvName =
  | 'VITE_MIPSORCU_SUPABASE_URL'
  | 'VITE_MIPSORCU_SUPABASE_PUBLISHABLE_KEY'
  | 'VITE_MIPSORCU_AUDIT_API_BASE_URL';

const requiredEnv = (name: AppConfigEnvName): string => {
  const value = import.meta.env[name];
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`missing required configuration: ${name}`);
  }

  return value;
};

const withoutTrailingSlash = (value: string): string => value.replace(/\/+$/, '');

export const loadConfig = (): AppConfig => ({
  supabaseUrl: withoutTrailingSlash(requiredEnv('VITE_MIPSORCU_SUPABASE_URL')),
  supabasePublishableKey: requiredEnv('VITE_MIPSORCU_SUPABASE_PUBLISHABLE_KEY'),
  auditApiBaseUrl: withoutTrailingSlash(requiredEnv('VITE_MIPSORCU_AUDIT_API_BASE_URL'))
});