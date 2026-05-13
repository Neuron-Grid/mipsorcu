/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_MIPSORCU_SUPABASE_URL: string;
  readonly VITE_MIPSORCU_SUPABASE_PUBLISHABLE_KEY: string;
  readonly VITE_MIPSORCU_AUDIT_API_BASE_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}