import { createClient, type Session, type SupabaseClient } from '@supabase/supabase-js';

import type { AppConfig } from './config';

export type AuthState = {
  readonly session: Session | null;
  readonly isLoading: boolean;
  readonly errorMessage: string | null;
};

export type Credentials = {
  readonly email: string;
  readonly password: string;
};

export const createSupabaseAuthClient = (config: AppConfig): SupabaseClient =>
  createClient(config.supabaseUrl, config.supabasePublishableKey, {
    auth: {
      autoRefreshToken: false,
      detectSessionInUrl: false,
      persistSession: false
    }
  });

export const signIn = async (
  supabase: SupabaseClient,
  credentials: Credentials
): Promise<Session> => {
  const { data, error } = await supabase.auth.signInWithPassword({
    email: credentials.email,
    password: credentials.password
  });

  if (error || data.session === null) {
    throw new Error('authentication_failed');
  }

  return data.session;
};

export const signOut = async (supabase: SupabaseClient): Promise<void> => {
  await supabase.auth.signOut();
};