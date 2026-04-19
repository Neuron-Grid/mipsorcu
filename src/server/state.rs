use std::path::PathBuf;
use std::sync::Arc;

use mipsorcu::audit::AuditRecorder;
use mipsorcu::auth::JwtVerifier;
use mipsorcu::types::{KeyVersion, MasterKey};

use super::supabase::{SupabaseAuditAppender, SupabaseClient};

#[derive(Clone)]
pub struct AppState {
    pub master_key: Arc<MasterKey>,
    pub key_version: KeyVersion,
    pub jwt_verifier: Arc<JwtVerifier>,
    pub supabase_client: Arc<SupabaseClient>,
    pub audit_recorder: Arc<AuditRecorder<SupabaseAuditAppender>>,
    pub audit_fallback_path: PathBuf,
}
