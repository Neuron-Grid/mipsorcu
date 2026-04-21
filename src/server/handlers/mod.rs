mod audit;
mod create;
mod decrypt;
mod health;
mod parsing;
mod read_row;
mod rotate;
mod shared;

pub use create::create_secret;
pub use decrypt::decrypt_secret;
pub use health::{health_check, not_found};
pub use rotate::rotate_secret;

pub(in crate::server) use read_row::{PreparedDecryptRow, parse_decrypt_row};

#[doc(hidden)]
pub mod testing {
    pub use super::read_row::PreparedDecryptRow;

    use crate::audit::{
        AuditAction, AuditEvent, AuditEventError, AuditEventId, AuditMetadata, RequestId,
    };
    use crate::server::dto::RotateSecretRequest;
    use crate::server::errors::ApiError;
    use crate::server::supabase::SecretVersionReadRow;
    use crate::{OwnerUserId, SecretId};

    pub fn build_failure_audit_event(
        audit_event_id: AuditEventId,
        request_id: &RequestId,
        actor_user_id: Option<&OwnerUserId>,
        target_secret_id: Option<&SecretId>,
        action: AuditAction,
        metadata_json: AuditMetadata,
    ) -> Result<AuditEvent, AuditEventError> {
        super::audit::build_failure_audit_event(
            audit_event_id,
            request_id,
            actor_user_id,
            target_secret_id,
            action,
            metadata_json,
        )
    }

    pub fn parse_decrypt_row(row: SecretVersionReadRow) -> Result<PreparedDecryptRow, ApiError> {
        super::read_row::parse_decrypt_row(row)
    }

    pub fn select_single_current_secret_version_row(
        rows: Vec<SecretVersionReadRow>,
    ) -> Result<SecretVersionReadRow, ApiError> {
        super::read_row::select_single_current_secret_version_row(rows)
    }

    pub fn validate_rotate_secret_request(body: RotateSecretRequest) -> Result<(), ApiError> {
        super::parsing::parse_rotate_secret_request(body).map(|_| ())
    }

    pub fn decode_bytea(value: &str) -> Result<Vec<u8>, ApiError> {
        super::read_row::decode_bytea(value)
    }

    pub fn parse_write_response_version(value: i32) -> Result<u32, ApiError> {
        super::shared::parse_write_response_version(value)
    }
}
