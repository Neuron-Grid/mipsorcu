mod create;
mod decrypt;
mod health;
mod parsing;
mod rotate;

pub use create::create_secret;
pub use decrypt::decrypt_secret;
pub use health::{health_check, not_found, ready_check};
pub use rotate::rotate_secret;

#[doc(hidden)]
pub mod testing {
    use crate::audit::{
        AuditAction, AuditEvent, AuditEventError, AuditEventId, AuditMetadata, RequestId,
    };
    use crate::server::dto::{CreateSecretRequest, RotateSecretRequest};
    use crate::server::errors::ApiError;
    pub use crate::server::read_model::PreparedDecryptRow;
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
        crate::server::audit_reporter::build_failure_audit_event(
            audit_event_id,
            request_id,
            actor_user_id,
            target_secret_id,
            action,
            metadata_json,
        )
    }

    pub fn parse_decrypt_row(row: SecretVersionReadRow) -> Result<PreparedDecryptRow, ApiError> {
        crate::server::read_model::testing::parse_decrypt_row(row)
    }

    pub fn select_single_current_secret_version_row(
        rows: Vec<SecretVersionReadRow>,
    ) -> Result<SecretVersionReadRow, ApiError> {
        crate::server::read_model::testing::select_single_current_secret_version_row(rows)
    }

    pub fn validate_create_secret_request(body: CreateSecretRequest) -> Result<(), ApiError> {
        super::parsing::parse_create_secret_request(body).map(|_| ())
    }

    pub fn validate_rotate_secret_request(body: RotateSecretRequest) -> Result<(), ApiError> {
        super::parsing::parse_rotate_secret_request(body).map(|_| ())
    }

    pub fn decode_bytea(value: &str) -> Result<Vec<u8>, ApiError> {
        crate::server::read_model::testing::decode_bytea(value)
    }
}
