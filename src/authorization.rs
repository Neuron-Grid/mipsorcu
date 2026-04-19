use crate::auth::VerifiedJwtClaims;
use crate::error::AuthorizationError;
use crate::types::{OwnerUserId, SecretVersion};

pub fn authorize_current_version_decrypt(
    claims: &VerifiedJwtClaims,
    owner_user_id: &OwnerUserId,
    requested_version: SecretVersion,
    current_version: SecretVersion,
) -> Result<(), AuthorizationError> {
    if claims.subject_user_id() != owner_user_id {
        return Err(AuthorizationError::OwnerMismatch);
    }

    if requested_version != current_version {
        return Err(AuthorizationError::NotCurrentVersion);
    }

    Ok(())
}
