use crate::auth::VerifiedJwtClaims;
use crate::error::AuthorizationError;
use crate::types::{OwnerUserId, SecretVersion};

pub fn authorize_new_secret_create(claims: &VerifiedJwtClaims) -> Result<(), AuthorizationError> {
    let _ = claims;

    Ok(())
}

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

pub fn authorize_existing_secret_version_write(
    claims: &VerifiedJwtClaims,
    owner_user_id: &OwnerUserId,
) -> Result<(), AuthorizationError> {
    if claims.subject_user_id() != owner_user_id {
        return Err(AuthorizationError::OwnerMismatch);
    }

    Ok(())
}
