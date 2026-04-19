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

pub fn authorize_existing_secret_version_write(
    claims: &VerifiedJwtClaims,
    owner_user_id: &OwnerUserId,
) -> Result<(), AuthorizationError> {
    if claims.subject_user_id() != owner_user_id {
        return Err(AuthorizationError::OwnerMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const OTHER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d480";

    fn claims_for(user_id: &str) -> VerifiedJwtClaims {
        VerifiedJwtClaims::from_verified_subject(
            OwnerUserId::parse(user_id).expect("test user id should parse"),
        )
    }

    #[test]
    fn existing_secret_version_write_allows_owner() {
        let owner_user_id = OwnerUserId::parse(OWNER_USER_ID).expect("owner id should parse");

        let result =
            authorize_existing_secret_version_write(&claims_for(OWNER_USER_ID), &owner_user_id);

        assert!(result.is_ok());
    }

    #[test]
    fn existing_secret_version_write_rejects_non_owner() {
        let owner_user_id = OwnerUserId::parse(OWNER_USER_ID).expect("owner id should parse");

        let result =
            authorize_existing_secret_version_write(&claims_for(OTHER_USER_ID), &owner_user_id);

        assert!(matches!(result, Err(AuthorizationError::OwnerMismatch)));
    }
}
