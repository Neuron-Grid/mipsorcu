use crate::types::OwnerUserId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJwtClaims {
    subject_user_id: OwnerUserId,
}

impl VerifiedJwtClaims {
    pub fn from_verified_subject(owner_user_id: OwnerUserId) -> Self {
        Self {
            subject_user_id: owner_user_id,
        }
    }

    pub fn subject_user_id(&self) -> &OwnerUserId {
        &self.subject_user_id
    }
}
