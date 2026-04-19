use std::fmt;

use serde_json::Value;

use crate::aad::AadV1;
use crate::auth::VerifiedJwtClaims;
use crate::authorization::authorize_current_version_decrypt;
use crate::crypto::{KeyWrapContext, decrypt_secret, unwrap_data_key};
use crate::error::{DecryptIntegrityError, SecretDecryptError};
use crate::types::{
    Ciphertext, Classification, CreatedAt, EncryptedDataKey, KeyVersion, MasterKey, Nonce,
    OwnerUserId, Plaintext, SecretId, SecretVersion,
};

pub struct DecryptCurrentSecretVersionInputParts {
    pub claims: VerifiedJwtClaims,
    pub secret_id: SecretId,
    pub version: SecretVersion,
    pub current_version: SecretVersion,
    pub owner_user_id: OwnerUserId,
    pub classification: Classification,
    pub created_at: CreatedAt,
    pub key_version: KeyVersion,
    pub encrypted_data_key: EncryptedDataKey,
    pub nonce_or_iv: Nonce,
    pub ciphertext: Ciphertext,
    pub aad_context: Value,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DecryptCurrentSecretVersionInput {
    claims: VerifiedJwtClaims,
    secret_id: SecretId,
    version: SecretVersion,
    current_version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_at: CreatedAt,
    key_version: KeyVersion,
    encrypted_data_key: EncryptedDataKey,
    nonce_or_iv: Nonce,
    ciphertext: Ciphertext,
    aad_context: Value,
}

impl DecryptCurrentSecretVersionInput {
    pub fn new(parts: DecryptCurrentSecretVersionInputParts) -> Self {
        Self {
            claims: parts.claims,
            secret_id: parts.secret_id,
            version: parts.version,
            current_version: parts.current_version,
            owner_user_id: parts.owner_user_id,
            classification: parts.classification,
            created_at: parts.created_at,
            key_version: parts.key_version,
            encrypted_data_key: parts.encrypted_data_key,
            nonce_or_iv: parts.nonce_or_iv,
            ciphertext: parts.ciphertext,
            aad_context: parts.aad_context,
        }
    }
}

impl fmt::Debug for DecryptCurrentSecretVersionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptCurrentSecretVersionInput")
            .field("claims", &self.claims)
            .field("secret_id", &self.secret_id)
            .field("version", &self.version)
            .field("current_version", &self.current_version)
            .field("owner_user_id", &self.owner_user_id)
            .field("classification", &self.classification)
            .field("created_at", &self.created_at)
            .field("key_version", &self.key_version)
            .field("encrypted_data_key", &self.encrypted_data_key)
            .field("nonce_or_iv", &self.nonce_or_iv)
            .field("ciphertext", &self.ciphertext)
            .field("aad_context", &"<redacted>")
            .finish()
    }
}

pub fn decrypt_current_secret_version(
    master_key: &MasterKey,
    input: DecryptCurrentSecretVersionInput,
) -> Result<Plaintext, SecretDecryptError> {
    authorize_current_version_decrypt(
        &input.claims,
        &input.owner_user_id,
        input.version,
        input.current_version,
    )?;

    let row_aad = row_aad_from_input(&input);
    verify_stored_aad_matches_row(&input.aad_context, &row_aad)?;

    let key_wrap_context = KeyWrapContext::new(input.secret_id, input.key_version);
    let data_key = unwrap_data_key(master_key, &key_wrap_context, &input.encrypted_data_key)?;

    decrypt_secret(&data_key, &row_aad, &input.nonce_or_iv, &input.ciphertext)
        .map_err(SecretDecryptError::from)
}

fn row_aad_from_input(input: &DecryptCurrentSecretVersionInput) -> AadV1 {
    AadV1::from_row_metadata(
        input.secret_id.clone(),
        input.version,
        input.owner_user_id.clone(),
        input.classification.clone(),
        input.created_at.clone(),
    )
}

fn verify_stored_aad_matches_row(
    stored_context: &Value,
    row_aad: &AadV1,
) -> Result<(), SecretDecryptError> {
    let stored_aad = AadV1::from_stored_context(stored_context)?;

    if stored_aad.canonical_bytes()? == row_aad.canonical_bytes()? {
        Ok(())
    } else {
        Err(DecryptIntegrityError::AadContextMismatch.into())
    }
}
