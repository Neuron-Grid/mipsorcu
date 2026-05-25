use std::fmt;

use serde_json::Value;

use crate::MasterKeyRing;
use crate::aad::AadV1;
use crate::auth::VerifiedJwtClaims;
use crate::authorization::authorize_current_version_decrypt;
use crate::crypto::{SecretVersionRecord, open_dispatched};
use crate::error::{DecryptIntegrityError, SecretDecryptError};
use crate::types::{
    Ciphertext, Classification, CreatedAt, EncryptedDataKey, KekAlgorithm, KeyVersion, MasterKey,
    Nonce, OwnerUserId, Plaintext, SecretId, SecretVersion, WrappedDek,
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
    pub encrypted_data_key: Option<EncryptedDataKey>,
    pub wrapped_dek: Option<WrappedDek>,
    pub dek_wrap_algorithm: Option<KekAlgorithm>,
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
    encrypted_data_key: Option<EncryptedDataKey>,
    wrapped_dek: Option<WrappedDek>,
    dek_wrap_algorithm: Option<KekAlgorithm>,
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
            wrapped_dek: parts.wrapped_dek,
            dek_wrap_algorithm: parts.dek_wrap_algorithm,
            nonce_or_iv: parts.nonce_or_iv,
            ciphertext: parts.ciphertext,
            aad_context: parts.aad_context,
        }
    }

    fn into_secret_version_record(self) -> SecretVersionRecord {
        SecretVersionRecord {
            secret_id: self.secret_id,
            key_version: self.key_version,
            ciphertext: self.ciphertext,
            nonce: self.nonce_or_iv,
            encrypted_data_key: self.encrypted_data_key,
            wrapped_dek: self.wrapped_dek,
            dek_wrap_algorithm: self.dek_wrap_algorithm,
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
            .field("wrapped_dek", &self.wrapped_dek)
            .field("dek_wrap_algorithm", &self.dek_wrap_algorithm)
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
    let master_key = MasterKey::parse(master_key.as_bytes())?;
    let keyring = MasterKeyRing::single(input.key_version, master_key)?;

    decrypt_current_secret_version_with_keyring(&keyring, input)
}

pub fn decrypt_current_secret_version_with_keyring(
    master_key_ring: &MasterKeyRing,
    input: DecryptCurrentSecretVersionInput,
) -> Result<Plaintext, SecretDecryptError> {
    let row_aad = validate_decrypt_input(&input)?;
    let record = input.into_secret_version_record();

    open_dispatched(master_key_ring, &record, &row_aad)
}

fn validate_decrypt_input(
    input: &DecryptCurrentSecretVersionInput,
) -> Result<AadV1, SecretDecryptError> {
    authorize_current_version_decrypt(
        &input.claims,
        &input.owner_user_id,
        input.version,
        input.current_version,
    )?;

    let row_aad = row_aad_from_input(input);
    verify_stored_aad_matches_row(&input.aad_context, &row_aad)?;

    Ok(row_aad)
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
