use serde_json::Value;

use crate::alias::aad::AliasAadV1;
use crate::alias::crypto::encrypt_alias;
use crate::alias::fingerprint::{AliasFingerprint, compute_alias_fingerprint};
use crate::alias::input::NormalizedAlias;
use crate::error::CryptoError;
use crate::types::{
    AliasEncryptionKey, AliasFingerprintKey, AliasFingerprintSchemaVersion, Ciphertext, CreatedAt,
    KeyVersion, Nonce, OwnerUserId, SecretAliasId, SecretId,
};

#[derive(Debug)]
pub struct PreparedAliasCreate {
    pub secret_alias_id: SecretAliasId,
    pub secret_id: SecretId,
    pub owner_user_id: OwnerUserId,
    pub ciphertext: Ciphertext,
    pub nonce: Nonce,
    pub alias_key_version: KeyVersion,
    pub alias_fingerprint: AliasFingerprint,
    pub fingerprint_key_version: KeyVersion,
    pub fingerprint_schema_version: AliasFingerprintSchemaVersion,
    pub aad_context: Value,
    pub created_at: CreatedAt,
}

#[derive(Debug)]
pub struct PreparedAliasUpdate {
    pub secret_alias_id: SecretAliasId,
    pub secret_id: SecretId,
    pub owner_user_id: OwnerUserId,
    pub ciphertext: Ciphertext,
    pub nonce: Nonce,
    pub alias_key_version: KeyVersion,
    pub new_alias_fingerprint: AliasFingerprint,
    pub fingerprint_key_version: KeyVersion,
    pub fingerprint_schema_version: AliasFingerprintSchemaVersion,
    pub aad_context: Value,
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_alias_create(
    encryption_key: &AliasEncryptionKey,
    encryption_key_version: KeyVersion,
    fingerprint_key: &AliasFingerprintKey,
    fingerprint_key_version: KeyVersion,
    secret_id: SecretId,
    owner_user_id: OwnerUserId,
    alias_input: NormalizedAlias,
    created_at: CreatedAt,
) -> Result<PreparedAliasCreate, CryptoError> {
    let secret_alias_id = SecretAliasId::generate()?;
    let aad = AliasAadV1::new(
        secret_alias_id.clone(),
        secret_id.clone(),
        owner_user_id.clone(),
        encryption_key_version,
    );
    let encrypted = encrypt_alias(encryption_key, &aad, &alias_input)?;
    let (ciphertext, nonce) = encrypted.into_parts();
    let alias_fingerprint =
        compute_alias_fingerprint(fingerprint_key, &owner_user_id, &alias_input)?;
    let aad_context = aad.to_stored_context()?;

    Ok(PreparedAliasCreate {
        secret_alias_id,
        secret_id,
        owner_user_id,
        ciphertext,
        nonce,
        alias_key_version: encryption_key_version,
        alias_fingerprint,
        fingerprint_key_version,
        fingerprint_schema_version: AliasFingerprintSchemaVersion::V1,
        aad_context,
        created_at,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_alias_update(
    encryption_key: &AliasEncryptionKey,
    encryption_key_version: KeyVersion,
    fingerprint_key: &AliasFingerprintKey,
    fingerprint_key_version: KeyVersion,
    secret_alias_id: SecretAliasId,
    secret_id: SecretId,
    owner_user_id: OwnerUserId,
    new_alias: NormalizedAlias,
) -> Result<PreparedAliasUpdate, CryptoError> {
    let aad = AliasAadV1::new(
        secret_alias_id.clone(),
        secret_id.clone(),
        owner_user_id.clone(),
        encryption_key_version,
    );
    let encrypted = encrypt_alias(encryption_key, &aad, &new_alias)?;
    let (ciphertext, nonce) = encrypted.into_parts();
    let new_alias_fingerprint =
        compute_alias_fingerprint(fingerprint_key, &owner_user_id, &new_alias)?;
    let aad_context = aad.to_stored_context()?;

    Ok(PreparedAliasUpdate {
        secret_alias_id,
        secret_id,
        owner_user_id,
        ciphertext,
        nonce,
        alias_key_version: encryption_key_version,
        new_alias_fingerprint,
        fingerprint_key_version,
        fingerprint_schema_version: AliasFingerprintSchemaVersion::V1,
        aad_context,
    })
}
