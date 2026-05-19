use crate::alias::aad::AliasAadV1;
use crate::alias::crypto::decrypt_alias;
use crate::alias::fingerprint::{AliasFingerprint, compute_alias_fingerprint};
use crate::alias::input::NormalizedAlias;
use crate::error::{CryptoError, DecryptIntegrityError, SecretDecryptError};
use crate::types::{
    AliasEncryptionKey, AliasFingerprintKey, Ciphertext, KeyVersion, Nonce, OwnerUserId,
    SecretAliasId, SecretId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedAlias {
    pub secret_alias_id: SecretAliasId,
    pub secret_id: SecretId,
    pub alias: NormalizedAlias,
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_alias_row(
    encryption_key: &AliasEncryptionKey,
    secret_alias_id: SecretAliasId,
    secret_id: SecretId,
    owner_user_id: OwnerUserId,
    alias_key_version: KeyVersion,
    ciphertext: &Ciphertext,
    nonce: &Nonce,
    aad_context: &serde_json::Value,
) -> Result<DecryptedAlias, SecretDecryptError> {
    let stored_aad = AliasAadV1::from_stored_context(aad_context)?;
    let row_aad = AliasAadV1::new(
        secret_alias_id.clone(),
        secret_id.clone(),
        owner_user_id,
        alias_key_version,
    );

    if stored_aad.canonical_bytes()? != row_aad.canonical_bytes()? {
        return Err(DecryptIntegrityError::AadContextMismatch.into());
    }

    let alias = decrypt_alias(encryption_key, &row_aad, nonce, ciphertext)?;

    Ok(DecryptedAlias {
        secret_alias_id,
        secret_id,
        alias,
    })
}

pub fn compute_lookup_fingerprint(
    fingerprint_key: &AliasFingerprintKey,
    owner_user_id: &OwnerUserId,
    alias: &NormalizedAlias,
) -> Result<AliasFingerprint, CryptoError> {
    compute_alias_fingerprint(fingerprint_key, owner_user_id, alias)
}
