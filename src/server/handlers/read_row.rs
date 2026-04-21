use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::crypto::ALGORITHM_XCHACHA20_POLY1305;
use crate::read::{DecryptCurrentSecretVersionInput, DecryptCurrentSecretVersionInputParts};
use crate::server::errors::ApiError;
use crate::server::state::AppState;
use crate::server::supabase::SecretVersionReadRow;
use crate::types::{
    Ciphertext, Classification, CreatedAt, EncryptedDataKey, KeyVersion, Nonce, OwnerUserId,
    SecretId, SecretVersion,
};
use crate::write::CurrentSecretVersionState;

pub struct PreparedDecryptRow {
    secret_id: SecretId,
    version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_at: CreatedAt,
    key_version: KeyVersion,
    encrypted_data_key: EncryptedDataKey,
    nonce_or_iv: Nonce,
    ciphertext: Ciphertext,
    aad_context: serde_json::Value,
}

struct DecodedSecretVersionBytes {
    encrypted_data_key: Vec<u8>,
    nonce_or_iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl PreparedDecryptRow {
    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    pub fn owner_user_id(&self) -> &OwnerUserId {
        &self.owner_user_id
    }

    #[cfg(test)]
    pub(in crate::server) fn created_at(&self) -> &CreatedAt {
        &self.created_at
    }

    pub fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    pub fn encrypted_data_key(&self) -> &EncryptedDataKey {
        &self.encrypted_data_key
    }

    pub fn nonce_or_iv(&self) -> &Nonce {
        &self.nonce_or_iv
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    #[cfg(test)]
    pub(in crate::server) fn set_aad_context(&mut self, aad_context: serde_json::Value) {
        self.aad_context = aad_context;
    }

    #[cfg(test)]
    pub(in crate::server) fn set_ciphertext(&mut self, ciphertext: Ciphertext) {
        self.ciphertext = ciphertext;
    }

    pub fn into_current_secret_version_state(self) -> CurrentSecretVersionState {
        CurrentSecretVersionState::new(
            self.secret_id,
            self.version,
            self.owner_user_id,
            self.classification,
            self.key_version,
            self.encrypted_data_key,
        )
    }

    pub(in crate::server) fn into_decrypt_input(
        self,
        claims: VerifiedJwtClaims,
    ) -> DecryptCurrentSecretVersionInput {
        DecryptCurrentSecretVersionInput::new(DecryptCurrentSecretVersionInputParts {
            claims,
            secret_id: self.secret_id,
            version: self.version,
            current_version: self.version,
            owner_user_id: self.owner_user_id,
            classification: self.classification,
            created_at: self.created_at,
            key_version: self.key_version,
            encrypted_data_key: self.encrypted_data_key,
            nonce_or_iv: self.nonce_or_iv,
            ciphertext: self.ciphertext,
            aad_context: self.aad_context,
        })
    }
}

pub(super) async fn fetch_single_current_secret_version(
    state: &AppState,
    secret_id: &SecretId,
    raw_jwt: &RawJwt,
) -> Result<PreparedDecryptRow, ApiError> {
    let rows = state
        .supabase_client
        .fetch_current_secret_version_for_user(&secret_id.as_canonical_string(), raw_jwt)
        .await
        .map_err(ApiError::from)?;

    select_single_current_secret_version_row(rows).and_then(parse_decrypt_row)
}

pub(in crate::server) fn parse_decrypt_row(
    row: SecretVersionReadRow,
) -> Result<PreparedDecryptRow, ApiError> {
    validate_decrypt_row_invariants(&row)?;
    let decoded = decode_secret_version_bytes(&row)?;

    Ok(PreparedDecryptRow {
        secret_id: SecretId::parse(&row.secret_id).map_err(|_| ApiError::DecryptFailed)?,
        version: parse_secret_version(row.version)?,
        owner_user_id: OwnerUserId::parse(&row.secrets.owner_user_id)
            .map_err(|_| ApiError::DecryptFailed)?,
        classification: Classification::new(&row.secrets.classification)
            .map_err(|_| ApiError::DecryptFailed)?,
        created_at: CreatedAt::parse(&row.created_at).map_err(|_| ApiError::DecryptFailed)?,
        key_version: parse_key_version(row.key_version)?,
        encrypted_data_key: EncryptedDataKey::parse(&decoded.encrypted_data_key)
            .map_err(|_| ApiError::DecryptFailed)?,
        nonce_or_iv: Nonce::parse(&decoded.nonce_or_iv).map_err(|_| ApiError::DecryptFailed)?,
        ciphertext: Ciphertext::new(decoded.ciphertext).map_err(|_| ApiError::DecryptFailed)?,
        aad_context: row.aad_context,
    })
}

pub(super) fn select_single_current_secret_version_row(
    rows: Vec<SecretVersionReadRow>,
) -> Result<SecretVersionReadRow, ApiError> {
    let current_rows = rows
        .into_iter()
        .filter(|row| row.secrets.current_version_id == row.id)
        .collect::<Vec<_>>();

    match current_rows.len() {
        0 => Err(ApiError::NotFound("secret not found".to_owned())),
        1 => current_rows
            .into_iter()
            .next()
            .ok_or_else(|| ApiError::InternalInvariantViolation("missing read row".to_owned())),
        count => Err(ApiError::InternalInvariantViolation(format!(
            "expected one current secret version row, got {count}"
        ))),
    }
}

fn validate_decrypt_row_invariants(row: &SecretVersionReadRow) -> Result<(), ApiError> {
    if row.algorithm != ALGORITHM_XCHACHA20_POLY1305 {
        return Err(ApiError::DecryptFailed);
    }

    if row.secrets.current_version_id != row.id {
        return Err(ApiError::DecryptFailed);
    }

    if row.created_by_user_id != row.secrets.owner_user_id {
        return Err(ApiError::DecryptFailed);
    }

    Ok(())
}

fn decode_secret_version_bytes(
    row: &SecretVersionReadRow,
) -> Result<DecodedSecretVersionBytes, ApiError> {
    Ok(DecodedSecretVersionBytes {
        encrypted_data_key: decode_bytea(&row.encrypted_data_key)?,
        nonce_or_iv: decode_bytea(&row.nonce_or_iv)?,
        ciphertext: decode_bytea(&row.ciphertext)?,
    })
}

fn parse_secret_version(value: i32) -> Result<SecretVersion, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|parsed| SecretVersion::new(parsed).ok())
        .ok_or(ApiError::DecryptFailed)
}

fn parse_key_version(value: i32) -> Result<KeyVersion, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|parsed| KeyVersion::new(parsed).ok())
        .ok_or(ApiError::DecryptFailed)
}

pub(super) fn decode_bytea(value: &str) -> Result<Vec<u8>, ApiError> {
    let hex_value = value.strip_prefix("\\x").ok_or(ApiError::DecryptFailed)?;
    hex::decode(hex_value).map_err(|_| ApiError::DecryptFailed)
}
