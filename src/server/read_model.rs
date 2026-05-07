use crate::aad::AadV1;
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::crypto::ALGORITHM_XCHACHA20_POLY1305;
use crate::read::{DecryptCurrentSecretVersionInput, DecryptCurrentSecretVersionInputParts};
use crate::server::errors::ApiError;
use crate::server::state::AppState;
use crate::server::supabase::{RestoreTestSampleRow, SecretVersionReadRow, SupabaseRpcError};
use crate::types::{
    Ciphertext, Classification, CreatedAt, EncryptedDataKey, KeyVersion, Nonce, OwnerUserId,
    SecretId, SecretVersion, SecretVersionId,
};
use crate::write::CurrentSecretVersionState;

pub enum FetchCurrentSecretVersionError {
    Upstream(SupabaseRpcError),
    Api(ApiError),
}

impl From<FetchCurrentSecretVersionError> for ApiError {
    fn from(error: FetchCurrentSecretVersionError) -> Self {
        match error {
            FetchCurrentSecretVersionError::Upstream(error) => Self::from(error),
            FetchCurrentSecretVersionError::Api(error) => error,
        }
    }
}

pub struct PreparedDecryptRow {
    secret_id: SecretId,
    secret_version_id: SecretVersionId,
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

struct PreparedDecryptRowParts {
    secret_id: String,
    secret_version_id: String,
    version: i32,
    owner_user_id: String,
    classification: String,
    created_at: String,
    key_version: i32,
    encrypted_data_key: String,
    nonce_or_iv: String,
    ciphertext: String,
    aad_context: serde_json::Value,
}

struct ReadModelMessages {
    secret_id_invalid: &'static str,
    version_invalid: &'static str,
    owner_user_id_invalid: &'static str,
    classification_invalid: &'static str,
    created_at_invalid: &'static str,
    key_version_invalid: &'static str,
    encrypted_data_key_invalid: &'static str,
    nonce_or_iv_invalid: &'static str,
    ciphertext_invalid: &'static str,
}

impl PreparedDecryptRow {
    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn secret_version_id(&self) -> &SecretVersionId {
        &self.secret_version_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    pub fn owner_user_id(&self) -> &OwnerUserId {
        &self.owner_user_id
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

    pub fn into_decrypt_input(self, claims: VerifiedJwtClaims) -> DecryptCurrentSecretVersionInput {
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

pub async fn fetch_current_secret_version(
    state: &AppState,
    secret_id: &SecretId,
    raw_jwt: &RawJwt,
) -> Result<PreparedDecryptRow, FetchCurrentSecretVersionError> {
    let rows = state
        .supabase_client
        .fetch_current_secret_version_for_user(secret_id, raw_jwt)
        .await
        .map_err(FetchCurrentSecretVersionError::Upstream)?;

    select_single_current_secret_version_row(rows)
        .and_then(parse_decrypt_row)
        .map_err(FetchCurrentSecretVersionError::Api)
}

fn parse_decrypt_row(row: SecretVersionReadRow) -> Result<PreparedDecryptRow, ApiError> {
    validate_decrypt_row_invariants(&row)?;
    build_prepared_decrypt_row(
        PreparedDecryptRowParts {
            secret_id: row.secret_id,
            secret_version_id: row.id,
            version: row.version,
            owner_user_id: row.secrets.owner_user_id,
            classification: row.classification,
            created_at: row.created_at,
            key_version: row.key_version,
            encrypted_data_key: row.encrypted_data_key,
            nonce_or_iv: row.nonce_or_iv,
            ciphertext: row.ciphertext,
            aad_context: row.aad_context,
        },
        ReadModelMessages {
            secret_id_invalid: "secret_id is invalid",
            version_invalid: "version is invalid",
            owner_user_id_invalid: "owner_user_id is invalid",
            classification_invalid: "secret version classification is invalid",
            created_at_invalid: "created_at is invalid",
            key_version_invalid: "key_version is invalid",
            encrypted_data_key_invalid: "encrypted_data_key is invalid",
            nonce_or_iv_invalid: "nonce_or_iv is invalid",
            ciphertext_invalid: "ciphertext is invalid",
        },
    )
}

pub fn parse_restore_test_sample(
    row: RestoreTestSampleRow,
) -> Result<PreparedDecryptRow, ApiError> {
    let secret_id = SecretId::parse(&row.secret_id).map_err(|_| {
        ApiError::DbIntegrityViolation("restore test secret_id is invalid".to_owned())
    })?;
    let version = parse_secret_version(row.version, "restore test version is invalid")?;
    let classification = Classification::new(&row.classification).map_err(|_| {
        ApiError::DbIntegrityViolation("restore test classification is invalid".to_owned())
    })?;
    let created_at = CreatedAt::parse(&row.created_at).map_err(|_| {
        ApiError::DbIntegrityViolation("restore test created_at is invalid".to_owned())
    })?;
    let stored_aad = AadV1::from_stored_context(&row.aad_context).map_err(|_| {
        ApiError::DbIntegrityViolation("restore test aad_context is invalid".to_owned())
    })?;
    let owner_user_id = stored_aad.owner_user_id().clone();
    let row_aad = AadV1::from_row_metadata(
        secret_id.clone(),
        version,
        owner_user_id.clone(),
        classification.clone(),
        created_at.clone(),
    );
    let stored_bytes = stored_aad.canonical_bytes().map_err(|_| {
        ApiError::DbIntegrityViolation("restore test aad_context is invalid".to_owned())
    })?;
    let row_bytes = row_aad.canonical_bytes().map_err(|_| {
        ApiError::DbIntegrityViolation("restore test aad_context does not match row".to_owned())
    })?;

    if stored_bytes != row_bytes {
        return Err(ApiError::DbIntegrityViolation(
            "restore test aad_context does not match row".to_owned(),
        ));
    }

    build_prepared_decrypt_row(
        PreparedDecryptRowParts {
            secret_id: secret_id.as_canonical_string(),
            secret_version_id: row.id,
            version: row.version,
            owner_user_id: owner_user_id.as_canonical_string(),
            classification: row.classification,
            created_at: row.created_at,
            key_version: row.key_version,
            encrypted_data_key: row.encrypted_data_key,
            nonce_or_iv: row.nonce_or_iv,
            ciphertext: row.ciphertext,
            aad_context: row.aad_context,
        },
        ReadModelMessages {
            secret_id_invalid: "restore test secret_id is invalid",
            version_invalid: "restore test version is invalid",
            owner_user_id_invalid: "restore test owner_user_id is invalid",
            classification_invalid: "restore test classification is invalid",
            created_at_invalid: "restore test created_at is invalid",
            key_version_invalid: "restore test key_version is invalid",
            encrypted_data_key_invalid: "restore test encrypted_data_key is invalid",
            nonce_or_iv_invalid: "restore test nonce_or_iv is invalid",
            ciphertext_invalid: "restore test ciphertext is invalid",
        },
    )
}

fn select_single_current_secret_version_row(
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

fn decode_bytea(value: &str) -> Result<Vec<u8>, ApiError> {
    let hex_value = value.strip_prefix("\\x").ok_or(ApiError::DecryptFailed)?;
    hex::decode(hex_value).map_err(|_| ApiError::DecryptFailed)
}

fn build_prepared_decrypt_row(
    parts: PreparedDecryptRowParts,
    messages: ReadModelMessages,
) -> Result<PreparedDecryptRow, ApiError> {
    let encrypted_data_key = decode_bytea(&parts.encrypted_data_key).map_err(|_| {
        ApiError::DbIntegrityViolation(messages.encrypted_data_key_invalid.to_owned())
    })?;
    let nonce_or_iv = decode_bytea(&parts.nonce_or_iv)
        .map_err(|_| ApiError::DbIntegrityViolation(messages.nonce_or_iv_invalid.to_owned()))?;
    let ciphertext = decode_bytea(&parts.ciphertext)
        .map_err(|_| ApiError::DbIntegrityViolation(messages.ciphertext_invalid.to_owned()))?;

    Ok(PreparedDecryptRow {
        secret_id: SecretId::parse(&parts.secret_id)
            .map_err(|_| ApiError::DbIntegrityViolation(messages.secret_id_invalid.to_owned()))?,
        secret_version_id: SecretVersionId::parse(&parts.secret_version_id).map_err(|_| {
            ApiError::DbIntegrityViolation("secret version id is invalid".to_owned())
        })?,
        version: parse_secret_version(parts.version, messages.version_invalid)?,
        owner_user_id: OwnerUserId::parse(&parts.owner_user_id).map_err(|_| {
            ApiError::DbIntegrityViolation(messages.owner_user_id_invalid.to_owned())
        })?,
        classification: Classification::new(&parts.classification).map_err(|_| {
            ApiError::DbIntegrityViolation(messages.classification_invalid.to_owned())
        })?,
        created_at: CreatedAt::parse(&parts.created_at)
            .map_err(|_| ApiError::DbIntegrityViolation(messages.created_at_invalid.to_owned()))?,
        key_version: parse_key_version(parts.key_version, messages.key_version_invalid)?,
        encrypted_data_key: EncryptedDataKey::parse(&encrypted_data_key).map_err(|_| {
            ApiError::DbIntegrityViolation(messages.encrypted_data_key_invalid.to_owned())
        })?,
        nonce_or_iv: Nonce::parse(&nonce_or_iv)
            .map_err(|_| ApiError::DbIntegrityViolation(messages.nonce_or_iv_invalid.to_owned()))?,
        ciphertext: Ciphertext::new(ciphertext)
            .map_err(|_| ApiError::DbIntegrityViolation(messages.ciphertext_invalid.to_owned()))?,
        aad_context: parts.aad_context,
    })
}

fn validate_decrypt_row_invariants(row: &SecretVersionReadRow) -> Result<(), ApiError> {
    if row.algorithm != ALGORITHM_XCHACHA20_POLY1305 {
        return Err(ApiError::DbIntegrityViolation(
            "secret version algorithm is invalid".to_owned(),
        ));
    }

    if row.secrets.current_version_id != row.id {
        return Err(ApiError::DbIntegrityViolation(
            "current_version_id does not match the selected version row".to_owned(),
        ));
    }

    if row.created_by_user_id != row.secrets.owner_user_id {
        return Err(ApiError::DbIntegrityViolation(
            "created_by_user_id does not match owner_user_id".to_owned(),
        ));
    }

    if row.classification != row.secrets.classification {
        return Err(ApiError::DbIntegrityViolation(
            "secret version classification does not match secret classification".to_owned(),
        ));
    }

    Ok(())
}

fn parse_secret_version(
    value: i32,
    invalid_message: &'static str,
) -> Result<SecretVersion, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|parsed| SecretVersion::new(parsed).ok())
        .ok_or_else(|| ApiError::DbIntegrityViolation(invalid_message.to_owned()))
}

fn parse_key_version(value: i32, invalid_message: &'static str) -> Result<KeyVersion, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|parsed| KeyVersion::new(parsed).ok())
        .ok_or_else(|| ApiError::DbIntegrityViolation(invalid_message.to_owned()))
}

#[doc(hidden)]
pub(crate) mod testing {
    use crate::server::errors::ApiError;
    use crate::server::supabase::SecretVersionReadRow;

    use super::PreparedDecryptRow;

    pub fn parse_decrypt_row(row: SecretVersionReadRow) -> Result<PreparedDecryptRow, ApiError> {
        super::parse_decrypt_row(row)
    }

    pub fn select_single_current_secret_version_row(
        rows: Vec<SecretVersionReadRow>,
    ) -> Result<SecretVersionReadRow, ApiError> {
        super::select_single_current_secret_version_row(rows)
    }

    pub fn decode_bytea(value: &str) -> Result<Vec<u8>, ApiError> {
        super::decode_bytea(value)
    }
}
