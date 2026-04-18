use std::fmt;

use serde_json::Value;

use crate::aad::AadV1;
use crate::crypto::{ALGORITHM_XCHACHA20_POLY1305, KeyWrapContext, encrypt_secret, wrap_data_key};
use crate::error::SecretWriteError;
use crate::types::{
    Ciphertext, Classification, CreatedAt, DataKey, DeviceId, EncryptedDataKey, KeyVersion,
    MasterKey, Nonce, OwnerUserId, Plaintext, SecretId, SecretVersion,
};

pub struct NewSecretVersionInput {
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_by_device_id: DeviceId,
    created_at: CreatedAt,
    key_version: KeyVersion,
    plaintext: Plaintext,
}

impl NewSecretVersionInput {
    pub fn new(
        owner_user_id: OwnerUserId,
        classification: Classification,
        created_by_device_id: DeviceId,
        created_at: CreatedAt,
        key_version: KeyVersion,
        plaintext: Plaintext,
    ) -> Self {
        Self {
            owner_user_id,
            classification,
            created_by_device_id,
            created_at,
            key_version,
            plaintext,
        }
    }
}

impl fmt::Debug for NewSecretVersionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewSecretVersionInput")
            .field("owner_user_id", &self.owner_user_id)
            .field("classification", &self.classification)
            .field("created_by_device_id", &self.created_by_device_id)
            .field("created_at", &self.created_at)
            .field("key_version", &self.key_version)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreparedSecretVersion {
    secret_id: SecretId,
    version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_by_device_id: DeviceId,
    created_at: CreatedAt,
    key_version: KeyVersion,
    ciphertext: Ciphertext,
    encrypted_data_key: EncryptedDataKey,
    nonce_or_iv: Nonce,
    aad_context: Value,
}

impl PreparedSecretVersion {
    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    pub fn owner_user_id(&self) -> &OwnerUserId {
        &self.owner_user_id
    }

    pub fn classification(&self) -> &Classification {
        &self.classification
    }

    pub fn created_by_device_id(&self) -> &DeviceId {
        &self.created_by_device_id
    }

    pub fn created_at(&self) -> &CreatedAt {
        &self.created_at
    }

    pub fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    pub fn algorithm(&self) -> &'static str {
        ALGORITHM_XCHACHA20_POLY1305
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    pub fn encrypted_data_key(&self) -> &EncryptedDataKey {
        &self.encrypted_data_key
    }

    pub fn nonce_or_iv(&self) -> &Nonce {
        &self.nonce_or_iv
    }

    pub fn aad_context(&self) -> &Value {
        &self.aad_context
    }
}

impl fmt::Debug for PreparedSecretVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSecretVersion")
            .field("secret_id", &self.secret_id)
            .field("version", &self.version)
            .field("owner_user_id", &self.owner_user_id)
            .field("classification", &self.classification)
            .field("created_by_device_id", &self.created_by_device_id)
            .field("created_at", &self.created_at)
            .field("key_version", &self.key_version)
            .field("algorithm", &self.algorithm())
            .field("ciphertext", &self.ciphertext)
            .field("encrypted_data_key", &self.encrypted_data_key)
            .field("nonce_or_iv", &self.nonce_or_iv)
            .field("aad_context", &"<redacted>")
            .finish()
    }
}

pub fn prepare_new_secret_version(
    master_key: &MasterKey,
    input: NewSecretVersionInput,
) -> Result<PreparedSecretVersion, SecretWriteError> {
    let secret_id = SecretId::generate()?;
    let version = SecretVersion::first();
    let data_key = DataKey::generate()?;
    let aad = AadV1::new(
        secret_id.clone(),
        version,
        input.owner_user_id.clone(),
        input.classification.clone(),
        input.created_at.clone(),
    );
    let encrypted_payload = encrypt_secret(&data_key, &aad, &input.plaintext)?;
    let key_wrap_context = KeyWrapContext::new(secret_id.clone(), input.key_version);
    let encrypted_data_key = wrap_data_key(master_key, &key_wrap_context, &data_key)?;
    let (ciphertext, nonce_or_iv, aad_context) = encrypted_payload.into_parts();

    Ok(PreparedSecretVersion {
        secret_id,
        version,
        owner_user_id: input.owner_user_id,
        classification: input.classification,
        created_by_device_id: input.created_by_device_id,
        created_at: input.created_at,
        key_version: input.key_version,
        ciphertext,
        encrypted_data_key,
        nonce_or_iv,
        aad_context,
    })
}
