use std::fmt;

use serde_json::Value;

use crate::MasterKeyRing;
use crate::aad::AadV1;
use crate::crypto::{
    ALGORITHM_XCHACHA20_POLY1305, KeyWrapContext, encrypt_secret, seal_v02, unwrap_data_key,
    wrap_data_key,
};
use crate::error::{CryptoError, SecretWriteError};
use crate::types::{
    Ciphertext, Classification, CreatedAt, DataKey, DeviceId, EncryptedDataKey, KekAlgorithm,
    KekVersion, KeyVersion, MasterKey, Nonce, OwnerUserId, Plaintext, SecretId, SecretVersion,
    SecretVersionId, WrappedDek,
};

use super::input::{
    CurrentSecretVersionStateParts, ExistingSecretVersionInput, NewSecretVersionInput,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretWriteAction {
    EncryptCreate,
    EncryptRotate,
}

impl SecretWriteAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptCreate => "encrypt_create",
            Self::EncryptRotate => "encrypt_rotate",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum PreparedSecretVersionKeyMaterial {
    LegacyV01 {
        encrypted_data_key: EncryptedDataKey,
        key_version: KeyVersion,
    },
    EnvelopeV02 {
        wrapped_dek: WrappedDek,
        dek_wrap_algorithm: KekAlgorithm,
        kek_version: KekVersion,
    },
}

impl PreparedSecretVersionKeyMaterial {
    pub fn key_version(&self) -> KeyVersion {
        match self {
            Self::LegacyV01 { key_version, .. } => *key_version,
            Self::EnvelopeV02 { kek_version, .. } => (*kek_version).into(),
        }
    }

    pub fn encrypted_data_key(&self) -> Option<&EncryptedDataKey> {
        match self {
            Self::LegacyV01 {
                encrypted_data_key, ..
            } => Some(encrypted_data_key),
            Self::EnvelopeV02 { .. } => None,
        }
    }

    pub fn wrapped_dek(&self) -> Option<&WrappedDek> {
        match self {
            Self::LegacyV01 { .. } => None,
            Self::EnvelopeV02 { wrapped_dek, .. } => Some(wrapped_dek),
        }
    }

    pub fn dek_wrap_algorithm(&self) -> Option<KekAlgorithm> {
        match self {
            Self::LegacyV01 { .. } => None,
            Self::EnvelopeV02 {
                dek_wrap_algorithm, ..
            } => Some(*dek_wrap_algorithm),
        }
    }

    pub fn kek_version(&self) -> Option<KekVersion> {
        match self {
            Self::LegacyV01 { .. } => None,
            Self::EnvelopeV02 { kek_version, .. } => Some(*kek_version),
        }
    }
}

impl fmt::Debug for PreparedSecretVersionKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyV01 {
                encrypted_data_key,
                key_version,
            } => formatter
                .debug_struct("LegacyV01")
                .field("encrypted_data_key", encrypted_data_key)
                .field("key_version", key_version)
                .finish(),
            Self::EnvelopeV02 {
                wrapped_dek,
                dek_wrap_algorithm,
                kek_version,
            } => formatter
                .debug_struct("EnvelopeV02")
                .field("wrapped_dek", wrapped_dek)
                .field("dek_wrap_algorithm", dek_wrap_algorithm)
                .field("kek_version", kek_version)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreparedSecretVersion {
    write_action: SecretWriteAction,
    secret_id: SecretId,
    secret_version_id: SecretVersionId,
    version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_by_device_id: DeviceId,
    created_at: CreatedAt,
    key_material: PreparedSecretVersionKeyMaterial,
    ciphertext: Ciphertext,
    nonce_or_iv: Nonce,
    aad_context: Value,
}

impl PreparedSecretVersion {
    pub fn write_action(&self) -> SecretWriteAction {
        self.write_action
    }

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
        self.key_material.key_version()
    }

    pub fn algorithm(&self) -> &'static str {
        ALGORITHM_XCHACHA20_POLY1305
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    pub fn key_material(&self) -> &PreparedSecretVersionKeyMaterial {
        &self.key_material
    }

    pub fn encrypted_data_key(&self) -> Option<&EncryptedDataKey> {
        self.key_material.encrypted_data_key()
    }

    pub fn wrapped_dek(&self) -> Option<&WrappedDek> {
        self.key_material.wrapped_dek()
    }

    pub fn dek_wrap_algorithm(&self) -> Option<KekAlgorithm> {
        self.key_material.dek_wrap_algorithm()
    }

    pub fn kek_version(&self) -> Option<KekVersion> {
        self.key_material.kek_version()
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
            .field("write_action", &self.write_action)
            .field("secret_id", &self.secret_id)
            .field("secret_version_id", &self.secret_version_id)
            .field("version", &self.version)
            .field("owner_user_id", &self.owner_user_id)
            .field("classification", &self.classification)
            .field("created_by_device_id", &self.created_by_device_id)
            .field("created_at", &self.created_at)
            .field("key_material", &self.key_material)
            .field("algorithm", &self.algorithm())
            .field("ciphertext", &self.ciphertext)
            .field("nonce_or_iv", &self.nonce_or_iv)
            .field("aad_context", &"<redacted>")
            .finish()
    }
}

pub fn prepare_new_secret_version(
    master_key: &MasterKey,
    input: NewSecretVersionInput,
) -> Result<PreparedSecretVersion, SecretWriteError> {
    let input = input.into_parts();
    prepare_new_secret_version_parts(master_key, input.key_version, input)
}

pub fn prepare_new_secret_version_with_keyring(
    master_key_ring: &MasterKeyRing,
    input: NewSecretVersionInput,
) -> Result<PreparedSecretVersion, SecretWriteError> {
    let input = input.into_parts();
    prepare_new_secret_version_v02_parts(master_key_ring, input)
}

fn prepare_new_secret_version_parts(
    master_key: &MasterKey,
    key_version: KeyVersion,
    input: super::input::NewSecretVersionInputParts,
) -> Result<PreparedSecretVersion, SecretWriteError> {
    let secret_id = SecretId::generate()?;
    let version = SecretVersion::first();
    let data_key = DataKey::generate()?;
    let key_wrap_context = KeyWrapContext::new(secret_id.clone(), key_version);
    let encrypted_data_key = wrap_data_key(master_key, &key_wrap_context, &data_key)?;

    prepare_secret_version_with_data_key(
        SecretWriteAction::EncryptCreate,
        SecretVersionMetadata {
            secret_id,
            version,
            owner_user_id: input.owner_user_id,
            classification: input.classification,
            created_by_device_id: input.created_by_device_id,
            created_at: input.created_at,
            key_version,
            encrypted_data_key,
        },
        &data_key,
        &input.plaintext,
    )
}

pub fn prepare_existing_secret_version(
    master_key: &MasterKey,
    input: ExistingSecretVersionInput,
) -> Result<PreparedSecretVersion, SecretWriteError> {
    let input = input.into_parts();
    let CurrentSecretVersionStateParts {
        secret_id,
        current_version,
        owner_user_id,
        classification,
        key_version,
        encrypted_data_key,
    } = input.current.into_parts();
    let version = current_version.next()?;
    let key_version = key_version.ok_or(SecretWriteError::Crypto(CryptoError::KeyUnwrapFailed))?;
    let encrypted_data_key =
        encrypted_data_key.ok_or(SecretWriteError::Crypto(CryptoError::KeyUnwrapFailed))?;
    let key_wrap_context = KeyWrapContext::new(secret_id.clone(), key_version);
    let data_key = unwrap_data_key(master_key, &key_wrap_context, &encrypted_data_key)?;

    prepare_secret_version_with_data_key(
        SecretWriteAction::EncryptRotate,
        SecretVersionMetadata {
            secret_id,
            version,
            owner_user_id,
            classification,
            created_by_device_id: input.created_by_device_id,
            created_at: input.created_at,
            key_version,
            encrypted_data_key,
        },
        &data_key,
        &input.plaintext,
    )
}

pub fn prepare_existing_secret_version_with_keyring(
    master_key_ring: &MasterKeyRing,
    input: ExistingSecretVersionInput,
) -> Result<PreparedSecretVersion, SecretWriteError> {
    let input = input.into_parts();
    let CurrentSecretVersionStateParts {
        secret_id,
        current_version,
        owner_user_id,
        classification,
        key_version: _,
        encrypted_data_key: _,
    } = input.current.into_parts();
    let version = current_version.next()?;
    prepare_secret_version_v02(
        master_key_ring,
        SecretWriteAction::EncryptRotate,
        SecretVersionV02Metadata {
            secret_id,
            version,
            owner_user_id,
            classification,
            created_by_device_id: input.created_by_device_id,
            created_at: input.created_at,
        },
        &input.plaintext,
    )
}

struct SecretVersionMetadata {
    secret_id: SecretId,
    version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_by_device_id: DeviceId,
    created_at: CreatedAt,
    key_version: KeyVersion,
    encrypted_data_key: EncryptedDataKey,
}

struct SecretVersionV02Metadata {
    secret_id: SecretId,
    version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_by_device_id: DeviceId,
    created_at: CreatedAt,
}

fn prepare_new_secret_version_v02_parts(
    master_key_ring: &MasterKeyRing,
    input: super::input::NewSecretVersionInputParts,
) -> Result<PreparedSecretVersion, SecretWriteError> {
    prepare_secret_version_v02(
        master_key_ring,
        SecretWriteAction::EncryptCreate,
        SecretVersionV02Metadata {
            secret_id: SecretId::generate()?,
            version: SecretVersion::first(),
            owner_user_id: input.owner_user_id,
            classification: input.classification,
            created_by_device_id: input.created_by_device_id,
            created_at: input.created_at,
        },
        &input.plaintext,
    )
}

fn prepare_secret_version_v02(
    master_key_ring: &MasterKeyRing,
    write_action: SecretWriteAction,
    metadata: SecretVersionV02Metadata,
    plaintext: &Plaintext,
) -> Result<PreparedSecretVersion, SecretWriteError> {
    let secret_version_id = SecretVersionId::generate()?;
    let aad = AadV1::from_row_metadata(
        metadata.secret_id.clone(),
        metadata.version,
        metadata.owner_user_id.clone(),
        metadata.classification.clone(),
        metadata.created_at.clone(),
    );
    let encrypted = seal_v02(master_key_ring.as_envvar_kek(), plaintext.as_bytes(), &aad)?;
    let (ciphertext, nonce_or_iv, wrapped_dek, dek_wrap_algorithm, kek_version, aad_context) =
        encrypted.into_parts();

    Ok(PreparedSecretVersion {
        write_action,
        secret_id: metadata.secret_id,
        secret_version_id,
        version: metadata.version,
        owner_user_id: metadata.owner_user_id,
        classification: metadata.classification,
        created_by_device_id: metadata.created_by_device_id,
        created_at: metadata.created_at,
        key_material: PreparedSecretVersionKeyMaterial::EnvelopeV02 {
            wrapped_dek,
            dek_wrap_algorithm,
            kek_version,
        },
        ciphertext,
        nonce_or_iv,
        aad_context,
    })
}

fn prepare_secret_version_with_data_key(
    write_action: SecretWriteAction,
    metadata: SecretVersionMetadata,
    data_key: &DataKey,
    plaintext: &Plaintext,
) -> Result<PreparedSecretVersion, SecretWriteError> {
    let secret_version_id = SecretVersionId::generate()?;
    let aad = AadV1::from_row_metadata(
        metadata.secret_id.clone(),
        metadata.version,
        metadata.owner_user_id.clone(),
        metadata.classification.clone(),
        metadata.created_at.clone(),
    );
    let encrypted_payload = encrypt_secret(data_key, &aad, plaintext)?;
    let (ciphertext, nonce_or_iv, aad_context) = encrypted_payload.into_parts();

    Ok(PreparedSecretVersion {
        write_action,
        secret_id: metadata.secret_id,
        secret_version_id,
        version: metadata.version,
        owner_user_id: metadata.owner_user_id,
        classification: metadata.classification,
        created_by_device_id: metadata.created_by_device_id,
        created_at: metadata.created_at,
        key_material: PreparedSecretVersionKeyMaterial::LegacyV01 {
            encrypted_data_key: metadata.encrypted_data_key,
            key_version: metadata.key_version,
        },
        ciphertext,
        nonce_or_iv,
        aad_context,
    })
}
