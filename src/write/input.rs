use std::fmt;

use crate::types::{
    Classification, CreatedAt, DeviceId, EncryptedDataKey, KeyVersion, OwnerUserId, Plaintext,
    SecretId, SecretVersion,
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

    pub(crate) fn into_parts(self) -> NewSecretVersionInputParts {
        NewSecretVersionInputParts {
            owner_user_id: self.owner_user_id,
            classification: self.classification,
            created_by_device_id: self.created_by_device_id,
            created_at: self.created_at,
            key_version: self.key_version,
            plaintext: self.plaintext,
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

pub(crate) struct NewSecretVersionInputParts {
    pub(crate) owner_user_id: OwnerUserId,
    pub(crate) classification: Classification,
    pub(crate) created_by_device_id: DeviceId,
    pub(crate) created_at: CreatedAt,
    pub(crate) key_version: KeyVersion,
    pub(crate) plaintext: Plaintext,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CurrentSecretVersionState {
    secret_id: SecretId,
    current_version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    key_version: Option<KeyVersion>,
    encrypted_data_key: Option<EncryptedDataKey>,
}

impl CurrentSecretVersionState {
    pub fn from_metadata(
        secret_id: SecretId,
        current_version: SecretVersion,
        owner_user_id: OwnerUserId,
        classification: Classification,
    ) -> Self {
        Self {
            secret_id,
            current_version,
            owner_user_id,
            classification,
            key_version: None,
            encrypted_data_key: None,
        }
    }

    pub fn new(
        secret_id: SecretId,
        current_version: SecretVersion,
        owner_user_id: OwnerUserId,
        classification: Classification,
        key_version: KeyVersion,
        encrypted_data_key: EncryptedDataKey,
    ) -> Self {
        Self {
            secret_id,
            current_version,
            owner_user_id,
            classification,
            key_version: Some(key_version),
            encrypted_data_key: Some(encrypted_data_key),
        }
    }

    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn current_version(&self) -> SecretVersion {
        self.current_version
    }

    pub fn owner_user_id(&self) -> &OwnerUserId {
        &self.owner_user_id
    }

    pub fn classification(&self) -> &Classification {
        &self.classification
    }

    pub fn key_version(&self) -> Option<KeyVersion> {
        self.key_version
    }

    pub fn encrypted_data_key(&self) -> Option<&EncryptedDataKey> {
        self.encrypted_data_key.as_ref()
    }

    pub(crate) fn into_parts(self) -> CurrentSecretVersionStateParts {
        CurrentSecretVersionStateParts {
            secret_id: self.secret_id,
            current_version: self.current_version,
            owner_user_id: self.owner_user_id,
            classification: self.classification,
            key_version: self.key_version,
            encrypted_data_key: self.encrypted_data_key,
        }
    }
}

impl fmt::Debug for CurrentSecretVersionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentSecretVersionState")
            .field("secret_id", &self.secret_id)
            .field("current_version", &self.current_version)
            .field("owner_user_id", &self.owner_user_id)
            .field("classification", &self.classification)
            .field("key_version", &self.key_version)
            .field("encrypted_data_key", &self.encrypted_data_key)
            .finish()
    }
}

pub(crate) struct CurrentSecretVersionStateParts {
    pub(crate) secret_id: SecretId,
    pub(crate) current_version: SecretVersion,
    pub(crate) owner_user_id: OwnerUserId,
    pub(crate) classification: Classification,
    pub(crate) key_version: Option<KeyVersion>,
    pub(crate) encrypted_data_key: Option<EncryptedDataKey>,
}

pub struct ExistingSecretVersionInput {
    current: CurrentSecretVersionState,
    created_by_device_id: DeviceId,
    created_at: CreatedAt,
    plaintext: Plaintext,
}

impl ExistingSecretVersionInput {
    pub fn new(
        current: CurrentSecretVersionState,
        created_by_device_id: DeviceId,
        created_at: CreatedAt,
        plaintext: Plaintext,
    ) -> Self {
        Self {
            current,
            created_by_device_id,
            created_at,
            plaintext,
        }
    }

    pub(crate) fn into_parts(self) -> ExistingSecretVersionInputParts {
        ExistingSecretVersionInputParts {
            current: self.current,
            created_by_device_id: self.created_by_device_id,
            created_at: self.created_at,
            plaintext: self.plaintext,
        }
    }
}

impl fmt::Debug for ExistingSecretVersionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExistingSecretVersionInput")
            .field("current", &self.current)
            .field("created_by_device_id", &self.created_by_device_id)
            .field("created_at", &self.created_at)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

pub(crate) struct ExistingSecretVersionInputParts {
    pub(crate) current: CurrentSecretVersionState,
    pub(crate) created_by_device_id: DeviceId,
    pub(crate) created_at: CreatedAt,
    pub(crate) plaintext: Plaintext,
}
