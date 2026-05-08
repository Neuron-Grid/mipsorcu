use std::fmt;

use crate::SecretId;
use crate::types::{Classification, CreatedAt, DeviceId, Plaintext};

pub(in crate::server) struct CreateSecretCommand {
    pub(super) classification: Classification,
    pub(super) device_id: DeviceId,
    pub(super) plaintext: Plaintext,
    pub(super) created_at: CreatedAt,
}

impl CreateSecretCommand {
    pub(in crate::server) fn new(
        classification: Classification,
        device_id: DeviceId,
        plaintext: Plaintext,
        created_at: CreatedAt,
    ) -> Self {
        Self {
            classification,
            device_id,
            plaintext,
            created_at,
        }
    }
}

impl fmt::Debug for CreateSecretCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateSecretCommand")
            .field("classification", &self.classification)
            .field("device_id", &self.device_id)
            .field("plaintext", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

pub(in crate::server) struct RotateSecretCommand {
    pub(super) requested_secret_id: SecretId,
    pub(super) device_id: DeviceId,
    pub(super) plaintext: Plaintext,
    pub(super) created_at: CreatedAt,
}

impl RotateSecretCommand {
    pub(in crate::server) fn new(
        requested_secret_id: SecretId,
        device_id: DeviceId,
        plaintext: Plaintext,
        created_at: CreatedAt,
    ) -> Self {
        Self {
            requested_secret_id,
            device_id,
            plaintext,
            created_at,
        }
    }
}

impl fmt::Debug for RotateSecretCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotateSecretCommand")
            .field("requested_secret_id", &self.requested_secret_id)
            .field("device_id", &self.device_id)
            .field("plaintext", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}
