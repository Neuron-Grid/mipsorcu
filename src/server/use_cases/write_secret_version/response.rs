use crate::{SecretId, SecretVersion, SecretVersionId};

#[derive(Debug)]
pub(in crate::server) struct WriteSecretVersionOutput {
    secret_id: SecretId,
    version: SecretVersion,
    secret_version_id: SecretVersionId,
}

impl WriteSecretVersionOutput {
    pub(super) fn new(
        secret_id: SecretId,
        version: SecretVersion,
        secret_version_id: SecretVersionId,
    ) -> Self {
        Self {
            secret_id,
            version,
            secret_version_id,
        }
    }

    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    pub fn secret_version_id(&self) -> &SecretVersionId {
        &self.secret_version_id
    }
}
