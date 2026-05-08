use crate::server::errors::ApiError;
use crate::server::read_model;
use crate::server::state::AppState;
use crate::{
    ExistingSecretVersionInput, NewSecretVersionInput, OwnerUserId, PreparedSecretVersion,
    prepare_existing_secret_version_with_keyring, prepare_new_secret_version_with_keyring,
};

use super::command::{CreateSecretCommand, RotateSecretCommand};

pub(super) async fn prepare_new_secret_version_for_request(
    state: &AppState,
    owner_user_id: OwnerUserId,
    command: CreateSecretCommand,
) -> Result<PreparedSecretVersion, ApiError> {
    let master_key_ring = state.master_key_ring.clone();
    let key_version = master_key_ring.active_key_version();

    tokio::task::spawn_blocking(move || {
        prepare_new_secret_version_with_keyring(
            &master_key_ring,
            NewSecretVersionInput::new(
                owner_user_id,
                command.classification,
                command.device_id,
                command.created_at,
                key_version,
                command.plaintext,
            ),
        )
    })
    .await
    .map_err(|error| ApiError::InternalError(error.to_string()))?
    .map_err(ApiError::from)
}

pub(super) async fn prepare_existing_secret_version_for_request(
    state: &AppState,
    current: read_model::PreparedDecryptRow,
    command: RotateSecretCommand,
) -> Result<PreparedSecretVersion, ApiError> {
    let master_key_ring = state.master_key_ring.clone();
    let current_state = current.into_current_secret_version_state();

    tokio::task::spawn_blocking(move || {
        prepare_existing_secret_version_with_keyring(
            &master_key_ring,
            ExistingSecretVersionInput::new(
                current_state,
                command.device_id,
                command.created_at,
                command.plaintext,
            ),
        )
    })
    .await
    .map_err(|error| ApiError::InternalError(error.to_string()))?
    .map_err(ApiError::from)
}
