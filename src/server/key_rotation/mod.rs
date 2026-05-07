use std::sync::Arc;

use crate::server::config::AppConfig;
use crate::server::ledger_appender::LedgerAppender;
use crate::server::supabase::SupabaseClient;

mod audit_event;
mod bytea;
mod command;
mod error;
mod flags;
mod ledger;
mod rotation_row;

pub use error::KeyRotationCliError;

pub async fn run_cli(config: AppConfig, args: &[String]) -> Result<(), KeyRotationCliError> {
    let Some((command, command_args)) = args.split_first() else {
        return Err(KeyRotationCliError::Usage(usage()));
    };

    let http_client = crate::server::config::build_outbound_http_client(&config)
        .map_err(|error| KeyRotationCliError::Config(error.to_string()))?;
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    ));
    let ledger_appender = Arc::new(LedgerAppender::new(
        supabase_client.clone(),
        config.ledger_signing_key.clone(),
    ));

    match command.as_str() {
        "status" => command::status(supabase_client, command_args).await,
        "start" => {
            command::start_with_ledger(supabase_client, ledger_appender, &config, command_args)
                .await
        }
        "rewrap" => command::rewrap(supabase_client, ledger_appender, &config, command_args).await,
        "complete" => command::complete(supabase_client, ledger_appender, command_args).await,
        _ => Err(KeyRotationCliError::Usage(usage())),
    }
}

pub fn usage() -> String {
    [
        "usage:",
        "  mipsorcu",
        "  mipsorcu key-rotation status --key-version <n>",
        "  mipsorcu key-rotation start --old-key-version <old> --new-key-version <new>",
        "  mipsorcu key-rotation rewrap --old-key-version <old> --new-key-version <new> --batch-limit <n>",
        "  mipsorcu key-rotation complete --old-key-version <old> --new-key-version <new>",
    ]
    .join("\n")
}
