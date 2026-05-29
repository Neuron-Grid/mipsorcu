use super::{EntrypointCommand, parse_entrypoint_command};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn parse_entrypoint_defaults_to_server_without_args() {
    assert_eq!(parse_entrypoint_command(&[]), EntrypointCommand::Server);
}

#[test]
fn parse_entrypoint_accepts_explicit_server_without_extra_args() {
    let args = args(&["server"]);

    assert_eq!(parse_entrypoint_command(&args), EntrypointCommand::Server);
}

#[test]
fn parse_entrypoint_rejects_explicit_server_with_extra_args() {
    let args = args(&["server", "--unexpected"]);

    assert_eq!(parse_entrypoint_command(&args), EntrypointCommand::Usage);
}

#[test]
fn parse_entrypoint_preserves_cli_subcommand_args() {
    let args = args(&["signature-key", "public-key", "--format", "json"]);

    assert_eq!(
        parse_entrypoint_command(&args),
        EntrypointCommand::SignatureKey(&args[1..])
    );
}
