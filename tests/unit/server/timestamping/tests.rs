use super::*;

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn period(value: &str) -> MonthlyDigestPeriod {
    MonthlyDigestPeriod::parse(value).expect("valid period")
}

fn usage_message(result: Result<ParsedTimestampingArgs, TimestampingCliError>) -> String {
    match result {
        Err(TimestampingCliError::Usage(message)) => message,
        other => panic!("expected Usage error, got {other:?}"),
    }
}

#[test]
fn parses_send_with_period_and_json() {
    let parsed =
        parse_timestamping_args(&args(&["send", "--month", "2025-01", "--format", "json"]))
            .expect("valid args");

    assert_eq!(
        parsed,
        ParsedTimestampingArgs {
            command: TimestampingCommand::Send {
                period: period("2025-01")
            }
        }
    );
}

#[test]
fn parses_verify_with_period_and_json() {
    let parsed =
        parse_timestamping_args(&args(&["verify", "--month", "2025-01", "--format", "json"]))
            .expect("valid args");

    assert_eq!(
        parsed,
        ParsedTimestampingArgs {
            command: TimestampingCommand::Verify {
                period: period("2025-01")
            }
        }
    );
}

#[test]
fn flag_order_is_independent() {
    let parsed =
        parse_timestamping_args(&args(&["--format", "json", "send", "--month", "2025-01"]))
            .expect("valid args");

    assert_eq!(
        parsed,
        ParsedTimestampingArgs {
            command: TimestampingCommand::Send {
                period: period("2025-01")
            }
        }
    );
}

#[test]
fn empty_args_is_usage_error() {
    assert!(matches!(
        parse_timestamping_args(&args(&[])),
        Err(TimestampingCliError::Usage(_))
    ));
}

#[test]
fn duplicate_subcommand_is_usage_error() {
    assert!(matches!(
        parse_timestamping_args(&args(&[
            "send", "verify", "--month", "2025-01", "--format", "json"
        ])),
        Err(TimestampingCliError::Usage(_))
    ));
}

#[test]
fn month_without_value_is_usage_error() {
    assert!(matches!(
        parse_timestamping_args(&args(&["send", "--month"])),
        Err(TimestampingCliError::Usage(_))
    ));
}

#[test]
fn month_followed_by_flag_is_usage_error() {
    assert!(matches!(
        parse_timestamping_args(&args(&["send", "--month", "--format", "json"])),
        Err(TimestampingCliError::Usage(_))
    ));
}

#[test]
fn unknown_flag_is_usage_error() {
    assert!(matches!(
        parse_timestamping_args(&args(&["send", "--bogus", "--format", "json"])),
        Err(TimestampingCliError::Usage(_))
    ));
}

#[test]
fn missing_format_is_usage_error() {
    assert!(matches!(
        parse_timestamping_args(&args(&["send", "--month", "2025-01"])),
        Err(TimestampingCliError::Usage(_))
    ));
}

#[test]
fn non_json_format_is_usage_error() {
    assert!(matches!(
        parse_timestamping_args(&args(&["send", "--month", "2025-01", "--format", "yaml"])),
        Err(TimestampingCliError::Usage(_))
    ));
}

#[test]
fn send_without_month_is_usage_error() {
    assert!(matches!(
        parse_timestamping_args(&args(&["send", "--format", "json"])),
        Err(TimestampingCliError::Usage(_))
    ));
}

#[test]
fn invalid_month_reports_invalid_message() {
    let message = usage_message(parse_timestamping_args(&args(&[
        "send",
        "--month",
        "not-a-month",
        "--format",
        "json",
    ])));

    assert!(
        message.contains("invalid --month"),
        "expected invalid --month message, got: {message}"
    );
}

#[test]
fn format_check_precedes_month_parse() {
    let message = usage_message(parse_timestamping_args(&args(&[
        "send",
        "--month",
        "not-a-month",
        "--format",
        "yaml",
    ])));

    assert!(
        !message.contains("invalid --month"),
        "format error must take precedence over month parse, got: {message}"
    );
    assert_eq!(message, usage());
}
