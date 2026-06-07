use super::*;

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn period(value: &str) -> MonthlyDigestPeriod {
    MonthlyDigestPeriod::parse(value).expect("valid period")
}

fn usage_message(result: Result<ParsedArchiveArgs, ArchiveCliError>) -> String {
    match result {
        Err(ArchiveCliError::Usage(message)) => message,
        other => panic!("expected Usage error, got {other:?}"),
    }
}

#[test]
fn parses_send_with_period_and_json() {
    let parsed = parse_archive_args(&args(&["send", "--month", "2025-01", "--format", "json"]))
        .expect("valid args");

    assert_eq!(
        parsed,
        ParsedArchiveArgs {
            command: ArchiveCommand::Send {
                period: period("2025-01")
            }
        }
    );
}

#[test]
fn parses_verify_with_period_and_json() {
    let parsed = parse_archive_args(&args(&["verify", "--month", "2025-01", "--format", "json"]))
        .expect("valid args");

    assert_eq!(
        parsed,
        ParsedArchiveArgs {
            command: ArchiveCommand::Verify {
                period: period("2025-01")
            }
        }
    );
}

#[test]
fn flag_order_is_independent() {
    let parsed = parse_archive_args(&args(&["--format", "json", "send", "--month", "2025-01"]))
        .expect("valid args");

    assert_eq!(
        parsed,
        ParsedArchiveArgs {
            command: ArchiveCommand::Send {
                period: period("2025-01")
            }
        }
    );
}

#[test]
fn empty_args_is_usage_error() {
    assert!(matches!(
        parse_archive_args(&args(&[])),
        Err(ArchiveCliError::Usage(_))
    ));
}

#[test]
fn duplicate_subcommand_is_usage_error() {
    assert!(matches!(
        parse_archive_args(&args(&[
            "send", "verify", "--month", "2025-01", "--format", "json"
        ])),
        Err(ArchiveCliError::Usage(_))
    ));
}

#[test]
fn month_without_value_is_usage_error() {
    assert!(matches!(
        parse_archive_args(&args(&["send", "--month"])),
        Err(ArchiveCliError::Usage(_))
    ));
}

#[test]
fn month_followed_by_flag_is_usage_error() {
    assert!(matches!(
        parse_archive_args(&args(&["send", "--month", "--format", "json"])),
        Err(ArchiveCliError::Usage(_))
    ));
}

#[test]
fn unknown_flag_is_usage_error() {
    assert!(matches!(
        parse_archive_args(&args(&["send", "--bogus", "--format", "json"])),
        Err(ArchiveCliError::Usage(_))
    ));
}

#[test]
fn missing_format_is_usage_error() {
    assert!(matches!(
        parse_archive_args(&args(&["send", "--month", "2025-01"])),
        Err(ArchiveCliError::Usage(_))
    ));
}

#[test]
fn non_json_format_is_usage_error() {
    assert!(matches!(
        parse_archive_args(&args(&["send", "--month", "2025-01", "--format", "yaml"])),
        Err(ArchiveCliError::Usage(_))
    ));
}

#[test]
fn send_without_month_is_usage_error() {
    assert!(matches!(
        parse_archive_args(&args(&["send", "--format", "json"])),
        Err(ArchiveCliError::Usage(_))
    ));
}

#[test]
fn invalid_month_reports_invalid_message() {
    let message = usage_message(parse_archive_args(&args(&[
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
    let message = usage_message(parse_archive_args(&args(&[
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
