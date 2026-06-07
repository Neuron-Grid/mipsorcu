use super::*;

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn period(value: &str) -> MonthlyDigestPeriod {
    MonthlyDigestPeriod::parse(value).expect("valid period")
}

fn usage_message(result: Result<ParsedDigestArgs, DigestCliError>) -> String {
    match result {
        Err(DigestCliError::Usage(message)) => message,
        other => panic!("expected Usage error, got {other:?}"),
    }
}

#[test]
fn parses_generate_with_period_and_json() {
    let parsed = parse_digest_args(&args(&[
        "generate",
        "--year-month",
        "2025-01",
        "--format",
        "json",
    ]))
    .expect("valid args");

    assert_eq!(
        parsed,
        ParsedDigestArgs {
            command: DigestCommand::Generate {
                period: period("2025-01")
            }
        }
    );
}

#[test]
fn parses_verify_with_period_and_json() {
    let parsed = parse_digest_args(&args(&[
        "verify",
        "--year-month",
        "2025-01",
        "--format",
        "json",
    ]))
    .expect("valid args");

    assert_eq!(
        parsed,
        ParsedDigestArgs {
            command: DigestCommand::Verify {
                period: period("2025-01")
            }
        }
    );
}

#[test]
fn parses_list_with_json() {
    let parsed = parse_digest_args(&args(&["list", "--format", "json"])).expect("valid args");

    assert_eq!(
        parsed,
        ParsedDigestArgs {
            command: DigestCommand::List
        }
    );
}

#[test]
fn list_ignores_year_month() {
    let parsed = parse_digest_args(&args(&[
        "list",
        "--year-month",
        "2025-01",
        "--format",
        "json",
    ]))
    .expect("valid args");

    assert_eq!(
        parsed,
        ParsedDigestArgs {
            command: DigestCommand::List
        }
    );
}

#[test]
fn flag_order_is_independent() {
    let parsed = parse_digest_args(&args(&[
        "--format",
        "json",
        "generate",
        "--year-month",
        "2025-01",
    ]))
    .expect("valid args");

    assert_eq!(
        parsed,
        ParsedDigestArgs {
            command: DigestCommand::Generate {
                period: period("2025-01")
            }
        }
    );
}

#[test]
fn empty_args_is_usage_error() {
    assert!(matches!(
        parse_digest_args(&args(&[])),
        Err(DigestCliError::Usage(_))
    ));
}

#[test]
fn duplicate_subcommand_is_usage_error() {
    assert!(matches!(
        parse_digest_args(&args(&[
            "generate",
            "verify",
            "--year-month",
            "2025-01",
            "--format",
            "json",
        ])),
        Err(DigestCliError::Usage(_))
    ));
}

#[test]
fn year_month_without_value_is_usage_error() {
    assert!(matches!(
        parse_digest_args(&args(&["generate", "--year-month"])),
        Err(DigestCliError::Usage(_))
    ));
}

#[test]
fn year_month_followed_by_flag_is_usage_error() {
    assert!(matches!(
        parse_digest_args(&args(&["generate", "--year-month", "--format", "json"])),
        Err(DigestCliError::Usage(_))
    ));
}

#[test]
fn unknown_flag_is_usage_error() {
    assert!(matches!(
        parse_digest_args(&args(&["generate", "--bogus", "--format", "json"])),
        Err(DigestCliError::Usage(_))
    ));
}

#[test]
fn missing_format_is_usage_error() {
    assert!(matches!(
        parse_digest_args(&args(&["generate", "--year-month", "2025-01"])),
        Err(DigestCliError::Usage(_))
    ));
}

#[test]
fn non_json_format_is_usage_error() {
    assert!(matches!(
        parse_digest_args(&args(&[
            "generate",
            "--year-month",
            "2025-01",
            "--format",
            "yaml",
        ])),
        Err(DigestCliError::Usage(_))
    ));
}

#[test]
fn generate_without_year_month_is_usage_error() {
    assert!(matches!(
        parse_digest_args(&args(&["generate", "--format", "json"])),
        Err(DigestCliError::Usage(_))
    ));
}

#[test]
fn invalid_year_month_reports_invalid_message() {
    let message = usage_message(parse_digest_args(&args(&[
        "generate",
        "--year-month",
        "not-a-month",
        "--format",
        "json",
    ])));

    assert!(
        message.contains("invalid --year-month"),
        "expected invalid --year-month message, got: {message}"
    );
}

#[test]
fn format_check_precedes_year_month_parse() {
    // `--format` が不正なら、period パースに到達する前に弾く。
    // よって汎用 usage 文言となり、`invalid --year-month` を含まない。
    let message = usage_message(parse_digest_args(&args(&[
        "generate",
        "--year-month",
        "not-a-month",
        "--format",
        "yaml",
    ])));

    assert!(
        !message.contains("invalid --year-month"),
        "format error must take precedence over year-month parse, got: {message}"
    );
    assert_eq!(message, usage());
}
