use std::ffi::OsString;
use std::fs;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const PROFILE_ID: &str = "pg-prove-local-socket-v1";
pub const JOBS: usize = 1;
/// Wall-clock deadline enforced by the T2 harness supervisor.
///
/// `pg_prove` has no timeout option, so this value must not be translated into
/// a command-line argument.
pub const SUITE_TIMEOUT_SECONDS: u64 = 900;
pub const SUITE_TIMEOUT: Duration = Duration::from_secs(SUITE_TIMEOUT_SECONDS);
pub const LOCALHOST_TCP_HOST: &str = "127.0.0.1";
pub const SUPPORT_INCLUDE: &str = r"\ir _support/common.psql";
pub const SUPPORT_RELATIVE_PATH: &str = "_support/common.psql";

pub const TEST_FILES: [&str; 22] = [
    "append_audit_event.sql",
    "audit_metadata_allowlist.sql",
    "audit_ui_read_rpcs.sql",
    "auditor_public_boundary.sql",
    "digest_verification.sql",
    "envelope_encryption_columns_test.sql",
    "envelope_migration.sql",
    "forbidden_key_parity.sql",
    "incident_detection.sql",
    "integrity_check.sql",
    "key_rotation.sql",
    "ledger_phase1_sql.sql",
    "ledger_use_case_integration.sql",
    "scheduler_lock.sql",
    "secret_alias_rpcs.sql",
    "secret_aliases.sql",
    "secret_store.sql",
    "signature_key_lifecycle.sql",
    "write_secret_version.sql",
    "write_secret_version_aad_context.sql",
    "write_secret_version_retention.sql",
    "write_secret_version_validation.sql",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixSocketEndpoint {
    directory: PathBuf,
    port: NonZeroU16,
}

impl UnixSocketEndpoint {
    pub fn new(directory: impl Into<PathBuf>, port: NonZeroU16) -> Result<Self, String> {
        let directory = directory.into();
        if !directory.is_absolute() {
            return Err("unix socket directory must be an absolute path".to_owned());
        }
        if directory.as_os_str().is_empty() {
            return Err("unix socket directory must not be empty".to_owned());
        }

        Ok(Self { directory, port })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn port(&self) -> NonZeroU16 {
        self.port
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalhostTcpEndpoint {
    port: NonZeroU16,
}

impl LocalhostTcpEndpoint {
    pub const fn new(port: NonZeroU16) -> Self {
        Self { port }
    }

    pub const fn port(self) -> NonZeroU16 {
        self.port
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunEndpoint {
    UnixSocket(UnixSocketEndpoint),
    LocalhostTcp(LocalhostTcpEndpoint),
}

impl RunEndpoint {
    fn host_argument(&self) -> OsString {
        match self {
            Self::UnixSocket(endpoint) => endpoint.directory().as_os_str().to_owned(),
            Self::LocalhostTcp(_) => OsString::from(LOCALHOST_TCP_HOST),
        }
    }

    fn port(&self) -> NonZeroU16 {
        match self {
            Self::UnixSocket(endpoint) => endpoint.port(),
            Self::LocalhostTcp(endpoint) => endpoint.port(),
        }
    }
}

/// Selects the verified Unix-socket endpoint when the harness found one;
/// otherwise the type-safe fallback is always `127.0.0.1` TCP.
pub fn select_run_endpoint(
    unix_socket_if_available: Option<UnixSocketEndpoint>,
    localhost_fallback: LocalhostTcpEndpoint,
) -> RunEndpoint {
    match unix_socket_if_available {
        Some(endpoint) => RunEndpoint::UnixSocket(endpoint),
        None => RunEndpoint::LocalhostTcp(localhost_fallback),
    }
}

pub struct PgConnectionTarget {
    database: String,
    username: String,
}

impl PgConnectionTarget {
    pub fn new(database: impl Into<String>, username: impl Into<String>) -> Result<Self, String> {
        let database = database.into();
        let username = username.into();
        validate_connection_identifier("database", &database)?;
        validate_connection_identifier("username", &username)?;

        Ok(Self { database, username })
    }

    pub fn database(&self) -> &str {
        &self.database
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}

fn validate_connection_identifier(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > 63 {
        return Err(format!("{field} exceeds the PostgreSQL name length limit"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(format!(
            "{field} must be a simple name, not a connection string or URI"
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSuite {
    root: PathBuf,
    test_files: Vec<PathBuf>,
    support_file: PathBuf,
}

impl ValidatedSuite {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn test_files(&self) -> &[PathBuf] {
        &self.test_files
    }

    pub fn support_file(&self) -> &Path {
        &self.support_file
    }
}

pub fn validate_suite(test_root: &Path) -> Result<ValidatedSuite, String> {
    let metadata = fs::symlink_metadata(test_root)
        .map_err(|error| format!("pgTAP suite root is unavailable: {error}"))?;
    if !metadata.file_type().is_dir() {
        return Err("pgTAP suite root is not a direct regular directory".to_owned());
    }
    let canonical_root = fs::canonicalize(test_root)
        .map_err(|error| format!("pgTAP suite root cannot be canonicalized: {error}"))?;

    validate_profile_file_order()?;
    let actual_sql_files = direct_files_with_extension(test_root, "sql")?;
    let expected_sql_files = TEST_FILES
        .iter()
        .map(|file| (*file).to_owned())
        .collect::<Vec<_>>();
    if actual_sql_files != expected_sql_files {
        return Err("pgTAP suite SQL inventory differs from the frozen 22-file profile".to_owned());
    }

    let support_directory = test_root.join("_support");
    let support_metadata = fs::symlink_metadata(&support_directory)
        .map_err(|error| format!("pgTAP support directory is unavailable: {error}"))?;
    if !support_metadata.file_type().is_dir() {
        return Err("pgTAP support path is not a direct regular directory".to_owned());
    }
    ensure_canonical_child(
        &canonical_root,
        &support_directory,
        "pgTAP support directory",
    )?;
    let support_entries = direct_entry_names(&support_directory)?;
    if support_entries != ["common.psql"] {
        return Err("pgTAP support inventory must contain only common.psql".to_owned());
    }

    let support_file = test_root.join(SUPPORT_RELATIVE_PATH);
    let support_metadata = fs::symlink_metadata(&support_file)
        .map_err(|error| format!("pgTAP support file is unavailable: {error}"))?;
    if !support_metadata.file_type().is_file() {
        return Err("pgTAP support file is not a direct regular file".to_owned());
    }
    ensure_canonical_child(&canonical_root, &support_file, "pgTAP support file")?;

    let mut test_files = Vec::with_capacity(TEST_FILES.len());
    for file in TEST_FILES {
        let path = test_root.join(file);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("frozen pgTAP file {file} is unavailable: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "frozen pgTAP file {file} is not a direct regular file"
            ));
        }
        ensure_canonical_child(&canonical_root, &path, "frozen pgTAP file")?;
        let sql = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read frozen pgTAP file {file}: {error}"))?;
        let include_count = sql
            .lines()
            .filter(|line| line.trim() == SUPPORT_INCLUDE)
            .count();
        if include_count != 1 {
            return Err(format!(
                "frozen pgTAP file {file} must include _support/common.psql exactly once"
            ));
        }
        test_files.push(path);
    }

    if test_files.iter().any(|path| path == &support_file) {
        return Err("support file must not be a direct pg_prove input".to_owned());
    }

    Ok(ValidatedSuite {
        root: test_root.to_path_buf(),
        test_files,
        support_file,
    })
}

fn validate_profile_file_order() -> Result<(), String> {
    if TEST_FILES.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("frozen pgTAP file order must be strictly alphabetical".to_owned());
    }
    Ok(())
}

fn direct_files_with_extension(root: &Path, extension: &str) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    let entries = fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate pgTAP suite root: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read pgTAP suite entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect pgTAP suite entry: {error}"))?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some(extension) {
            if !file_type.is_file() {
                return Err(format!(
                    "pgTAP suite entry {} with .{extension} suffix must be a direct regular file",
                    entry.path().display()
                ));
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "pgTAP SQL filename is not UTF-8".to_owned())?;
            files.push(name);
        }
    }
    files.sort_unstable();
    Ok(files)
}

fn ensure_canonical_child(canonical_root: &Path, path: &Path, label: &str) -> Result<(), String> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        format!(
            "{label} {} cannot be canonicalized: {error}",
            path.display()
        )
    })?;
    if !canonical.starts_with(canonical_root) {
        return Err(format!(
            "{label} {} resolves outside the frozen suite root",
            path.display()
        ));
    }
    Ok(())
}

fn direct_entry_names(root: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let entries = fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate pgTAP support directory: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read pgTAP support entry: {error}"))?;
        names.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "pgTAP support filename is not UTF-8".to_owned())?,
        );
    }
    names.sort_unstable();
    Ok(names)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PgProveInvocation {
    program: &'static str,
    arguments: Vec<OsString>,
    suite_timeout: Duration,
}

impl PgProveInvocation {
    pub fn program(&self) -> &'static str {
        self.program
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub const fn suite_timeout(&self) -> Duration {
        self.suite_timeout
    }
}

pub fn build_invocation(
    suite: &ValidatedSuite,
    endpoint: &RunEndpoint,
    connection: &PgConnectionTarget,
) -> PgProveInvocation {
    let mut arguments = vec![
        OsString::from("--norc"),
        OsString::from("--jobs"),
        OsString::from(JOBS.to_string()),
        OsString::from("--verbose"),
        OsString::from("--parse"),
        OsString::from("--normalize"),
        OsString::from("--nocolor"),
        OsString::from("--set"),
        OsString::from("ON_ERROR_STOP=1"),
        OsString::from("--host"),
        endpoint.host_argument(),
        OsString::from("--port"),
        OsString::from(endpoint.port().get().to_string()),
        OsString::from("--dbname"),
        OsString::from(connection.database()),
        OsString::from("--username"),
        OsString::from(connection.username()),
    ];
    arguments.extend(
        suite
            .test_files()
            .iter()
            .map(|path| path.as_os_str().to_owned()),
    );

    PgProveInvocation {
        program: "pg_prove",
        arguments,
        suite_timeout: SUITE_TIMEOUT,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileResult {
    Pass,
    Fail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerFileResult {
    pub file: String,
    /// Number of numbered TAP assertions observed for this file.
    pub executed: usize,
    /// TAP-semantic passes: `ok` assertions and expected TODO failures.
    pub passed: usize,
    /// `not ok` assertions that are not covered by TODO.
    pub failed: usize,
    pub skipped: usize,
    pub todo: usize,
    pub result: FileResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PgProveRunResult {
    pub profile_id: &'static str,
    pub files: Vec<PerFileResult>,
    pub total_files: usize,
    pub total_tests: usize,
}

/// Adds evidence counters without allowing debug panics or release-mode wraparound.
pub(crate) fn checked_counter_add(
    current: usize,
    increment: usize,
    counter_name: &str,
) -> Result<usize, String> {
    current
        .checked_add(increment)
        .ok_or_else(|| format!("pg_prove {counter_name} overflow"))
}

#[derive(Default)]
struct FileAccumulator {
    file: String,
    plan: Option<usize>,
    executed: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    todo: usize,
    result: Option<FileResult>,
}

impl FileAccumulator {
    fn new(file: &str) -> Self {
        Self {
            file: file.to_owned(),
            ..Self::default()
        }
    }

    fn finish(self) -> Result<PerFileResult, String> {
        let plan = self
            .plan
            .ok_or_else(|| format!("{} is missing its TAP plan", self.file))?;
        if plan == 0 || self.executed == 0 {
            return Err(format!(
                "{} must execute at least one TAP assertion",
                self.file
            ));
        }
        if plan != self.executed {
            return Err(format!(
                "{} TAP plan does not match its executed count",
                self.file
            ));
        }
        let result = self
            .result
            .ok_or_else(|| format!("{} is missing its per-file result", self.file))?;

        Ok(PerFileResult {
            file: self.file,
            executed: self.executed,
            passed: self.passed,
            failed: self.failed,
            skipped: self.skipped,
            todo: self.todo,
            result,
        })
    }
}

pub fn parse_pg_prove_result(exit_code: i32, output: &str) -> Result<PgProveRunResult, String> {
    if exit_code != 0 {
        return Err("pg_prove exited with a non-zero status".to_owned());
    }
    if contains_case_insensitive(output, "BAIL OUT!") {
        return Err("pg_prove output contains a TAP bailout".to_owned());
    }
    if contains_case_insensitive(output, "PARSE ERROR") {
        return Err("pg_prove output contains a TAP parse error".to_owned());
    }

    let mut files = Vec::with_capacity(TEST_FILES.len());
    let mut current: Option<FileAccumulator> = None;
    let mut next_file_index = 0_usize;
    let mut summary: Option<(usize, usize)> = None;
    let mut success_banner_count = 0_usize;
    let mut overall_pass_count = 0_usize;

    for (line_index, line) in output.lines().enumerate() {
        let line_number = checked_counter_add(line_index, 1, "output line number")?;
        let trimmed = line.trim();
        if let Some((file, inline_result)) = parse_file_header(trimmed)? {
            if next_file_index >= TEST_FILES.len() || file != TEST_FILES[next_file_index] {
                return Err(format!(
                    "pg_prove file order or inventory mismatch at output line {}",
                    line_number
                ));
            }
            if let Some(previous) = current.take() {
                files.push(previous.finish()?);
            }
            let mut accumulator = FileAccumulator::new(file);
            accumulator.result = inline_result;
            current = Some(accumulator);
            next_file_index = checked_counter_add(next_file_index, 1, "file index")?;
            continue;
        }
        if looks_like_unknown_sql_header(trimmed) {
            return Err(format!(
                "pg_prove output contains an unknown SQL test at line {}",
                line_number
            ));
        }

        if trimmed == "All tests successful." {
            success_banner_count =
                checked_counter_add(success_banner_count, 1, "success banner count")?;
            continue;
        }
        if trimmed == "Result: PASS" {
            overall_pass_count = checked_counter_add(overall_pass_count, 1, "overall PASS count")?;
            continue;
        }
        if trimmed.starts_with("Result:") {
            return Err("pg_prove overall result is not PASS".to_owned());
        }
        if let Some(parsed_summary) = parse_summary(trimmed)? {
            if summary.replace(parsed_summary).is_some() {
                return Err("pg_prove output contains duplicate summary lines".to_owned());
            }
            continue;
        }

        let Some(active) = current.as_mut() else {
            continue;
        };
        if trimmed == "ok" {
            if active.result.replace(FileResult::Pass).is_some() {
                return Err(format!("{} has duplicate per-file results", active.file));
            }
            continue;
        }
        if trimmed == "not ok" {
            if active.result.replace(FileResult::Fail).is_some() {
                return Err(format!("{} has duplicate per-file results", active.file));
            }
            continue;
        }
        if let Some(plan) = parse_plan(trimmed)? {
            if active.plan.replace(plan).is_some() {
                return Err(format!("{} has duplicate TAP plans", active.file));
            }
            continue;
        }
        if let Some(assertion) = parse_assertion(trimmed)? {
            let expected_number =
                checked_counter_add(active.executed, 1, "executed assertion count")?;
            if assertion.number != expected_number {
                return Err(format!(
                    "{} has a non-sequential TAP assertion number",
                    active.file
                ));
            }
            active.executed = expected_number;
            active.passed = checked_counter_add(
                active.passed,
                usize::from(assertion.ok || assertion.todo),
                "passed assertion count",
            )?;
            active.skipped = checked_counter_add(
                active.skipped,
                usize::from(assertion.skipped),
                "skipped assertion count",
            )?;
            active.todo = checked_counter_add(
                active.todo,
                usize::from(assertion.todo),
                "TODO assertion count",
            )?;
            if !assertion.ok && !assertion.todo {
                active.failed = checked_counter_add(active.failed, 1, "failed assertion count")?;
            }
        }
    }

    if let Some(last) = current.take() {
        files.push(last.finish()?);
    }
    if next_file_index != TEST_FILES.len() || files.len() != TEST_FILES.len() {
        return Err("pg_prove output is missing one or more frozen test files".to_owned());
    }
    if success_banner_count != 1 || overall_pass_count != 1 {
        return Err("pg_prove output is missing its unique overall PASS result".to_owned());
    }

    let (total_files, total_tests) =
        summary.ok_or_else(|| "pg_prove output is missing its summary".to_owned())?;
    if total_files != TEST_FILES.len() {
        return Err("pg_prove summary file count differs from the frozen profile".to_owned());
    }
    let parsed_test_count = files.iter().try_fold(0_usize, |count, file| {
        checked_counter_add(count, file.executed, "parsed test total")
    })?;
    if total_tests != parsed_test_count {
        return Err("pg_prove summary test count differs from per-file results".to_owned());
    }
    if files
        .iter()
        .any(|file| file.result != FileResult::Pass || file.failed != 0)
    {
        return Err("one or more pgTAP files did not pass".to_owned());
    }

    Ok(PgProveRunResult {
        profile_id: PROFILE_ID,
        files,
        total_files,
        total_tests,
    })
}

fn contains_case_insensitive(value: &str, needle: &str) -> bool {
    value.to_ascii_uppercase().contains(needle)
}

fn parse_file_header(line: &str) -> Result<Option<(&'static str, Option<FileResult>)>, String> {
    for file in TEST_FILES {
        let Some(position) = line.rfind(file) else {
            continue;
        };
        let prefix = &line[..position];
        if !(prefix.is_empty() || prefix.ends_with('/') || prefix.ends_with('\\')) {
            continue;
        }
        let suffix = line[position + file.len()..].trim_start();
        if !suffix.starts_with("..") {
            continue;
        }
        let status = suffix.trim_start_matches('.').trim();
        let result = match status {
            "" => None,
            "ok" => Some(FileResult::Pass),
            "not ok" => Some(FileResult::Fail),
            _ => return Err(format!("{file} has an unrecognized per-file status")),
        };
        return Ok(Some((file, result)));
    }
    Ok(None)
}

fn looks_like_unknown_sql_header(line: &str) -> bool {
    line.find(".sql").is_some_and(|position| {
        line[position + ".sql".len()..]
            .trim_start()
            .starts_with("..")
    })
}

fn parse_summary(line: &str) -> Result<Option<(usize, usize)>, String> {
    let Some(rest) = line.strip_prefix("Files=") else {
        return Ok(None);
    };
    let mut fields = rest.split(',');
    let files = fields
        .next()
        .ok_or_else(|| "pg_prove summary lacks its file count".to_owned())?
        .trim()
        .parse::<usize>()
        .map_err(|_| "pg_prove summary has an invalid file count".to_owned())?;
    let tests_field = fields
        .next()
        .ok_or_else(|| "pg_prove summary lacks its test count".to_owned())?
        .trim();
    let tests = tests_field
        .strip_prefix("Tests=")
        .ok_or_else(|| "pg_prove summary has an invalid test field".to_owned())?
        .trim()
        .parse::<usize>()
        .map_err(|_| "pg_prove summary has an invalid test count".to_owned())?;
    Ok(Some((files, tests)))
}

fn parse_plan(line: &str) -> Result<Option<usize>, String> {
    let Some(rest) = line.strip_prefix("1..") else {
        return Ok(None);
    };
    let digit_count = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digit_count == 0 {
        return Err("TAP plan has no test count".to_owned());
    }
    let count = rest[..digit_count]
        .parse::<usize>()
        .map_err(|_| "TAP plan has an invalid test count".to_owned())?;
    let trailing = rest[digit_count..].trim();
    if !trailing.is_empty() && !trailing.starts_with('#') {
        return Err("TAP plan has invalid trailing content".to_owned());
    }
    Ok(Some(count))
}

struct ParsedAssertion {
    number: usize,
    ok: bool,
    skipped: bool,
    todo: bool,
}

fn parse_assertion(line: &str) -> Result<Option<ParsedAssertion>, String> {
    let (ok, rest) = if let Some(rest) = line.strip_prefix("not ok") {
        (false, rest)
    } else if let Some(rest) = line.strip_prefix("ok") {
        (true, rest)
    } else {
        return Ok(None);
    };
    if !rest.starts_with(char::is_whitespace) {
        return Ok(None);
    }
    let rest = rest.trim_start();
    let digit_count = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digit_count == 0 {
        return Err("TAP assertion is missing its sequence number".to_owned());
    }
    let number = rest[..digit_count]
        .parse::<usize>()
        .map_err(|_| "TAP assertion has an invalid sequence number".to_owned())?;
    let directive = rest[digit_count..]
        .rsplit_once('#')
        .map(|(_, value)| value.trim().to_ascii_uppercase());
    let skipped = directive
        .as_deref()
        .is_some_and(|value| value == "SKIP" || value.starts_with("SKIP "));
    let todo = directive
        .as_deref()
        .is_some_and(|value| value == "TODO" || value.starts_with("TODO "));
    if skipped && todo {
        return Err("TAP assertion has conflicting SKIP and TODO directives".to_owned());
    }
    if skipped && !ok {
        return Err("a skipped TAP assertion must have ok status".to_owned());
    }

    Ok(Some(ParsedAssertion {
        number,
        ok,
        skipped,
        todo,
    }))
}
