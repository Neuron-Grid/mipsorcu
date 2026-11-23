//! Strict, non-secret task policy loaded from an operator-controlled JSON file.

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{fs, io::Read, net::IpAddr, path::Path, time::Duration};

use serde::Deserialize;

use crate::{
    agent::AutonomyConfig,
    domain::TrustedPolicy,
    github::{GitHubError, GitHubPolicy, RequiredCheck, TrustedLogDestination},
};

const MAX_POLICY_BYTES: u64 = 64 * 1024;

#[derive(Clone)]
pub struct PolicyBundle {
    task: TrustedPolicy,
    github: GitHubPolicy,
    validation_check: String,
    log_destination: Option<TrustedLogDestination>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    Io,
    TooLarge,
    InvalidFormat,
    InvalidValue,
    InvalidGitHubPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    repository: String,
    base_branch: String,
    base_sha: String,
    head_repository: String,
    head_ref_prefix: String,
    pull_author: String,
    allowed_assignee: String,
    required_checks: Vec<CheckFile>,
    minimum_approvals: usize,
    validation_check: String,
    log_destination: Option<LogDestinationFile>,
    limits: LimitsFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogDestinationFile {
    hostname: String,
    addresses: Vec<IpAddr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckFile {
    name: String,
    app_id: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    max_attempts: u32,
    max_runtime_seconds: u64,
    max_model_tokens: u64,
}

impl PolicyBundle {
    /// Loads an operator-pinned base SHA. A base branch advance requires an explicit
    /// trusted-policy update and task replan; database values never supply this SHA.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let mut file = open_policy_file(path)?;
        if file.metadata().map_err(|_| PolicyError::Io)?.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::TooLarge);
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_POLICY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PolicyError::Io)?;
        if bytes.len() as u64 > MAX_POLICY_BYTES {
            return Err(PolicyError::TooLarge);
        }
        Self::parse(&bytes)
    }

    pub fn task_policy(&self) -> &TrustedPolicy {
        &self.task
    }

    pub fn github_policy(&self) -> &GitHubPolicy {
        &self.github
    }

    pub fn validation_check(&self) -> &str {
        &self.validation_check
    }

    /// Only use a bundle loaded from an operator-controlled path, not a task or database.
    pub fn log_destination(&self) -> Option<&TrustedLogDestination> {
        self.log_destination.as_ref()
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes.len() as u64 > MAX_POLICY_BYTES {
            return Err(PolicyError::TooLarge);
        }
        let file: PolicyFile =
            serde_json::from_slice(bytes).map_err(|_| PolicyError::InvalidFormat)?;
        if file.version != 1
            || file.base_branch != "develop"
            || !valid_sha(&file.base_sha)
            || file.allowed_assignee.trim().is_empty()
            || file.required_checks.is_empty()
            || file.validation_check.trim().is_empty()
            || file.limits.max_attempts
                != u32::from(AutonomyConfig::approved_mock_defaults().max_repair_attempts)
            || file.limits.max_runtime_seconds == 0
            || file.limits.max_runtime_seconds > i64::MAX as u64
            || file.limits.max_model_tokens == 0
            || file.limits.max_model_tokens > i64::MAX as u64
        {
            return Err(PolicyError::InvalidValue);
        }

        let mut checks = Vec::with_capacity(file.required_checks.len());
        for check in &file.required_checks {
            checks.push(
                RequiredCheck::new(check.name.clone(), check.app_id)
                    .map_err(|_| PolicyError::InvalidValue)?,
            );
        }
        for (index, check) in checks.iter().enumerate() {
            if checks[..index]
                .iter()
                .any(|previous| previous.name == check.name)
            {
                return Err(PolicyError::InvalidValue);
            }
        }
        if !checks
            .iter()
            .any(|check| check.name == file.validation_check)
        {
            return Err(PolicyError::InvalidValue);
        }

        let github = GitHubPolicy::new(
            file.repository,
            file.base_branch.clone(),
            file.head_repository,
            file.head_ref_prefix,
            file.pull_author,
            checks.clone(),
            file.minimum_approvals,
        )
        .map_err(map_github_error)?;
        let task = TrustedPolicy {
            base_ref: file.base_branch,
            base_sha: file.base_sha.to_ascii_lowercase(),
            allowed_assignee: file.allowed_assignee,
            required_checks: checks.into_iter().map(|check| check.name).collect(),
            max_attempts: file.limits.max_attempts,
            max_runtime: Duration::from_secs(file.limits.max_runtime_seconds),
            max_model_tokens: file.limits.max_model_tokens,
        };
        let log_destination = file
            .log_destination
            .map(|destination| {
                TrustedLogDestination::new(&destination.hostname, &destination.addresses)
                    .map_err(|_| PolicyError::InvalidValue)
            })
            .transpose()?;
        Ok(Self {
            task,
            github,
            validation_check: file.validation_check,
            log_destination,
        })
    }
}

fn open_policy_file(path: &Path) -> Result<fs::File, PolicyError> {
    let before = fs::symlink_metadata(path).map_err(|_| PolicyError::Io)?;
    if !before.file_type().is_file() {
        return Err(PolicyError::InvalidValue);
    }
    let file = fs::File::open(path).map_err(|_| PolicyError::Io)?;
    let opened = file.metadata().map_err(|_| PolicyError::Io)?;
    let after = fs::symlink_metadata(path).map_err(|_| PolicyError::Io)?;
    if !opened.is_file()
        || !after.file_type().is_file()
        || !same_file(&before, &opened)
        || !same_file(&opened, &after)
    {
        return Err(PolicyError::InvalidValue);
    }
    Ok(file)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    false
}

fn map_github_error(error: GitHubError) -> PolicyError {
    match error {
        GitHubError::InvalidPolicy => PolicyError::InvalidGitHubPolicy,
        _ => PolicyError::InvalidGitHubPolicy,
    }
}

fn valid_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{PolicyBundle, PolicyError};

    const VALID: &str = r#"{
        "version": 1,
        "repository": "org/repo",
        "base_branch": "develop",
        "base_sha": "0123456789012345678901234567890123456789",
        "head_repository": "org/repo",
        "head_ref_prefix": "orchestrator",
        "pull_author": "orchestrator-bot",
        "allowed_assignee": "codex-worker",
        "required_checks": [{"name":"ci", "app_id": 42}],
        "minimum_approvals": 1,
        "validation_check": "ci",
        "limits": {"max_attempts": 3, "max_runtime_seconds": 600, "max_model_tokens": 10000}
    }"#;

    #[test]
    fn parses_strict_policy_and_uses_pinned_base_sha() {
        let bundle = PolicyBundle::parse(VALID.as_bytes()).expect("valid fixture parses");
        let policy = bundle.task_policy();
        assert_eq!(policy.base_sha, "0123456789012345678901234567890123456789");
        assert_eq!(policy.base_ref, "develop");
        assert_eq!(policy.allowed_assignee, "codex-worker");
        assert_eq!(policy.required_checks, ["ci"]);
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.max_runtime.as_secs(), 600);
        assert_eq!(policy.max_model_tokens, 10_000);
        let _github_policy = bundle.github_policy();
        assert!(bundle.log_destination().is_none());
    }

    #[test]
    fn log_destination_is_optional_and_rejects_untrusted_addresses() {
        let with_destination = |value: &str| {
            VALID.replace(
                "\"version\": 1,",
                &format!("\"version\": 1, \"log_destination\": {value},"),
            )
        };
        let policy = with_destination(r#"{"hostname":"logs.example","addresses":["1.1.1.1"]}"#);
        assert!(
            PolicyBundle::parse(policy.as_bytes())
                .unwrap()
                .log_destination()
                .is_some()
        );
        for value in [
            r#"{"hostname":"logs.example","addresses":["127.0.0.1"]}"#,
            r#"{"hostname":"logs.example","addresses":[]}"#,
            r#"{"hostname":"logs.example","addresses":["1.1.1.1"],"extra":true}"#,
            r#"{"hostname":"logs.example","addresses":["not-an-ip"]}"#,
        ] {
            assert!(PolicyBundle::parse(with_destination(value).as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_unknown_fields_and_unsafe_or_empty_limits() {
        let unknown = VALID.replace("\"version\": 1,", "\"version\": 1, \"token\": \"secret\",");
        assert!(matches!(
            PolicyBundle::parse(unknown.as_bytes()),
            Err(PolicyError::InvalidFormat)
        ));
        let zero_limit = VALID.replace("\"max_attempts\": 3", "\"max_attempts\": 0");
        assert!(matches!(
            PolicyBundle::parse(zero_limit.as_bytes()),
            Err(PolicyError::InvalidValue)
        ));
        let invalid_sha = VALID.replace("0123456789012345678901234567890123456789", "deadbeef");
        assert!(matches!(
            PolicyBundle::parse(invalid_sha.as_bytes()),
            Err(PolicyError::InvalidValue)
        ));
        let duplicate_check = VALID.replace(
            "[{\"name\":\"ci\", \"app_id\": 42}]",
            "[{\"name\":\"ci\", \"app_id\": 42}, {\"name\":\"ci\", \"app_id\": 42}]",
        );
        assert!(matches!(
            PolicyBundle::parse(duplicate_check.as_bytes()),
            Err(PolicyError::InvalidValue)
        ));
    }

    #[test]
    fn rejects_other_base_branches_and_repair_limits() {
        for invalid in [
            VALID.replace("\"base_branch\": \"develop\"", "\"base_branch\": \"main\""),
            VALID.replace(
                "\"base_branch\": \"develop\"",
                "\"base_branch\": \"release\"",
            ),
            VALID.replace("\"max_attempts\": 3", "\"max_attempts\": 2"),
            VALID.replace("\"max_attempts\": 3", "\"max_attempts\": 4"),
        ] {
            assert!(matches!(
                PolicyBundle::parse(invalid.as_bytes()),
                Err(PolicyError::InvalidValue)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn loads_only_the_regular_file_opened_at_the_policy_path() {
        use std::{fs, os::unix::fs::symlink};

        let root = std::env::temp_dir().join(format!("mipsorcu-policy-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("temporary directory is created");
        let policy_path = root.join("policy.json");
        let link_path = root.join("policy-link.json");
        let configured = VALID.replace(
            "\"version\": 1,",
            "\"version\": 1, \"log_destination\": {\"hostname\":\"logs.example\",\"addresses\":[\"1.1.1.1\"]},",
        );
        fs::write(&policy_path, configured).expect("policy fixture is written");
        symlink(&policy_path, &link_path).expect("symlink fixture is created");

        assert!(
            PolicyBundle::load(&policy_path)
                .unwrap()
                .log_destination()
                .is_some()
        );
        assert_eq!(
            PolicyBundle::load(&link_path).err(),
            Some(PolicyError::InvalidValue)
        );

        fs::remove_dir_all(root).expect("temporary directory is removed");
    }

    #[test]
    fn rejects_invalid_repository_branches_approvals_and_check_identity() {
        for invalid in [
            VALID.replace("org/repo", "org/../repo"),
            VALID.replace("develop", "../main"),
            VALID.replace("\"minimum_approvals\": 1", "\"minimum_approvals\": 0"),
            VALID.replace("\"app_id\": 42", "\"app_id\": 0"),
        ] {
            assert!(matches!(
                PolicyBundle::parse(invalid.as_bytes()),
                Err(PolicyError::InvalidValue | PolicyError::InvalidGitHubPolicy)
            ));
        }
    }
}
