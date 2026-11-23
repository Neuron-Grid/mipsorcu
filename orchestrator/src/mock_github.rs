//! Deterministic, in-memory GitHub write simulation. This module never performs I/O.

use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};

use crate::agent::Provider;

const MAX_JOURNAL_ENTRIES: usize = 64;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockGitHubPolicy {
    allowed_targets: Vec<String>,
    required_checks: Vec<String>,
    implementer: Provider,
    reviewer: Provider,
}

impl MockGitHubPolicy {
    pub fn new(
        allowed_targets: Vec<String>,
        required_checks: Vec<String>,
    ) -> Result<Self, MockGitHubError> {
        if allowed_targets.is_empty()
            || allowed_targets
                .iter()
                .any(|branch| branch.trim().is_empty())
            || required_checks.is_empty()
            || required_checks.iter().any(|check| check.trim().is_empty())
        {
            return Err(MockGitHubError::InvalidPolicy);
        }
        Self::with_agents(
            allowed_targets,
            required_checks,
            Provider::Codex,
            Provider::Claude,
        )
    }

    pub fn with_agents(
        allowed_targets: Vec<String>,
        required_checks: Vec<String>,
        implementer: Provider,
        reviewer: Provider,
    ) -> Result<Self, MockGitHubError> {
        if allowed_targets.is_empty()
            || allowed_targets
                .iter()
                .any(|branch| branch.trim().is_empty())
            || required_checks.is_empty()
            || required_checks.iter().any(|check| check.trim().is_empty())
            || implementer == reviewer
        {
            return Err(MockGitHubError::InvalidPolicy);
        }
        Ok(Self {
            allowed_targets,
            required_checks,
            implementer,
            reviewer,
        })
    }

    fn permits_target(&self, target: &str) -> bool {
        target == "develop" && self.allowed_targets.iter().any(|allowed| allowed == target)
    }

    fn permits_work_branch(&self, branch: &str) -> bool {
        let branch = branch.strip_prefix("refs/heads/").unwrap_or(branch);
        branch != "main"
            && branch != "develop"
            && !self.allowed_targets.iter().any(|target| target == branch)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockPullRequest {
    pub number: u64,
    pub branch: String,
    pub target: String,
    pub title: String,
    pub head_sha: String,
    pub merged: bool,
    pub merge_sha: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum MockGitHubRequest {
    CreateBranch {
        branch: String,
        base_sha: String,
    },
    GetHead {
        branch: String,
    },
    CommitPush {
        branch: String,
        expected_head_sha: String,
        new_head_sha: String,
    },
    UpsertPullRequest {
        branch: String,
        target: String,
        title: String,
    },
    SetCheck {
        head_sha: String,
        name: String,
        passed: bool,
    },
    GetChecks {
        head_sha: String,
    },
    SetReview {
        head_sha: String,
        reviewer: Provider,
        approved: bool,
    },
    Merge {
        pull_number: u64,
        expected_head_sha: String,
        target: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum MockGitHubOutput {
    BranchCreated {
        branch: String,
        head_sha: String,
    },
    BranchHead {
        branch: String,
        head_sha: String,
    },
    Pushed {
        branch: String,
        head_sha: String,
    },
    PullRequest(MockPullRequest),
    CheckUpdated {
        head_sha: String,
        name: String,
        passed: bool,
    },
    CiResults {
        head_sha: String,
        checks: Vec<(String, bool)>,
    },
    ReviewUpdated {
        head_sha: String,
        approved: bool,
    },
    SimulatedMerge {
        pull_number: u64,
        merge_sha: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MockGitHubError {
    InvalidPolicy,
    InvalidRequest,
    IdempotencyConflict,
    BranchExists,
    BranchMissing,
    HeadMismatch,
    PullRequestMissing,
    TargetNotAllowed,
    MainMergeForbidden,
    CiNotSuccessful,
    ReviewNotApproved,
    AlreadyMerged,
}

#[derive(Clone, Debug)]
struct Branch {
    head_sha: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockGitHubJournalEntry {
    pub idempotency_key: String,
    pub request: MockGitHubRequest,
    pub result: Result<MockGitHubOutput, MockGitHubError>,
}

impl fmt::Debug for MockPullRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MockPullRequest([REDACTED])")
    }
}

impl fmt::Debug for MockGitHubRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MockGitHubRequest([REDACTED])")
    }
}

impl fmt::Debug for MockGitHubOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MockGitHubOutput([REDACTED])")
    }
}

impl fmt::Debug for MockGitHubJournalEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MockGitHubJournalEntry([REDACTED])")
    }
}

/// A stateful mock whose operations are replayed by idempotency key without repeating effects.
pub struct MockGitHubAdapter {
    policy: MockGitHubPolicy,
    branches: HashMap<String, Branch>,
    pulls: HashMap<u64, MockPullRequest>,
    checks: HashMap<String, HashMap<String, bool>>,
    reviews: HashMap<String, (Provider, bool)>,
    operations: HashMap<String, MockGitHubJournalEntry>,
    journal: Vec<MockGitHubJournalEntry>,
    next_pull: u64,
}

impl MockGitHubAdapter {
    pub fn new(policy: MockGitHubPolicy) -> Self {
        Self {
            policy,
            branches: HashMap::new(),
            pulls: HashMap::new(),
            checks: HashMap::new(),
            reviews: HashMap::new(),
            operations: HashMap::new(),
            journal: Vec::new(),
            next_pull: 1,
        }
    }

    /// Rebuild mock state by replaying the persisted operation journal.
    pub fn restore(
        policy: MockGitHubPolicy,
        journal: &[MockGitHubJournalEntry],
    ) -> Result<Self, MockGitHubError> {
        if journal.len() > MAX_JOURNAL_ENTRIES {
            return Err(MockGitHubError::InvalidRequest);
        }
        let mut adapter = Self::new(policy);
        for entry in journal {
            let prior_len = adapter.journal.len();
            if adapter.execute(&entry.idempotency_key, entry.request.clone()) != entry.result
                || adapter.journal.len() != prior_len + 1
            {
                return Err(MockGitHubError::InvalidRequest);
            }
        }
        Ok(adapter)
    }

    /// Replace state only after the persisted journal passes every replay check.
    pub fn restore_journal(
        &mut self,
        journal: &[MockGitHubJournalEntry],
    ) -> Result<(), MockGitHubError> {
        let restored = Self::restore(self.policy.clone(), journal)?;
        *self = restored;
        Ok(())
    }

    pub fn journal(&self) -> &[MockGitHubJournalEntry] {
        &self.journal
    }

    pub fn execute(
        &mut self,
        idempotency_key: &str,
        request: MockGitHubRequest,
    ) -> Result<MockGitHubOutput, MockGitHubError> {
        if idempotency_key.trim().is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(MockGitHubError::InvalidRequest);
        }
        if let Some(previous) = self.operations.get(idempotency_key) {
            return if previous.request == request {
                previous.result.clone()
            } else {
                Err(MockGitHubError::IdempotencyConflict)
            };
        }
        if self.journal.len() >= MAX_JOURNAL_ENTRIES {
            return Err(MockGitHubError::InvalidRequest);
        }
        let result = self.apply(&request);
        let entry = MockGitHubJournalEntry {
            idempotency_key: idempotency_key.to_owned(),
            request,
            result: result.clone(),
        };
        self.operations
            .insert(idempotency_key.to_owned(), entry.clone());
        self.journal.push(entry);
        result
    }

    pub fn pull_request(&self, number: u64) -> Option<&MockPullRequest> {
        self.pulls.get(&number)
    }

    pub fn checks_passed(&self, head_sha: &str) -> Vec<String> {
        self.policy
            .required_checks
            .iter()
            .filter(|name| {
                self.checks
                    .get(&head_sha.to_ascii_lowercase())
                    .and_then(|checks| checks.get(*name))
                    == Some(&true)
            })
            .cloned()
            .collect()
    }

    pub fn review_approved(&self, head_sha: &str) -> bool {
        self.reviews.get(&head_sha.to_ascii_lowercase()) == Some(&(self.policy.reviewer, true))
    }

    pub fn merge(
        &mut self,
        idempotency_key: &str,
        pull_number: u64,
        expected_head_sha: &str,
        target: &str,
    ) -> Result<MockGitHubOutput, MockGitHubError> {
        self.execute(
            idempotency_key,
            MockGitHubRequest::Merge {
                pull_number,
                expected_head_sha: expected_head_sha.to_owned(),
                target: target.to_owned(),
            },
        )
    }

    fn apply(&mut self, request: &MockGitHubRequest) -> Result<MockGitHubOutput, MockGitHubError> {
        match request {
            MockGitHubRequest::CreateBranch { branch, base_sha } => {
                if !valid_name(branch) || !valid_sha(base_sha) {
                    return Err(MockGitHubError::InvalidRequest);
                }
                if !self.policy.permits_work_branch(branch) {
                    return Err(MockGitHubError::TargetNotAllowed);
                }
                if self.branches.contains_key(branch) {
                    return Err(MockGitHubError::BranchExists);
                }
                self.branches.insert(
                    branch.clone(),
                    Branch {
                        head_sha: base_sha.to_ascii_lowercase(),
                    },
                );
                Ok(MockGitHubOutput::BranchCreated {
                    branch: branch.clone(),
                    head_sha: base_sha.to_ascii_lowercase(),
                })
            }
            MockGitHubRequest::GetHead { branch } => {
                let head_sha = self
                    .branches
                    .get(branch)
                    .ok_or(MockGitHubError::BranchMissing)?
                    .head_sha
                    .clone();
                Ok(MockGitHubOutput::BranchHead {
                    branch: branch.clone(),
                    head_sha,
                })
            }
            MockGitHubRequest::CommitPush {
                branch,
                expected_head_sha,
                new_head_sha,
            } => {
                if !valid_sha(expected_head_sha) || !valid_sha(new_head_sha) {
                    return Err(MockGitHubError::InvalidRequest);
                }
                if !self.policy.permits_work_branch(branch) {
                    return Err(MockGitHubError::TargetNotAllowed);
                }
                let branch_state = self
                    .branches
                    .get_mut(branch)
                    .ok_or(MockGitHubError::BranchMissing)?;
                if !branch_state
                    .head_sha
                    .eq_ignore_ascii_case(expected_head_sha)
                {
                    return Err(MockGitHubError::HeadMismatch);
                }
                branch_state.head_sha = new_head_sha.to_ascii_lowercase();
                for pull in self.pulls.values_mut() {
                    if pull.branch == *branch && !pull.merged {
                        pull.head_sha = new_head_sha.to_ascii_lowercase();
                    }
                }
                Ok(MockGitHubOutput::Pushed {
                    branch: branch.clone(),
                    head_sha: new_head_sha.to_ascii_lowercase(),
                })
            }
            MockGitHubRequest::UpsertPullRequest {
                branch,
                target,
                title,
            } => {
                if !self.policy.permits_target(target) {
                    return Err(MockGitHubError::TargetNotAllowed);
                }
                if !valid_name(branch) || title.trim().is_empty() {
                    return Err(MockGitHubError::InvalidRequest);
                }
                let head_sha = self
                    .branches
                    .get(branch)
                    .ok_or(MockGitHubError::BranchMissing)?
                    .head_sha
                    .clone();
                if let Some(existing) = self
                    .pulls
                    .values_mut()
                    .find(|pull| pull.branch == *branch && !pull.merged)
                {
                    existing.target = target.clone();
                    existing.title = title.clone();
                    existing.head_sha = head_sha;
                    return Ok(MockGitHubOutput::PullRequest(existing.clone()));
                }
                let number = self.next_pull;
                self.next_pull = self
                    .next_pull
                    .checked_add(1)
                    .ok_or(MockGitHubError::InvalidRequest)?;
                let pull = MockPullRequest {
                    number,
                    branch: branch.clone(),
                    target: target.clone(),
                    title: title.clone(),
                    head_sha,
                    merged: false,
                    merge_sha: None,
                };
                self.pulls.insert(number, pull.clone());
                Ok(MockGitHubOutput::PullRequest(pull))
            }
            MockGitHubRequest::SetCheck {
                head_sha,
                name,
                passed,
            } => {
                if !valid_sha(head_sha) || name.trim().is_empty() {
                    return Err(MockGitHubError::InvalidRequest);
                }
                self.checks
                    .entry(head_sha.to_ascii_lowercase())
                    .or_default()
                    .insert(name.clone(), *passed);
                Ok(MockGitHubOutput::CheckUpdated {
                    head_sha: head_sha.to_ascii_lowercase(),
                    name: name.clone(),
                    passed: *passed,
                })
            }
            MockGitHubRequest::GetChecks { head_sha } => {
                if !valid_sha(head_sha) {
                    return Err(MockGitHubError::InvalidRequest);
                }
                let checks = self
                    .policy
                    .required_checks
                    .iter()
                    .map(|name| {
                        let passed = self
                            .checks
                            .get(&head_sha.to_ascii_lowercase())
                            .and_then(|checks| checks.get(name))
                            == Some(&true);
                        (name.clone(), passed)
                    })
                    .collect();
                Ok(MockGitHubOutput::CiResults {
                    head_sha: head_sha.to_ascii_lowercase(),
                    checks,
                })
            }
            MockGitHubRequest::SetReview {
                head_sha,
                reviewer,
                approved,
            } => {
                if !valid_sha(head_sha)
                    || *reviewer != self.policy.reviewer
                    || *reviewer == self.policy.implementer
                {
                    return Err(MockGitHubError::ReviewNotApproved);
                }
                self.reviews
                    .insert(head_sha.to_ascii_lowercase(), (*reviewer, *approved));
                Ok(MockGitHubOutput::ReviewUpdated {
                    head_sha: head_sha.to_ascii_lowercase(),
                    approved: *approved,
                })
            }
            MockGitHubRequest::Merge {
                pull_number,
                expected_head_sha,
                target,
            } => {
                if target == "main" {
                    return Err(MockGitHubError::MainMergeForbidden);
                }
                if !self.policy.permits_target(target) {
                    return Err(MockGitHubError::TargetNotAllowed);
                }
                if !valid_sha(expected_head_sha) {
                    return Err(MockGitHubError::InvalidRequest);
                }
                let pull = self
                    .pulls
                    .get(pull_number)
                    .ok_or(MockGitHubError::PullRequestMissing)?;
                if pull.merged {
                    return Err(MockGitHubError::AlreadyMerged);
                }
                if pull.target != *target {
                    return Err(MockGitHubError::TargetNotAllowed);
                }
                if !pull.head_sha.eq_ignore_ascii_case(expected_head_sha) {
                    return Err(MockGitHubError::HeadMismatch);
                }
                if self
                    .branches
                    .get(&pull.branch)
                    .is_none_or(|branch| !branch.head_sha.eq_ignore_ascii_case(expected_head_sha))
                {
                    return Err(MockGitHubError::HeadMismatch);
                }
                if !self.policy.required_checks.iter().all(|name| {
                    self.checks
                        .get(&pull.head_sha.to_ascii_lowercase())
                        .and_then(|checks| checks.get(name))
                        == Some(&true)
                }) {
                    return Err(MockGitHubError::CiNotSuccessful);
                }
                if self.reviews.get(&pull.head_sha.to_ascii_lowercase())
                    != Some(&(self.policy.reviewer, true))
                {
                    return Err(MockGitHubError::ReviewNotApproved);
                }
                let merge_sha = deterministic_merge_sha(*pull_number, expected_head_sha);
                let pull = self
                    .pulls
                    .get_mut(pull_number)
                    .ok_or(MockGitHubError::PullRequestMissing)?;
                pull.merged = true;
                pull.merge_sha = Some(merge_sha.clone());
                Ok(MockGitHubOutput::SimulatedMerge {
                    pull_number: *pull_number,
                    merge_sha,
                })
            }
        }
    }
}

fn valid_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn valid_name(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.contains("..")
        && !value.contains("@{")
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || "~^:?*[\\".contains(ch))
}
fn deterministic_merge_sha(number: u64, head: &str) -> String {
    // Mock-only identifier; it is deterministic and carries no claim about a real Git object.
    let suffix = format!("{number:040x}");
    format!("{}{}", &head[..20], &suffix[20..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEAD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEXT: &str = "cccccccccccccccccccccccccccccccccccccccc";

    fn adapter() -> MockGitHubAdapter {
        MockGitHubAdapter::new(
            MockGitHubPolicy::new(vec!["develop".into()], vec!["unit".into()]).unwrap(),
        )
    }

    #[test]
    fn journal_round_trips_and_rejects_unknown_fields_at_every_level() {
        let journal = vec![MockGitHubJournalEntry {
            idempotency_key: "head".into(),
            request: MockGitHubRequest::GetHead {
                branch: "work-1".into(),
            },
            result: Ok(MockGitHubOutput::BranchHead {
                branch: "work-1".into(),
                head_sha: HEAD.into(),
            }),
        }];
        let serialized = serde_json::to_value(&journal).unwrap();
        assert_eq!(
            serde_json::from_value::<Vec<MockGitHubJournalEntry>>(serialized.clone()).unwrap(),
            journal
        );
        assert!(crate::postgres::valid_mock_journal(&serialized));

        let mut legacy_pull = serde_json::to_value(vec![MockGitHubJournalEntry {
            idempotency_key: "pull".into(),
            request: MockGitHubRequest::UpsertPullRequest {
                branch: "work-1".into(),
                target: "develop".into(),
                title: "task".into(),
            },
            result: Ok(MockGitHubOutput::PullRequest(MockPullRequest {
                number: 1,
                branch: "work-1".into(),
                target: "develop".into(),
                title: "task".into(),
                head_sha: HEAD.into(),
                merged: false,
                merge_sha: None,
            })),
        }])
        .unwrap();
        legacy_pull[0]["result"]["Ok"]
            .as_object_mut()
            .unwrap()
            .remove("merge_sha");
        assert!(
            crate::postgres::valid_mock_journal(&legacy_pull),
            "a previously optional pull request field may remain absent"
        );

        let mut unknown_entry = serialized.clone();
        unknown_entry[0]["unexpected"] = serde_json::json!("opaque");
        assert!(!crate::postgres::valid_mock_journal(&unknown_entry));

        let mut unknown_request = serialized.clone();
        unknown_request[0]["request"]["unexpected"] = serde_json::json!("opaque");
        assert!(!crate::postgres::valid_mock_journal(&unknown_request));

        let mut unknown_output = serialized;
        unknown_output[0]["result"]["Ok"]["unexpected"] = serde_json::json!("opaque");
        assert!(!crate::postgres::valid_mock_journal(&unknown_output));

        legacy_pull[0]["result"]["Ok"]["unexpected"] = serde_json::json!("opaque");
        assert!(!crate::postgres::valid_mock_journal(&legacy_pull));
    }

    fn ready_pull(adapter: &mut MockGitHubAdapter) -> u64 {
        adapter
            .execute(
                "branch",
                MockGitHubRequest::CreateBranch {
                    branch: "work-1".into(),
                    base_sha: BASE.into(),
                },
            )
            .unwrap();
        adapter
            .execute(
                "push",
                MockGitHubRequest::CommitPush {
                    branch: "work-1".into(),
                    expected_head_sha: BASE.into(),
                    new_head_sha: HEAD.into(),
                },
            )
            .unwrap();
        assert_eq!(
            adapter.execute(
                "head",
                MockGitHubRequest::GetHead {
                    branch: "work-1".into()
                }
            ),
            Ok(MockGitHubOutput::BranchHead {
                branch: "work-1".into(),
                head_sha: HEAD.into()
            })
        );
        let MockGitHubOutput::PullRequest(pull) = adapter
            .execute(
                "pr",
                MockGitHubRequest::UpsertPullRequest {
                    branch: "work-1".into(),
                    target: "develop".into(),
                    title: "task".into(),
                },
            )
            .unwrap()
        else {
            unreachable!()
        };
        adapter
            .execute(
                "ci",
                MockGitHubRequest::SetCheck {
                    head_sha: HEAD.into(),
                    name: "unit".into(),
                    passed: true,
                },
            )
            .unwrap();
        assert_eq!(
            adapter.execute(
                "checks",
                MockGitHubRequest::GetChecks {
                    head_sha: HEAD.into()
                }
            ),
            Ok(MockGitHubOutput::CiResults {
                head_sha: HEAD.into(),
                checks: vec![("unit".into(), true)]
            })
        );
        adapter
            .execute(
                "review",
                MockGitHubRequest::SetReview {
                    head_sha: HEAD.into(),
                    reviewer: Provider::Claude,
                    approved: true,
                },
            )
            .unwrap();
        pull.number
    }

    #[test]
    fn merge_requires_ci_review_matching_head_and_allowed_target() {
        let mut mock = adapter();
        let pr = ready_pull(&mut mock);
        assert_eq!(
            mock.execute(
                "merge",
                MockGitHubRequest::Merge {
                    pull_number: pr,
                    expected_head_sha: HEAD.into(),
                    target: "develop".into()
                }
            ),
            Ok(MockGitHubOutput::SimulatedMerge {
                pull_number: pr,
                merge_sha: deterministic_merge_sha(pr, HEAD)
            })
        );
        assert_eq!(mock.pull_request(pr).map(|pull| pull.merged), Some(true));
    }

    #[test]
    fn rejects_main_failed_ci_and_stale_head() {
        let mut mock = adapter();
        mock.execute(
            "b",
            MockGitHubRequest::CreateBranch {
                branch: "w".into(),
                base_sha: BASE.into(),
            },
        )
        .unwrap();
        mock.execute(
            "p",
            MockGitHubRequest::CommitPush {
                branch: "w".into(),
                expected_head_sha: BASE.into(),
                new_head_sha: HEAD.into(),
            },
        )
        .unwrap();
        let MockGitHubOutput::PullRequest(pr) = mock
            .execute(
                "pr",
                MockGitHubRequest::UpsertPullRequest {
                    branch: "w".into(),
                    target: "develop".into(),
                    title: "x".into(),
                },
            )
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(
            mock.execute(
                "main",
                MockGitHubRequest::Merge {
                    pull_number: pr.number,
                    expected_head_sha: HEAD.into(),
                    target: "main".into()
                }
            ),
            Err(MockGitHubError::MainMergeForbidden)
        );
        mock.execute(
            "review",
            MockGitHubRequest::SetReview {
                head_sha: HEAD.into(),
                reviewer: Provider::Claude,
                approved: true,
            },
        )
        .unwrap();
        assert_eq!(
            mock.execute(
                "failed-ci",
                MockGitHubRequest::SetCheck {
                    head_sha: HEAD.into(),
                    name: "unit".into(),
                    passed: false
                }
            ),
            Ok(MockGitHubOutput::CheckUpdated {
                head_sha: HEAD.into(),
                name: "unit".into(),
                passed: false
            })
        );
        assert_eq!(
            mock.execute(
                "no-ci",
                MockGitHubRequest::Merge {
                    pull_number: pr.number,
                    expected_head_sha: HEAD.into(),
                    target: "develop".into()
                }
            ),
            Err(MockGitHubError::CiNotSuccessful)
        );
        mock.execute(
            "passed-ci",
            MockGitHubRequest::SetCheck {
                head_sha: HEAD.into(),
                name: "unit".into(),
                passed: true,
            },
        )
        .unwrap();
        assert_eq!(
            mock.execute(
                "stale",
                MockGitHubRequest::Merge {
                    pull_number: pr.number,
                    expected_head_sha: NEXT.into(),
                    target: "develop".into()
                }
            ),
            Err(MockGitHubError::HeadMismatch)
        );
    }

    #[test]
    fn rejects_direct_changes_to_protected_branches_and_other_targets() {
        let policy = MockGitHubPolicy::new(
            vec!["develop".into(), "release".into()],
            vec!["unit".into()],
        )
        .unwrap();
        let mut mock = MockGitHubAdapter::new(policy);
        for branch in [
            "main",
            "develop",
            "release",
            "refs/heads/main",
            "refs/heads/develop",
            "refs/heads/release",
        ] {
            assert_eq!(
                mock.execute(
                    &format!("create-{branch}"),
                    MockGitHubRequest::CreateBranch {
                        branch: branch.into(),
                        base_sha: BASE.into(),
                    },
                ),
                Err(MockGitHubError::TargetNotAllowed)
            );
            assert_eq!(
                mock.execute(
                    &format!("push-{branch}"),
                    MockGitHubRequest::CommitPush {
                        branch: branch.into(),
                        expected_head_sha: BASE.into(),
                        new_head_sha: HEAD.into(),
                    },
                ),
                Err(MockGitHubError::TargetNotAllowed)
            );
            assert_eq!(
                mock.execute(
                    &format!("read-{branch}"),
                    MockGitHubRequest::GetHead {
                        branch: branch.into(),
                    },
                ),
                Err(MockGitHubError::BranchMissing)
            );
        }
        assert_eq!(
            mock.execute(
                "release-pr",
                MockGitHubRequest::UpsertPullRequest {
                    branch: "work-1".into(),
                    target: "release".into(),
                    title: "test".into(),
                },
            ),
            Err(MockGitHubError::TargetNotAllowed)
        );
        let restored = MockGitHubAdapter::restore(mock.policy.clone(), mock.journal()).unwrap();
        assert_eq!(restored.journal(), mock.journal());
    }

    #[test]
    fn duplicate_key_replays_without_side_effects_and_rejects_conflicts() {
        let mut mock = adapter();
        let request = MockGitHubRequest::CreateBranch {
            branch: "w".into(),
            base_sha: BASE.into(),
        };
        let first = mock.execute("same", request.clone());
        assert_eq!(mock.execute("same", request), first);
        assert_eq!(
            mock.execute(
                "same",
                MockGitHubRequest::CreateBranch {
                    branch: "other".into(),
                    base_sha: BASE.into()
                }
            ),
            Err(MockGitHubError::IdempotencyConflict)
        );
    }

    #[test]
    fn journal_restore_replays_and_rejects_tampered_results_or_duplicate_keys() {
        let mut mock = adapter();
        let pr = ready_pull(&mut mock);
        mock.merge("merge", pr, HEAD, "develop").unwrap();
        let restored = MockGitHubAdapter::restore(mock.policy.clone(), mock.journal()).unwrap();
        assert_eq!(restored.pull_request(pr), mock.pull_request(pr));

        let mut corrupt = mock.journal().to_vec();
        if let Some(entry) = corrupt.last_mut() {
            entry.result = Err(MockGitHubError::CiNotSuccessful);
        }
        assert!(matches!(
            MockGitHubAdapter::restore(mock.policy.clone(), &corrupt),
            Err(MockGitHubError::InvalidRequest)
        ));
        let mut duplicated = mock.journal().to_vec();
        duplicated.push(duplicated[0].clone());
        assert!(matches!(
            MockGitHubAdapter::restore(mock.policy.clone(), &duplicated),
            Err(MockGitHubError::InvalidRequest)
        ));
    }

    #[test]
    fn review_must_come_from_configured_independent_provider_and_merge_checks_live_branch_head() {
        let mut mock = adapter();
        mock.execute(
            "b",
            MockGitHubRequest::CreateBranch {
                branch: "w".into(),
                base_sha: BASE.into(),
            },
        )
        .unwrap();
        mock.execute(
            "p",
            MockGitHubRequest::CommitPush {
                branch: "w".into(),
                expected_head_sha: BASE.into(),
                new_head_sha: HEAD.into(),
            },
        )
        .unwrap();
        let MockGitHubOutput::PullRequest(pr) = mock
            .execute(
                "pr",
                MockGitHubRequest::UpsertPullRequest {
                    branch: "w".into(),
                    target: "develop".into(),
                    title: "task".into(),
                },
            )
            .unwrap()
        else {
            unreachable!()
        };
        mock.execute(
            "ci",
            MockGitHubRequest::SetCheck {
                head_sha: HEAD.into(),
                name: "unit".into(),
                passed: true,
            },
        )
        .unwrap();
        assert_eq!(
            mock.execute(
                "bad-review",
                MockGitHubRequest::SetReview {
                    head_sha: HEAD.into(),
                    reviewer: Provider::Codex,
                    approved: true
                }
            ),
            Err(MockGitHubError::ReviewNotApproved)
        );
        mock.execute(
            "good-review",
            MockGitHubRequest::SetReview {
                head_sha: HEAD.into(),
                reviewer: Provider::Claude,
                approved: true,
            },
        )
        .unwrap();
        mock.execute(
            "advance",
            MockGitHubRequest::CommitPush {
                branch: "w".into(),
                expected_head_sha: HEAD.into(),
                new_head_sha: NEXT.into(),
            },
        )
        .unwrap();
        assert_eq!(mock.pull_request(pr.number).unwrap().head_sha, NEXT);
        assert!(mock.checks_passed(NEXT).is_empty());
        assert!(!mock.review_approved(NEXT));
        assert_eq!(
            mock.merge("merge-stale", pr.number, HEAD, "develop"),
            Err(MockGitHubError::HeadMismatch)
        );
    }
}
