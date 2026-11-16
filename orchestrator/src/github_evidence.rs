//! Builds domain facts only from policy-bound, fresh GitHub API results.

use crate::{
    domain::{ObservedFacts, State, TaskRecord, TrustedPolicy},
    engine::EvidenceSource,
    github::{
        GitHubAdapter, GitHubError, IssueExpectation, PullExpectation, PullStatus, VerifiedIssue,
        VerifiedPullRequest,
    },
    policy::PolicyBundle,
    workspace::{observe_worktree, observe_worktree_head},
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub struct GitHubEvidenceSource {
    adapter: GitHubAdapter,
    trusted_policy: TrustedPolicy,
    validation_check: String,
    repository_root: PathBuf,
    workspace_root: PathBuf,
}

impl GitHubEvidenceSource {
    pub fn new(
        bundle: &PolicyBundle,
        token: &str,
        repository_root: &Path,
        workspace_root: &Path,
    ) -> Result<Self, GitHubError> {
        let adapter = GitHubAdapter::new(bundle.github_policy().clone(), token)?;
        let repository_root =
            fs::canonicalize(repository_root).map_err(|_| GitHubError::InvalidConfiguration)?;
        let workspace_root =
            fs::canonicalize(workspace_root).map_err(|_| GitHubError::InvalidConfiguration)?;
        if !repository_root.is_dir()
            || !workspace_root.is_dir()
            || repository_root.starts_with(&workspace_root)
            || workspace_root.starts_with(&repository_root)
        {
            return Err(GitHubError::InvalidConfiguration);
        }
        Ok(Self {
            adapter,
            trusted_policy: bundle.task_policy().clone(),
            validation_check: bundle.validation_check().to_owned(),
            repository_root,
            workspace_root,
        })
    }

    async fn observe_local_head(&self, task: &TaskRecord) -> Result<Option<String>, ()> {
        let task_uuid = Uuid::parse_str(&task.task_id).map_err(|_| ())?;
        if task_uuid.to_string() != task.task_id {
            return Err(());
        }
        let repository_root = self.repository_root.clone();
        let path = self.workspace_root.join(task_uuid.to_string());
        let expected_head = task.head_sha.clone();
        tokio::task::spawn_blocking(move || {
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return if expected_head.is_none() {
                        Ok(None)
                    } else {
                        Err(())
                    };
                }
                Err(_) => return Err(()),
                Ok(metadata) if metadata.file_type().is_symlink() => return Err(()),
                Ok(_) => {}
            }
            match fs::canonicalize(&path) {
                Ok(canonical) if canonical == path => {}
                _ => return Err(()),
            }
            match expected_head.as_deref() {
                Some(expected) => observe_worktree(&repository_root, &path, expected)
                    .map(Some)
                    .map_err(|_| ()),
                None => observe_worktree_head(&repository_root, &path)
                    .map(Some)
                    .map_err(|_| ()),
            }
        })
        .await
        .map_err(|_| ())?
    }
}

impl EvidenceSource for GitHubEvidenceSource {
    async fn observe(
        &self,
        task: &TaskRecord,
        policy: &TrustedPolicy,
    ) -> Result<ObservedFacts, ()> {
        if !same_policy(policy, &self.trusted_policy) {
            return Err(());
        }
        let local_head = self.observe_local_head(task).await?;
        if !local_head_matches_task(
            local_head.as_deref(),
            task.head_sha.as_deref(),
            &policy.base_sha,
        ) {
            return Err(());
        }

        let pull_number = task.pull_request;
        let Some(pull_number) = pull_number else {
            if task.state == State::Completed {
                return Err(());
            }
            let issue = self
                .adapter
                .verify_issue(
                    task.issue_number,
                    IssueExpectation::Open,
                    Some(&policy.base_sha),
                )
                .await
                .map_err(|_| ())?;
            return facts_from_issue(task, policy, &issue, local_head.as_deref());
        };

        let head_sha = task.head_sha.as_deref().ok_or(())?;
        if local_head.as_deref() != Some(head_sha) {
            return Err(());
        }
        if task.assignee.as_deref() != Some(policy.allowed_assignee.as_str()) {
            return Err(());
        }
        let (issue_expectation, pull_expectation) =
            self.expected_states(task, pull_number, head_sha).await?;
        let verified = self
            .adapter
            .verify_task(
                task.issue_number,
                pull_number,
                &task.base_sha,
                head_sha,
                issue_expectation,
                pull_expectation,
            )
            .await
            .map_err(|_| ())?;
        let issue = self
            .adapter
            .verify_issue(
                task.issue_number,
                issue_expectation,
                (pull_expectation == PullExpectation::Open).then_some(policy.base_sha.as_str()),
            )
            .await
            .map_err(|_| ())?;
        facts_from_pull(task, policy, &issue, &verified, &self.validation_check)
    }
}

impl GitHubEvidenceSource {
    async fn expected_states(
        &self,
        task: &TaskRecord,
        pull_number: u64,
        head_sha: &str,
    ) -> Result<(IssueExpectation, PullExpectation), ()> {
        for &(issue, pull) in expected_state_candidates(task.state) {
            match self
                .adapter
                .verify_task(
                    task.issue_number,
                    pull_number,
                    &task.base_sha,
                    head_sha,
                    issue,
                    pull,
                )
                .await
            {
                Ok(_) => return Ok((issue, pull)),
                Err(GitHubError::IssueStateMismatch | GitHubError::PullStateMismatch) => {}
                Err(_) => return Err(()),
            }
        }
        Err(())
    }
}

fn expected_state_candidates(state: State) -> &'static [(IssueExpectation, PullExpectation)] {
    use IssueExpectation::{Closed, Open};
    use PullExpectation::{Merged, Open as PullOpen};
    match state {
        State::Completed => &[(Open, Merged), (Closed, Merged)],
        State::Merging => &[(Open, PullOpen), (Open, Merged), (Closed, Merged)],
        _ => &[(Open, PullOpen)],
    }
}

fn local_head_matches_task(
    local_head: Option<&str>,
    task_head: Option<&str>,
    policy_base_sha: &str,
) -> bool {
    match task_head {
        Some(expected) => local_head == Some(expected),
        None => local_head.is_none() || local_head == Some(policy_base_sha),
    }
}

fn facts_from_issue(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    issue: &VerifiedIssue,
    observed_head: Option<&str>,
) -> Result<ObservedFacts, ()> {
    if issue.issue_number != task.issue_number
        || issue.issue_state != "open"
        || issue.base_branch != policy.base_ref
        || issue.base_sha != policy.base_sha
        || task.base_sha != policy.base_sha
    {
        return Err(());
    }
    Ok(ObservedFacts {
        policy_base_ref: policy.base_ref.clone(),
        policy_base_sha: policy.base_sha.clone(),
        issue_open: true,
        base_sha: issue.base_sha.clone(),
        head_sha: observed_head.unwrap_or_default().to_owned(),
        validated_head_sha: None,
        pr_number: None,
        pr_head_sha: None,
        pr_base_ref: None,
        pr_base_sha: None,
        pr_merged: false,
        checks_passed: vec![],
        reviewer_approved: false,
        approved_assignee: policy.allowed_assignee.clone(),
        merge_commit_sha: None,
        base_contains_merge_commit: false,
    })
}

fn facts_from_pull(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    issue: &VerifiedIssue,
    pull: &VerifiedPullRequest,
    validation_check: &str,
) -> Result<ObservedFacts, ()> {
    if issue.issue_number != task.issue_number
        || pull.issue_number != task.issue_number
        || task.pull_request != Some(pull.pull_number)
        || issue.issue_state != pull.issue_state
        || issue.base_branch != policy.base_ref
        || pull.base_branch != policy.base_ref
        || pull.head_sha != task.head_sha.as_deref().ok_or(())?
        || !policy
            .required_checks
            .iter()
            .all(|required| pull.successful_checks.contains(required))
        || !pull
            .successful_checks
            .iter()
            .any(|check| check == validation_check)
        || task.assignee.as_deref() != Some(policy.allowed_assignee.as_str())
    {
        return Err(());
    }
    if matches!(task.state, State::Merging | State::Completed) {
        pull.require_approvals().map_err(|_| ())?;
    }
    let merged = pull.pull_state == PullStatus::Merged;
    Ok(ObservedFacts {
        policy_base_ref: policy.base_ref.clone(),
        policy_base_sha: policy.base_sha.clone(),
        issue_open: issue.issue_state == "open",
        base_sha: issue.base_sha.clone(),
        head_sha: pull.head_sha.clone(),
        validated_head_sha: Some(pull.head_sha.clone()),
        pr_number: Some(pull.pull_number),
        pr_head_sha: Some(pull.head_sha.clone()),
        pr_base_ref: Some(pull.base_branch.clone()),
        pr_base_sha: Some(pull.base_sha.clone()),
        pr_merged: merged,
        checks_passed: pull.successful_checks.clone(),
        reviewer_approved: pull.approvals_satisfied,
        approved_assignee: policy.allowed_assignee.clone(),
        merge_commit_sha: pull.merge_commit_sha.clone(),
        base_contains_merge_commit: pull.base_contains_merge_commit,
    })
}

fn same_policy(left: &TrustedPolicy, right: &TrustedPolicy) -> bool {
    left.base_ref == right.base_ref
        && left.base_sha == right.base_sha
        && left.allowed_assignee == right.allowed_assignee
        && left.required_checks == right.required_checks
        && left.max_attempts == right.max_attempts
        && left.max_runtime == right.max_runtime
        && left.max_model_tokens == right.max_model_tokens
}

#[cfg(test)]
mod tests {
    use super::{
        expected_state_candidates, facts_from_issue, facts_from_pull, local_head_matches_task,
    };
    use crate::{
        domain::{State, TaskRecord, TrustedPolicy},
        github::{PullStatus, VerifiedIssue, VerifiedPullRequest},
    };
    use std::time::Duration;

    fn policy() -> TrustedPolicy {
        TrustedPolicy {
            base_ref: "develop".into(),
            base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            allowed_assignee: "worker".into(),
            required_checks: vec!["ci".into()],
            max_attempts: 2,
            max_runtime: Duration::from_secs(60),
            max_model_tokens: 100,
        }
    }

    fn issue() -> VerifiedIssue {
        VerifiedIssue {
            issue_number: 7,
            issue_state: "open".into(),
            base_branch: "develop".into(),
            base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        }
    }

    fn task() -> TaskRecord {
        TaskRecord {
            task_id: "task".into(),
            issue_number: 7,
            base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            max_attempts: 3,
            head_sha: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()),
            state: State::Merging,
            attempts: 1,
            assignee: Some("worker".into()),
            implementer: None,
            reviewer: None,
            session_id: None,
            mock_github_journal: None,
            mock_runtime_fingerprint: None,
            validation_passed: true,
            pull_request: Some(9),
            checkpoint: None,
            elapsed: Duration::from_secs(1),
            model_tokens: 1,
            model_budget: 100,
        }
    }

    fn pull() -> VerifiedPullRequest {
        VerifiedPullRequest {
            issue_number: 7,
            pull_number: 9,
            issue_state: "open".into(),
            pull_state: PullStatus::Open,
            base_branch: "develop".into(),
            base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            merge_commit_sha: None,
            base_contains_merge_commit: false,
            successful_checks: vec!["ci".into()],
            approval_count: 1,
            approvals_satisfied: true,
        }
    }

    #[test]
    fn issue_only_facts_have_no_head_or_validation_claim() {
        let task = TaskRecord {
            head_sha: None,
            pull_request: None,
            state: State::Planning,
            assignee: None,
            validation_passed: false,
            ..task()
        };
        let task = TaskRecord {
            base_sha: policy().base_sha.clone(),
            ..task
        };
        let facts = facts_from_issue(&task, &policy(), &issue(), None).unwrap();
        assert!(facts.issue_open);
        assert_eq!(facts.base_sha, policy().base_sha);
        assert!(facts.head_sha.is_empty());
        assert!(facts.validated_head_sha.is_none());
        assert!(facts.pr_number.is_none());
        assert!(!facts.reviewer_approved);
    }

    #[test]
    fn pull_facts_require_matching_issue_head_assignee_and_checks() {
        let facts = facts_from_pull(&task(), &policy(), &issue(), &pull(), "ci").unwrap();
        assert_eq!(
            facts.validated_head_sha.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        assert_eq!(facts.pr_number, Some(9));
        assert_eq!(facts.approved_assignee, "worker");

        let mut stale = pull();
        stale.issue_number = 8;
        assert!(facts_from_pull(&task(), &policy(), &issue(), &stale, "ci").is_err());
        assert!(facts_from_pull(&task(), &policy(), &issue(), &pull(), "integration").is_err());
    }

    #[test]
    fn approvals_are_required_only_at_merging_or_completion() {
        let mut pull = pull();
        pull.approval_count = 0;
        pull.approvals_satisfied = false;
        let reviewing = TaskRecord {
            state: State::Reviewing,
            ..task()
        };
        assert!(facts_from_pull(&reviewing, &policy(), &issue(), &pull, "ci").is_ok());
        assert!(facts_from_pull(&task(), &policy(), &issue(), &pull, "ci").is_err());
    }

    #[test]
    fn completed_accepts_open_or_closed_issue_only_with_merged_pull() {
        use crate::github::IssueExpectation::{Closed, Open};
        use crate::github::PullExpectation::Merged;

        assert_eq!(
            expected_state_candidates(State::Completed),
            &[(Open, Merged), (Closed, Merged)]
        );
    }

    #[test]
    fn initial_worktree_head_must_match_the_trusted_base() {
        let base = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(local_head_matches_task(None, None, base));
        assert!(local_head_matches_task(Some(base), None, base));
        assert!(!local_head_matches_task(Some(other), None, base));
        assert!(local_head_matches_task(Some(other), Some(other), base));
        assert!(!local_head_matches_task(Some(base), Some(other), base));
    }
}
