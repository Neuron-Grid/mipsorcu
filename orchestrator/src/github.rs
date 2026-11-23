//! GitHub evidence verification and boundary-gated branch and PR creation.
//!
//! The repository and base branch come from trusted configuration supplied when the
//! adapter is built. Branch and PR creation require permits that production code
//! cannot construct until durable intent and live fencing can be independently proven.

use reqwest::{Client, Response, StatusCode, header};
use serde::{Deserialize, Deserializer, de::IgnoredAny};
use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

const API_ROOT: &str = "https://api.github.com";
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_ISSUE_TITLE_BYTES: usize = 1024;
const MAX_ISSUE_BODY_BYTES: usize = 60 * 1024;
const MAX_ACTION_NAME_BYTES: usize = 1024;
const MAX_ACTION_STEPS: usize = 512;
const MAX_JOB_LOG_BYTES: usize = 1024 * 1024;
const MAX_LOG_ADDRESSES: usize = 16;
const MAX_BRANCH_REF_BYTES: usize = 255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitHubPolicy {
    repository: String,
    base_branch: String,
    head_repository: String,
    head_ref_prefix: String,
    pull_author: String,
    required_checks: Vec<RequiredCheck>,
    minimum_approvals: usize,
}

impl GitHubPolicy {
    /// Construct policy from trusted configuration, never from task database fields.
    pub fn new(
        repository: impl Into<String>,
        base_branch: impl Into<String>,
        head_repository: impl Into<String>,
        head_ref_prefix: impl Into<String>,
        pull_author: impl Into<String>,
        required_checks: Vec<RequiredCheck>,
        minimum_approvals: usize,
    ) -> Result<Self, GitHubError> {
        let repository = repository.into();
        let base_branch = base_branch.into();
        let head_repository = head_repository.into();
        let head_ref_prefix = head_ref_prefix.into();
        let pull_author = pull_author.into();
        let mut parts = repository.split('/');
        let repository_is_valid = parts.next().is_some_and(valid_component)
            && parts.next().is_some_and(valid_component)
            && parts.next().is_none();
        if !repository_is_valid
            || base_branch != "develop"
            || !valid_repository(&head_repository)
            || !valid_branch_prefix(&head_ref_prefix)
            || !valid_component(&pull_author)
            || required_checks.is_empty()
            || minimum_approvals == 0
            || required_checks
                .iter()
                .any(|check| check.name.is_empty() || check.app_id == 0)
        {
            return Err(GitHubError::InvalidPolicy);
        }
        Ok(Self {
            repository,
            base_branch,
            head_repository,
            head_ref_prefix,
            pull_author,
            required_checks,
            minimum_approvals,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredCheck {
    pub name: String,
    pub app_id: u64,
}

/// One-shot input for branch creation. Production construction stays disabled until
/// durable unused-intent and live-fence proofs exist; fields are private by design.
pub struct BranchWritePermit {
    task_id: uuid::Uuid,
    operation_id: uuid::Uuid,
    issue_number: u64,
    fencing_token: u64,
    pinned_base_sha: String,
}

/// One-shot input for creating a task PR. Production construction remains disabled
/// until durable intent and live fencing can be independently proven.
pub struct PullRequestWritePermit {
    task_id: uuid::Uuid,
    operation_id: uuid::Uuid,
    issue_number: u64,
    fencing_token: u64,
    pinned_base_sha: String,
    trusted_head_sha: String,
}

/// Identity-only observation of a non-default-base PR. This value grants no
/// permission to link an issue, merge, or complete the task.
pub struct UnlinkedPullRequestCandidate {
    number: u64,
}

impl UnlinkedPullRequestCandidate {
    pub fn number(&self) -> u64 {
        self.number
    }
}

/// One-shot input for explicitly linking an observed PR to its intended issue.
/// Production construction remains disabled pending durable intent and fencing.
pub struct IssueLinkPermit {
    task_id: uuid::Uuid,
    operation_id: uuid::Uuid,
    link_operation_id: uuid::Uuid,
    issue_number: u64,
    pull_number: u64,
    fencing_token: u64,
    pinned_base_sha: String,
    trusted_head_sha: String,
}

/// One-shot transport input for closing an Issue after a verified merge.
/// Production construction remains disabled until durable intent and live fencing
/// can be independently proven by a trusted control plane.
pub struct CloseIssuePermit {
    task_id: uuid::Uuid,
    operation_id: uuid::Uuid,
    close_operation_id: uuid::Uuid,
    issue_number: u64,
    pull_number: u64,
    fencing_token: u64,
    pinned_base_sha: String,
    trusted_head_sha: String,
    merge_commit_sha: String,
}

#[cfg(test)]
impl BranchWritePermit {
    fn synthetic(
        task_id: uuid::Uuid,
        operation_id: uuid::Uuid,
        issue_number: u64,
        fencing_token: u64,
        pinned_base_sha: impl Into<String>,
    ) -> Self {
        Self {
            task_id,
            operation_id,
            issue_number,
            fencing_token,
            pinned_base_sha: pinned_base_sha.into(),
        }
    }
}

#[cfg(test)]
impl PullRequestWritePermit {
    fn synthetic(
        task_id: uuid::Uuid,
        operation_id: uuid::Uuid,
        issue_number: u64,
        fencing_token: u64,
        pinned_base_sha: impl Into<String>,
        trusted_head_sha: impl Into<String>,
    ) -> Self {
        Self {
            task_id,
            operation_id,
            issue_number,
            fencing_token,
            pinned_base_sha: pinned_base_sha.into(),
            trusted_head_sha: trusted_head_sha.into(),
        }
    }
}

#[cfg(test)]
impl IssueLinkPermit {
    fn synthetic(pull_number: u64) -> Self {
        Self {
            task_id: uuid::Uuid::from_u128(1),
            operation_id: uuid::Uuid::from_u128(2),
            link_operation_id: uuid::Uuid::from_u128(3),
            issue_number: 5,
            pull_number,
            fencing_token: 7,
            pinned_base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            trusted_head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        }
    }
}

#[cfg(test)]
impl CloseIssuePermit {
    fn synthetic() -> Self {
        Self {
            task_id: uuid::Uuid::from_u128(1),
            operation_id: uuid::Uuid::from_u128(2),
            close_operation_id: uuid::Uuid::from_u128(4),
            issue_number: 5,
            pull_number: 7,
            fencing_token: 8,
            pinned_base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            trusted_head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            merge_commit_sha: "dddddddddddddddddddddddddddddddddddddddd".to_owned(),
        }
    }
}

impl RequiredCheck {
    pub fn new(name: impl Into<String>, app_id: u64) -> Result<Self, GitHubError> {
        let name = name.into();
        if name.is_empty() || app_id == 0 {
            return Err(GitHubError::InvalidPolicy);
        }
        Ok(Self { name, app_id })
    }
}

#[derive(Clone)]
pub struct GitHubAdapter {
    client: Client,
    logs_api_client: Client,
    branch_write_client: Client,
    policy: GitHubPolicy,
    api_root: String,
}

impl GitHubAdapter {
    pub fn new(policy: GitHubPolicy, token: &str) -> Result<Self, GitHubError> {
        Self::build(policy, token, API_ROOT)
    }

    fn build(policy: GitHubPolicy, token: &str, api_root: &str) -> Result<Self, GitHubError> {
        if token.trim().is_empty()
            || !api_root.starts_with("http://") && !api_root.starts_with("https://")
        {
            return Err(GitHubError::InvalidConfiguration);
        }
        let mut headers = header::HeaderMap::new();
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| GitHubError::InvalidConfiguration)?;
        authorization.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, authorization);
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "x-github-api-version",
            header::HeaderValue::from_static("2022-11-28"),
        );
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("mipsorcu-orchestrator"),
        );
        let logs_api_client = Client::builder()
            .default_headers(headers.clone())
            .timeout(Duration::from_secs(10))
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| GitHubError::InvalidConfiguration)?;
        let branch_write_headers = headers.clone();
        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| GitHubError::InvalidConfiguration)?;
        let branch_write_client = Client::builder()
            .default_headers(branch_write_headers)
            .timeout(Duration::from_secs(10))
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| GitHubError::InvalidConfiguration)?;
        Ok(Self {
            client,
            logs_api_client,
            branch_write_client,
            policy,
            api_root: api_root.trim_end_matches('/').to_owned(),
        })
    }

    /// Create the one branch derived from a guarded task permit.
    ///
    /// A 201 response proves only that GitHub returned the expected ref and SHA. It
    /// does not prove a durable task transition or authorize any later operation.
    /// Every failure or cancellation after attempting the POST is ambiguous and must
    /// not be retried.
    /// Production cannot construct `BranchWritePermit` until an unused durable intent
    /// and a live task fence can be independently proven; this method is therefore
    /// intentionally unreachable from production call paths for now.
    pub async fn create_work_branch(
        &self,
        permit: BranchWritePermit,
    ) -> Result<String, GitHubError> {
        let branch = format!("orchestrator/{}", permit.task_id);
        if permit.task_id.is_nil()
            || permit.operation_id.is_nil()
            || permit.issue_number == 0
            || permit.fencing_token == 0
            || !valid_sha(&permit.pinned_base_sha)
            || self.policy.repository != self.policy.head_repository
            || !branch.starts_with(&format!("{}/", self.policy.head_ref_prefix))
            || !valid_branch(&branch)
            || branch.len() > MAX_BRANCH_REF_BYTES
            || matches!(branch.as_str(), "main" | "develop")
        {
            return Err(GitHubError::InvalidTaskReference);
        }

        let issue = self
            .read_open_issue(permit.issue_number, &permit.pinned_base_sha)
            .await?;
        if !issue.base_sha.eq_ignore_ascii_case(&permit.pinned_base_sha) {
            return Err(GitHubError::StaleRevision);
        }

        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let response = self
            .branch_write_client
            .post(format!("{root}/git/refs"))
            .json(&CreateRefRequest {
                reference: format!("refs/heads/{branch}"),
                sha: permit.pinned_base_sha.clone(),
            })
            .send()
            .await
            .map_err(|_| GitHubError::AmbiguousBranchWrite)?;
        if response.status() != StatusCode::CREATED {
            return Err(GitHubError::AmbiguousBranchWrite);
        }
        let created: CreateRefResponse = read_bounded_json(response)
            .await
            .map_err(|_| GitHubError::AmbiguousBranchWrite)?;
        if created.reference != format!("refs/heads/{branch}")
            || !created
                .object
                .sha
                .eq_ignore_ascii_case(&permit.pinned_base_sha)
            || created.object.kind != "commit"
        {
            return Err(GitHubError::AmbiguousBranchWrite);
        }
        Ok(branch)
    }

    /// Create one deterministic PR after verifying the task's pinned issue and head.
    /// Any failure after the single POST is ambiguous and must not be replayed.
    /// Production cannot construct `PullRequestWritePermit` until durable unused-intent
    /// and live-fence proofs exist; the remote checks do not eliminate GitHub races.
    pub async fn create_pull_request(
        &self,
        permit: PullRequestWritePermit,
    ) -> Result<u64, GitHubError> {
        let branch = format!("orchestrator/{}", permit.task_id);
        if permit.task_id.is_nil()
            || permit.operation_id.is_nil()
            || permit.issue_number == 0
            || permit.fencing_token == 0
            || !valid_sha(&permit.pinned_base_sha)
            || !valid_sha(&permit.trusted_head_sha)
            || self.policy.repository != self.policy.head_repository
            || !branch.starts_with(&format!("{}/", self.policy.head_ref_prefix))
            || !valid_branch(&branch)
            || branch.len() > MAX_BRANCH_REF_BYTES
            || matches!(branch.as_str(), "main" | "develop")
        {
            return Err(GitHubError::InvalidTaskReference);
        }

        let issue = self
            .read_open_issue(permit.issue_number, &permit.pinned_base_sha)
            .await?;
        if !issue.base_sha.eq_ignore_ascii_case(&permit.pinned_base_sha) {
            return Err(GitHubError::StaleRevision);
        }

        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let branch_ref: CreateRefResponse = self
            .get_json(&format!("{root}/git/ref/heads/{branch}"))
            .await?;
        if branch_ref.reference != format!("refs/heads/{branch}")
            || branch_ref.object.kind != "commit"
            || !branch_ref
                .object
                .sha
                .eq_ignore_ascii_case(&permit.trusted_head_sha)
        {
            return Err(GitHubError::StaleRevision);
        }

        let repository: RepositoryDefaultBranch = self.get_json(&root).await?;
        if repository.default_branch != self.policy.base_branch {
            return Err(GitHubError::DefaultBranchMismatch);
        }

        let marker = format!("<!-- mipsorcu-operation:{} -->", permit.operation_id);
        let body = format!("Closes #{}\n\n{marker}", permit.issue_number);
        let title = format!("Task for issue #{}", permit.issue_number);
        let response = self
            .branch_write_client
            .post(format!("{root}/pulls"))
            .json(&CreatePullRequestRequest {
                title,
                body,
                head: branch.clone(),
                base: self.policy.base_branch.clone(),
            })
            .send()
            .await
            .map_err(|_| GitHubError::AmbiguousPullWrite)?;
        if response.status() != StatusCode::CREATED {
            return Err(GitHubError::AmbiguousPullWrite);
        }
        let created: PullResponse = read_bounded_json(response)
            .await
            .map_err(|_| GitHubError::AmbiguousPullWrite)?;
        let expected_body = format!("Closes #{}\n\n{marker}", permit.issue_number);
        if created.body.as_deref() != Some(expected_body.as_str())
            || validate_pull_candidate(
                &created,
                &permit.pinned_base_sha,
                &branch,
                &permit.trusted_head_sha,
                &marker,
                &self.policy,
            )
            .is_err()
        {
            return Err(GitHubError::AmbiguousPullWrite);
        }
        let observed = self
            .observe_pull_request_candidate(
                permit.issue_number,
                permit.operation_id,
                &permit.pinned_base_sha,
                &branch,
                &permit.trusted_head_sha,
            )
            .await
            .map_err(|_| GitHubError::AmbiguousPullWrite)?;
        if observed != created.number {
            return Err(GitHubError::AmbiguousPullWrite);
        }
        Ok(created.number)
    }

    /// Create a non-default-base PR without an automatic closing keyword. The
    /// returned candidate is identity evidence only; issue linking is a separate,
    /// independently gated operation.
    pub async fn create_unlinked_develop_pull_request(
        &self,
        permit: PullRequestWritePermit,
    ) -> Result<UnlinkedPullRequestCandidate, GitHubError> {
        let branch = format!("orchestrator/{}", permit.task_id);
        if permit.task_id.is_nil()
            || permit.operation_id.is_nil()
            || permit.issue_number == 0
            || permit.fencing_token == 0
            || !valid_sha(&permit.pinned_base_sha)
            || !valid_sha(&permit.trusted_head_sha)
            || self.policy.repository != self.policy.head_repository
            || !branch.starts_with(&format!("{}/", self.policy.head_ref_prefix))
            || !valid_branch(&branch)
            || branch.len() > MAX_BRANCH_REF_BYTES
            || matches!(branch.as_str(), "main" | "develop")
        {
            return Err(GitHubError::InvalidTaskReference);
        }
        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let repository: RepositoryDefaultBranch = self.get_json(&root).await?;
        if repository.default_branch == self.policy.base_branch {
            return Err(GitHubError::DefaultBranchMismatch);
        }
        let issue = self
            .read_open_issue(permit.issue_number, &permit.pinned_base_sha)
            .await?;
        if !issue.base_sha.eq_ignore_ascii_case(&permit.pinned_base_sha) {
            return Err(GitHubError::StaleRevision);
        }
        let branch_ref: CreateRefResponse = self
            .get_json(&format!("{root}/git/ref/heads/{branch}"))
            .await?;
        if branch_ref.reference != format!("refs/heads/{branch}")
            || branch_ref.object.kind != "commit"
            || !branch_ref
                .object
                .sha
                .eq_ignore_ascii_case(&permit.trusted_head_sha)
        {
            return Err(GitHubError::StaleRevision);
        }
        let marker = format!("<!-- mipsorcu-operation:{} -->", permit.operation_id);
        let response = self
            .branch_write_client
            .post(format!("{root}/pulls"))
            .json(&CreatePullRequestRequest {
                title: format!("Task for issue #{}", permit.issue_number),
                body: marker.clone(),
                head: branch.clone(),
                base: self.policy.base_branch.clone(),
            })
            .send()
            .await
            .map_err(|_| GitHubError::AmbiguousPullWrite)?;
        if response.status() != StatusCode::CREATED {
            return Err(GitHubError::AmbiguousPullWrite);
        }
        let created: PullResponse = read_bounded_json(response)
            .await
            .map_err(|_| GitHubError::AmbiguousPullWrite)?;
        if created.body.as_deref() != Some(marker.as_str())
            || validate_pull_candidate(
                &created,
                &permit.pinned_base_sha,
                &branch,
                &permit.trusted_head_sha,
                &marker,
                &self.policy,
            )
            .is_err()
        {
            return Err(GitHubError::AmbiguousPullWrite);
        }
        let observed = self
            .observe_pull_request_candidate_inner(
                permit.issue_number,
                permit.operation_id,
                &permit.pinned_base_sha,
                &branch,
                &permit.trusted_head_sha,
                false,
            )
            .await
            .map_err(|_| GitHubError::AmbiguousPullWrite)?;
        if observed != created.number {
            return Err(GitHubError::AmbiguousPullWrite);
        }
        Ok(UnlinkedPullRequestCandidate {
            number: created.number,
        })
    }

    /// Add the manually linked closing reference once, after independently
    /// re-reading both GraphQL node identities and the exact PR revision. Any
    /// post-send failure or cancellation is ambiguous and must never be replayed.
    pub async fn link_pull_request_issue(
        &self,
        permit: IssueLinkPermit,
    ) -> Result<u64, GitHubError> {
        if permit.task_id.is_nil()
            || permit.operation_id.is_nil()
            || permit.link_operation_id.is_nil()
            || permit.operation_id == permit.link_operation_id
            || permit.issue_number == 0
            || permit.pull_number == 0
            || permit.fencing_token == 0
            || !valid_sha(&permit.pinned_base_sha)
            || !valid_sha(&permit.trusted_head_sha)
        {
            return Err(GitHubError::InvalidTaskReference);
        }
        let branch = format!("orchestrator/{}", permit.task_id);
        let marker = format!("<!-- mipsorcu-operation:{} -->", permit.operation_id);
        let ids = self
            .read_issue_link_node_ids(&permit, &branch, &marker)
            .await?;
        let root = format!("{}/graphql", self.api_root);
        let response = self
            .branch_write_client
            .post(root)
            .json(&serde_json::json!({
                "query": "mutation($input:AddCloseIssueReferencesInput!){addCloseIssueReferences(input:$input){issue{id} clientMutationId}}",
                "variables": {"input": {
                    "issueId": ids.issue_id,
                    "pullRequestIds": [ids.pull_id],
                    "clientMutationId": permit.link_operation_id.to_string()
                }}
            }))
            .send()
            .await
            .map_err(|_| GitHubError::AmbiguousIssueLink)?;
        let result: IssueLinkMutationResponse = self
            .decode_response(response)
            .await
            .map_err(|_| GitHubError::AmbiguousIssueLink)?;
        if result
            .errors
            .as_ref()
            .is_some_and(|errors| !errors.is_empty())
        {
            return Err(GitHubError::AmbiguousIssueLink);
        }
        let payload = result
            .data
            .and_then(|data| data.add_close_issue_references)
            .ok_or(GitHubError::AmbiguousIssueLink)?;
        if payload.client_mutation_id.as_deref()
            != Some(permit.link_operation_id.to_string().as_str())
            || payload.issue.id != ids.issue_id
        {
            return Err(GitHubError::AmbiguousIssueLink);
        }
        let linked = self
            .observe_pull_request_candidate(
                permit.issue_number,
                permit.operation_id,
                &permit.pinned_base_sha,
                &branch,
                &permit.trusted_head_sha,
            )
            .await
            .map_err(|_| GitHubError::AmbiguousIssueLink)?;
        if linked != permit.pull_number {
            return Err(GitHubError::AmbiguousIssueLink);
        }
        Ok(linked)
    }

    /// Closes an Issue once after two observations bind the same task branch, PR,
    /// head, base and merge commit. Any failure after the PATCH is ambiguous.
    pub async fn close_merged_pull_request_issue(
        &self,
        permit: CloseIssuePermit,
    ) -> Result<u64, GitHubError> {
        if permit.task_id.is_nil()
            || permit.operation_id.is_nil()
            || permit.close_operation_id.is_nil()
            || permit.operation_id == permit.close_operation_id
            || permit.issue_number == 0
            || permit.pull_number == 0
            || permit.fencing_token == 0
            || !valid_sha(&permit.pinned_base_sha)
            || !valid_sha(&permit.trusted_head_sha)
            || !valid_sha(&permit.merge_commit_sha)
        {
            return Err(GitHubError::InvalidTaskReference);
        }
        let branch = format!("orchestrator/{}", permit.task_id);
        if !valid_branch(&branch) || branch.len() > MAX_BRANCH_REF_BYTES {
            return Err(GitHubError::InvalidTaskReference);
        }
        let before = self
            .observe_issue_close_target(&permit, &branch, IssueExpectation::Open)
            .await?;
        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let response = self
            .branch_write_client
            .patch(format!("{root}/issues/{}", permit.issue_number))
            .json(&CloseIssueRequest { state: "closed" })
            .send()
            .await
            .map_err(|_| GitHubError::AmbiguousIssueClose)?;
        if response.status() != StatusCode::OK {
            return Err(GitHubError::AmbiguousIssueClose);
        }
        let closed: IssueResponse = read_bounded_json(response)
            .await
            .map_err(|_| GitHubError::AmbiguousIssueClose)?;
        if closed.number != permit.issue_number || closed.state != "closed" {
            return Err(GitHubError::AmbiguousIssueClose);
        }
        let after = self
            .observe_issue_close_target(&permit, &branch, IssueExpectation::Closed)
            .await
            .map_err(|_| GitHubError::AmbiguousIssueClose)?;
        if before.same_pull_identity(&after) {
            Ok(permit.issue_number)
        } else {
            Err(GitHubError::AmbiguousIssueClose)
        }
    }

    async fn observe_issue_close_target(
        &self,
        permit: &CloseIssuePermit,
        branch: &str,
        expected_issue: IssueExpectation,
    ) -> Result<ObservedPullRequest, GitHubError> {
        let observed = self
            .observe_task_inner(VerificationRequest {
                issue_number: permit.issue_number,
                pull_number: permit.pull_number,
                expected_base_sha: &permit.pinned_base_sha,
                expected_head_sha: &permit.trusted_head_sha,
                expected_head_ref: Some(branch),
                expected_operation_id: Some(permit.operation_id),
                expected_issue,
                expected_pull: PullExpectation::Merged,
                require_successful_checks: true,
            })
            .await?;
        if observed.head_sha != permit.trusted_head_sha
            || observed.merge_commit_sha.as_deref() != Some(permit.merge_commit_sha.as_str())
            || !observed.base_contains_merge_commit
            || observed.ci_status != CiStatus::Passed
            || !observed.approvals_satisfied
        {
            return Err(GitHubError::StaleRevision);
        }
        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let base_ancestry: CompareResponse = self
            .get_json(&format!(
                "{root}/compare/{}...{}",
                permit.pinned_base_sha, observed.base_sha
            ))
            .await?;
        if !matches!(base_ancestry.status.as_str(), "ahead" | "identical") {
            return Err(GitHubError::MergeNotOnBase);
        }
        Ok(observed)
    }

    /// Re-fetch Issue, PR, checks and reviews and compare them with the trusted policy
    /// and task's expected revision. Any missing, stale, incomplete or failed evidence
    /// returns an error. No DB field grants permission to bypass these checks.
    pub async fn verify_task(
        &self,
        issue_number: u64,
        pull_number: u64,
        expected_base_sha: &str,
        expected_head_sha: &str,
        expected_issue: IssueExpectation,
        expected_pull: PullExpectation,
    ) -> Result<VerifiedPullRequest, GitHubError> {
        let observed = self
            .observe_task_inner(VerificationRequest {
                issue_number,
                pull_number,
                expected_base_sha,
                expected_head_sha,
                expected_head_ref: None,
                expected_operation_id: None,
                expected_issue,
                expected_pull,
                require_successful_checks: true,
            })
            .await?;
        if observed.ci_status != CiStatus::Passed {
            return Err(GitHubError::ChecksNotSuccessful);
        }
        Ok(VerifiedPullRequest {
            issue_number: observed.issue_number,
            pull_number: observed.pull_number,
            issue_state: observed.issue_state,
            pull_state: observed.pull_state,
            base_branch: observed.base_branch,
            base_sha: observed.base_sha,
            head_sha: observed.head_sha,
            merge_commit_sha: observed.merge_commit_sha,
            base_contains_merge_commit: observed.base_contains_merge_commit,
            successful_checks: self
                .policy
                .required_checks
                .iter()
                .map(|check| check.name.clone())
                .collect(),
            approval_count: observed.approval_count,
            approvals_satisfied: observed.approvals_satisfied,
        })
    }

    /// Observe PR identity, formal review and CI state for the current head SHA.
    /// Unlike `verify_task`, this reports pending/failed checks for repair routing;
    /// it does not grant validation or merge permission.
    pub async fn observe_task(
        &self,
        issue_number: u64,
        pull_number: u64,
        expected_base_sha: &str,
        expected_head_sha: &str,
        expected_issue: IssueExpectation,
        expected_pull: PullExpectation,
    ) -> Result<ObservedPullRequest, GitHubError> {
        self.observe_task_inner(VerificationRequest {
            issue_number,
            pull_number,
            expected_base_sha,
            expected_head_sha,
            expected_head_ref: None,
            expected_operation_id: None,
            expected_issue,
            expected_pull,
            require_successful_checks: false,
        })
        .await
    }

    /// Finds a single open PR bearing the marker derived from an operation UUID.
    ///
    /// The marker is only a lookup key for remote reconciliation. A caller-supplied
    /// operation UUID does not grant permission to create, replay, merge, or complete
    /// an operation; callers must retain their independent durable-operation gates.
    /// GitHub list results are not a transaction, so the repeated reads only reject
    /// changes observed during this call and cannot prevent a later race.
    pub async fn observe_pull_request_candidate(
        &self,
        issue_number: u64,
        operation_id: uuid::Uuid,
        expected_base_sha: &str,
        expected_branch: &str,
        expected_head_sha: &str,
    ) -> Result<u64, GitHubError> {
        self.observe_pull_request_candidate_inner(
            issue_number,
            operation_id,
            expected_base_sha,
            expected_branch,
            expected_head_sha,
            true,
        )
        .await
    }

    async fn observe_pull_request_candidate_inner(
        &self,
        issue_number: u64,
        operation_id: uuid::Uuid,
        expected_base_sha: &str,
        expected_branch: &str,
        expected_head_sha: &str,
        require_issue_link: bool,
    ) -> Result<u64, GitHubError> {
        if issue_number == 0
            || operation_id.is_nil()
            || !valid_sha(expected_base_sha)
            || !valid_sha(expected_head_sha)
            || !valid_branch(expected_branch)
            || expected_branch.len() > MAX_BRANCH_REF_BYTES
            || !expected_branch.starts_with(&self.policy.head_ref_prefix)
        {
            return Err(GitHubError::InvalidTaskReference);
        }

        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let base_before = self.fetch_base_sha(&root).await?;
        if !base_before.eq_ignore_ascii_case(expected_base_sha) {
            return Err(GitHubError::StaleRevision);
        }
        let issue_before = self
            .fetch_issue(&root, issue_number, IssueExpectation::Open)
            .await?;
        let owner = self
            .policy
            .head_repository
            .split('/')
            .next()
            .ok_or(GitHubError::InvalidPolicy)?;
        let marker = format!("<!-- mipsorcu-operation:{} -->", operation_id);
        let pulls = self
            .fetch_pull_candidates(&root, owner, expected_branch)
            .await?;
        if pulls.len() >= 100 {
            return Err(GitHubError::IncompleteEvidence);
        }
        let marked = pulls
            .iter()
            .filter(|pull| {
                pull.body
                    .as_deref()
                    .is_some_and(|body| body.contains(&marker))
            })
            .collect::<Vec<_>>();
        if marked.len() != 1 {
            return Err(if marked.is_empty() {
                GitHubError::PullCandidateNotFound
            } else {
                GitHubError::AmbiguousPullCandidate
            });
        }
        let candidate = marked.first().ok_or(GitHubError::PullCandidateNotFound)?;
        if candidate.number == 0
            || candidate
                .body
                .as_deref()
                .is_none_or(|body| body.matches(&marker).count() != 1)
        {
            return Err(GitHubError::InvalidResponse);
        }
        let first: PullResponse = self
            .get_json(&format!("{root}/pulls/{}", candidate.number))
            .await?;
        if first.number != candidate.number || first.body != candidate.body {
            return Err(GitHubError::InvalidResponse);
        }
        validate_pull_candidate(
            &first,
            expected_base_sha,
            expected_branch,
            expected_head_sha,
            &marker,
            &self.policy,
        )?;
        if require_issue_link && !self.pull_closes_issue(first.number, issue_number).await? {
            return Err(GitHubError::IssuePullMismatch);
        }
        let final_pulls = self
            .fetch_pull_candidates(&root, owner, expected_branch)
            .await?;
        if final_pulls.len() >= 100 {
            return Err(GitHubError::IncompleteEvidence);
        }
        let final_marked = final_pulls
            .iter()
            .filter(|pull| {
                pull.body
                    .as_deref()
                    .is_some_and(|body| body.contains(&marker))
            })
            .collect::<Vec<_>>();
        if final_marked.len() != 1 {
            return Err(GitHubError::StaleRevision);
        }
        let final_candidate = final_marked.first().ok_or(GitHubError::StaleRevision)?;
        if final_candidate.number != candidate.number
            || final_candidate.body != candidate.body
            || final_candidate
                .body
                .as_deref()
                .is_none_or(|body| body.matches(&marker).count() != 1)
        {
            return Err(GitHubError::StaleRevision);
        }
        let latest: PullResponse = self
            .get_json(&format!("{root}/pulls/{}", final_candidate.number))
            .await?;
        validate_pull_candidate(
            &latest,
            expected_base_sha,
            expected_branch,
            expected_head_sha,
            &marker,
            &self.policy,
        )?;
        if latest.number != final_candidate.number
            || latest.body != final_candidate.body
            || latest != first
        {
            return Err(GitHubError::StaleRevision);
        }
        if require_issue_link && !self.pull_closes_issue(latest.number, issue_number).await? {
            return Err(GitHubError::StaleRevision);
        }
        let issue_after = self
            .fetch_issue(&root, issue_number, IssueExpectation::Open)
            .await?;
        let base_after = self.fetch_base_sha(&root).await?;
        if issue_before.number != issue_after.number
            || issue_before.state != issue_after.state
            || !base_after.eq_ignore_ascii_case(expected_base_sha)
        {
            return Err(GitHubError::StaleRevision);
        }
        Ok(first.number)
    }

    async fn fetch_pull_candidates(
        &self,
        root: &str,
        owner: &str,
        branch: &str,
    ) -> Result<Vec<PullCandidateListEntry>, GitHubError> {
        let mut url = reqwest::Url::parse(&format!("{root}/pulls"))
            .map_err(|_| GitHubError::InvalidConfiguration)?;
        url.query_pairs_mut()
            .append_pair("state", "all")
            .append_pair("head", &format!("{owner}:{branch}"))
            .append_pair("base", &self.policy.base_branch)
            .append_pair("per_page", "100");
        self.get_json(url.as_str()).await
    }

    /// Read the Actions jobs and steps attached to the failed required checks for
    /// this unchanged PR revision. Names are untrusted input and must not be
    /// forwarded until confidentiality and prompt-injection controls are applied;
    /// quoting alone is not a defense. This does not fetch logs or grant permission.
    pub async fn read_failed_actions_evidence(
        &self,
        issue_number: u64,
        pull_number: u64,
        expected_base_sha: &str,
        expected_head_sha: &str,
        expected_issue: IssueExpectation,
    ) -> Result<FailedActionsEvidence, GitHubError> {
        let before = self
            .observe_task(
                issue_number,
                pull_number,
                expected_base_sha,
                expected_head_sha,
                expected_issue,
                PullExpectation::Open,
            )
            .await?;
        if before.ci_status != CiStatus::Failed {
            return Err(GitHubError::ChecksNotSuccessful);
        }
        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let initial = self
            .fetch_required_ci_evidence(&root, expected_head_sha, false)
            .await?;
        let failed = initial
            .check_runs
            .iter()
            .filter(|check| check.ci_status == CiStatus::Failed)
            .collect::<Vec<_>>();
        if failed.is_empty() {
            return Err(GitHubError::IncompleteEvidence);
        }
        let mut checks = Vec::with_capacity(failed.len());
        for check in failed {
            let check_id = check.id.ok_or(GitHubError::IncompleteEvidence)?;
            let suite_id = check
                .check_suite_id
                .ok_or(GitHubError::IncompleteEvidence)?;
            let run = self
                .fetch_actions_run(
                    &root,
                    suite_id,
                    pull_number,
                    expected_base_sha,
                    expected_head_sha,
                )
                .await?;
            let jobs = self
                .fetch_actions_jobs(&root, &run, check_id, expected_head_sha)
                .await?;
            if self
                .fetch_actions_run(
                    &root,
                    suite_id,
                    pull_number,
                    expected_base_sha,
                    expected_head_sha,
                )
                .await?
                != run
            {
                return Err(GitHubError::StaleRevision);
            }
            checks.push(FailedCheckActions {
                check_name: check.name.clone(),
                check_run_id: check_id,
                check_suite_id: suite_id,
                run_id: run.id,
                run_attempt: run.run_attempt,
                jobs,
            });
        }
        let final_ci = self
            .fetch_required_ci_evidence(&root, expected_head_sha, false)
            .await?;
        let after = self
            .observe_task(
                issue_number,
                pull_number,
                expected_base_sha,
                expected_head_sha,
                expected_issue,
                PullExpectation::Open,
            )
            .await?;
        if initial != final_ci || before != after || after.ci_status != CiStatus::Failed {
            return Err(GitHubError::StaleRevision);
        }
        Ok(FailedActionsEvidence {
            repository: self.policy.repository.clone(),
            issue_number,
            pull_number,
            base_sha: expected_base_sha.to_owned(),
            head_sha: expected_head_sha.to_owned(),
            expected_issue,
            checks,
        })
    }

    /// Download one failed job's untrusted log into bounded memory. The trusted
    /// destination must come from operator policy, never from a task or the database.
    /// The returned bytes must not be logged, persisted, or sent to an agent without
    /// independent confidentiality and prompt-injection controls.
    pub async fn read_failed_job_log(
        &self,
        evidence: &FailedActionsEvidence,
        job_id: u64,
        destination: &TrustedLogDestination,
    ) -> Result<SensitiveJobLog, GitHubError> {
        if evidence.repository != self.policy.repository
            || job_id == 0
            || evidence
                .checks
                .iter()
                .flat_map(|check| &check.jobs)
                .filter(|job| job.id == job_id)
                .count()
                != 1
        {
            return Err(GitHubError::InvalidTaskReference);
        }
        let before = self.refresh_failed_actions(evidence).await?;
        if &before != evidence {
            return Err(GitHubError::StaleRevision);
        }
        let endpoint = format!(
            "{}/repos/{}/actions/jobs/{job_id}/logs",
            self.api_root, self.policy.repository
        );
        let redirect = self
            .logs_api_client
            .get(endpoint)
            .send()
            .await
            .map_err(|_| GitHubError::Unavailable)?;
        if redirect.status() != StatusCode::FOUND {
            return Err(GitHubError::Unavailable);
        }
        let mut locations = redirect.headers().get_all(header::LOCATION).iter();
        let location = locations
            .next()
            .ok_or(GitHubError::InvalidResponse)?
            .to_str()
            .map_err(|_| GitHubError::InvalidResponse)?;
        if locations.next().is_some()
            || location.len() > 8192
            || location
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
            || location
                .split_once("://")
                .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
                .is_some_and(|authority| authority.contains('@'))
        {
            return Err(GitHubError::InvalidResponse);
        }
        let url = reqwest::Url::parse(location).map_err(|_| GitHubError::InvalidResponse)?;
        destination.validate_url(&url)?;
        let client = destination.client()?;
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| GitHubError::Unavailable)?;
        let bytes = read_bounded_job_log(response).await?;
        if self.refresh_failed_actions(evidence).await? != before {
            return Err(GitHubError::StaleRevision);
        }
        Ok(SensitiveJobLog(bytes))
    }

    async fn refresh_failed_actions(
        &self,
        evidence: &FailedActionsEvidence,
    ) -> Result<FailedActionsEvidence, GitHubError> {
        self.read_failed_actions_evidence(
            evidence.issue_number,
            evidence.pull_number,
            &evidence.base_sha,
            &evidence.head_sha,
            evidence.expected_issue,
        )
        .await
    }

    async fn fetch_actions_run(
        &self,
        root: &str,
        check_suite_id: u64,
        pull_number: u64,
        base_sha: &str,
        head_sha: &str,
    ) -> Result<WorkflowRun, GitHubError> {
        let runs: WorkflowRunsResponse = self
            .get_json(&format!(
                "{root}/actions/runs?check_suite_id={check_suite_id}&head_sha={head_sha}&per_page=100"
            ))
            .await?;
        if u64::try_from(runs.workflow_runs.len()).ok() != Some(runs.total_count)
            || runs.workflow_runs.len() != 1
        {
            return Err(GitHubError::IncompleteEvidence);
        }
        let run = runs
            .workflow_runs
            .into_iter()
            .next()
            .ok_or(GitHubError::IncompleteEvidence)?;
        if run.id == 0
            || run.run_attempt == 0
            || run.check_suite_id != check_suite_id
            || !matches!(run.event.as_str(), "pull_request" | "pull_request_target")
            || !run.head_sha.eq_ignore_ascii_case(head_sha)
            || run.repository.full_name != self.policy.repository
            || run.pull_requests.len() != 1
        {
            return Err(GitHubError::RepositoryMismatch);
        }
        let pull = &run.pull_requests[0];
        let repository_url = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let head_repository_url =
            format!("{}/repos/{}", self.api_root, self.policy.head_repository);
        if pull.number != pull_number
            || !pull.head.sha.eq_ignore_ascii_case(head_sha)
            || pull.base.ref_name != self.policy.base_branch
            || !pull.base.sha.eq_ignore_ascii_case(base_sha)
            || pull.base.repo.name
                != self
                    .policy
                    .repository
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
            || pull.base.repo.id == 0
            || pull.base.repo.url != repository_url
            || pull.head.repo.name
                != self
                    .policy
                    .head_repository
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
            || pull.head.repo.id == 0
            || pull.head.repo.url != head_repository_url
        {
            return Err(GitHubError::StaleRevision);
        }
        Ok(run)
    }

    async fn fetch_actions_jobs(
        &self,
        root: &str,
        run: &WorkflowRun,
        check_run_id: u64,
        head_sha: &str,
    ) -> Result<Vec<FailedActionJob>, GitHubError> {
        let jobs_url = format!(
            "{root}/actions/runs/{}/attempts/{}/jobs?per_page=100",
            run.id, run.run_attempt
        );
        let check_run_url = format!("{root}/check-runs/{check_run_id}");
        let jobs: WorkflowJobsResponse = self.get_json(&jobs_url).await?;
        let job = select_failed_action_job(jobs, &check_run_url, run, head_sha)?;
        let result = vec![FailedActionJob {
            id: job.id,
            name: job.name.clone(),
            conclusion: job.conclusion.clone(),
            steps: job
                .steps
                .iter()
                .map(|step| FailedActionStep {
                    number: step.number,
                    name: step.name.clone(),
                    status: step.status.clone(),
                    conclusion: step.conclusion.clone(),
                })
                .collect(),
        }];
        let latest_jobs: WorkflowJobsResponse = self.get_json(&jobs_url).await?;
        if select_failed_action_job(latest_jobs, &check_run_url, run, head_sha)? != job {
            return Err(GitHubError::StaleRevision);
        }
        Ok(result)
    }

    async fn observe_task_inner(
        &self,
        request: VerificationRequest<'_>,
    ) -> Result<ObservedPullRequest, GitHubError> {
        let VerificationRequest {
            issue_number,
            pull_number,
            expected_base_sha,
            expected_head_sha,
            expected_head_ref,
            expected_operation_id,
            expected_issue,
            expected_pull,
            require_successful_checks,
        } = request;
        if issue_number == 0
            || pull_number == 0
            || !valid_sha(expected_base_sha)
            || !valid_sha(expected_head_sha)
        {
            return Err(GitHubError::InvalidTaskReference);
        }
        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let current_base_sha = self.fetch_base_sha(&root).await?;
        if expected_pull == PullExpectation::Open
            && !current_base_sha.eq_ignore_ascii_case(expected_base_sha)
        {
            return Err(GitHubError::StaleRevision);
        }
        let issue = self
            .fetch_issue(&root, issue_number, expected_issue)
            .await?;

        let pull: PullResponse = self
            .get_json(&format!("{root}/pulls/{pull_number}"))
            .await?;
        if pull.number != pull_number
            || pull.base.repo.full_name != self.policy.repository
            || pull.head.repo.full_name != self.policy.head_repository
            || !pull.head.ref_name.starts_with(&self.policy.head_ref_prefix)
            || !pull
                .user
                .login
                .eq_ignore_ascii_case(&self.policy.pull_author)
        {
            return Err(GitHubError::RepositoryMismatch);
        }
        if pull.base.ref_name != self.policy.base_branch
            || !valid_sha(&pull.base.sha)
            || !pull.head.sha.eq_ignore_ascii_case(expected_head_sha)
            || expected_head_ref.is_some_and(|expected| pull.head.ref_name != expected)
            || expected_operation_id.is_some_and(|operation_id| {
                !has_unique_operation_marker(pull.body.as_deref(), operation_id)
            })
            || (expected_pull == PullExpectation::Open
                && !pull.base.sha.eq_ignore_ascii_case(expected_base_sha))
        {
            return Err(GitHubError::StaleRevision);
        }
        match expected_pull {
            PullExpectation::Open if pull.state != "open" || pull.merged => {
                return Err(GitHubError::PullStateMismatch);
            }
            PullExpectation::Merged if pull.state != "closed" || !pull.merged => {
                return Err(GitHubError::PullStateMismatch);
            }
            _ => {}
        }

        if !self.pull_closes_issue(pull_number, issue_number).await? {
            return Err(GitHubError::IssuePullMismatch);
        }
        let merge_commit_sha = if expected_pull == PullExpectation::Merged {
            let merge_sha = pull
                .merge_commit_sha
                .as_deref()
                .filter(|sha| valid_sha(sha))
                .ok_or(GitHubError::InvalidResponse)?;
            let comparison: CompareResponse = self
                .get_json(&format!("{root}/compare/{merge_sha}...{current_base_sha}"))
                .await?;
            if !matches!(comparison.status.as_str(), "ahead" | "identical") {
                return Err(GitHubError::MergeNotOnBase);
            }
            Some(merge_sha.to_owned())
        } else {
            None
        };

        let initial_ci_evidence = self
            .fetch_required_ci_evidence(&root, &pull.head.sha, require_successful_checks)
            .await?;
        if require_successful_checks && initial_ci_evidence.status != CiStatus::Passed {
            return Err(GitHubError::ChecksNotSuccessful);
        }

        let reviews: Vec<ReviewResponse> = self
            .get_json(&format!("{root}/pulls/{pull_number}/reviews?per_page=100"))
            .await?;
        if reviews.len() >= 100 {
            return Err(GitHubError::IncompleteEvidence);
        }
        if pull.user.id == 0 {
            return Err(GitHubError::InvalidResponse);
        }
        let initial_reviews = latest_review_decisions(&reviews)?;
        let approval_count = initial_reviews
            .values()
            .filter(|review| {
                review.state == "APPROVED"
                    && review.commit_id.eq_ignore_ascii_case(&pull.head.sha)
                    && review.user_id != pull.user.id
            })
            .count();
        let approvals_satisfied = approval_count >= self.policy.minimum_approvals;

        let latest_pull: PullResponse = self
            .get_json(&format!("{root}/pulls/{pull_number}"))
            .await?;
        if latest_pull.number != pull.number
            || latest_pull.base.ref_name != self.policy.base_branch
            || latest_pull.base.sha != pull.base.sha
            || latest_pull.head.sha != pull.head.sha
            || latest_pull.state != pull.state
            || latest_pull.merged != pull.merged
            || latest_pull.base.repo.full_name != self.policy.repository
            || latest_pull.head.repo.full_name != pull.head.repo.full_name
            || latest_pull.head.ref_name != pull.head.ref_name
            || !latest_pull
                .user
                .login
                .eq_ignore_ascii_case(&pull.user.login)
            || latest_pull.user.id != pull.user.id
            || latest_pull.head.repo.full_name != self.policy.head_repository
            || !latest_pull
                .user
                .login
                .eq_ignore_ascii_case(&self.policy.pull_author)
        {
            return Err(GitHubError::StaleRevision);
        }
        let latest_issue = self
            .fetch_issue(&root, issue_number, expected_issue)
            .await?;
        if latest_issue.state != issue.state {
            return Err(GitHubError::IssueStateMismatch);
        }
        let latest_base_sha = self.fetch_base_sha(&root).await?;
        if latest_base_sha != current_base_sha {
            return Err(GitHubError::StaleRevision);
        }
        if expected_pull == PullExpectation::Merged {
            let merge_sha = merge_commit_sha
                .as_deref()
                .ok_or(GitHubError::InvalidResponse)?;
            let comparison: CompareResponse = self
                .get_json(&format!("{root}/compare/{merge_sha}...{latest_base_sha}"))
                .await?;
            if !matches!(comparison.status.as_str(), "ahead" | "identical") {
                return Err(GitHubError::MergeNotOnBase);
            }
        }
        let final_ci_evidence = self
            .fetch_required_ci_evidence(&root, &pull.head.sha, require_successful_checks)
            .await?;
        if final_ci_evidence != initial_ci_evidence {
            return Err(GitHubError::StaleRevision);
        }
        let final_reviews: Vec<ReviewResponse> = self
            .get_json(&format!("{root}/pulls/{pull_number}/reviews?per_page=100"))
            .await?;
        if final_reviews.len() >= 100 {
            return Err(GitHubError::IncompleteEvidence);
        }
        if latest_review_decisions(&final_reviews)? != initial_reviews {
            return Err(GitHubError::StaleRevision);
        }
        if !self.pull_closes_issue(pull_number, issue_number).await? {
            return Err(GitHubError::StaleRevision);
        }

        Ok(ObservedPullRequest {
            issue_number,
            pull_number,
            issue_state: issue.state,
            pull_state: if pull.merged {
                PullStatus::Merged
            } else {
                PullStatus::Open
            },
            base_branch: pull.base.ref_name,
            base_sha: pull.base.sha,
            head_sha: pull.head.sha,
            merge_commit_sha,
            base_contains_merge_commit: expected_pull == PullExpectation::Merged,
            ci_status: initial_ci_evidence.status,
            approval_count,
            approvals_satisfied,
        })
    }

    async fn fetch_required_ci_evidence(
        &self,
        root: &str,
        head_sha: &str,
        require_successful_checks: bool,
    ) -> Result<RequiredCiEvidence, GitHubError> {
        let checks: CheckRunsResponse = self
            .get_json(&format!(
                "{root}/commits/{head_sha}/check-runs?per_page=100"
            ))
            .await?;
        if u64::try_from(checks.check_runs.len()).ok() != Some(checks.total_count) {
            return Err(GitHubError::IncompleteEvidence);
        }
        let mut check_runs = Vec::with_capacity(self.policy.required_checks.len());
        for required in &self.policy.required_checks {
            let named = checks
                .check_runs
                .iter()
                .filter(|check| check.name == required.name)
                .collect::<Vec<_>>();
            if named.iter().any(|check| check.app.id != required.app_id) {
                return Err(GitHubError::AmbiguousCheck);
            }
            let latest = named.into_iter().max_by_key(|check| check.id);
            let check_run_status = latest
                .map(|run| classify_check_run(&run.status, run.conclusion.as_deref()))
                .unwrap_or(CiStatus::Unknown);
            check_runs.push(RequiredCheckRunEvidence {
                name: required.name.clone(),
                app_id: latest.map(|run| run.app.id),
                id: latest.map(|run| run.id),
                check_suite_id: latest
                    .and_then(|run| run.check_suite.as_ref().map(|suite| suite.id)),
                status: latest.map_or_else(|| "missing".to_owned(), |run| run.status.clone()),
                conclusion: latest.and_then(|run| run.conclusion.clone()),
                ci_status: check_run_status,
            });
        }
        if require_successful_checks
            && check_runs
                .iter()
                .any(|check| check.ci_status != CiStatus::Passed)
        {
            return Err(GitHubError::ChecksNotSuccessful);
        }

        let statuses: CombinedStatusResponse = self
            .get_json(&format!("{root}/commits/{head_sha}/status?per_page=100"))
            .await?;
        if !valid_sha(&statuses.sha) || !statuses.sha.eq_ignore_ascii_case(head_sha) {
            return Err(GitHubError::InvalidResponse);
        }
        if u64::try_from(statuses.statuses.len()).ok() != Some(statuses.total_count) {
            return Err(GitHubError::IncompleteEvidence);
        }
        let mut commit_statuses = Vec::with_capacity(self.policy.required_checks.len());
        let mut required_statuses = Vec::with_capacity(self.policy.required_checks.len());
        for required in &self.policy.required_checks {
            let matching = statuses
                .statuses
                .iter()
                .filter(|status| status.context.eq_ignore_ascii_case(&required.name))
                .collect::<Vec<_>>();
            if matching.len() > 1 {
                return Err(GitHubError::AmbiguousCheck);
            }
            let state = matching.first().map(|status| status.state.as_str());
            let legacy_status = state.map(classify_commit_status);
            let run_status = check_runs
                .iter()
                .find(|check| check.name == required.name)
                .map_or(CiStatus::Unknown, |check| check.ci_status);
            required_statuses.push(combine_ci_status(run_status, legacy_status));
            commit_statuses.push(RequiredCommitStatusEvidence {
                name: required.name.clone(),
                state: state.map(str::to_owned),
            });
        }

        let status = aggregate_ci_status(&required_statuses);
        if require_successful_checks && status != CiStatus::Passed {
            return Err(GitHubError::ChecksNotSuccessful);
        }
        Ok(RequiredCiEvidence {
            check_runs,
            commit_statuses,
            status,
        })
    }

    /// Read the current open Issue text for a task pinned to the trusted base SHA.
    /// The text is untrusted and may contain secrets or prompt injection. Callers must
    /// not log or persist it, or forward it before applying their own security controls.
    pub async fn read_open_issue(
        &self,
        issue_number: u64,
        expected_base_sha: &str,
    ) -> Result<IssueInput, GitHubError> {
        if issue_number == 0 || !valid_sha(expected_base_sha) {
            return Err(GitHubError::InvalidTaskReference);
        }
        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let base_sha = self.fetch_base_sha(&root).await?;
        if !base_sha.eq_ignore_ascii_case(expected_base_sha) {
            return Err(GitHubError::StaleRevision);
        }
        let url = format!("{root}/issues/{issue_number}");
        let first: IssueInputResponse = self.get_json(&url).await?;
        first.validate(issue_number)?;
        let latest: IssueInputResponse = self.get_json(&url).await?;
        latest.validate(issue_number)?;
        if first != latest
            || !self
                .fetch_base_sha(&root)
                .await?
                .eq_ignore_ascii_case(&base_sha)
        {
            return Err(GitHubError::StaleRevision);
        }
        Ok(IssueInput {
            issue_number,
            base_sha,
            title: first.title,
            body: first.body,
        })
    }

    /// Verify an Issue before a PR exists, capturing or rechecking the trusted base head.
    pub async fn verify_issue(
        &self,
        issue_number: u64,
        expected_issue: IssueExpectation,
        expected_base_sha: Option<&str>,
    ) -> Result<VerifiedIssue, GitHubError> {
        if issue_number == 0 || expected_base_sha.is_some_and(|sha| !valid_sha(sha)) {
            return Err(GitHubError::InvalidTaskReference);
        }
        let root = format!("{}/repos/{}", self.api_root, self.policy.repository);
        let issue = self
            .fetch_issue(&root, issue_number, expected_issue)
            .await?;
        let base_sha = self.fetch_base_sha(&root).await?;
        if expected_base_sha.is_some_and(|sha| !base_sha.eq_ignore_ascii_case(sha)) {
            return Err(GitHubError::StaleRevision);
        }
        if self.fetch_base_sha(&root).await? != base_sha {
            return Err(GitHubError::StaleRevision);
        }
        let latest_issue = self
            .fetch_issue(&root, issue_number, expected_issue)
            .await?;
        if latest_issue.state != issue.state {
            return Err(GitHubError::IssueStateMismatch);
        }
        Ok(VerifiedIssue {
            issue_number,
            issue_state: issue.state,
            base_branch: self.policy.base_branch.clone(),
            base_sha,
        })
    }

    async fn fetch_base_sha(&self, root: &str) -> Result<String, GitHubError> {
        let commit: CommitResponse = self
            .get_json(&format!("{root}/commits/{}", self.policy.base_branch))
            .await?;
        if !valid_sha(&commit.sha) {
            return Err(GitHubError::InvalidResponse);
        }
        Ok(commit.sha)
    }

    async fn fetch_issue(
        &self,
        root: &str,
        issue_number: u64,
        expected: IssueExpectation,
    ) -> Result<IssueResponse, GitHubError> {
        let issue: IssueResponse = self
            .get_json(&format!("{root}/issues/{issue_number}"))
            .await?;
        if issue.number != issue_number || issue.state != expected.as_api_state() {
            return Err(GitHubError::IssueStateMismatch);
        }
        Ok(issue)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, GitHubError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| GitHubError::Unavailable)?;
        self.decode_response(response).await
    }

    async fn decode_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: Response,
    ) -> Result<T, GitHubError> {
        if response.status() != StatusCode::OK {
            return Err(GitHubError::Unavailable);
        }
        if response
            .headers()
            .get_all(header::LINK)
            .iter()
            .next()
            .is_some()
        {
            return Err(GitHubError::IncompleteEvidence);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(GitHubError::ResponseTooLarge);
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| GitHubError::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(GitHubError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| GitHubError::InvalidResponse)
    }

    async fn pull_closes_issue(
        &self,
        pull_number: u64,
        issue_number: u64,
    ) -> Result<bool, GitHubError> {
        let mut repository = self.policy.repository.split('/');
        let owner = repository.next().ok_or(GitHubError::InvalidPolicy)?;
        let name = repository.next().ok_or(GitHubError::InvalidPolicy)?;
        let pull_number =
            i32::try_from(pull_number).map_err(|_| GitHubError::InvalidTaskReference)?;
        let response = self.client.post(format!("{}/graphql", self.api_root))
            .json(&serde_json::json!({
                "query": "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){nameWithOwner pullRequest(number:$number){closingIssuesReferences(first:100){nodes{number repository{nameWithOwner}} pageInfo{hasNextPage}}}}}",
                "variables": {"owner": owner, "name": name, "number": pull_number}
            }))
            .send().await.map_err(|_| GitHubError::Unavailable)?;
        let result: GraphqlResponse = self.decode_response(response).await?;
        if result
            .errors
            .as_ref()
            .is_some_and(|errors| !errors.is_empty())
        {
            return Err(GitHubError::InvalidResponse);
        }
        let connection = result
            .data
            .and_then(|data| data.repository)
            .filter(|repo| repo.name_with_owner == self.policy.repository)
            .and_then(|repo| repo.pull_request)
            .map(|pull| pull.closing_issues_references)
            .ok_or(GitHubError::InvalidResponse)?;
        if connection.page_info.has_next_page || connection.nodes.len() >= 100 {
            return Err(GitHubError::IncompleteEvidence);
        }
        Ok(connection.nodes.iter().any(|issue| {
            issue.number == issue_number
                && issue.repository.name_with_owner == self.policy.repository
        }))
    }

    async fn read_issue_link_node_ids(
        &self,
        permit: &IssueLinkPermit,
        branch: &str,
        marker: &str,
    ) -> Result<IssueLinkNodeIds, GitHubError> {
        let mut repository = self.policy.repository.split('/');
        let owner = repository.next().ok_or(GitHubError::InvalidPolicy)?;
        let name = repository.next().ok_or(GitHubError::InvalidPolicy)?;
        let issue_number =
            i32::try_from(permit.issue_number).map_err(|_| GitHubError::InvalidTaskReference)?;
        let pull_number =
            i32::try_from(permit.pull_number).map_err(|_| GitHubError::InvalidTaskReference)?;
        let response = self
            .client
            .post(format!("{}/graphql", self.api_root))
            .json(&serde_json::json!({
                "query": "query($owner:String!,$name:String!,$issue:Int!,$pull:Int!){repository(owner:$owner,name:$name){nameWithOwner issue(number:$issue){id number state} pullRequest(number:$pull){id number state body headRepository{nameWithOwner} baseRepository{nameWithOwner} headRefName headRefOid baseRefName baseRefOid author{login}}}}",
                "variables": {"owner": owner, "name": name, "issue": issue_number, "pull": pull_number}
            }))
            .send()
            .await
            .map_err(|_| GitHubError::Unavailable)?;
        let result: IssueLinkQueryResponse = self.decode_response(response).await?;
        if result
            .errors
            .as_ref()
            .is_some_and(|errors| !errors.is_empty())
        {
            return Err(GitHubError::InvalidResponse);
        }
        let repository = result
            .data
            .and_then(|data| data.repository)
            .filter(|repository| repository.name_with_owner == self.policy.repository)
            .ok_or(GitHubError::RepositoryMismatch)?;
        let issue = repository.issue.ok_or(GitHubError::IssueStateMismatch)?;
        let pull = repository
            .pull_request
            .ok_or(GitHubError::PullCandidateNotFound)?;
        if pull
            .head_repository
            .as_ref()
            .is_none_or(|repository| repository.name_with_owner != self.policy.head_repository)
            || pull
                .base_repository
                .as_ref()
                .is_none_or(|repository| repository.name_with_owner != self.policy.repository)
        {
            return Err(GitHubError::RepositoryMismatch);
        }
        if issue.number != permit.issue_number
            || issue.state != "OPEN"
            || pull.number != permit.pull_number
            || pull.state != "OPEN"
            || pull.head_ref_name != branch
            || !pull
                .head_ref_oid
                .eq_ignore_ascii_case(&permit.trusted_head_sha)
            || pull.base_ref_name != self.policy.base_branch
            || !pull
                .base_ref_oid
                .eq_ignore_ascii_case(&permit.pinned_base_sha)
            || pull.body.as_deref() != Some(marker)
            || pull.author.login != self.policy.pull_author
            || issue.id.is_empty()
            || pull.id.is_empty()
        {
            return Err(GitHubError::IssuePullMismatch);
        }
        Ok(IssueLinkNodeIds {
            issue_id: issue.id,
            pull_id: pull.id,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueExpectation {
    Open,
    Closed,
}
impl IssueExpectation {
    fn as_api_state(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullExpectation {
    Open,
    Merged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullStatus {
    Open,
    Merged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiStatus {
    Passed,
    Pending,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedPullRequest {
    pub issue_number: u64,
    pub pull_number: u64,
    pub issue_state: String,
    pub pull_state: PullStatus,
    pub base_branch: String,
    pub base_sha: String,
    pub head_sha: String,
    pub merge_commit_sha: Option<String>,
    pub base_contains_merge_commit: bool,
    pub ci_status: CiStatus,
    pub approval_count: usize,
    pub approvals_satisfied: bool,
}

impl ObservedPullRequest {
    fn same_pull_identity(&self, other: &Self) -> bool {
        self.issue_number == other.issue_number
            && self.pull_number == other.pull_number
            && self.pull_state == other.pull_state
            && self.base_branch == other.base_branch
            && self.base_sha == other.base_sha
            && self.head_sha == other.head_sha
            && self.merge_commit_sha == other.merge_commit_sha
            && self.base_contains_merge_commit == other.base_contains_merge_commit
            && self.ci_status == other.ci_status
            && self.approval_count == other.approval_count
            && self.approvals_satisfied == other.approvals_satisfied
    }
}

struct VerificationRequest<'a> {
    issue_number: u64,
    pull_number: u64,
    expected_base_sha: &'a str,
    expected_head_sha: &'a str,
    expected_head_ref: Option<&'a str>,
    expected_operation_id: Option<uuid::Uuid>,
    expected_issue: IssueExpectation,
    expected_pull: PullExpectation,
    require_successful_checks: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPullRequest {
    pub issue_number: u64,
    pub pull_number: u64,
    pub issue_state: String,
    pub pull_state: PullStatus,
    pub base_branch: String,
    pub base_sha: String,
    pub head_sha: String,
    pub merge_commit_sha: Option<String>,
    pub base_contains_merge_commit: bool,
    pub successful_checks: Vec<String>,
    pub approval_count: usize,
    pub approvals_satisfied: bool,
}

impl VerifiedPullRequest {
    /// Enforce the trusted approval threshold at the merge/completion boundary.
    pub fn require_approvals(&self) -> Result<(), GitHubError> {
        if self.approvals_satisfied {
            Ok(())
        } else {
            Err(GitHubError::ReviewsInsufficient)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIssue {
    pub issue_number: u64,
    pub issue_state: String,
    pub base_branch: String,
    pub base_sha: String,
}

/// An operator-pinned log host and its independently supplied public addresses.
/// Construct this only from trusted operator policy, never from a task or database.
#[derive(Clone)]
pub struct TrustedLogDestination {
    hostname: String,
    addresses: Vec<SocketAddr>,
}

impl TrustedLogDestination {
    pub fn new(hostname: &str, addresses: &[IpAddr]) -> Result<Self, GitHubError> {
        let origin = reqwest::Url::parse(&format!("https://{hostname}/"))
            .map_err(|_| GitHubError::InvalidConfiguration)?;
        if origin.host_str() != Some(hostname)
            || !hostname.contains('.')
            || hostname.parse::<IpAddr>().is_ok()
            || hostname.len() > 253
            || hostname.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
            || addresses.is_empty()
            || addresses.len() > MAX_LOG_ADDRESSES
            || addresses.iter().any(|address| !acceptable_log_ip(*address))
        {
            return Err(GitHubError::InvalidConfiguration);
        }
        Ok(Self {
            hostname: hostname.to_owned(),
            addresses: addresses
                .iter()
                .map(|address| SocketAddr::new(*address, 443))
                .collect(),
        })
    }

    fn validate_url(&self, url: &reqwest::Url) -> Result<(), GitHubError> {
        if url.scheme() != "https"
            || url.host_str() != Some(self.hostname.as_str())
            || url.port_or_known_default() != Some(443)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(GitHubError::InvalidResponse);
        }
        Ok(())
    }

    fn client(&self) -> Result<Client, GitHubError> {
        Client::builder()
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(&self.hostname, &self.addresses)
            .build()
            .map_err(|_| GitHubError::InvalidConfiguration)
    }
}

fn acceptable_log_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            (a & 0xe000) == 0x2000
                && !(a == 0x2001 && (b & 0xfe00) == 0)
                && !(a == 0x2001 && b == 0x0db8)
                && a != 0x2002
                && !(a == 0x3fff && (b & 0xf000) == 0)
        }
    }
}

async fn read_bounded_job_log(mut response: Response) -> Result<Vec<u8>, GitHubError> {
    if response.status() != StatusCode::OK {
        return Err(GitHubError::Unavailable);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JOB_LOG_BYTES as u64)
    {
        return Err(GitHubError::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GitHubError::Unavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_JOB_LOG_BYTES {
            return Err(GitHubError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn read_bounded_json<T: for<'de> Deserialize<'de>>(
    mut response: Response,
) -> Result<T, GitHubError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(GitHubError::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GitHubError::Unavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(GitHubError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| GitHubError::InvalidResponse)
}

/// Untrusted log bytes, held only in memory. Access does not make them safe to
/// log, persist, or forward to an agent.
pub struct SensitiveJobLog(Vec<u8>);

impl SensitiveJobLog {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SensitiveJobLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveJobLog([REDACTED])")
    }
}

/// Ephemeral, untrusted Actions diagnostics for one stable PR revision.
/// Names are intentionally omitted from Debug output and this type is not serializable.
#[derive(PartialEq, Eq)]
pub struct FailedActionsEvidence {
    repository: String,
    issue_number: u64,
    pull_number: u64,
    base_sha: String,
    head_sha: String,
    expected_issue: IssueExpectation,
    checks: Vec<FailedCheckActions>,
}

impl FailedActionsEvidence {
    pub fn repository(&self) -> &str {
        &self.repository
    }
    pub fn issue_number(&self) -> u64 {
        self.issue_number
    }
    pub fn pull_number(&self) -> u64 {
        self.pull_number
    }
    pub fn head_sha(&self) -> &str {
        &self.head_sha
    }
    pub fn checks(&self) -> &[FailedCheckActions] {
        &self.checks
    }
}

impl fmt::Debug for FailedActionsEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FailedActionsEvidence")
            .field("repository", &self.repository)
            .field("issue_number", &self.issue_number)
            .field("pull_number", &self.pull_number)
            .field("head_sha", &self.head_sha)
            .field("check_count", &self.checks.len())
            .field("action_text", &"[REDACTED]")
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct FailedCheckActions {
    check_name: String,
    check_run_id: u64,
    check_suite_id: u64,
    run_id: u64,
    run_attempt: u64,
    jobs: Vec<FailedActionJob>,
}

impl FailedCheckActions {
    pub fn check_name(&self) -> &str {
        &self.check_name
    }
    pub fn check_run_id(&self) -> u64 {
        self.check_run_id
    }
    pub fn check_suite_id(&self) -> u64 {
        self.check_suite_id
    }
    pub fn run_id(&self) -> u64 {
        self.run_id
    }
    pub fn run_attempt(&self) -> u64 {
        self.run_attempt
    }
    pub fn jobs(&self) -> &[FailedActionJob] {
        &self.jobs
    }
}

impl fmt::Debug for FailedCheckActions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FailedCheckActions")
            .field("check_run_id", &self.check_run_id)
            .field("check_suite_id", &self.check_suite_id)
            .field("run_id", &self.run_id)
            .field("run_attempt", &self.run_attempt)
            .field("job_count", &self.jobs.len())
            .field("check_name", &"[REDACTED]")
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct FailedActionJob {
    id: u64,
    name: String,
    conclusion: String,
    steps: Vec<FailedActionStep>,
}

impl FailedActionJob {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn conclusion(&self) -> &str {
        &self.conclusion
    }
    pub fn steps(&self) -> &[FailedActionStep] {
        &self.steps
    }
}

impl fmt::Debug for FailedActionJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FailedActionJob")
            .field("id", &self.id)
            .field("conclusion", &self.conclusion)
            .field("step_count", &self.steps.len())
            .field("name", &"[REDACTED]")
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct FailedActionStep {
    number: u64,
    name: String,
    status: String,
    conclusion: Option<String>,
}

impl FailedActionStep {
    pub fn number(&self) -> u64 {
        self.number
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn status(&self) -> &str {
        &self.status
    }
    pub fn conclusion(&self) -> Option<&str> {
        self.conclusion.as_deref()
    }
}

impl fmt::Debug for FailedActionStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FailedActionStep")
            .field("number", &self.number)
            .field("conclusion", &self.conclusion)
            .field("name", &"[REDACTED]")
            .finish()
    }
}

/// Ephemeral, untrusted Issue text; never a source of policy or authority.
pub struct IssueInput {
    pub issue_number: u64,
    pub base_sha: String,
    title: String,
    body: Option<String>,
}

impl IssueInput {
    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn body(&self) -> Option<&str> {
        self.body.as_deref()
    }
}

impl fmt::Debug for IssueInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssueInput")
            .field("issue_number", &self.issue_number)
            .field("base_sha", &self.base_sha)
            .field("text", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitHubError {
    InvalidPolicy,
    InvalidConfiguration,
    InvalidTaskReference,
    Unavailable,
    /// The branch POST may have taken effect; automatic replay is forbidden.
    AmbiguousBranchWrite,
    /// The PR POST may have taken effect; automatic replay is forbidden.
    AmbiguousPullWrite,
    /// The issue-link mutation may have taken effect; automatic replay is forbidden.
    AmbiguousIssueLink,
    /// The issue-close PATCH may have taken effect; automatic replay is forbidden.
    AmbiguousIssueClose,
    /// Closing keywords are only linked automatically for the repository default branch.
    DefaultBranchMismatch,
    InvalidResponse,
    ResponseTooLarge,
    IncompleteEvidence,
    IssueStateMismatch,
    RepositoryMismatch,
    StaleRevision,
    PullStateMismatch,
    ChecksNotSuccessful,
    ReviewsInsufficient,
    AmbiguousCheck,
    IssuePullMismatch,
    PullCandidateNotFound,
    AmbiguousPullCandidate,
    MergeNotOnBase,
}

#[derive(Deserialize)]
struct IssueResponse {
    number: u64,
    state: String,
}

#[derive(serde::Serialize)]
struct CloseIssueRequest {
    state: &'static str,
}

#[derive(serde::Serialize)]
struct CreateRefRequest {
    #[serde(rename = "ref")]
    reference: String,
    sha: String,
}

#[derive(serde::Serialize)]
struct CreatePullRequestRequest {
    title: String,
    body: String,
    head: String,
    base: String,
}

#[derive(Deserialize)]
struct CreateRefResponse {
    #[serde(rename = "ref")]
    reference: String,
    object: CreateRefObject,
}

#[derive(Deserialize)]
struct CreateRefObject {
    sha: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize, PartialEq, Eq)]
struct IssueInputResponse {
    id: u64,
    number: u64,
    state: String,
    updated_at: String,
    title: String,
    #[serde(deserialize_with = "deserialize_issue_body")]
    body: Option<String>,
    #[serde(default, deserialize_with = "field_is_present")]
    pull_request: bool,
}

impl IssueInputResponse {
    fn validate(&self, issue_number: u64) -> Result<(), GitHubError> {
        if self.number != issue_number || self.state != "open" {
            return Err(GitHubError::IssueStateMismatch);
        }
        if self.id == 0
            || self.pull_request
            || self.updated_at.is_empty()
            || self.updated_at.len() > 64
            || self.title.trim().is_empty()
            || self.title.len() > MAX_ISSUE_TITLE_BYTES
            || self.title.contains('\0')
            || self
                .body
                .as_ref()
                .is_some_and(|body| body.len() > MAX_ISSUE_BODY_BYTES || body.contains('\0'))
        {
            return Err(GitHubError::InvalidResponse);
        }
        Ok(())
    }
}

fn deserialize_issue_body<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

fn field_is_present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}
#[derive(Deserialize)]
struct CommitResponse {
    sha: String,
}
#[derive(Deserialize)]
struct RepositoryDefaultBranch {
    default_branch: String,
}
#[derive(Deserialize)]
struct CompareResponse {
    status: String,
}
#[derive(Deserialize)]
struct GraphqlResponse {
    data: Option<GraphqlData>,
    errors: Option<Vec<serde_json::Value>>,
}
#[derive(Deserialize)]
struct GraphqlData {
    repository: Option<GraphqlRepository>,
}

#[derive(Deserialize)]
struct IssueLinkQueryResponse {
    data: Option<IssueLinkQueryData>,
    errors: Option<Vec<serde_json::Value>>,
}
#[derive(Deserialize)]
struct IssueLinkQueryData {
    repository: Option<IssueLinkQueryRepository>,
}
#[derive(Deserialize)]
struct IssueLinkQueryRepository {
    #[serde(rename = "nameWithOwner")]
    name_with_owner: String,
    issue: Option<IssueLinkQueryIssue>,
    #[serde(rename = "pullRequest")]
    pull_request: Option<IssueLinkQueryPull>,
}
#[derive(Deserialize)]
struct IssueLinkQueryIssue {
    id: String,
    number: u64,
    state: String,
}
#[derive(Deserialize)]
struct IssueLinkQueryPull {
    id: String,
    number: u64,
    state: String,
    body: Option<String>,
    #[serde(rename = "headRepository")]
    head_repository: Option<IssueLinkQueryRemoteRepository>,
    #[serde(rename = "baseRepository")]
    base_repository: Option<IssueLinkQueryRemoteRepository>,
    #[serde(rename = "headRefName")]
    head_ref_name: String,
    #[serde(rename = "headRefOid")]
    head_ref_oid: String,
    #[serde(rename = "baseRefName")]
    base_ref_name: String,
    #[serde(rename = "baseRefOid")]
    base_ref_oid: String,
    author: IssueLinkQueryAuthor,
}
#[derive(Deserialize)]
struct IssueLinkQueryRemoteRepository {
    #[serde(rename = "nameWithOwner")]
    name_with_owner: String,
}
#[derive(Deserialize)]
struct IssueLinkQueryAuthor {
    login: String,
}
#[derive(Deserialize)]
struct IssueLinkNodeIds {
    issue_id: String,
    pull_id: String,
}
#[derive(Deserialize)]
struct IssueLinkMutationResponse {
    data: Option<IssueLinkMutationData>,
    errors: Option<Vec<serde_json::Value>>,
}
#[derive(Deserialize)]
struct IssueLinkMutationData {
    #[serde(rename = "addCloseIssueReferences")]
    add_close_issue_references: Option<IssueLinkMutationPayload>,
}
#[derive(Deserialize)]
struct IssueLinkMutationPayload {
    issue: IssueLinkMutationIssue,
    #[serde(rename = "clientMutationId")]
    client_mutation_id: Option<String>,
}
#[derive(Deserialize)]
struct IssueLinkMutationIssue {
    id: String,
}
#[derive(Deserialize)]
struct GraphqlRepository {
    #[serde(rename = "nameWithOwner")]
    name_with_owner: String,
    #[serde(rename = "pullRequest")]
    pull_request: Option<GraphqlPullRequest>,
}
#[derive(Deserialize)]
struct GraphqlPullRequest {
    #[serde(rename = "closingIssuesReferences")]
    closing_issues_references: GraphqlIssueConnection,
}
#[derive(Deserialize)]
struct GraphqlIssueConnection {
    nodes: Vec<GraphqlIssue>,
    #[serde(rename = "pageInfo")]
    page_info: GraphqlPageInfo,
}
#[derive(Deserialize)]
struct GraphqlIssue {
    number: u64,
    repository: GraphqlIssueRepository,
}
#[derive(Deserialize)]
struct GraphqlIssueRepository {
    #[serde(rename = "nameWithOwner")]
    name_with_owner: String,
}
#[derive(Deserialize)]
struct GraphqlPageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
}
#[derive(Deserialize, PartialEq, Eq)]
struct PullCandidateListEntry {
    number: u64,
    #[serde(deserialize_with = "deserialize_issue_body")]
    body: Option<String>,
}
#[derive(Deserialize, PartialEq, Eq)]
struct PullResponse {
    number: u64,
    state: String,
    merged: bool,
    merge_commit_sha: Option<String>,
    body: Option<String>,
    user: ReviewUser,
    base: PullRef,
    head: PullRef,
}
#[derive(Deserialize, PartialEq, Eq)]
struct PullRef {
    #[serde(rename = "ref")]
    ref_name: String,
    sha: String,
    repo: PullRepo,
}
#[derive(Deserialize, PartialEq, Eq)]
struct PullRepo {
    full_name: String,
}
#[derive(Deserialize)]
struct CheckRunsResponse {
    total_count: u64,
    check_runs: Vec<CheckRun>,
}
#[derive(Deserialize)]
struct CombinedStatusResponse {
    total_count: u64,
    statuses: Vec<CommitStatus>,
    sha: String,
}
#[derive(Deserialize)]
struct CommitStatus {
    context: String,
    state: String,
}
#[derive(PartialEq, Eq)]
struct RequiredCiEvidence {
    check_runs: Vec<RequiredCheckRunEvidence>,
    commit_statuses: Vec<RequiredCommitStatusEvidence>,
    status: CiStatus,
}
#[derive(PartialEq, Eq)]
struct RequiredCheckRunEvidence {
    name: String,
    app_id: Option<u64>,
    id: Option<u64>,
    check_suite_id: Option<u64>,
    status: String,
    conclusion: Option<String>,
    ci_status: CiStatus,
}
#[derive(PartialEq, Eq)]
struct RequiredCommitStatusEvidence {
    name: String,
    state: Option<String>,
}

fn classify_check_run(status: &str, conclusion: Option<&str>) -> CiStatus {
    match status {
        "queued" | "in_progress" | "requested" | "waiting" | "pending" => CiStatus::Pending,
        "completed" => match conclusion {
            Some("success") => CiStatus::Passed,
            Some("failure" | "timed_out" | "startup_failure") => CiStatus::Failed,
            _ => CiStatus::Unknown,
        },
        _ => CiStatus::Unknown,
    }
}

fn classify_commit_status(state: &str) -> CiStatus {
    match state {
        "success" => CiStatus::Passed,
        "failure" | "error" => CiStatus::Failed,
        "pending" => CiStatus::Pending,
        _ => CiStatus::Unknown,
    }
}

fn combine_ci_status(check_run: CiStatus, legacy: Option<CiStatus>) -> CiStatus {
    if check_run == CiStatus::Failed || legacy == Some(CiStatus::Failed) {
        CiStatus::Failed
    } else if check_run == CiStatus::Pending || legacy == Some(CiStatus::Pending) {
        CiStatus::Pending
    } else if check_run == CiStatus::Passed
        && legacy.is_none_or(|status| status == CiStatus::Passed)
    {
        CiStatus::Passed
    } else {
        CiStatus::Unknown
    }
}

fn aggregate_ci_status(checks: &[CiStatus]) -> CiStatus {
    if checks.is_empty() {
        CiStatus::Unknown
    } else if checks.contains(&CiStatus::Failed) {
        CiStatus::Failed
    } else if checks.iter().all(|status| *status == CiStatus::Passed) {
        CiStatus::Passed
    } else if checks
        .iter()
        .all(|status| matches!(status, CiStatus::Passed | CiStatus::Pending))
        && checks.contains(&CiStatus::Pending)
    {
        CiStatus::Pending
    } else {
        CiStatus::Unknown
    }
}

#[derive(Deserialize)]
struct CheckRun {
    id: u64,
    name: String,
    status: String,
    conclusion: Option<String>,
    app: CheckApp,
    #[serde(default)]
    check_suite: Option<CheckSuite>,
}
#[derive(Deserialize)]
struct CheckSuite {
    id: u64,
}
#[derive(Deserialize)]
struct CheckApp {
    id: u64,
}

#[derive(Deserialize, PartialEq, Eq)]
struct WorkflowRunsResponse {
    total_count: u64,
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(Deserialize, PartialEq, Eq)]
struct WorkflowRun {
    id: u64,
    run_attempt: u64,
    check_suite_id: u64,
    event: String,
    head_sha: String,
    repository: WorkflowRepository,
    pull_requests: Vec<WorkflowPullRequest>,
}

#[derive(Deserialize, PartialEq, Eq)]
struct WorkflowRepository {
    full_name: String,
}

#[derive(Deserialize, PartialEq, Eq)]
struct WorkflowPullRequest {
    number: u64,
    base: WorkflowPullRef,
    head: WorkflowPullRef,
}

#[derive(Deserialize, PartialEq, Eq)]
struct WorkflowPullRef {
    #[serde(rename = "ref")]
    ref_name: String,
    sha: String,
    repo: WorkflowPullRepository,
}

#[derive(Deserialize, PartialEq, Eq)]
struct WorkflowPullRepository {
    id: u64,
    url: String,
    name: String,
}

#[derive(Deserialize, PartialEq, Eq)]
struct WorkflowJobsResponse {
    total_count: u64,
    jobs: Vec<WorkflowJob>,
}

#[derive(Deserialize, PartialEq, Eq)]
struct WorkflowJob {
    id: u64,
    run_id: u64,
    #[serde(default)]
    run_attempt: Option<u64>,
    head_sha: String,
    check_run_url: String,
    status: String,
    conclusion: String,
    name: String,
    steps: Vec<WorkflowStep>,
}

#[derive(Deserialize, PartialEq, Eq)]
struct WorkflowStep {
    number: u64,
    name: String,
    status: String,
    conclusion: Option<String>,
}
#[derive(Deserialize)]
struct ReviewResponse {
    id: u64,
    state: String,
    commit_id: String,
    submitted_at: String,
    user: ReviewUser,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReviewDecision {
    user_id: u64,
    id: u64,
    state: String,
    commit_id: String,
    submitted_at: String,
}
#[derive(Deserialize, PartialEq, Eq)]
struct ReviewUser {
    login: String,
    id: u64,
}

fn latest_review_decisions(
    reviews: &[ReviewResponse],
) -> Result<BTreeMap<u64, ReviewDecision>, GitHubError> {
    let mut latest = BTreeMap::new();
    for review in reviews {
        if review.user.id == 0 {
            return Err(GitHubError::InvalidResponse);
        }
        let decision = ReviewDecision {
            user_id: review.user.id,
            id: review.id,
            state: review.state.clone(),
            commit_id: review.commit_id.clone(),
            submitted_at: review.submitted_at.clone(),
        };
        if latest
            .get(&review.user.id)
            .is_none_or(|current: &ReviewDecision| {
                (current.submitted_at.as_str(), current.id)
                    < (decision.submitted_at.as_str(), decision.id)
            })
        {
            latest.insert(review.user.id, decision);
        }
    }
    Ok(latest)
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && value != "."
        && value != ".."
}
fn valid_repository(value: &str) -> bool {
    let mut parts = value.split('/');
    parts.next().is_some_and(valid_component)
        && parts.next().is_some_and(valid_component)
        && parts.next().is_none()
}
fn valid_branch(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.starts_with('-')
        && !value.contains("..")
        && !value.contains("//")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
}
fn valid_branch_prefix(value: &str) -> bool {
    valid_branch(value)
}

fn validate_pull_candidate(
    pull: &PullResponse,
    expected_base_sha: &str,
    expected_branch: &str,
    expected_head_sha: &str,
    marker: &str,
    policy: &GitHubPolicy,
) -> Result<(), GitHubError> {
    if pull.number == 0
        || pull.user.id == 0
        || pull.base.repo.full_name != policy.repository
        || pull.head.repo.full_name != policy.head_repository
        || pull.base.ref_name != policy.base_branch
        || pull.head.ref_name != expected_branch
        || !pull.user.login.eq_ignore_ascii_case(&policy.pull_author)
        || pull.state != "open"
        || pull.merged
        || pull
            .body
            .as_deref()
            .is_none_or(|body| body.matches(marker).count() != 1)
    {
        return Err(GitHubError::RepositoryMismatch);
    }
    if !valid_sha(&pull.base.sha)
        || !pull.base.sha.eq_ignore_ascii_case(expected_base_sha)
        || !valid_sha(&pull.head.sha)
        || !pull.head.sha.eq_ignore_ascii_case(expected_head_sha)
    {
        return Err(GitHubError::StaleRevision);
    }
    Ok(())
}

fn valid_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn has_unique_operation_marker(body: Option<&str>, operation_id: uuid::Uuid) -> bool {
    let Some(body) = body else {
        return false;
    };
    let marker = format!("<!-- mipsorcu-operation:{operation_id} -->");
    body.matches("<!-- mipsorcu-operation:").count() == 1 && body.matches(&marker).count() == 1
}
fn valid_untrusted_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ACTION_NAME_BYTES && !value.contains('\0')
}
fn valid_action_steps(steps: &[WorkflowStep]) -> bool {
    if steps.len() > MAX_ACTION_STEPS {
        return false;
    }
    let mut previous = 0;
    for step in steps {
        let state_valid = step.status == "completed"
            && step
                .conclusion
                .as_deref()
                .is_some_and(valid_step_conclusion);
        if step.number <= previous || !valid_untrusted_name(&step.name) || !state_valid {
            return false;
        }
        previous = step.number;
    }
    true
}
fn valid_step_conclusion(value: &str) -> bool {
    matches!(
        value,
        "success"
            | "failure"
            | "neutral"
            | "cancelled"
            | "skipped"
            | "timed_out"
            | "action_required"
    )
}
fn select_failed_action_job(
    jobs: WorkflowJobsResponse,
    check_run_url: &str,
    run: &WorkflowRun,
    head_sha: &str,
) -> Result<WorkflowJob, GitHubError> {
    if u64::try_from(jobs.jobs.len()).ok() != Some(jobs.total_count) || jobs.jobs.len() > 100 {
        return Err(GitHubError::IncompleteEvidence);
    }
    let mut job_ids = std::collections::BTreeSet::new();
    if jobs
        .jobs
        .iter()
        .any(|job| job.id == 0 || !job_ids.insert(job.id))
    {
        return Err(GitHubError::IncompleteEvidence);
    }
    let mut matching = jobs
        .jobs
        .into_iter()
        .filter(|job| job.check_run_url == check_run_url);
    let job = matching.next().ok_or(GitHubError::IncompleteEvidence)?;
    if matching.next().is_some()
        || job.run_id != run.id
        || job
            .run_attempt
            .is_some_and(|attempt| attempt != run.run_attempt)
        || !job.head_sha.eq_ignore_ascii_case(head_sha)
        || job.status != "completed"
        || !matches!(job.conclusion.as_str(), "failure" | "timed_out")
        || !valid_untrusted_name(&job.name)
        || !valid_action_steps(&job.steps)
    {
        return Err(GitHubError::IncompleteEvidence);
    }
    Ok(job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::{Child, Command},
        thread,
    };

    fn mock(responses: Vec<&'static str>) -> (String, thread::JoinHandle<()>) {
        mock_with_status("200 OK", responses)
    }

    fn mock_with_status(
        status: &'static str,
        responses: Vec<&'static str>,
    ) -> (String, thread::JoinHandle<()>) {
        mock_with_headers(
            status,
            responses.into_iter().map(|body| (body, "")).collect(),
        )
    }

    fn mock_with_headers(
        status: &'static str,
        responses: Vec<(&'static str, &'static str)>,
    ) -> (String, thread::JoinHandle<()>) {
        mock_sequence(
            responses
                .into_iter()
                .map(|(body, headers)| (status, body, headers))
                .collect(),
            false,
        )
    }

    fn mock_sequence(
        responses: Vec<(&'static str, &'static str, &'static str)>,
        check_log_request: bool,
    ) -> (String, thread::JoinHandle<()>) {
        mock_sequence_checked(responses, check_log_request, None)
    }

    fn mock_sequence_checked(
        responses: Vec<(&'static str, &'static str, &'static str)>,
        check_log_request: bool,
        expected_requests: Option<Vec<&'static str>>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let mock_address = address.clone();
        let worker = thread::spawn(move || {
            for (index, (status, body, headers)) in responses.into_iter().enumerate() {
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() >= deadline {
                                return;
                            }
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                };
                let body = body.replace("__API_ROOT__", &mock_address);
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    let length = stream.read(&mut chunk).unwrap();
                    assert!(length > 0);
                    request.extend_from_slice(&chunk[..length]);
                    assert!(request.len() <= 16_384);
                    let Some(header_end) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                if let Some(expected) = expected_requests.as_ref() {
                    let request_text = String::from_utf8_lossy(&request);
                    let request_line = request_text.lines().next().unwrap_or_default();
                    assert_eq!(Some(request_line), expected.get(index).copied());
                    if request_line.starts_with("PATCH /repos/org/repo/issues/") {
                        let body_start = request
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .expect("request headers should be complete")
                            + 4;
                        let body: serde_json::Value =
                            serde_json::from_slice(&request[body_start..]).unwrap();
                        assert_eq!(body["state"], "closed");
                    }
                    if request_line.starts_with("POST /graphql ") {
                        assert!(request_text.contains("\"query\":\"query("));
                        assert!(!request_text.contains("\"query\":\"mutation"));
                    }
                }
                if check_log_request && status != "200 OK" {
                    let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
                    assert!(request.starts_with("get /repos/org/repo/actions/jobs/999/logs "));
                    assert!(request.contains("\r\nauthorization: bearer test-token\r\n"));
                }
                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    headers,
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (address, worker)
    }

    fn policy() -> GitHubPolicy {
        GitHubPolicy::new(
            "org/repo",
            "develop",
            "org/repo",
            "orchestrator-",
            "bot",
            vec![RequiredCheck::new("ci", 4).unwrap()],
            1,
        )
        .unwrap()
    }

    fn branch_policy(head_repository: &str, head_ref_prefix: &str) -> GitHubPolicy {
        GitHubPolicy::new(
            "org/repo",
            "develop",
            head_repository,
            head_ref_prefix,
            "bot",
            vec![RequiredCheck::new("ci", 4).unwrap()],
            1,
        )
        .unwrap()
    }

    fn branch_permit() -> BranchWritePermit {
        BranchWritePermit::synthetic(
            uuid::Uuid::from_u128(1),
            uuid::Uuid::from_u128(2),
            5,
            7,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
    }

    fn pull_request_permit() -> PullRequestWritePermit {
        PullRequestWritePermit::synthetic(
            uuid::Uuid::from_u128(1),
            uuid::Uuid::from_u128(2),
            5,
            7,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
    }

    fn branch_server(
        base_sha: &'static str,
        issue_body: &'static str,
        post_response: Option<(&'static str, String)>,
    ) -> (
        String,
        thread::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let post_count = Arc::new(AtomicUsize::new(0));
        let worker_count = Arc::clone(&post_count);
        let worker = thread::spawn(move || {
            let task_id = uuid::Uuid::from_u128(1);
            for index in 0..5 {
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() >= deadline {
                                return;
                            }
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    let length = stream.read(&mut chunk).unwrap();
                    assert!(length > 0);
                    request.extend_from_slice(&chunk[..length]);
                    let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let request_text = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = request_text
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                let request_text = String::from_utf8_lossy(&request);
                let request_line = request_text.lines().next().unwrap_or_default();
                let body_start = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let body = &request[body_start..];
                let (status, response_body) = match index {
                    0 | 3 => {
                        assert_eq!(request_line, "GET /repos/org/repo/commits/develop HTTP/1.1");
                        ("200 OK", format!(r#"{{"sha":"{base_sha}"}}"#))
                    }
                    1 | 2 => {
                        assert_eq!(request_line, "GET /repos/org/repo/issues/5 HTTP/1.1");
                        ("200 OK", issue_body.to_owned())
                    }
                    _ => {
                        worker_count.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(request_line, "POST /repos/org/repo/git/refs HTTP/1.1");
                        let json: serde_json::Value = serde_json::from_slice(body).unwrap();
                        assert_eq!(json["ref"], format!("refs/heads/orchestrator/{task_id}"));
                        assert_eq!(json["sha"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                        let Some((status, response_body)) = post_response.as_ref() else {
                            drop(stream);
                            observe_followup_posts(&listener, &worker_count);
                            return;
                        };
                        (*status, response_body.clone())
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                    response_body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
            observe_followup_posts(&listener, &worker_count);
        });
        (address, worker, post_count)
    }

    fn pull_request_server(
        base_sha: &'static str,
        branch_sha: &'static str,
        default_branch: &'static str,
        issue_response: &'static str,
        post_status: Option<&'static str>,
        closes_issue: bool,
    ) -> (
        String,
        thread::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let post_count = Arc::new(AtomicUsize::new(0));
        let worker_count = Arc::clone(&post_count);
        let worker = thread::spawn(move || {
            let task_id = uuid::Uuid::from_u128(1);
            let operation_id = uuid::Uuid::from_u128(2);
            let marker = format!("<!-- mipsorcu-operation:{operation_id} -->");
            let actual_default_branch = default_branch.split(':').next().unwrap_or(default_branch);
            let body = if actual_default_branch == "develop" {
                format!("Closes #5\n\n{marker}")
            } else {
                marker.clone()
            };
            let branch = format!("orchestrator/{task_id}");
            let pull = format!(
                r#"{{"number":7,"state":"open","merged":false,"merge_commit_sha":null,"body":{},"user":{{"login":"bot","id":9}},"base":{{"ref":"develop","sha":"{base_sha}","repo":{{"full_name":"org/repo"}}}},"head":{{"ref":"{branch}","sha":"{branch_sha}","repo":{{"full_name":"org/repo"}}}}}}"#,
                serde_json::to_string(&body).unwrap()
            );
            loop {
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() >= deadline {
                                return;
                            }
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    let Ok(length) = stream.read(&mut chunk) else {
                        return;
                    };
                    if length == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..length]);
                    if request.len() > 16_384 {
                        return;
                    }
                    let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                let header_end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                let request_headers = String::from_utf8_lossy(&request[..header_end]);
                let request_line = request_headers.lines().next().unwrap_or_default();
                let request_body = &request[header_end + 4..];
                let (status, response_body) = match request_line {
                    "GET /repos/org/repo HTTP/1.1" => (
                        "200 OK",
                        format!(r#"{{"default_branch":"{actual_default_branch}"}}"#),
                    ),
                    "GET /repos/org/repo/commits/develop HTTP/1.1" => {
                        ("200 OK", format!(r#"{{"sha":"{base_sha}"}}"#))
                    }
                    "GET /repos/org/repo/issues/5 HTTP/1.1" => {
                        ("200 OK", issue_response.to_owned())
                    }
                    request_line
                        if request_line
                            == format!("GET /repos/org/repo/git/ref/heads/{branch} HTTP/1.1") =>
                    {
                        (
                            "200 OK",
                            format!(
                                r#"{{"ref":"refs/heads/{branch}","object":{{"sha":"{branch_sha}","type":"commit"}}}}"#
                            ),
                        )
                    }
                    "POST /repos/org/repo/pulls HTTP/1.1" => {
                        worker_count.fetch_add(1, Ordering::SeqCst);
                        let Ok(json) = serde_json::from_slice::<serde_json::Value>(request_body)
                        else {
                            return;
                        };
                        assert_eq!(json["title"], "Task for issue #5");
                        assert_eq!(json["body"], body);
                        assert_eq!(json["head"], branch);
                        assert_eq!(json["base"], "develop");
                        let Some(status) = post_status else {
                            drop(stream);
                            observe_followup_posts(&listener, &worker_count);
                            return;
                        };
                        if status != "201 Created" {
                            (status, "{}".to_owned())
                        } else {
                            (status, pull.clone())
                        }
                    }
                    request_line
                        if request_line.starts_with("GET /repos/org/repo/pulls?")
                            && request_line.contains("state=all")
                            && request_line.contains("head=org%3Aorchestrator%2F")
                            && request_line.contains("base=develop")
                            && request_line.contains("per_page=100") =>
                    {
                        (
                            "200 OK",
                            format!(
                                r#"[{{"number":7,"body":{}}}]"#,
                                serde_json::to_string(&body).unwrap()
                            ),
                        )
                    }
                    "GET /repos/org/repo/pulls/7 HTTP/1.1" => ("200 OK", pull.clone()),
                    "POST /graphql HTTP/1.1" => {
                        let request: serde_json::Value =
                            serde_json::from_slice(request_body).unwrap();
                        let query = request["query"].as_str().unwrap_or_default();
                        if query.contains("addCloseIssueReferences") {
                            worker_count.fetch_add(1, Ordering::SeqCst);
                            if default_branch == "main:ambiguous-link" {
                                drop(stream);
                                observe_followup_posts(&listener, &worker_count);
                                return;
                            }
                            if default_branch == "main:mutation-missing-payload" {
                                ("200 OK", r#"{"data":{}}"#.to_owned())
                            } else if default_branch == "main:mutation-partial-errors" {
                                (
                                    "200 OK",
                                    format!(
                                        r#"{{"data":{{"addCloseIssueReferences":{{"issue":{{"id":"ISSUE_NODE_5"}},"clientMutationId":"{}"}}}},"errors":[{{"message":"partial"}}]}}"#,
                                        request["variables"]["input"]["clientMutationId"]
                                            .as_str()
                                            .unwrap_or_default()
                                    ),
                                )
                            } else if default_branch == "main:mutation-missing-correlation" {
                                (
                                    "200 OK",
                                    r#"{"data":{"addCloseIssueReferences":{"issue":{"id":"ISSUE_NODE_5"},"clientMutationId":null}}}"#.to_owned(),
                                )
                            } else if default_branch == "main:mutation-wrong-correlation" {
                                (
                                    "200 OK",
                                    r#"{"data":{"addCloseIssueReferences":{"issue":{"id":"ISSUE_NODE_5"},"clientMutationId":"wrong"}}}"#.to_owned(),
                                )
                            } else {
                                let client_mutation_id =
                                    request["variables"]["input"]["clientMutationId"]
                                        .as_str()
                                        .unwrap_or_default();
                                let returned_issue_id = if default_branch == "main:foreign-issue-id"
                                {
                                    "ISSUE_NODE_FOREIGN"
                                } else {
                                    "ISSUE_NODE_5"
                                };
                                (
                                    "200 OK",
                                    format!(
                                        r#"{{"data":{{"addCloseIssueReferences":{{"issue":{{"id":"{returned_issue_id}"}},"clientMutationId":"{client_mutation_id}"}}}}}}"#
                                    ),
                                )
                            }
                        } else if query.contains("issue(number:$issue)") {
                            let repo_name = if default_branch == "main:foreign-repository" {
                                "org/foreign"
                            } else {
                                "org/repo"
                            };
                            let head_sha = if default_branch == "main:wrong-head" {
                                "cccccccccccccccccccccccccccccccccccccccc"
                            } else {
                                branch_sha
                            };
                            let head_repository = if default_branch == "main:fork-head" {
                                "org/fork"
                            } else {
                                "org/repo"
                            };
                            let base_repository = if default_branch == "main:wrong-base-repository"
                            {
                                "org/other"
                            } else {
                                "org/repo"
                            };
                            let (issue_id, pull_id) = match default_branch {
                                "main:missing-issue-id" => ("", "PULL_NODE_7"),
                                "main:missing-pull-id" => ("ISSUE_NODE_5", ""),
                                _ => ("ISSUE_NODE_5", "PULL_NODE_7"),
                            };
                            let issue_json = match default_branch {
                                "main:missing-issue" => "null".to_owned(),
                                "main:wrong-issue" => {
                                    r#"{"id":"ISSUE_NODE_6","number":6,"state":"OPEN"}"#.to_owned()
                                }
                                _ => format!(r#"{{"id":"{issue_id}","number":5,"state":"OPEN"}}"#),
                            };
                            (
                                "200 OK",
                                format!(
                                    r#"{{"data":{{"repository":{{"nameWithOwner":"{repo_name}","issue":{issue_json},"pullRequest":{{"id":"{pull_id}","number":7,"state":"OPEN","body":{},"headRepository":{{"nameWithOwner":"{head_repository}"}},"baseRepository":{{"nameWithOwner":"{base_repository}"}},"headRefName":"{branch}","headRefOid":"{head_sha}","baseRefName":"develop","baseRefOid":"{base_sha}","author":{{"login":"bot"}}}}}}}}}}"#,
                                    serde_json::to_string(&body).unwrap(),
                                ),
                            )
                        } else {
                            let nodes = if closes_issue {
                                r#"[{"number":5,"repository":{"nameWithOwner":"org/repo"}}]"#
                            } else {
                                "[]"
                            };
                            (
                                "200 OK",
                                format!(
                                    r#"{{"data":{{"repository":{{"nameWithOwner":"org/repo","pullRequest":{{"closingIssuesReferences":{{"nodes":{nodes},"pageInfo":{{"hasNextPage":false}}}}}}}}}}}}"#
                                ),
                            )
                        }
                    }
                    _ => return,
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                    response_body.len()
                );
                if stream.write_all(response.as_bytes()).is_err() {
                    return;
                }
                if request_line == "POST /repos/org/repo/pulls HTTP/1.1" && status != "201 Created"
                {
                    observe_followup_posts(&listener, &worker_count);
                    return;
                }
            }
        });
        (address, worker, post_count)
    }

    fn observe_followup_posts(listener: &TcpListener, post_count: &std::sync::atomic::AtomicUsize) {
        use std::sync::atomic::Ordering;

        // This finite window catches immediate client replays, not later external retries.
        let deadline = std::time::Instant::now() + Duration::from_millis(200);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .unwrap();
                    let mut request = [0_u8; 2048];
                    let length = stream.read(&mut request).unwrap_or(0);
                    if String::from_utf8_lossy(&request[..length]).starts_with("POST ") {
                        post_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    }

    #[test]
    fn log_destination_rejects_untrusted_hosts_addresses_and_redirects() {
        let public: IpAddr = "1.1.1.1".parse().unwrap();
        let destination = TrustedLogDestination::new("logs.example", &[public]).unwrap();
        for host in [
            "localhost",
            "LOGS.example",
            "user@logs.example",
            "logs.example:443",
            "-bad.example",
            "1.1.1.1",
        ] {
            assert!(
                TrustedLogDestination::new(host, &[public]).is_err(),
                "{host}"
            );
        }
        for ip in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
        ] {
            assert!(
                TrustedLogDestination::new("logs.example", &[ip.parse().unwrap()]).is_err(),
                "{ip}"
            );
        }
        assert!(TrustedLogDestination::new("logs.example", &[]).is_err());
        assert!(
            TrustedLogDestination::new("logs.example", &[public, "127.0.0.1".parse().unwrap()])
                .is_err()
        );
        assert!(
            TrustedLogDestination::new("logs.example", &["2606:4700:4700::1111".parse().unwrap()])
                .is_ok()
        );
        for value in [
            "http://logs.example/path",
            "https://other.example/path",
            "https://logs.example:444/path",
            "https://user@logs.example/path",
            "https://logs.example/path#fragment",
        ] {
            assert!(
                destination
                    .validate_url(&reqwest::Url::parse(value).unwrap())
                    .is_err(),
                "{value}"
            );
        }
        assert!(
            destination
                .validate_url(
                    &reqwest::Url::parse("https://logs.example/path?signature=redacted").unwrap()
                )
                .is_ok()
        );
    }

    #[tokio::test]
    async fn job_log_is_bounded_and_redacted() {
        let (root, worker) = mock(vec!["confidential log"]);
        let response = Client::new().get(&root).send().await.unwrap();
        let log = SensitiveJobLog(read_bounded_job_log(response).await.unwrap());
        worker.join().unwrap();
        assert_eq!(log.as_bytes(), b"confidential log");
        assert!(!format!("{log:?}").contains("confidential"));

        let oversized = Box::leak("x".repeat(MAX_JOB_LOG_BYTES + 1).into_boxed_str());
        let (root, worker) = mock(vec![oversized]);
        let response = Client::new().get(&root).send().await.unwrap();
        assert_eq!(
            read_bounded_job_log(response).await,
            Err(GitHubError::ResponseTooLarge)
        );
        // The reader may close the connection as soon as the oversized length is known.
        let _ = worker.join();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let root = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let chunk = vec![b'x'; 65536];
            for _ in 0..17 {
                if stream
                    .write_all(b"10000\r\n")
                    .and_then(|()| stream.write_all(&chunk))
                    .and_then(|()| stream.write_all(b"\r\n"))
                    .is_err()
                {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        let response = Client::new().get(&root).send().await.unwrap();
        assert_eq!(
            read_bounded_job_log(response).await,
            Err(GitHubError::ResponseTooLarge)
        );
        worker.join().unwrap();

        let (root, worker) = mock_with_status("302 Found", vec![""]);
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = client.get(&root).send().await.unwrap();
        assert_eq!(
            read_bounded_job_log(response).await,
            Err(GitHubError::Unavailable)
        );
        worker.join().unwrap();
    }
    fn issue() -> &'static str {
        r#"{"number":5,"state":"open"}"#
    }
    fn base() -> &'static str {
        r#"{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
    }
    fn advanced_base() -> &'static str {
        r#"{"sha":"cccccccccccccccccccccccccccccccccccccccc"}"#
    }
    fn later_base() -> &'static str {
        r#"{"sha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}"#
    }
    fn pull() -> &'static str {
        r#"{"number":7,"state":"open","merged":false,"merge_commit_sha":null,"user":{"login":"bot","id":10},"base":{"ref":"develop","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"full_name":"org/repo"}},"head":{"ref":"orchestrator-0123","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"org/repo"}}}"#
    }
    fn merged_pull() -> &'static str {
        r#"{"number":7,"state":"closed","merged":true,"merge_commit_sha":"dddddddddddddddddddddddddddddddddddddddd","user":{"login":"bot","id":10},"base":{"ref":"develop","sha":"cccccccccccccccccccccccccccccccccccccccc","repo":{"full_name":"org/repo"}},"head":{"ref":"orchestrator-0123","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"org/repo"}}}"#
    }
    fn close_adapter() -> GitHubPolicy {
        GitHubPolicy::new(
            "org/repo",
            "develop",
            "org/repo",
            "orchestrator",
            "bot",
            vec![RequiredCheck::new("ci", 4).unwrap()],
            1,
        )
        .unwrap()
    }
    fn close_pull(task_id: uuid::Uuid, operation_id: uuid::Uuid) -> &'static str {
        close_pull_with_body(
            task_id,
            &format!("<!-- mipsorcu-operation:{operation_id} -->"),
        )
    }
    fn close_pull_with_body(task_id: uuid::Uuid, body: &str) -> &'static str {
        close_pull_with_identity(
            task_id,
            body,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "dddddddddddddddddddddddddddddddddddddddd",
        )
    }
    fn close_pull_with_identity(
        task_id: uuid::Uuid,
        body: &str,
        head_sha: &str,
        merge_sha: &str,
    ) -> &'static str {
        let body = serde_json::to_string(body).unwrap();
        Box::leak(
            format!(
                r#"{{"number":7,"state":"closed","merged":true,"merge_commit_sha":"{merge_sha}","body":{body},"user":{{"login":"bot","id":10}},"base":{{"ref":"develop","sha":"cccccccccccccccccccccccccccccccccccccccc","repo":{{"full_name":"org/repo"}}}},"head":{{"ref":"orchestrator/{task_id}","sha":"{head_sha}","repo":{{"full_name":"org/repo"}}}}}}"#
            )
            .into_boxed_str(),
        )
    }
    fn close_observation(
        issue_response: &'static str,
        pull_response: &'static str,
    ) -> Vec<&'static str> {
        vec![
            advanced_base(),
            issue_response,
            pull_response,
            linked_issue(),
            r#"{"status":"identical"}"#,
            checks(),
            empty_statuses(),
            reviews(),
            pull_response,
            issue_response,
            advanced_base(),
            r#"{"status":"identical"}"#,
            checks(),
            empty_statuses(),
            reviews(),
            linked_issue(),
            r#"{"status":"ahead"}"#,
        ]
    }
    fn close_observation_requests() -> Vec<&'static str> {
        vec![
            "GET /repos/org/repo/commits/develop HTTP/1.1",
            "GET /repos/org/repo/issues/5 HTTP/1.1",
            "GET /repos/org/repo/pulls/7 HTTP/1.1",
            "POST /graphql HTTP/1.1",
            "GET /repos/org/repo/compare/dddddddddddddddddddddddddddddddddddddddd...cccccccccccccccccccccccccccccccccccccccc HTTP/1.1",
            "GET /repos/org/repo/commits/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/check-runs?per_page=100 HTTP/1.1",
            "GET /repos/org/repo/commits/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/status?per_page=100 HTTP/1.1",
            "GET /repos/org/repo/pulls/7/reviews?per_page=100 HTTP/1.1",
            "GET /repos/org/repo/pulls/7 HTTP/1.1",
            "GET /repos/org/repo/issues/5 HTTP/1.1",
            "GET /repos/org/repo/commits/develop HTTP/1.1",
            "GET /repos/org/repo/compare/dddddddddddddddddddddddddddddddddddddddd...cccccccccccccccccccccccccccccccccccccccc HTTP/1.1",
            "GET /repos/org/repo/commits/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/check-runs?per_page=100 HTTP/1.1",
            "GET /repos/org/repo/commits/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/status?per_page=100 HTTP/1.1",
            "GET /repos/org/repo/pulls/7/reviews?per_page=100 HTTP/1.1",
            "POST /graphql HTTP/1.1",
            "GET /repos/org/repo/compare/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...cccccccccccccccccccccccccccccccccccccccc HTTP/1.1",
        ]
    }
    fn close_observation_requests_for(base_sha: &'static str) -> Vec<&'static str> {
        let mut requests = close_observation_requests();
        let comparison = Box::leak(
            format!(
                "GET /repos/org/repo/compare/dddddddddddddddddddddddddddddddddddddddd...{base_sha} HTTP/1.1"
            )
            .into_boxed_str(),
        );
        requests[4] = comparison;
        requests[11] = comparison;
        requests
    }
    fn closed_issue() -> &'static str {
        r#"{"number":5,"state":"closed"}"#
    }
    fn linked_issue() -> &'static str {
        r#"{"data":{"repository":{"nameWithOwner":"org/repo","pullRequest":{"closingIssuesReferences":{"nodes":[{"number":5,"repository":{"nameWithOwner":"org/repo"}}],"pageInfo":{"hasNextPage":false}}}}}}"#
    }
    fn checks() -> &'static str {
        r#"{"total_count":1,"check_runs":[{"id":10,"name":"ci","status":"completed","conclusion":"success","app":{"id":4}}]}"#
    }
    fn failed_checks() -> &'static str {
        r#"{"total_count":1,"check_runs":[{"id":10,"name":"ci","status":"completed","conclusion":"failure","app":{"id":4},"check_suite":{"id":55}}]}"#
    }
    fn empty_statuses() -> &'static str {
        r#"{"state":"pending","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","total_count":0,"statuses":[]}"#
    }
    fn successful_status() -> &'static str {
        r#"{"state":"success","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","total_count":1,"statuses":[{"context":"ci","state":"success"}]}"#
    }
    fn reviews() -> &'static str {
        r#"[{"id":1,"state":"APPROVED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:00:00Z","user":{"login":"reviewer","id":20}}]"#
    }
    fn hundred_reviews() -> &'static str {
        Box::leak(format!("[{}]", (0..100).map(|index| format!(
            r#"{{"id":{},"state":"COMMENTED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:00:00Z","user":{{"login":"reviewer-{}","id":{}}}}}"#,
            index + 1, index + 1, index + 20
        )).collect::<Vec<_>>().join(",")).into_boxed_str())
    }
    fn actions_run() -> &'static str {
        r#"{"total_count":1,"workflow_runs":[{"id":77,"run_attempt":2,"check_suite_id":55,"event":"pull_request","head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repository":{"full_name":"org/repo"},"pull_requests":[{"number":7,"base":{"ref":"develop","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"id":1,"url":"__API_ROOT__/repos/org/repo","name":"repo"}},"head":{"ref":"orchestrator-0123","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"id":1,"url":"__API_ROOT__/repos/org/repo","name":"repo"}}}]}]}"#
    }
    fn actions_run_target() -> &'static str {
        Box::leak(
            actions_run()
                .replace(
                    "\"event\":\"pull_request\"",
                    "\"event\":\"pull_request_target\"",
                )
                .into_boxed_str(),
        )
    }
    fn actions_jobs() -> &'static str {
        r#"{"total_count":1,"jobs":[{"id":999,"run_id":77,"run_attempt":2,"head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","check_run_url":"__API_ROOT__/repos/org/repo/check-runs/10","status":"completed","conclusion":"failure","name":"build job","steps":[{"number":1,"name":"setup","status":"completed","conclusion":"success"},{"number":2,"name":"test","status":"completed","conclusion":"failure"}]}]}"#
    }
    async fn observe_open_reviews_with(
        initial: &'static str,
        final_reviews: &'static str,
    ) -> Result<ObservedPullRequest, GitHubError> {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            empty_statuses(),
            initial,
            pull(),
            issue(),
            base(),
            checks(),
            empty_statuses(),
            final_reviews,
            linked_issue(),
        ]);
        let result = adapter(&root)
            .observe_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        result
    }
    fn failed_actions_prefix() -> Vec<&'static str> {
        vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            failed_checks(),
            empty_statuses(),
            reviews(),
            pull(),
            issue(),
            base(),
            failed_checks(),
            empty_statuses(),
            reviews(),
            linked_issue(),
            failed_checks(),
            empty_statuses(),
        ]
    }
    fn failed_actions_responses(run: &'static str) -> Vec<&'static str> {
        let mut responses = failed_actions_prefix();
        responses.extend([run, actions_jobs(), actions_jobs(), run]);
        responses.extend([failed_checks(), empty_statuses()]);
        responses.extend([
            base(),
            issue(),
            pull(),
            linked_issue(),
            failed_checks(),
            empty_statuses(),
            reviews(),
            pull(),
            issue(),
            base(),
            failed_checks(),
            empty_statuses(),
            reviews(),
            linked_issue(),
        ]);
        responses
    }
    async fn verify_open_review_change(
        final_reviews: &'static str,
    ) -> Result<VerifiedPullRequest, GitHubError> {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            empty_statuses(),
            reviews(),
            pull(),
            issue(),
            base(),
            checks(),
            empty_statuses(),
            final_reviews,
            linked_issue(),
        ]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        result
    }
    async fn verify_open_reviews(
        reviews: &'static str,
    ) -> Result<VerifiedPullRequest, GitHubError> {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            empty_statuses(),
            reviews,
            pull(),
            issue(),
            base(),
            checks(),
            empty_statuses(),
            reviews,
            linked_issue(),
        ]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        result
    }
    async fn verify_open_statuses(
        initial_statuses: &'static str,
    ) -> Result<VerifiedPullRequest, GitHubError> {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            initial_statuses,
            reviews(),
            pull(),
            issue(),
            base(),
            checks(),
            initial_statuses,
            reviews(),
            linked_issue(),
        ]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        result
    }
    async fn observe_open_ci(
        check_runs: &'static str,
        combined_status: &'static str,
    ) -> Result<ObservedPullRequest, GitHubError> {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            check_runs,
            combined_status,
            reviews(),
            pull(),
            issue(),
            base(),
            check_runs,
            combined_status,
            reviews(),
            linked_issue(),
        ]);
        let result = adapter(&root)
            .observe_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        result
    }
    fn adapter(root: &str) -> GitHubAdapter {
        GitHubAdapter::build(policy(), "test-token", root).unwrap()
    }

    fn operation_marker() -> (uuid::Uuid, String) {
        let id = uuid::Uuid::from_u128(1);
        (id, format!("<!-- mipsorcu-operation:{id} -->"))
    }

    fn candidate_pull(
        number: u64,
        branch: &str,
        base_sha: &str,
        head_sha: &str,
        body: &str,
    ) -> &'static str {
        Box::leak(
            format!(
                r#"{{"number":{number},"state":"open","merged":false,"merge_commit_sha":null,"body":{},"user":{{"login":"bot","id":10}},"base":{{"ref":"develop","sha":"{base_sha}","repo":{{"full_name":"org/repo"}}}},"head":{{"ref":"{branch}","sha":"{head_sha}","repo":{{"full_name":"org/repo"}}}}}}"#,
                serde_json::to_string(body).unwrap()
            )
            .into_boxed_str(),
        )
    }

    fn candidate_list(number: u64, body: &str) -> &'static str {
        Box::leak(
            format!(
                r#"[{{"number":{number},"body":{}}}]"#,
                serde_json::to_string(body).unwrap()
            )
            .into_boxed_str(),
        )
    }

    fn full_candidate_page(body: &str) -> &'static str {
        let entry = candidate_list(7, body);
        let entry = &entry[1..entry.len() - 1];
        let page = format!(
            "[{}]",
            std::iter::repeat_n(entry, 100)
                .collect::<Vec<_>>()
                .join(",")
        );
        Box::leak(page.into_boxed_str())
    }

    fn candidate_lookup_responses(
        pull: &'static str,
        final_pull: &'static str,
        marker: &str,
        final_list: &'static str,
    ) -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("200 OK", base(), ""),
            ("200 OK", issue(), ""),
            ("200 OK", candidate_list(7, marker), ""),
            ("200 OK", final_pull, ""),
            ("200 OK", linked_issue(), ""),
            ("200 OK", final_list, ""),
            ("200 OK", pull, ""),
            ("200 OK", linked_issue(), ""),
            ("200 OK", issue(), ""),
            ("200 OK", base(), ""),
        ]
    }

    #[tokio::test]
    async fn observes_one_stable_pull_request_candidate_without_granting_authority() {
        let (operation_id, marker) = operation_marker();
        let pull = candidate_pull(
            7,
            "orchestrator-0123",
            &"a".repeat(40),
            &"b".repeat(40),
            &marker,
        );
        let responses = candidate_lookup_responses(pull, pull, &marker, candidate_list(7, &marker));
        let (root, worker) = mock_sequence_checked(
            responses,
            false,
            Some(vec![
                "GET /repos/org/repo/commits/develop HTTP/1.1",
                "GET /repos/org/repo/issues/5 HTTP/1.1",
                "GET /repos/org/repo/pulls?state=all&head=org%3Aorchestrator-0123&base=develop&per_page=100 HTTP/1.1",
                "GET /repos/org/repo/pulls/7 HTTP/1.1",
                "POST /graphql HTTP/1.1",
                "GET /repos/org/repo/pulls?state=all&head=org%3Aorchestrator-0123&base=develop&per_page=100 HTTP/1.1",
                "GET /repos/org/repo/pulls/7 HTTP/1.1",
                "POST /graphql HTTP/1.1",
                "GET /repos/org/repo/issues/5 HTTP/1.1",
                "GET /repos/org/repo/commits/develop HTTP/1.1",
            ]),
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Ok(7));
    }

    #[tokio::test]
    async fn candidate_observation_rejects_wrong_identity_and_duplicate_markers() {
        let (operation_id, marker) = operation_marker();
        let wrong = candidate_pull(
            7,
            "orchestrator-other",
            &"a".repeat(40),
            &"b".repeat(40),
            &marker,
        );
        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                ("200 OK", candidate_list(7, &marker), ""),
                ("200 OK", wrong, ""),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::RepositoryMismatch));

        let wrong_number = candidate_pull(
            8,
            "orchestrator-0123",
            &"a".repeat(40),
            &"b".repeat(40),
            &marker,
        );
        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                ("200 OK", candidate_list(7, &marker), ""),
                ("200 OK", wrong_number, ""),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::InvalidResponse));

        let one_entry = candidate_list(7, &marker);
        let two_entry = candidate_list(8, &marker);
        let list = Box::leak(
            format!(
                "[{},{}]",
                &one_entry[1..one_entry.len() - 1],
                &two_entry[1..two_entry.len() - 1]
            )
            .into_boxed_str(),
        );
        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                ("200 OK", list, ""),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::AmbiguousPullCandidate));

        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                ("200 OK", "[]", ""),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::PullCandidateNotFound));

        let list_missing_body = Box::leak(
            format!(
                r#"[{{"number":7}},{{"number":8,"body":{}}}]"#,
                serde_json::to_string(&marker).unwrap()
            )
            .into_boxed_str(),
        );
        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                ("200 OK", list_missing_body, ""),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::InvalidResponse));

        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                ("200 OK", full_candidate_page(&marker), ""),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::IncompleteEvidence));
    }

    #[tokio::test]
    async fn candidate_observation_requires_list_and_detail_bodies_to_match() {
        let (operation_id, marker) = operation_marker();
        let base_sha = "a".repeat(40);
        let head_sha = "b".repeat(40);
        let list_body = format!("{marker}\nlist body");
        let detail_body = format!("{marker}\ndifferent body");
        let detail = candidate_pull(7, "orchestrator-0123", &base_sha, &head_sha, &detail_body);
        let list = candidate_list(7, &list_body);
        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                ("200 OK", list, ""),
                ("200 OK", detail, ""),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &base_sha,
                "orchestrator-0123",
                &head_sha,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::InvalidResponse));

        let first_body = format!("{marker}\nfirst body");
        let changed_body = format!("{marker}\nchanged after recheck");
        let first = candidate_pull(7, "orchestrator-0123", &base_sha, &head_sha, &first_body);
        let latest = candidate_pull(7, "orchestrator-0123", &base_sha, &head_sha, &changed_body);
        let stable_list = candidate_list(7, &first_body);
        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                ("200 OK", stable_list, ""),
                ("200 OK", first, ""),
                ("200 OK", linked_issue(), ""),
                ("200 OK", stable_list, ""),
                ("200 OK", latest, ""),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &base_sha,
                "orchestrator-0123",
                &head_sha,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::StaleRevision));
    }

    #[tokio::test]
    async fn candidate_observation_rejects_pagination_duplicate_body_marker_and_stale_pr() {
        let (operation_id, marker) = operation_marker();
        let one = candidate_pull(
            7,
            "orchestrator-0123",
            &"a".repeat(40),
            &"b".repeat(40),
            &marker,
        );
        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                (
                    "200 OK",
                    candidate_list(7, &marker),
                    "Link: <http://127.0.0.1/next>; rel=\"next\"\r\n",
                ),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::IncompleteEvidence));

        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                (
                    "200 OK",
                    candidate_list(7, &format!("{marker}{marker}")),
                    "",
                ),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::InvalidResponse));

        let changed = candidate_pull(
            7,
            "orchestrator-0123",
            &"a".repeat(40),
            &"c".repeat(40),
            &marker,
        );
        let (root, worker) = mock_sequence(
            vec![
                ("200 OK", base(), ""),
                ("200 OK", issue(), ""),
                ("200 OK", candidate_list(7, &marker), ""),
                ("200 OK", one, ""),
                ("200 OK", linked_issue(), ""),
                ("200 OK", candidate_list(7, &marker), ""),
                ("200 OK", changed, ""),
            ],
            false,
        );
        let result = adapter(&root)
            .observe_pull_request_candidate(
                5,
                operation_id,
                &"a".repeat(40),
                "orchestrator-0123",
                &"b".repeat(40),
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::StaleRevision));
    }

    #[tokio::test]
    async fn api_failure_rejects_evidence_without_exposing_response_body() {
        let (root, worker) = mock_with_status("503 Service Unavailable", vec!["sensitive-fixture"]);
        let result = adapter(&root)
            .verify_issue(5, IssueExpectation::Open, None)
            .await;
        worker.join().unwrap();
        let error = result.unwrap_err();
        assert_eq!(error, GitHubError::Unavailable);
        assert!(!format!("{error:?}").contains("sensitive-fixture"));
    }

    #[tokio::test]
    async fn verifies_current_issue_pull_checks_and_reviews_using_mock_http() {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            empty_statuses(),
            reviews(),
            pull(),
            issue(),
            base(),
            checks(),
            empty_statuses(),
            reviews(),
            linked_issue(),
        ]);
        let verified = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await
            .unwrap();
        worker.join().unwrap();
        assert_eq!(verified.approval_count, 1);
        assert!(verified.approvals_satisfied);
        assert_eq!(verified.require_approvals(), Ok(()));
        assert_eq!(verified.pull_state, PullStatus::Open);
    }

    #[tokio::test]
    async fn rejects_closing_reference_removed_during_final_evidence_refresh() {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            empty_statuses(),
            reviews(),
            pull(),
            issue(),
            base(),
            checks(),
            empty_statuses(),
            reviews(),
            r#"{"data":{"repository":{"nameWithOwner":"org/repo","pullRequest":{"closingIssuesReferences":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}}"#,
        ]);
        let result = adapter(&root)
            .observe_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::StaleRevision));
    }

    #[tokio::test]
    async fn rejects_required_ci_evidence_that_changes_during_final_pr_recheck() {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            successful_status(),
            reviews(),
            pull(),
            issue(),
            base(),
            checks(),
            empty_statuses(),
        ]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert!(matches!(result, Err(GitHubError::StaleRevision)));

        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            successful_status(),
            reviews(),
            pull(),
            issue(),
            base(),
            r#"{"total_count":1,"check_runs":[{"id":11,"name":"ci","status":"completed","conclusion":"failure","app":{"id":4}}]}"#,
        ]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::ChecksNotSuccessful));
    }

    #[tokio::test]
    async fn same_named_legacy_status_must_succeed_but_absent_context_is_allowed() {
        let no_legacy_status = verify_open_statuses(empty_statuses()).await.unwrap();
        assert_eq!(no_legacy_status.pull_state, PullStatus::Open);

        let successful_legacy_status = verify_open_statuses(
            r#"{"state":"success","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","total_count":1,"statuses":[{"context":"ci","state":"success"}]}"#,
        )
        .await;
        assert!(successful_legacy_status.is_ok());

        let case_variant_failure = verify_open_statuses(
            r#"{"state":"failure","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","total_count":1,"statuses":[{"context":"CI","state":"failure"}]}"#,
        )
        .await;
        assert_eq!(case_variant_failure, Err(GitHubError::ChecksNotSuccessful));

        for state in ["failure", "error", "pending"] {
            let body = match state {
                "failure" => {
                    r#"{"state":"failure","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","total_count":1,"statuses":[{"context":"ci","state":"failure"}]}"#
                }
                "error" => {
                    r#"{"state":"failure","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","total_count":1,"statuses":[{"context":"ci","state":"error"}]}"#
                }
                _ => {
                    r#"{"state":"pending","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","total_count":1,"statuses":[{"context":"ci","state":"pending"}]}"#
                }
            };
            assert_eq!(
                verify_open_statuses(body).await,
                Err(GitHubError::ChecksNotSuccessful),
                "legacy status state {state} must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn combined_status_rejects_duplicate_missing_or_stale_evidence() {
        let duplicate = verify_open_statuses(
            r#"{"state":"success","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","total_count":2,"statuses":[{"context":"ci","state":"success"},{"context":"ci","state":"success"}]}"#,
        )
        .await;
        assert_eq!(duplicate, Err(GitHubError::AmbiguousCheck));

        let incomplete = verify_open_statuses(
            r#"{"state":"success","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","total_count":2,"statuses":[{"context":"other","state":"success"}]}"#,
        )
        .await;
        assert_eq!(incomplete, Err(GitHubError::IncompleteEvidence));

        let stale = verify_open_statuses(
            r#"{"state":"success","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","total_count":0,"statuses":[]}"#,
        )
        .await;
        assert_eq!(stale, Err(GitHubError::InvalidResponse));

        let missing = verify_open_statuses(
            r#"{"state":"pending","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","statuses":[]}"#,
        )
        .await;
        assert_eq!(missing, Err(GitHubError::InvalidResponse));
    }

    #[tokio::test]
    async fn combined_status_rejects_pagination_without_fetching_another_page() {
        let (root, worker) = mock_with_headers(
            "200 OK",
            vec![
                (base(), ""),
                (issue(), ""),
                (pull(), ""),
                (linked_issue(), ""),
                (checks(), ""),
                (
                    empty_statuses(),
                    "Link: <http://127.0.0.1/next>; rel=\"next\"\r\n",
                ),
            ],
        );
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::IncompleteEvidence));
    }

    #[tokio::test]
    async fn check_run_pagination_is_incomplete_and_cannot_be_observed_as_passed() {
        let (root, worker) = mock_with_headers(
            "200 OK",
            vec![
                (base(), ""),
                (issue(), ""),
                (pull(), ""),
                (linked_issue(), ""),
                (checks(), "Link: <http://127.0.0.1/next>; rel=next\r\n"),
            ],
        );
        let result = adapter(&root)
            .observe_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::IncompleteEvidence));
    }

    #[tokio::test]
    async fn combined_status_rejects_oversized_response() {
        let oversized = Box::leak(
            format!(
                "{{\"state\":\"success\",\"sha\":\"{}\",\"total_count\":0,\"statuses\":[],\"padding\":\"{}\"}}",
                "b".repeat(40),
                "x".repeat(MAX_RESPONSE_BYTES)
            )
            .into_boxed_str(),
        );
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            oversized,
        ]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::ResponseTooLarge));
    }

    #[tokio::test]
    async fn reports_missing_approval_before_review_but_merge_gate_rejects_it() {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            empty_statuses(),
            "[]",
            pull(),
            issue(),
            base(),
            checks(),
            empty_statuses(),
            "[]",
            linked_issue(),
        ]);
        let verified = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await
            .unwrap();
        worker.join().unwrap();
        assert_eq!(verified.approval_count, 0);
        assert!(!verified.approvals_satisfied);
        assert_eq!(
            verified.require_approvals(),
            Err(GitHubError::ReviewsInsufficient)
        );
    }

    #[tokio::test]
    async fn rejects_review_evidence_at_page_limit_before_and_after_refresh() {
        let page_limit = hundred_reviews();
        assert_eq!(
            observe_open_reviews_with(page_limit, reviews()).await,
            Err(GitHubError::IncompleteEvidence)
        );
        assert_eq!(
            observe_open_reviews_with("[]", page_limit).await,
            Err(GitHubError::IncompleteEvidence)
        );
    }

    #[tokio::test]
    async fn rejects_any_link_header_without_parsing_or_following_it() {
        for headers in [
            "Link: <http://example.invalid/?page=2>; rel=\"next\"\r\n",
            "Link: malformed pagination metadata\r\nLink: <http://example.invalid/>; rel=\"last\"\r\n",
        ] {
            let (root, worker) = mock_with_headers("200 OK", vec![(base(), headers)]);
            let result = adapter(&root)
                .verify_issue(5, IssueExpectation::Open, None)
                .await;
            worker.join().unwrap();
            assert_eq!(result, Err(GitHubError::IncompleteEvidence));
        }
    }

    #[tokio::test]
    async fn reads_failed_actions_job_and_steps_bound_to_run_attempt_and_check_url() {
        for run in [actions_run(), actions_run_target()] {
            let (root, worker) = mock(failed_actions_responses(run));
            let evidence = adapter(&root)
                .read_failed_actions_evidence(
                    5,
                    7,
                    &"a".repeat(40),
                    &"b".repeat(40),
                    IssueExpectation::Open,
                )
                .await
                .unwrap();
            worker.join().unwrap();
            assert_eq!(evidence.repository(), "org/repo");
            assert_eq!(evidence.checks().len(), 1);
            let check = &evidence.checks()[0];
            assert_eq!(check.check_run_id(), 10);
            assert_eq!(check.check_suite_id(), 55);
            assert_eq!(check.run_id(), 77);
            assert_eq!(check.run_attempt(), 2);
            assert_eq!(check.jobs().len(), 1);
            assert_eq!(check.jobs()[0].id(), 999);
            assert_eq!(check.jobs()[0].name(), "build job");
            assert_eq!(check.jobs()[0].steps()[1].name(), "test");
            assert_eq!(check.jobs()[0].steps()[1].conclusion(), Some("failure"));
            let debug = format!("{evidence:?}");
            assert!(!debug.contains("build job"));
            assert!(!debug.contains("setup"));
            assert!(!debug.contains("test"));
        }
    }

    #[tokio::test]
    async fn log_read_rejects_unbound_job_and_changed_actions_before_download() {
        let (root, worker) = mock(failed_actions_responses(actions_run()));
        let mut evidence = adapter(&root)
            .read_failed_actions_evidence(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
            )
            .await
            .unwrap();
        worker.join().unwrap();
        let destination =
            TrustedLogDestination::new("logs.example", &["1.1.1.1".parse().unwrap()]).unwrap();
        assert!(matches!(
            adapter("http://127.0.0.1:1")
                .read_failed_job_log(&evidence, 998, &destination)
                .await,
            Err(GitHubError::InvalidTaskReference)
        ));

        evidence.checks[0].check_name = "changed".to_owned();
        let (root, worker) = mock(failed_actions_responses(actions_run()));
        assert!(matches!(
            adapter(&root)
                .read_failed_job_log(&evidence, 999, &destination)
                .await,
            Err(GitHubError::StaleRevision)
        ));
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn log_read_rejects_invalid_api_redirects_without_following_them() {
        for (status, headers, expected) in [
            ("404 Not Found", "", GitHubError::Unavailable),
            ("302 Found", "", GitHubError::InvalidResponse),
            (
                "302 Found",
                "Location: https://logs.example/a\r\nLocation: https://logs.example/b\r\n",
                GitHubError::InvalidResponse,
            ),
            (
                "302 Found",
                "Location: https://127.0.0.1:0/path\r\n",
                GitHubError::InvalidResponse,
            ),
            (
                "302 Found",
                "Location: https://@logs.example/path\r\n",
                GitHubError::InvalidResponse,
            ),
            (
                "302 Found",
                "Location: https:\t//logs.example/path\r\n",
                GitHubError::InvalidResponse,
            ),
        ] {
            let log_sink = TcpListener::bind("127.0.0.1:0").unwrap();
            log_sink.set_nonblocking(true).unwrap();
            let mut responses = Vec::new();
            for _ in 0..2 {
                responses.extend(
                    failed_actions_responses(actions_run())
                        .into_iter()
                        .map(|body| ("200 OK", body, "")),
                );
            }
            responses.push((status, "", headers));
            let (root, worker) = mock_sequence(responses, true);
            let adapter = adapter(&root);
            let evidence = adapter
                .read_failed_actions_evidence(
                    5,
                    7,
                    &"a".repeat(40),
                    &"b".repeat(40),
                    IssueExpectation::Open,
                )
                .await
                .unwrap();
            let mut destination =
                TrustedLogDestination::new("logs.example", &["1.1.1.1".parse().unwrap()]).unwrap();
            destination.addresses = vec![log_sink.local_addr().unwrap()];
            assert!(
                matches!(adapter.read_failed_job_log(&evidence, 999, &destination).await, Err(error) if error == expected)
            );
            worker.join().unwrap();
            assert!(
                matches!(log_sink.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
        }
    }

    #[tokio::test]
    async fn rejects_missing_or_ambiguous_actions_runs() {
        let run_object = actions_run()
            .strip_prefix(r#"{"total_count":1,"workflow_runs":["#)
            .and_then(|value| value.strip_suffix("]}"))
            .unwrap();
        let multiple_runs = Box::leak(
            format!(r#"{{"total_count":2,"workflow_runs":[{run_object},{run_object}]}}"#)
                .into_boxed_str(),
        );
        let wrong_head = Box::leak(
            actions_run()
                .replace(
                    "\"head_sha\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
                    "\"head_sha\":\"cccccccccccccccccccccccccccccccccccccccc\"",
                )
                .into_boxed_str(),
        );
        let wrong_pull = Box::leak(
            actions_run()
                .replace("\"number\":7", "\"number\":8")
                .into_boxed_str(),
        );
        let wrong_repository_url = Box::leak(
            actions_run()
                .replace(
                    "__API_ROOT__/repos/org/repo",
                    "__API_ROOT__/repos/other/repo",
                )
                .into_boxed_str(),
        );
        let wrong_event = Box::leak(
            actions_run()
                .replace(
                    "\"event\":\"pull_request\"",
                    "\"event\":\"workflow_dispatch\"",
                )
                .into_boxed_str(),
        );
        for response in [
            r#"{"total_count":0,"workflow_runs":[]}"#,
            multiple_runs,
            wrong_head,
            wrong_pull,
            wrong_repository_url,
            wrong_event,
        ] {
            let mut responses = failed_actions_prefix();
            responses.push(response);
            let (root, worker) = mock(responses);
            let result = adapter(&root)
                .read_failed_actions_evidence(
                    5,
                    7,
                    &"a".repeat(40),
                    &"b".repeat(40),
                    IssueExpectation::Open,
                )
                .await;
            worker.join().unwrap();
            assert!(matches!(
                result,
                Err(GitHubError::IncompleteEvidence
                    | GitHubError::RepositoryMismatch
                    | GitHubError::StaleRevision)
            ));
        }
    }

    #[tokio::test]
    async fn rejects_actions_job_page_incomplete_or_wrong_check_binding() {
        for jobs in [
            r#"{"total_count":2,"jobs":[{"id":999,"run_id":77,"head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","check_run_url":"__API_ROOT__/repos/org/repo/check-runs/10","status":"completed","conclusion":"failure","name":"build job","steps":[]}] }"#,
            r#"{"total_count":1,"jobs":[{"id":999,"run_id":77,"head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","check_run_url":"__API_ROOT__/repos/org/repo/check-runs/11","status":"completed","conclusion":"failure","name":"build job","steps":[]}] }"#,
        ] {
            let mut responses = failed_actions_prefix();
            responses.extend([actions_run(), jobs]);
            let (root, worker) = mock(responses);
            let result = adapter(&root)
                .read_failed_actions_evidence(
                    5,
                    7,
                    &"a".repeat(40),
                    &"b".repeat(40),
                    IssueExpectation::Open,
                )
                .await;
            worker.join().unwrap();
            assert!(matches!(result, Err(GitHubError::IncompleteEvidence)));
        }
    }

    #[tokio::test]
    async fn rejects_job_attempt_mismatch_and_invalid_step_metadata() {
        let invalid_jobs = [
            actions_jobs().replace("\"run_attempt\":2", "\"run_attempt\":1"),
            actions_jobs().replace("\"run_id\":77", "\"run_id\":78"),
            actions_jobs().replace(
                "\"head_sha\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
                "\"head_sha\":\"cccccccccccccccccccccccccccccccccccccccc\"",
            ),
            actions_jobs().replace("\"id\":999", "\"id\":0"),
            actions_jobs().replace("\"number\":2", "\"number\":1"),
            actions_jobs().replace(
                "\"status\":\"completed\",\"conclusion\":\"success\"",
                "\"status\":\"in_progress\",\"conclusion\":null",
            ),
            actions_jobs().replace(
                "\"status\":\"completed\",\"conclusion\":\"failure\"}]}]}",
                "\"status\":\"in_progress\",\"conclusion\":\"failure\"}]}]}",
            ),
        ];
        for invalid in invalid_jobs {
            let invalid = Box::leak(invalid.into_boxed_str());
            let mut responses = failed_actions_prefix();
            responses.extend([actions_run(), invalid]);
            let (root, worker) = mock(responses);
            let result = adapter(&root)
                .read_failed_actions_evidence(
                    5,
                    7,
                    &"a".repeat(40),
                    &"b".repeat(40),
                    IssueExpectation::Open,
                )
                .await;
            worker.join().unwrap();
            assert!(matches!(result, Err(GitHubError::IncompleteEvidence)));
        }
    }

    #[tokio::test]
    async fn rejects_selected_job_or_step_changes_during_recheck() {
        for changed in [
            actions_jobs().replace("build job", "changed job"),
            actions_jobs().replace("\"name\":\"test\"", "\"name\":\"changed step\""),
        ] {
            let changed = Box::leak(changed.into_boxed_str());
            let mut responses = failed_actions_prefix();
            responses.extend([actions_run(), actions_jobs(), changed]);
            let (root, worker) = mock(responses);
            let result = adapter(&root)
                .read_failed_actions_evidence(
                    5,
                    7,
                    &"a".repeat(40),
                    &"b".repeat(40),
                    IssueExpectation::Open,
                )
                .await;
            worker.join().unwrap();
            assert!(matches!(result, Err(GitHubError::StaleRevision)));
        }
    }

    #[tokio::test]
    async fn rejects_pagination_on_actions_run_list() {
        let mut responses = failed_actions_prefix()
            .into_iter()
            .map(|body| (body, ""))
            .collect::<Vec<_>>();
        responses.push((actions_run(), "Link: malformed pagination metadata\r\n"));
        let (root, worker) = mock_with_headers("200 OK", responses);
        let result = adapter(&root)
            .read_failed_actions_evidence(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert!(matches!(result, Err(GitHubError::IncompleteEvidence)));
    }

    #[tokio::test]
    async fn latest_review_and_author_exclusion_use_stable_github_user_ids() {
        let changed_login = verify_open_reviews(
            r#"[
                {"id":1,"state":"APPROVED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:00:00Z","user":{"login":"reviewer","id":20}},
                {"id":2,"state":"CHANGES_REQUESTED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:01:00Z","user":{"login":"Reviewer","id":20}}
            ]"#,
        )
        .await
        .unwrap();
        assert_eq!(changed_login.approval_count, 0);
        assert_eq!(
            changed_login.require_approvals(),
            Err(GitHubError::ReviewsInsufficient)
        );

        let author_renamed = verify_open_reviews(
            r#"[{"id":3,"state":"APPROVED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:00:00Z","user":{"login":"old-bot-login","id":10}}]"#,
        )
        .await
        .unwrap();
        assert_eq!(author_renamed.approval_count, 0);
        assert_eq!(
            author_renamed.require_approvals(),
            Err(GitHubError::ReviewsInsufficient)
        );
    }

    #[tokio::test]
    async fn final_review_refresh_rejects_changed_decision_reviewer_or_head() {
        for final_reviews in [
            r#"[{"id":2,"state":"CHANGES_REQUESTED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:01:00Z","user":{"login":"reviewer","id":20}}]"#,
            r#"[{"id":2,"state":"APPROVED","commit_id":"cccccccccccccccccccccccccccccccccccccccc","submitted_at":"2026-11-16T00:01:00Z","user":{"login":"reviewer","id":20}}]"#,
            r#"[{"id":2,"state":"APPROVED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:01:00Z","user":{"login":"new-reviewer","id":21}}]"#,
        ] {
            assert_eq!(
                verify_open_review_change(final_reviews).await,
                Err(GitHubError::StaleRevision)
            );
        }
    }

    #[tokio::test]
    async fn missing_or_zero_github_user_id_rejects_review_evidence() {
        for reviews in [
            r#"[{"id":4,"state":"APPROVED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:00:00Z","user":{"login":"reviewer"}}]"#,
            r#"[{"id":4,"state":"APPROVED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:00:00Z","user":{"login":"reviewer","id":0}}]"#,
        ] {
            assert_eq!(
                verify_open_reviews(reviews).await,
                Err(GitHubError::InvalidResponse)
            );
        }
    }

    #[tokio::test]
    async fn rejects_stale_head_before_check_or_review_requests() {
        let (root, worker) = mock(vec![base(), issue(), pull()]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"c".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::StaleRevision));
    }

    #[tokio::test]
    async fn rejects_a_task_base_sha_that_is_not_the_current_trusted_branch_head() {
        let (root, worker) = mock(vec![advanced_base()]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::StaleRevision));
    }

    #[tokio::test]
    async fn rejects_unsuccessful_required_checks() {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            r#"{"total_count":1,"check_runs":[{"id":10,"name":"ci","status":"completed","conclusion":"failure","app":{"id":4}}]}"#,
        ]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::ChecksNotSuccessful));
    }

    #[tokio::test]
    async fn observes_pending_failed_and_unknown_check_runs_without_validation_proof() {
        for (body, expected) in [
            (
                r#"{"total_count":1,"check_runs":[{"id":10,"name":"ci","status":"in_progress","conclusion":null,"app":{"id":4}}]}"#,
                CiStatus::Pending,
            ),
            (
                r#"{"total_count":1,"check_runs":[{"id":10,"name":"ci","status":"completed","conclusion":"failure","app":{"id":4}}]}"#,
                CiStatus::Failed,
            ),
            (
                r#"{"total_count":1,"check_runs":[{"id":10,"name":"ci","status":"completed","conclusion":"skipped","app":{"id":4}}]}"#,
                CiStatus::Unknown,
            ),
            (r#"{"total_count":0,"check_runs":[]}"#, CiStatus::Unknown),
        ] {
            let observed = observe_open_ci(body, empty_statuses()).await.unwrap();
            assert_eq!(observed.ci_status, expected);
            assert_eq!(
                observed.head_sha,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            );
        }
    }

    #[test]
    fn incomplete_checks_never_become_pending_or_passed() {
        assert_eq!(aggregate_ci_status(&[CiStatus::Pending]), CiStatus::Pending);
        assert_eq!(
            aggregate_ci_status(&[CiStatus::Passed, CiStatus::Pending]),
            CiStatus::Pending
        );
        assert_eq!(
            aggregate_ci_status(&[CiStatus::Unknown, CiStatus::Pending]),
            CiStatus::Unknown
        );
        assert_eq!(
            aggregate_ci_status(&[CiStatus::Failed, CiStatus::Unknown]),
            CiStatus::Failed
        );
    }

    #[tokio::test]
    async fn latest_pending_run_supersedes_older_success_for_the_same_check() {
        let observed = observe_open_ci(
            r#"{"total_count":2,"check_runs":[{"id":10,"name":"ci","status":"completed","conclusion":"success","app":{"id":4}},{"id":11,"name":"ci","status":"in_progress","conclusion":null,"app":{"id":4}}]}"#,
            empty_statuses(),
        )
        .await
        .unwrap();
        assert_eq!(observed.ci_status, CiStatus::Pending);
    }

    #[tokio::test]
    async fn combines_explicit_legacy_statuses_without_relabeling_unknown_as_failure() {
        for (state, expected) in [
            ("failure", CiStatus::Failed),
            ("error", CiStatus::Failed),
            ("pending", CiStatus::Pending),
            ("neutral", CiStatus::Unknown),
        ] {
            let status = Box::leak(
                format!(
                    r#"{{"state":"{}","sha":"{}","total_count":1,"statuses":[{{"context":"ci","state":"{}"}}]}}"#,
                    match state {
                        "pending" => "pending",
                        "error" => "error",
                        _ => "failure",
                    },
                    "b".repeat(40),
                    state
                )
                .into_boxed_str(),
            );
            let observed = observe_open_ci(checks(), status).await.unwrap();
            assert_eq!(observed.ci_status, expected, "legacy state {state}");
        }
    }

    #[tokio::test]
    async fn rejects_a_newer_failed_run_even_when_an_older_same_name_run_passed() {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            r#"{"total_count":2,"check_runs":[{"id":10,"name":"ci","status":"completed","conclusion":"success","app":{"id":4}},{"id":11,"name":"ci","status":"completed","conclusion":"failure","app":{"id":4}}]}"#,
        ]);
        let result = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Open,
                PullExpectation::Open,
            )
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::ChecksNotSuccessful));
    }

    #[tokio::test]
    async fn captures_issue_and_base_before_a_pull_request_exists() {
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (root, worker) = mock(vec![issue(), base(), base(), issue()]);
        let verified = adapter(&root)
            .verify_issue(5, IssueExpectation::Open, Some(sha))
            .await
            .unwrap();
        worker.join().unwrap();
        assert_eq!(verified.base_sha, sha);
    }

    #[tokio::test]
    async fn reads_open_issue_text_without_exposing_it_in_debug() {
        let issue = r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"private title","body":"private issue text"}"#;
        let (root, worker) = mock(vec![base(), issue, issue, base()]);
        let result = adapter(&root)
            .read_open_issue(5, &"a".repeat(40))
            .await
            .unwrap();
        worker.join().unwrap();
        assert_eq!(result.title(), "private title");
        assert_eq!(result.body(), Some("private issue text"));
        assert_eq!(result.issue_number, 5);
        let debug = format!("{result:?}");
        assert!(!debug.contains("private title"));
        assert!(!debug.contains("private issue text"));
    }

    #[tokio::test]
    async fn rejects_issue_or_base_changed_during_text_read() {
        let first = r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"first","body":null}"#;
        let changed = r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-02T00:00:00Z","title":"changed","body":null}"#;
        for responses in [
            vec![base(), first, changed],
            vec![base(), first, first, advanced_base()],
        ] {
            let (root, worker) = mock(responses);
            let result = adapter(&root).read_open_issue(5, &"a".repeat(40)).await;
            worker.join().unwrap();
            assert!(matches!(result, Err(GitHubError::StaleRevision)));
        }
    }

    #[tokio::test]
    async fn rejects_pull_requests_and_incomplete_or_oversized_issue_text() {
        let oversized = Box::leak(
            format!(
                r#"{{"id":12,"number":5,"state":"open","updated_at":"now","title":"title","body":"{}"}}"#,
                "x".repeat(60 * 1024 + 1)
            )
            .into_boxed_str(),
        );
        let invalid: [&str; 3] = [
            r#"{"id":12,"number":5,"state":"open","updated_at":"now","title":"title","body":null,"pull_request":null}"#,
            r#"{"id":12,"number":5,"state":"open","updated_at":"now","title":"title"}"#,
            oversized,
        ];
        for issue in invalid {
            let (root, worker) = mock(vec![base(), issue]);
            let result = adapter(&root).read_open_issue(5, &"a".repeat(40)).await;
            worker.join().unwrap();
            assert!(matches!(result, Err(GitHubError::InvalidResponse)));
        }
    }

    #[tokio::test]
    async fn accepts_merged_pr_when_base_advanced_and_contains_merge_commit() {
        let (root, worker) = mock(vec![
            advanced_base(),
            closed_issue(),
            merged_pull(),
            linked_issue(),
            r#"{"status":"ahead"}"#,
            checks(),
            empty_statuses(),
            reviews(),
            merged_pull(),
            closed_issue(),
            advanced_base(),
            r#"{"status":"ahead"}"#,
            checks(),
            empty_statuses(),
            reviews(),
            linked_issue(),
        ]);
        let verified = adapter(&root)
            .verify_task(
                5,
                7,
                &"a".repeat(40),
                &"b".repeat(40),
                IssueExpectation::Closed,
                PullExpectation::Merged,
            )
            .await
            .unwrap();
        worker.join().unwrap();
        assert_eq!(verified.pull_state, PullStatus::Merged);
        assert_eq!(
            verified.merge_commit_sha.as_deref(),
            Some("dddddddddddddddddddddddddddddddddddddddd")
        );
        assert!(verified.base_contains_merge_commit);
    }

    #[test]
    fn rejects_path_injection_and_non_sha_revisions() {
        assert_eq!(
            GitHubPolicy::new(
                "org/repo/extra",
                "develop",
                "org/repo",
                "orchestrator-",
                "bot",
                vec![],
                0
            ),
            Err(GitHubError::InvalidPolicy)
        );
        assert!(!valid_sha("abcdef"));
    }

    #[test]
    fn bounds_untrusted_action_names_and_step_count() {
        assert!(valid_untrusted_name(&"x".repeat(MAX_ACTION_NAME_BYTES)));
        assert!(!valid_untrusted_name(
            &"x".repeat(MAX_ACTION_NAME_BYTES + 1)
        ));
        let steps = (1..=MAX_ACTION_STEPS + 1)
            .map(|number| WorkflowStep {
                number: number as u64,
                name: "step".to_owned(),
                status: "completed".to_owned(),
                conclusion: Some("success".to_owned()),
            })
            .collect::<Vec<_>>();
        assert!(!valid_action_steps(&steps));
    }

    #[test]
    fn rejects_non_develop_base_in_direct_policy_construction() {
        for base in ["main", "release", "feature/test"] {
            assert_eq!(
                GitHubPolicy::new(
                    "org/repo",
                    base,
                    "org/repo",
                    "orchestrator-",
                    "bot",
                    vec![RequiredCheck::new("ci", 42).unwrap()],
                    1,
                ),
                Err(GitHubError::InvalidPolicy)
            );
        }
    }

    #[tokio::test]
    async fn creates_a_branch_once_and_validates_the_201_response() {
        use std::sync::atomic::Ordering;

        let task_id = uuid::Uuid::from_u128(1);
        let response = format!(
            r#"{{"ref":"refs/heads/orchestrator/{task_id}","object":{{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"commit"}}}}"#
        );
        let (root, worker, posts) = branch_server(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
            Some(("201 Created", response)),
        );
        let adapter = GitHubAdapter::build(
            branch_policy("org/repo", "orchestrator"),
            "test-token",
            &root,
        )
        .unwrap();
        assert_eq!(
            adapter.create_work_branch(branch_permit()).await.unwrap(),
            format!("orchestrator/{task_id}")
        );
        worker.join().unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn issue_link_rejects_missing_or_foreign_issue_node_before_mutation() {
        use std::sync::atomic::Ordering;

        for (mode, expected) in [
            ("main:missing-issue", GitHubError::IssueStateMismatch),
            ("main:foreign-repository", GitHubError::RepositoryMismatch),
            ("main:wrong-issue", GitHubError::IssuePullMismatch),
            ("main:wrong-head", GitHubError::IssuePullMismatch),
            ("main:fork-head", GitHubError::RepositoryMismatch),
            (
                "main:wrong-base-repository",
                GitHubError::RepositoryMismatch,
            ),
            ("main:missing-issue-id", GitHubError::IssuePullMismatch),
            ("main:missing-pull-id", GitHubError::IssuePullMismatch),
        ] {
            let (root, worker, posts) = pull_request_server(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                mode,
                r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
                Some("201 Created"),
                true,
            );
            let adapter = GitHubAdapter::build(
                branch_policy("org/repo", "orchestrator"),
                "test-token",
                &root,
            )
            .unwrap();
            let candidate = adapter
                .create_unlinked_develop_pull_request(pull_request_permit())
                .await
                .unwrap();
            assert_eq!(
                adapter
                    .link_pull_request_issue(IssueLinkPermit::synthetic(candidate.number()))
                    .await,
                Err(expected),
                "case {mode}"
            );
            worker.join().unwrap();
            assert_eq!(posts.load(Ordering::SeqCst), 1, "case {mode}");
        }
    }

    #[tokio::test]
    async fn issue_link_rejects_foreign_mutation_issue_id_after_single_send() {
        use std::sync::atomic::Ordering;

        let (root, worker, posts) = pull_request_server(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "main:foreign-issue-id",
            r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
            Some("201 Created"),
            true,
        );
        let adapter = GitHubAdapter::build(
            branch_policy("org/repo", "orchestrator"),
            "test-token",
            &root,
        )
        .unwrap();
        let candidate = adapter
            .create_unlinked_develop_pull_request(pull_request_permit())
            .await
            .unwrap();
        assert_eq!(
            adapter
                .link_pull_request_issue(IssueLinkPermit::synthetic(candidate.number()))
                .await,
            Err(GitHubError::AmbiguousIssueLink)
        );
        worker.join().unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn issue_link_rejects_partial_or_uncorrelated_mutation_response() {
        use std::sync::atomic::Ordering;

        for mode in [
            "main:mutation-missing-payload",
            "main:mutation-partial-errors",
            "main:mutation-missing-correlation",
            "main:mutation-wrong-correlation",
        ] {
            let (root, worker, posts) = pull_request_server(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                mode,
                r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
                Some("201 Created"),
                true,
            );
            let adapter = GitHubAdapter::build(
                branch_policy("org/repo", "orchestrator"),
                "test-token",
                &root,
            )
            .unwrap();
            let candidate = adapter
                .create_unlinked_develop_pull_request(pull_request_permit())
                .await
                .unwrap();
            assert_eq!(
                adapter
                    .link_pull_request_issue(IssueLinkPermit::synthetic(candidate.number()))
                    .await,
                Err(GitHubError::AmbiguousIssueLink),
                "case {mode}"
            );
            worker.join().unwrap();
            assert_eq!(posts.load(Ordering::SeqCst), 2, "case {mode}");
        }
    }

    #[tokio::test]
    async fn ambiguous_issue_link_mutation_is_not_replayed() {
        use std::sync::atomic::Ordering;

        let (root, worker, posts) = pull_request_server(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "main:ambiguous-link",
            r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
            Some("201 Created"),
            true,
        );
        let adapter = GitHubAdapter::build(
            branch_policy("org/repo", "orchestrator"),
            "test-token",
            &root,
        )
        .unwrap();
        let candidate = adapter
            .create_unlinked_develop_pull_request(pull_request_permit())
            .await
            .unwrap();
        assert_eq!(
            adapter
                .link_pull_request_issue(IssueLinkPermit::synthetic(candidate.number()))
                .await,
            Err(GitHubError::AmbiguousIssueLink)
        );
        worker.join().unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ambiguous_post_failures_are_not_replayed() {
        use std::sync::atomic::Ordering;

        let task_id = uuid::Uuid::from_u128(1);
        let wrong_ref = format!(
            r#"{{"ref":"refs/heads/other/{task_id}","object":{{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"commit"}}}}"#
        );
        for response in [
            Some(("422 Unprocessable Entity", "{}".to_owned())),
            Some(("201 Created", "not-json".to_owned())),
            Some(("201 Created", wrong_ref)),
            None,
        ] {
            let (root, worker, posts) = branch_server(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
                response,
            );
            let adapter = GitHubAdapter::build(
                branch_policy("org/repo", "orchestrator"),
                "test-token",
                &root,
            )
            .unwrap();
            assert_eq!(
                adapter.create_work_branch(branch_permit()).await,
                Err(GitHubError::AmbiguousBranchWrite)
            );
            worker.join().unwrap();
            assert_eq!(posts.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn rejects_stale_base_pull_request_and_policy_before_post() {
        use std::sync::atomic::Ordering;

        let (root, worker, posts) = branch_server(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
            None,
        );
        let adapter = GitHubAdapter::build(
            branch_policy("org/repo", "orchestrator"),
            "test-token",
            &root,
        )
        .unwrap();
        assert_eq!(
            adapter.create_work_branch(branch_permit()).await,
            Err(GitHubError::StaleRevision)
        );
        worker.join().unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 0);

        let (root, worker, posts) = branch_server(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null,"pull_request":{}}"#,
            None,
        );
        let adapter = GitHubAdapter::build(
            branch_policy("org/repo", "orchestrator"),
            "test-token",
            &root,
        )
        .unwrap();
        assert!(adapter.create_work_branch(branch_permit()).await.is_err());
        worker.join().unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 0);

        for policy in [
            branch_policy("org/other", "orchestrator"),
            branch_policy("org/repo", "task"),
        ] {
            let adapter = GitHubAdapter::build(policy, "test-token", "http://127.0.0.1:1").unwrap();
            assert_eq!(
                adapter.create_work_branch(branch_permit()).await,
                Err(GitHubError::InvalidTaskReference)
            );
        }
    }

    #[tokio::test]
    async fn creates_a_pull_request_once_and_confirms_closing_issue() {
        use std::sync::atomic::Ordering;

        let (root, worker, posts) = pull_request_server(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "develop",
            r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"untrusted issue title","body":"untrusted issue body"}"#,
            Some("201 Created"),
            true,
        );
        let adapter = GitHubAdapter::build(
            branch_policy("org/repo", "orchestrator"),
            "test-token",
            &root,
        )
        .unwrap();
        assert_eq!(
            adapter.create_pull_request(pull_request_permit()).await,
            Ok(7)
        );
        worker.join().unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn nondefault_develop_pr_is_observed_then_manually_linked_once() {
        use std::sync::atomic::Ordering;

        let (root, worker, posts) = pull_request_server(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "main",
            r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
            Some("201 Created"),
            true,
        );
        let adapter = GitHubAdapter::build(
            branch_policy("org/repo", "orchestrator"),
            "test-token",
            &root,
        )
        .unwrap();
        let candidate = adapter
            .create_unlinked_develop_pull_request(pull_request_permit())
            .await
            .unwrap();
        assert_eq!(candidate.number(), 7);
        assert_eq!(
            adapter
                .link_pull_request_issue(IssueLinkPermit::synthetic(candidate.number()))
                .await,
            Ok(7)
        );
        worker.join().unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rejects_stale_pull_base_head_and_non_default_base_before_post() {
        use std::sync::atomic::Ordering;

        for (base_sha, branch_sha, default_branch, expected) in [
            (
                "cccccccccccccccccccccccccccccccccccccccc",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "develop",
                GitHubError::StaleRevision,
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "cccccccccccccccccccccccccccccccccccccccc",
                "develop",
                GitHubError::StaleRevision,
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "main",
                GitHubError::DefaultBranchMismatch,
            ),
        ] {
            let (root, worker, posts) = pull_request_server(
                base_sha,
                branch_sha,
                default_branch,
                r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
                Some("201 Created"),
                true,
            );
            let adapter = GitHubAdapter::build(
                branch_policy("org/repo", "orchestrator"),
                "test-token",
                &root,
            )
            .unwrap();
            assert_eq!(
                adapter.create_pull_request(pull_request_permit()).await,
                Err(expected)
            );
            worker.join().unwrap();
            assert_eq!(posts.load(Ordering::SeqCst), 0);
        }

        let (root, worker, posts) = pull_request_server(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "develop",
            r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null,"pull_request":{}}"#,
            Some("201 Created"),
            true,
        );
        let adapter = GitHubAdapter::build(
            branch_policy("org/repo", "orchestrator"),
            "test-token",
            &root,
        )
        .unwrap();
        assert!(
            adapter
                .create_pull_request(pull_request_permit())
                .await
                .is_err()
        );
        worker.join().unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ambiguous_pull_post_and_failed_postcondition_are_not_replayed() {
        use std::sync::atomic::Ordering;

        for (post_status, closes_issue) in [
            (Some("422 Unprocessable Entity"), true),
            (Some("201 Invalid JSON"), true),
            (Some("201 Created"), false),
            (None, true),
        ] {
            let (root, worker, posts) = pull_request_server(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "develop",
                r#"{"id":12,"number":5,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"title","body":null}"#,
                post_status,
                closes_issue,
            );
            let adapter = GitHubAdapter::build(
                branch_policy("org/repo", "orchestrator"),
                "test-token",
                &root,
            )
            .unwrap();
            assert_eq!(
                adapter.create_pull_request(pull_request_permit()).await,
                Err(GitHubError::AmbiguousPullWrite)
            );
            worker.join().unwrap();
            assert_eq!(posts.load(Ordering::SeqCst), 1);
        }
    }

    const CRASH_TEST_DATABASE_URL: &str = "MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL";
    const CRASH_TEST_PHASE: &str = "MIPSORCU_GITHUB_CRASH_TEST_PHASE";
    const CRASH_TEST_API_ROOT: &str = "MIPSORCU_GITHUB_CRASH_TEST_API_ROOT";
    const CRASH_TEST_MARKER: &str = "MIPSORCU_GITHUB_CRASH_TEST_MARKER";
    const CRASH_TEST_OWNER: &str = "github-branch-crash-child";
    const CRASH_TEST_TASK_ID: uuid::Uuid =
        uuid::Uuid::from_u128(0x20261121000300000000000000000001);
    const CRASH_TEST_IDEMPOTENCY_KEY: uuid::Uuid =
        uuid::Uuid::from_u128(0x20261121000300000000000000000002);
    const CRASH_TEST_BASE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Clone)]
    struct CrashPolicy;

    impl crate::engine::TrustedPolicySource for CrashPolicy {
        async fn load_policy(
            &self,
            _: &crate::domain::TaskRecord,
        ) -> Result<crate::domain::TrustedPolicy, ()> {
            Ok(crate::domain::TrustedPolicy {
                base_ref: "develop".to_owned(),
                base_sha: CRASH_TEST_BASE_SHA.to_owned(),
                allowed_assignee: "bot".to_owned(),
                required_checks: vec!["ci".to_owned()],
                max_attempts: 3,
                max_runtime: Duration::from_secs(60),
                max_model_tokens: 100,
            })
        }
    }

    #[derive(Clone)]
    struct CrashEvidence;

    impl crate::engine::EvidenceSource for CrashEvidence {
        async fn observe(
            &self,
            _: &crate::domain::TaskRecord,
            _: &crate::domain::TrustedPolicy,
        ) -> Result<crate::domain::ObservedFacts, ()> {
            Ok(crate::domain::ObservedFacts {
                policy_base_ref: "develop".to_owned(),
                policy_base_sha: CRASH_TEST_BASE_SHA.to_owned(),
                issue_open: true,
                base_sha: CRASH_TEST_BASE_SHA.to_owned(),
                ..crate::domain::ObservedFacts::default()
            })
        }
    }

    struct CrashRecovery;

    impl crate::postgres::RecoveryVerifier for CrashRecovery {
        fn verify_stopped(&self, _: uuid::Uuid, _: &str, _: i64) -> Option<serde_json::Value> {
            Some(serde_json::json!({"test_child_killed_by_parent": true}))
        }
    }

    #[derive(Clone)]
    struct BranchCrashRunner {
        database_url: String,
        api_root: String,
        marker: Option<std::path::PathBuf>,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::engine::StageRunner for BranchCrashRunner {
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
            Ok(())
        }

        fn agent_roles(&self) -> (crate::agent::Provider, crate::agent::Provider) {
            (
                crate::agent::Provider::Codex,
                crate::agent::Provider::Claude,
            )
        }

        fn supports_cancellation(&self) -> bool {
            true
        }

        async fn execute_with_cancellation(
            &self,
            lease: &crate::postgres::Lease,
            operation_key: uuid::Uuid,
            stage: crate::engine::Stage,
            task: &crate::domain::TaskRecord,
            policy: &crate::domain::TrustedPolicy,
            budget: crate::engine::ExecutionBudget,
            cancellation: crate::agent::Cancellation,
        ) -> Result<crate::engine::StageOutput, crate::engine::StageFailure> {
            if cancellation.cancelled() {
                return Err(crate::engine::StageFailure::Cancelled);
            }
            self.execute(lease, operation_key, stage, task, policy, budget)
                .await
        }

        async fn stop_and_verify(
            &self,
            _: &crate::postgres::Lease,
            _: uuid::Uuid,
        ) -> Result<(), ()> {
            // The parent test has already waited for the only synthetic child.
            Ok(())
        }

        async fn execute(
            &self,
            lease: &crate::postgres::Lease,
            operation_key: uuid::Uuid,
            stage: crate::engine::Stage,
            task: &crate::domain::TaskRecord,
            _: &crate::domain::TrustedPolicy,
            _: crate::engine::ExecutionBudget,
        ) -> Result<crate::engine::StageOutput, crate::engine::StageFailure> {
            use std::sync::atomic::Ordering;

            self.calls.fetch_add(1, Ordering::SeqCst);
            if stage != crate::engine::Stage::Plan {
                return Err(crate::engine::StageFailure::InvalidConfiguration);
            }

            let (client, connection) =
                tokio_postgres::connect(&self.database_url, tokio_postgres::NoTls)
                    .await
                    .map_err(|_| crate::engine::StageFailure::Internal)?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let live_intent: i64 = client
                .query_one(
                    "SELECT count(*) FROM orchestrator.task_operations o \
                     JOIN orchestrator.tasks t ON t.id=o.task_id \
                     JOIN orchestrator.execution_lease l ON l.task_id=t.id AND l.fencing_token=o.fencing_token \
                     WHERE o.operation_key=$1 AND o.task_id=$2 AND o.result IS NULL \
                       AND o.operation='plan' AND t.status::text='planning' \
                       AND l.owner=$3 AND l.expires_at > clock_timestamp()",
                    &[&operation_key, &lease.task_id, &lease.owner],
                )
                .await
                .map_err(|_| crate::engine::StageFailure::Internal)?
                .get(0);
            if live_intent != 1 || lease.task_id != CRASH_TEST_TASK_ID {
                return Err(crate::engine::StageFailure::InvalidOperationResult);
            }

            // This test-only permit exercises the adapter after a real durable Engine intent.
            // It does not derive production authority from database or fake GitHub state.
            let permit = BranchWritePermit::synthetic(
                lease.task_id,
                operation_key,
                task.issue_number,
                u64::try_from(lease.fencing_token)
                    .map_err(|_| crate::engine::StageFailure::InvalidOperationResult)?,
                CRASH_TEST_BASE_SHA,
            );
            let adapter = GitHubAdapter::build(
                branch_policy("org/repo", "orchestrator"),
                "synthetic-test-token",
                &self.api_root,
            )
            .map_err(|_| crate::engine::StageFailure::InvalidConfiguration)?;
            adapter
                .create_work_branch(permit)
                .await
                .map_err(|_| crate::engine::StageFailure::Internal)?;

            if let Some(marker) = &self.marker {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(marker)
                    .map_err(|_| crate::engine::StageFailure::Internal)?;
                std::future::pending::<()>().await;
            }

            Ok(crate::engine::StageOutput {
                assignee: Some("bot".to_owned()),
                implementer: Some("codex".to_owned()),
                reviewer: Some("claude".to_owned()),
                session_id: Some("github-branch-crash-test".to_owned()),
                head_sha: None,
                pull_request: None,
                validation_passed: false,
                local_validation_passed: None,
                model_tokens: 1,
                mock_github_journal: None,
                plan: Some(crate::engine::MockPlan {
                    requirements: vec!["test fixture".to_owned()],
                    steps: vec!["create a simulated branch".to_owned()],
                }),
                code_change: None,
            })
        }
    }

    struct BranchCrashServer {
        address: String,
        posts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        remote_ref: std::sync::Arc<std::sync::Mutex<Option<(String, String)>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl BranchCrashServer {
        fn start() -> Self {
            use std::sync::{
                Arc,
                atomic::{AtomicBool, AtomicUsize},
            };

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = format!("http://{}", listener.local_addr().unwrap());
            let posts = Arc::new(AtomicUsize::new(0));
            let remote_ref = Arc::new(std::sync::Mutex::new(None));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_posts = Arc::clone(&posts);
            let thread_ref = Arc::clone(&remote_ref);
            let thread_stop = Arc::clone(&stop);
            let worker = thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while !thread_stop.load(std::sync::atomic::Ordering::SeqCst)
                    && std::time::Instant::now() < deadline
                {
                    let (mut stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => return,
                    };
                    if stream.set_nonblocking(false).is_err() {
                        return;
                    }
                    if stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .is_err()
                    {
                        return;
                    }
                    let mut request = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    loop {
                        let length = match stream.read(&mut chunk) {
                            Ok(length) if length > 0 => length,
                            _ => return,
                        };
                        request.extend_from_slice(&chunk[..length]);
                        if request.len() > 16_384 {
                            return;
                        }
                        let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let headers = String::from_utf8_lossy(&request[..header_end]);
                        let content_length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        if request.len() >= header_end + 4 + content_length {
                            break;
                        }
                    }

                    let header_end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let request_line = String::from_utf8_lossy(&request[..header_end])
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    let body_start = header_end + 4;
                    let body = &request[body_start..];
                    let (status, response_body) = match request_line.as_str() {
                        "GET /repos/org/repo/commits/develop HTTP/1.1" => (
                            "200 OK",
                            format!(r#"{{"sha":"{CRASH_TEST_BASE_SHA}"}}"#),
                        ),
                        "GET /repos/org/repo/issues/17 HTTP/1.1" => (
                            "200 OK",
                            r#"{"id":17,"number":17,"state":"open","updated_at":"2026-01-01T00:00:00Z","title":"test","body":null}"#.to_owned(),
                        ),
                        "POST /repos/org/repo/git/refs HTTP/1.1" => {
                            thread_posts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
                                return;
                            };
                            if json["sha"] != CRASH_TEST_BASE_SHA {
                                return;
                            }
                            let Some(reference) = json["ref"].as_str() else {
                                return;
                            };
                            let mut stored_ref = match thread_ref.lock() {
                                Ok(stored_ref) => stored_ref,
                                Err(_) => return,
                            };
                            if stored_ref.is_some() {
                                ("422 Unprocessable Entity", "{}".to_owned())
                            } else {
                                *stored_ref = Some((reference.to_owned(), CRASH_TEST_BASE_SHA.to_owned()));
                                (
                                    "201 Created",
                                    format!(r#"{{"ref":"{reference}","object":{{"sha":"{CRASH_TEST_BASE_SHA}","type":"commit"}}}}"#),
                                )
                            }
                        }
                        _ => return,
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                        response_body.len()
                    );
                    if stream.write_all(response.as_bytes()).is_err() {
                        return;
                    }
                }
            });
            Self {
                address,
                posts,
                remote_ref,
                stop,
                worker: Some(worker),
            }
        }

        fn stop_and_join(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                worker.join().expect("fake GitHub server thread");
            }
        }
    }

    impl Drop for BranchCrashServer {
        fn drop(&mut self) {
            self.stop_and_join();
        }
    }

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    fn crash_test_database_url() -> String {
        let database_url = std::env::var(CRASH_TEST_DATABASE_URL)
            .expect("isolated PostgreSQL runner must set the test database URL");
        let config: tokio_postgres::Config = database_url
            .parse()
            .unwrap_or_else(|_| panic!("invalid PostgreSQL test URL"));
        assert!(
            matches!(config.get_hosts(), [tokio_postgres::config::Host::Tcp(host)] if host == "127.0.0.1")
                && config.get_hostaddrs().is_empty(),
            "test PostgreSQL must use the runner's loopback TCP address"
        );
        assert_eq!(
            config.get_dbname(),
            Some("orchestrator_test_github_crash"),
            "test PostgreSQL must use its dedicated disposable database"
        );
        assert_eq!(
            config.get_user(),
            Some("orchestrator_test"),
            "test PostgreSQL must use the dedicated non-superuser role"
        );
        database_url
    }

    async fn crash_test_engine(
        database_url: &str,
        api_root: String,
        marker: Option<std::path::PathBuf>,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        lease_ttl: Duration,
    ) -> crate::engine::Engine<
        crate::engine::PostgresEngineStore,
        CrashPolicy,
        CrashEvidence,
        BranchCrashRunner,
        CrashRecovery,
    > {
        crate::engine::Engine {
            store: crate::engine::PostgresEngineStore::new(
                crate::postgres::TaskStore::connect(database_url)
                    .await
                    .expect("connect isolated PostgreSQL engine store"),
            ),
            policies: CrashPolicy,
            evidence: CrashEvidence,
            runner: BranchCrashRunner {
                database_url: database_url.to_owned(),
                api_root,
                marker,
                calls,
            },
            recovery: CrashRecovery,
            mock_github: None,
            lease_ttl,
        }
    }

    #[tokio::test]
    async fn closes_issue_when_develop_is_default_but_auto_close_has_not_run() {
        let task_id = uuid::Uuid::from_u128(1);
        let operation_id = uuid::Uuid::from_u128(2);
        let pull = close_pull(task_id, operation_id);
        let mut responses = close_observation(issue(), pull)
            .into_iter()
            .map(|body| ("200 OK", body, ""))
            .collect::<Vec<_>>();
        responses.push(("200 OK", closed_issue(), ""));
        let mut after = close_observation(closed_issue(), pull);
        after[0] = later_base();
        after[4] = r#"{"status":"ahead"}"#;
        after[10] = later_base();
        after[11] = r#"{"status":"ahead"}"#;
        responses.extend(after.into_iter().map(|body| ("200 OK", body, "")));
        let mut expected = close_observation_requests();
        expected.push("PATCH /repos/org/repo/issues/5 HTTP/1.1");
        expected.extend(close_observation_requests_for(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ));
        let (root, worker) = mock_sequence_checked(responses, false, Some(expected));
        let result = GitHubAdapter::build(close_adapter(), "test-token", &root)
            .unwrap()
            .close_merged_pull_request_issue(CloseIssuePermit::synthetic())
            .await;
        worker.join().unwrap();
        assert_eq!(result, Ok(5));
    }

    #[tokio::test]
    async fn rejects_issue_close_preflight_identity_before_patch() {
        let task_id = uuid::Uuid::from_u128(1);
        let operation_id = uuid::Uuid::from_u128(2);
        let marker = format!("<!-- mipsorcu-operation:{operation_id} -->");
        let cases = [
            (
                close_pull_with_body(task_id, "Closes #5"),
                issue(),
                GitHubError::StaleRevision,
                3,
            ),
            (
                close_pull_with_body(task_id, &format!("{marker}\n{marker}")),
                issue(),
                GitHubError::StaleRevision,
                3,
            ),
            (
                close_pull_with_identity(
                    task_id,
                    &marker,
                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "dddddddddddddddddddddddddddddddddddddddd",
                ),
                issue(),
                GitHubError::StaleRevision,
                3,
            ),
            (
                close_pull_with_body(task_id, &marker),
                closed_issue(),
                GitHubError::IssueStateMismatch,
                2,
            ),
        ];
        for (pull, issue_body, expected_error, request_count) in cases {
            let prefix = close_observation(issue_body, pull);
            let responses = prefix
                .iter()
                .take(request_count)
                .map(|body| ("200 OK", *body, ""))
                .collect();
            let expected = close_observation_requests()
                .into_iter()
                .take(request_count)
                .collect();
            let (root, worker) = mock_sequence_checked(responses, false, Some(expected));
            let result = GitHubAdapter::build(close_adapter(), "test-token", &root)
                .unwrap()
                .close_merged_pull_request_issue(CloseIssuePermit::synthetic())
                .await;
            worker.join().unwrap();
            assert_eq!(result, Err(expected_error));
        }
    }

    #[tokio::test]
    async fn issue_close_patch_failure_is_ambiguous_and_never_replayed() {
        let task_id = uuid::Uuid::from_u128(1);
        let operation_id = uuid::Uuid::from_u128(2);
        let pull = close_pull(task_id, operation_id);
        let mut responses = close_observation(issue(), pull)
            .into_iter()
            .map(|body| ("200 OK", body, ""))
            .collect::<Vec<_>>();
        responses.push(("500 Internal Server Error", "{}", ""));
        let mut expected = close_observation_requests();
        expected.push("PATCH /repos/org/repo/issues/5 HTTP/1.1");
        let (root, worker) = mock_sequence_checked(responses, false, Some(expected));
        let result = GitHubAdapter::build(close_adapter(), "test-token", &root)
            .unwrap()
            .close_merged_pull_request_issue(CloseIssuePermit::synthetic())
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::AmbiguousIssueClose));
    }

    #[tokio::test]
    async fn changed_merged_identity_after_issue_close_is_ambiguous() {
        let task_id = uuid::Uuid::from_u128(1);
        let operation_id = uuid::Uuid::from_u128(2);
        let pull = close_pull(task_id, operation_id);
        let changed_pull = close_pull_with_identity(
            task_id,
            "<!-- mipsorcu-operation:00000000-0000-0000-0000-000000000002 -->",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "dddddddddddddddddddddddddddddddddddddddd",
        );
        let mut responses = close_observation(issue(), pull)
            .into_iter()
            .map(|body| ("200 OK", body, ""))
            .collect::<Vec<_>>();
        responses.push(("200 OK", closed_issue(), ""));
        responses.extend(
            close_observation(closed_issue(), changed_pull)
                .into_iter()
                .take(4)
                .map(|body| ("200 OK", body, "")),
        );
        let mut expected = close_observation_requests();
        expected.push("PATCH /repos/org/repo/issues/5 HTTP/1.1");
        expected.extend(close_observation_requests().into_iter().take(4));
        let (root, worker) = mock_sequence_checked(responses, false, Some(expected));
        let result = GitHubAdapter::build(close_adapter(), "test-token", &root)
            .unwrap()
            .close_merged_pull_request_issue(CloseIssuePermit::synthetic())
            .await;
        worker.join().unwrap();
        assert_eq!(result, Err(GitHubError::AmbiguousIssueClose));
    }

    #[tokio::test]
    #[ignore = "requires the disposable network-none PostgreSQL runner"]
    async fn branch_post_success_then_child_crash_recovers_ambiguous_without_replay() {
        use std::{
            fs,
            os::unix::process::ExitStatusExt,
            sync::atomic::{AtomicUsize, Ordering},
        };

        let database_url = crash_test_database_url();
        if std::env::var(CRASH_TEST_PHASE).as_deref() == Ok("post") {
            let api_root = std::env::var(CRASH_TEST_API_ROOT)
                .expect("parent supplies only its fake loopback API root");
            let parsed_root = reqwest::Url::parse(&api_root)
                .unwrap_or_else(|_| panic!("invalid synthetic API root"));
            assert!(
                parsed_root.scheme() == "http"
                    && parsed_root.host_str() == Some("127.0.0.1")
                    && parsed_root.port().is_some_and(|port| port != 0)
                    && parsed_root.username().is_empty()
                    && parsed_root.password().is_none()
                    && parsed_root.path() == "/"
                    && parsed_root.query().is_none()
                    && parsed_root.fragment().is_none(),
                "synthetic API must use the parent loopback server"
            );
            let marker = std::path::PathBuf::from(
                std::env::var(CRASH_TEST_MARKER).expect("parent supplies child marker path"),
            );
            let marker_name = marker.file_name().and_then(|name| name.to_str());
            assert!(
                marker.parent() == Some(std::path::Path::new("/tmp"))
                    && marker_name
                        .and_then(|name| name.strip_prefix("mipsorcu-github-crash-"))
                        .and_then(|name| name.strip_suffix(".ready"))
                        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()),
                "child marker must be a uniquely named temporary file"
            );
            let engine = crash_test_engine(
                &database_url,
                api_root,
                Some(marker),
                std::sync::Arc::new(AtomicUsize::new(0)),
                Duration::from_secs(2),
            )
            .await;
            let _ = engine.run_one(CRASH_TEST_TASK_ID, CRASH_TEST_OWNER).await;
            panic!("parent must kill the child after the simulated branch POST");
        }

        let config: tokio_postgres::Config = database_url
            .parse()
            .unwrap_or_else(|_| panic!("invalid isolated PostgreSQL URL"));
        let (bootstrap, connection) = config
            .connect(tokio_postgres::NoTls)
            .await
            .expect("connect disposable test database");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let dedicated_non_superuser: bool = bootstrap
            .query_one(
                "SELECT rolname = 'orchestrator_test' AND NOT rolsuper \
                 FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .expect("inspect dedicated database role")
            .get(0);
        assert!(dedicated_non_superuser);
        let existing_schema: i64 = bootstrap
            .query_one(
                "SELECT count(*) FROM pg_namespace \
                 WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public') \
                   AND nspname NOT LIKE 'pg_toast%'",
                &[],
            )
            .await
            .expect("inspect schemas before migration")
            .get(0);
        let existing_public_objects: i64 = bootstrap
            .query_one(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                 WHERE n.nspname='public' AND c.relkind IN ('r','v','m','S','f','p')",
                &[],
            )
            .await
            .expect("inspect public objects before migration")
            .get(0);
        assert_eq!((existing_schema, existing_public_objects), (0, 0));
        for migration in [
            include_str!("../migrations/0001_orchestrator.sql"),
            include_str!("../migrations/0002_execution_metadata.sql"),
            include_str!("../migrations/0003_mock_runtime_fingerprint.sql"),
        ] {
            bootstrap
                .batch_execute(migration)
                .await
                .expect("apply migration only after isolated empty-schema checks");
        }
        drop(bootstrap);

        let task_store = crate::postgres::TaskStore::connect(&database_url)
            .await
            .expect("connect dedicated test store");
        task_store
            .create(&crate::postgres::NewTask {
                task_id: CRASH_TEST_TASK_ID,
                repository: "org/repo".to_owned(),
                issue_number: 17,
                base_sha: CRASH_TEST_BASE_SHA.to_owned(),
                max_attempts: 3,
                execution_timeout: Duration::from_secs(60),
                model_budget: 100,
                idempotency_key: CRASH_TEST_IDEMPOTENCY_KEY,
            })
            .await
            .expect("create disposable branch-crash task");
        drop(task_store);

        let mut server = BranchCrashServer::start();
        let marker = std::env::temp_dir().join(format!(
            "mipsorcu-github-crash-{}.ready",
            uuid::Uuid::new_v4()
        ));
        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "github::tests::branch_post_success_then_child_crash_recovers_ambiguous_without_replay",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", "/tmp")
            .env(CRASH_TEST_DATABASE_URL, &database_url)
            .env(CRASH_TEST_PHASE, "post")
            .env(CRASH_TEST_API_ROOT, &server.address)
            .env(CRASH_TEST_MARKER, &marker)
            .spawn()
            .expect("spawn only the synthetic test child");
        let mut child = ChildGuard(child);
        tokio::time::timeout(Duration::from_secs(15), async {
            while !marker.exists() {
                assert!(
                    child.0.try_wait().expect("poll test child").is_none(),
                    "test child exited before the parent observed the successful POST"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("test child must report successful branch response within the bound");
        assert!(
            child
                .0
                .try_wait()
                .expect("confirm child remains alive")
                .is_none(),
            "child must still be running between remote success and durable completion"
        );

        let (client, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
            .await
            .expect("open independent recovery observer connection");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let persisted = client
            .query_one(
                "SELECT o.operation_key, o.fencing_token, o.result, t.status::text, \
                        l.owner, l.expires_at > clock_timestamp() \
                 FROM orchestrator.task_operations o \
                 JOIN orchestrator.tasks t ON t.id=o.task_id \
                 JOIN orchestrator.execution_lease l ON l.task_id=t.id AND l.fencing_token=o.fencing_token \
                 WHERE o.task_id=$1 AND o.operation='plan'",
                &[&CRASH_TEST_TASK_ID],
            )
            .await
            .expect("read child durable operation and active lease");
        let operation_key: uuid::Uuid = persisted.get(0);
        let fencing_token: i64 = persisted.get(1);
        let result: Option<serde_json::Value> = persisted.get(2);
        let state: String = persisted.get(3);
        let owner: String = persisted.get(4);
        let lease_live: bool = persisted.get(5);
        assert!(result.is_none());
        assert_eq!(state, "planning");
        assert_eq!(owner, CRASH_TEST_OWNER);
        assert!(lease_live);

        let remote_ref = server
            .remote_ref
            .lock()
            .expect("read fake GitHub state")
            .clone();
        assert_eq!(
            remote_ref,
            Some((
                format!("refs/heads/orchestrator/{CRASH_TEST_TASK_ID}"),
                CRASH_TEST_BASE_SHA.to_owned(),
            ))
        );
        assert_eq!(server.posts.load(Ordering::SeqCst), 1);

        child
            .0
            .kill()
            .expect("SIGKILL only the spawned child process");
        let child_status = child.0.wait().expect("wait for killed child");
        assert_eq!(child_status.signal(), Some(9));
        fs::remove_file(&marker).expect("remove child synchronization marker");
        drop(child);

        let prior = crate::postgres::Lease {
            task_id: CRASH_TEST_TASK_ID,
            owner,
            fencing_token,
        };
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let expired: bool = client
                    .query_one(
                        "SELECT expires_at <= clock_timestamp() FROM orchestrator.execution_lease WHERE task_id=$1",
                        &[&CRASH_TEST_TASK_ID],
                    )
                    .await
                    .expect("observe lease expiry using PostgreSQL clock")
                    .get(0);
                if expired {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("child lease must expire within the bound");
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let engine = crash_test_engine(
            &database_url,
            server.address.clone(),
            None,
            std::sync::Arc::clone(&calls),
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(
            engine
                .recover_and_run(&prior, "github-branch-crash-recovery")
                .await
                .expect("recover the killed child under a later fence"),
            crate::engine::StepResult::BlockedAmbiguousOperation
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(server.posts.load(Ordering::SeqCst), 1);
        assert_eq!(
            *server
                .remote_ref
                .lock()
                .expect("read persisted fake remote state"),
            Some((
                format!("refs/heads/orchestrator/{CRASH_TEST_TASK_ID}"),
                CRASH_TEST_BASE_SHA.to_owned(),
            ))
        );

        let recovered = client
            .query_one(
                "SELECT t.status::text, o.result, l.task_id, l.fencing_token \
                 FROM orchestrator.tasks t \
                 JOIN orchestrator.task_operations o ON o.task_id=t.id \
                 CROSS JOIN orchestrator.execution_lease l \
                 WHERE t.id=$1 AND o.operation_key=$2",
                &[&CRASH_TEST_TASK_ID, &operation_key],
            )
            .await
            .expect("inspect blocked durable operation after recovery");
        assert_eq!(recovered.get::<_, String>(0), "blocked");
        assert!(recovered.get::<_, Option<serde_json::Value>>(1).is_none());
        assert_eq!(recovered.get::<_, Option<uuid::Uuid>>(2), None);
        assert!(recovered.get::<_, i64>(3) > fencing_token);

        let stale_complete = crate::postgres::TaskStore::connect(&database_url)
            .await
            .expect("connect stale-fence observer")
            .complete_operation(
                &prior,
                operation_key,
                &serde_json::json!({"simulated": true}),
                0,
            )
            .await;
        assert!(matches!(
            stale_complete,
            Err(crate::postgres::StoreError::LeaseLost)
        ));

        server.stop_and_join();
        assert_eq!(server.posts.load(Ordering::SeqCst), 1);
    }
}
