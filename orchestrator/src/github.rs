//! Read-only GitHub verification for orchestrator tasks.
//!
//! The repository and base branch come from trusted configuration supplied when the
//! adapter is built. This module deliberately exposes no GitHub write operations.

use reqwest::{Client, Response, StatusCode, header};
use serde::Deserialize;
use std::{collections::BTreeMap, time::Duration};

const API_ROOT: &str = "https://api.github.com";
const MAX_RESPONSE_BYTES: usize = 1_048_576;

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
            || !valid_branch(&base_branch)
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
        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| GitHubError::InvalidConfiguration)?;
        Ok(Self {
            client,
            policy,
            api_root: api_root.trim_end_matches('/').to_owned(),
        })
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

        let checks: CheckRunsResponse = self
            .get_json(&format!(
                "{root}/commits/{}/check-runs?per_page=100",
                pull.head.sha
            ))
            .await?;
        if checks.total_count as usize != checks.check_runs.len() {
            return Err(GitHubError::IncompleteEvidence);
        }
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
            if !latest.is_some_and(|check| {
                check.status == "completed" && check.conclusion.as_deref() == Some("success")
            }) {
                return Err(GitHubError::ChecksNotSuccessful);
            }
        }

        let reviews: Vec<ReviewResponse> = self
            .get_json(&format!("{root}/pulls/{pull_number}/reviews?per_page=100"))
            .await?;
        let mut latest_by_reviewer = BTreeMap::<&str, &ReviewResponse>::new();
        for review in &reviews {
            if let Some(user) = review.user.as_ref() {
                let replace = latest_by_reviewer
                    .get(user.login.as_str())
                    .is_none_or(|latest| {
                        (latest.submitted_at.as_str(), latest.id)
                            < (review.submitted_at.as_str(), review.id)
                    });
                if replace {
                    latest_by_reviewer.insert(&user.login, review);
                }
            }
        }
        let approval_count = latest_by_reviewer
            .values()
            .filter(|review| {
                review.state == "APPROVED"
                    && review.commit_id.eq_ignore_ascii_case(&pull.head.sha)
                    && review
                        .user
                        .as_ref()
                        .is_some_and(|user| !user.login.eq_ignore_ascii_case(&pull.user.login))
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
            || !latest_pull
                .user
                .login
                .eq_ignore_ascii_case(&pull.user.login)
            || latest_pull.head.ref_name != pull.head.ref_name
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

        Ok(VerifiedPullRequest {
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
            successful_checks: self
                .policy
                .required_checks
                .iter()
                .map(|check| check.name.clone())
                .collect(),
            approval_count,
            approvals_satisfied,
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
            .get(header::LINK)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|v| {
                let v = v.to_ascii_lowercase();
                v.contains("rel=\"next\"") || v.contains("rel=next")
            })
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitHubError {
    InvalidPolicy,
    InvalidConfiguration,
    InvalidTaskReference,
    Unavailable,
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
    MergeNotOnBase,
}

#[derive(Deserialize)]
struct IssueResponse {
    number: u64,
    state: String,
}
#[derive(Deserialize)]
struct CommitResponse {
    sha: String,
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
#[derive(Deserialize)]
struct PullResponse {
    number: u64,
    state: String,
    merged: bool,
    merge_commit_sha: Option<String>,
    user: ReviewUser,
    base: PullRef,
    head: PullRef,
}
#[derive(Deserialize)]
struct PullRef {
    #[serde(rename = "ref")]
    ref_name: String,
    sha: String,
    repo: PullRepo,
}
#[derive(Deserialize)]
struct PullRepo {
    full_name: String,
}
#[derive(Deserialize)]
struct CheckRunsResponse {
    total_count: u64,
    check_runs: Vec<CheckRun>,
}
#[derive(Deserialize)]
struct CheckRun {
    id: u64,
    name: String,
    status: String,
    conclusion: Option<String>,
    app: CheckApp,
}
#[derive(Deserialize)]
struct CheckApp {
    id: u64,
}
#[derive(Deserialize)]
struct ReviewResponse {
    id: u64,
    state: String,
    commit_id: String,
    submitted_at: String,
    user: Option<ReviewUser>,
}
#[derive(Deserialize)]
struct ReviewUser {
    login: String,
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
fn valid_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn mock(responses: Vec<&'static str>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            for body in responses {
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
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
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
    fn issue() -> &'static str {
        r#"{"number":5,"state":"open"}"#
    }
    fn base() -> &'static str {
        r#"{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
    }
    fn advanced_base() -> &'static str {
        r#"{"sha":"cccccccccccccccccccccccccccccccccccccccc"}"#
    }
    fn pull() -> &'static str {
        r#"{"number":7,"state":"open","merged":false,"merge_commit_sha":null,"user":{"login":"bot"},"base":{"ref":"develop","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"full_name":"org/repo"}},"head":{"ref":"orchestrator-0123","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"org/repo"}}}"#
    }
    fn merged_pull() -> &'static str {
        r#"{"number":7,"state":"closed","merged":true,"merge_commit_sha":"dddddddddddddddddddddddddddddddddddddddd","user":{"login":"bot"},"base":{"ref":"develop","sha":"cccccccccccccccccccccccccccccccccccccccc","repo":{"full_name":"org/repo"}},"head":{"ref":"orchestrator-0123","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"org/repo"}}}"#
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
    fn reviews() -> &'static str {
        r#"[{"id":1,"state":"APPROVED","commit_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","submitted_at":"2026-11-16T00:00:00Z","user":{"login":"reviewer"}}]"#
    }
    fn adapter(root: &str) -> GitHubAdapter {
        GitHubAdapter::build(policy(), "test-token", root).unwrap()
    }

    #[tokio::test]
    async fn verifies_current_issue_pull_checks_and_reviews_using_mock_http() {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            reviews(),
            pull(),
            issue(),
            base(),
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
    async fn reports_missing_approval_before_review_but_merge_gate_rejects_it() {
        let (root, worker) = mock(vec![
            base(),
            issue(),
            pull(),
            linked_issue(),
            checks(),
            "[]",
            pull(),
            issue(),
            base(),
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
    async fn accepts_merged_pr_when_base_advanced_and_contains_merge_commit() {
        let (root, worker) = mock(vec![
            advanced_base(),
            closed_issue(),
            merged_pull(),
            linked_issue(),
            r#"{"status":"ahead"}"#,
            checks(),
            reviews(),
            merged_pull(),
            closed_issue(),
            advanced_base(),
            r#"{"status":"ahead"}"#,
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
}
