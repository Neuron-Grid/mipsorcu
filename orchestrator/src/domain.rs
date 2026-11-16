use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Queued,
    Planning,
    Implementing,
    Validating,
    Reviewing,
    Merging,
    Completed,
    Repairing,
    Paused,
    Blocked,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRecord {
    pub task_id: String,
    pub issue_number: u64,
    pub base_sha: String,
    pub max_attempts: u32,
    pub head_sha: Option<String>,
    pub state: State,
    pub attempts: u32,
    pub assignee: Option<String>,
    pub implementer: Option<String>,
    pub reviewer: Option<String>,
    pub session_id: Option<String>,
    pub mock_github_journal: Option<serde_json::Value>,
    pub mock_runtime_fingerprint: Option<String>,
    pub validation_passed: bool,
    pub pull_request: Option<u64>,
    pub checkpoint: Option<State>,
    pub elapsed: Duration,
    pub model_tokens: u64,
    pub model_budget: u64,
}

impl TaskRecord {
    pub fn validate(&self) -> Result<(), Error> {
        if self.task_id.is_empty() || self.issue_number == 0 || !is_sha(&self.base_sha) {
            return Err(Error::CorruptRecord);
        }
        if self.max_attempts == 0 || self.attempts > self.max_attempts || self.model_budget == 0 {
            return Err(Error::CorruptRecord);
        }
        if self.head_sha.as_deref().is_some_and(|sha| !is_sha(sha)) {
            return Err(Error::CorruptRecord);
        }
        if self.assignee.as_deref().is_some_and(str::is_empty)
            || self.implementer.as_deref().is_some_and(str::is_empty)
            || self.reviewer.as_deref().is_some_and(str::is_empty)
            || self.session_id.as_deref().is_some_and(str::is_empty)
            || self.pull_request == Some(0)
            || self.mock_github_journal.as_ref().is_some_and(|journal| {
                !journal.is_array()
                    || serde_json::to_vec(journal).map_or(true, |bytes| bytes.len() > 64 * 1024)
            })
            || self
                .mock_runtime_fingerprint
                .as_deref()
                .is_some_and(|fingerprint| {
                    fingerprint.len() != 64
                        || !fingerprint
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        {
            return Err(Error::CorruptRecord);
        }
        let valid = match self.state {
            State::Queued => {
                self.head_sha.is_none() && self.pull_request.is_none() && self.checkpoint.is_none()
            }
            State::Planning => {
                self.head_sha.is_none() && self.pull_request.is_none() && self.checkpoint.is_none()
            }
            State::Implementing | State::Repairing => {
                self.pull_request.is_none() && self.checkpoint.is_none()
            }
            State::Validating => {
                self.head_sha.is_some() && self.pull_request.is_none() && self.checkpoint.is_none()
            }
            State::Reviewing | State::Merging => {
                self.head_sha.is_some()
                    && self.pull_request.is_some()
                    && self.validation_passed
                    && self.checkpoint.is_none()
            }
            State::Completed => {
                self.head_sha.is_some()
                    && self.pull_request.is_some()
                    && self.validation_passed
                    && self.checkpoint.is_none()
            }
            State::Paused | State::Blocked => {
                self.checkpoint.is_some_and(|s| {
                    !matches!(
                        s,
                        State::Queued
                            | State::Paused
                            | State::Blocked
                            | State::Failed
                            | State::Completed
                    )
                }) && self.pull_request.is_none_or(|_| self.head_sha.is_some())
            }
            State::Failed => self.checkpoint.is_none(),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::CorruptRecord)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CorruptRecord,
    InvalidTransition,
    StaleBase,
    StaleHead,
    IssueUnavailable,
    PullRequestMismatch,
    ChecksIncomplete,
    NotApproved,
    AlreadyMerged,
    LimitExceeded,
    MissingCheckpoint,
}

#[derive(Clone, Debug)]
pub struct TrustedPolicy {
    pub base_ref: String,
    pub base_sha: String,
    pub allowed_assignee: String,
    pub required_checks: Vec<String>,
    pub max_attempts: u32,
    pub max_runtime: Duration,
    pub max_model_tokens: u64,
}

// Facts must come from a fresh GitHub read and the trusted policy source; never deserialize this from the task row.
#[derive(Clone, Debug, Default)]
pub struct ObservedFacts {
    pub policy_base_ref: String,
    pub policy_base_sha: String,
    pub issue_open: bool,
    pub base_sha: String,
    pub head_sha: String,
    pub validated_head_sha: Option<String>,
    pub pr_number: Option<u64>,
    pub pr_head_sha: Option<String>,
    pub pr_base_ref: Option<String>,
    pub pr_base_sha: Option<String>,
    pub pr_merged: bool,
    pub checks_passed: Vec<String>,
    pub reviewer_approved: bool,
    pub approved_assignee: String,
    pub merge_commit_sha: Option<String>,
    pub base_contains_merge_commit: bool,
}

pub fn transition(
    task: &mut TaskRecord,
    to: State,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), Error> {
    let current = task.clone();
    transition_from(&current, task, to, policy, facts)?;
    Ok(())
}

pub fn transition_from(
    current: &TaskRecord,
    proposed: &mut TaskRecord,
    to: State,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), Error> {
    current.validate()?;
    validate_policy(policy)?;
    let allowed_attempts = proposed.attempts == current.attempts
        || (to == State::Repairing
            && current.attempts.checked_add(1) == Some(proposed.attempts)
            && proposed.attempts <= policy.max_attempts);
    if proposed.task_id != current.task_id
        || proposed.issue_number != current.issue_number
        || proposed.base_sha != current.base_sha
        || proposed.max_attempts != current.max_attempts
        || proposed.model_budget != current.model_budget
        || proposed.mock_runtime_fingerprint != current.mock_runtime_fingerprint
        || (!(current.state == State::Planning && to == State::Implementing)
            && (proposed.implementer != current.implementer
                || proposed.reviewer != current.reviewer
                || proposed.session_id != current.session_id))
        || (proposed.implementer != current.implementer
            && (current.implementer.is_some() || proposed.implementer.is_none()))
        || (proposed.reviewer != current.reviewer
            && (current.reviewer.is_some() || proposed.reviewer.is_none()))
        || (proposed.session_id != current.session_id
            && (current.session_id.is_some() || proposed.session_id.is_none()))
        || !journal_extends(
            current.mock_github_journal.as_ref(),
            proposed.mock_github_journal.as_ref(),
        )
        || !allowed_attempts
        || proposed.model_tokens < current.model_tokens
        || !matches!(proposed.state, s if s == current.state || s == to)
        || (proposed.checkpoint != current.checkpoint
            && !(matches!(to, State::Paused | State::Blocked)
                && proposed.checkpoint == Some(current.state)))
    {
        return Err(Error::InvalidTransition);
    }
    let mut candidate = proposed.clone();
    if !matches!(
        to,
        State::Paused | State::Blocked | State::Failed | State::Completed
    ) && (current.attempts > policy.max_attempts
        || current.elapsed > policy.max_runtime
        || current.model_tokens > policy.max_model_tokens
        || candidate.elapsed > policy.max_runtime
        || candidate.model_tokens > policy.max_model_tokens)
    {
        return Err(Error::LimitExceeded);
    }
    if !facts.issue_open && to != State::Completed {
        return Err(Error::IssueUnavailable);
    }
    if facts.policy_base_sha != policy.base_sha || facts.policy_base_ref != policy.base_ref {
        return Err(Error::StaleBase);
    }
    if to != State::Completed
        && (facts.base_sha != current.base_sha || current.base_sha != policy.base_sha)
    {
        return Err(Error::StaleBase);
    }

    if current.state == State::Paused || current.state == State::Blocked {
        if to != current.checkpoint.ok_or(Error::MissingCheckpoint)? {
            return Err(Error::InvalidTransition);
        }
    } else if !allowed(current.state, to) {
        return Err(Error::InvalidTransition);
    }

    if !fields_are_valid(current, &candidate, to, policy, facts)? {
        return Err(Error::InvalidTransition);
    }
    let prior_state = current.state;
    match to {
        State::Implementing | State::Repairing => candidate.validation_passed = false,
        State::Validating => candidate.validation_passed = false,
        State::Reviewing => {
            candidate.validation_passed = true;
        }
        State::Merging => {
            candidate.validation_passed = true;
        }
        State::Completed => {
            candidate.validation_passed = true;
        }
        State::Paused | State::Blocked => candidate.checkpoint = Some(prior_state),
        State::Failed => candidate.checkpoint = None,
        State::Queued | State::Planning => {}
    }
    if matches!(prior_state, State::Paused | State::Blocked) {
        candidate.checkpoint = None;
    }
    candidate.state = to;
    candidate.validate()?;
    *proposed = candidate;
    Ok(())
}

fn journal_extends(
    current: Option<&serde_json::Value>,
    proposed: Option<&serde_json::Value>,
) -> bool {
    let current = current.and_then(serde_json::Value::as_array);
    let proposed = proposed.and_then(serde_json::Value::as_array);
    match (current, proposed) {
        (None, None) => true,
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (Some(current), Some(proposed)) => proposed.starts_with(current),
    }
}

/// Revalidates a stored completion against current policy and GitHub merge evidence.
pub fn validate_completed(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), Error> {
    task.validate()?;
    validate_policy(policy)?;
    if task.state != State::Completed {
        return Err(Error::InvalidTransition);
    }
    if facts.policy_base_sha != policy.base_sha || facts.policy_base_ref != policy.base_ref {
        return Err(Error::StaleBase);
    }
    require_head(task, facts)?;
    require_validation(task, facts)?;
    require_merged_pr(task, facts, policy)?;
    if !facts.reviewer_approved {
        return Err(Error::NotApproved);
    }
    require_checks(policy, facts)
}

fn fields_are_valid(
    current: &TaskRecord,
    proposed: &TaskRecord,
    to: State,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<bool, Error> {
    if current.assignee != proposed.assignee
        && (to != State::Implementing
            || proposed.assignee.as_deref() != Some(policy.allowed_assignee.as_str())
            || facts.approved_assignee != policy.allowed_assignee)
    {
        return Err(Error::NotApproved);
    }
    match to {
        State::Implementing => {
            if proposed.assignee.as_deref() != Some(policy.allowed_assignee.as_str())
                || facts.approved_assignee != policy.allowed_assignee
            {
                return Err(Error::NotApproved);
            }
            if proposed.head_sha != current.head_sha
                || proposed.pull_request != current.pull_request
                || proposed.pull_request.is_some()
                || proposed.validation_passed
            {
                return Ok(false);
            }
        }
        State::Validating => {
            if proposed.assignee != current.assignee
                || proposed.pull_request != current.pull_request
                || proposed.pull_request.is_some()
                || proposed.validation_passed
            {
                return Ok(false);
            }
            let head = proposed.head_sha.as_deref().ok_or(Error::StaleHead)?;
            if !is_sha(head) || head != facts.head_sha {
                return Err(Error::StaleHead);
            }
        }
        State::Reviewing => {
            if proposed.assignee != current.assignee
                || proposed.head_sha != current.head_sha
                || !proposed.validation_passed
            {
                return Ok(false);
            }
            require_head(proposed, facts)?;
            require_validation(proposed, facts)?;
            require_pr(proposed, facts, policy)?;
        }
        State::Merging => {
            if proposed.assignee != current.assignee
                || proposed.head_sha != current.head_sha
                || proposed.pull_request != current.pull_request
                || !proposed.validation_passed
            {
                return Ok(false);
            }
            require_head(proposed, facts)?;
            require_validation(proposed, facts)?;
            require_pr(proposed, facts, policy)?;
            if !facts.reviewer_approved {
                return Err(Error::NotApproved);
            }
            require_checks(policy, facts)?;
            if facts.pr_merged {
                return Err(Error::AlreadyMerged);
            }
        }
        State::Completed => {
            if proposed.assignee != current.assignee
                || proposed.head_sha != current.head_sha
                || proposed.pull_request != current.pull_request
                || !proposed.validation_passed
            {
                return Ok(false);
            }
            require_head(proposed, facts)?;
            require_validation(proposed, facts)?;
            require_merged_pr(proposed, facts, policy)?;
            if !facts.reviewer_approved {
                return Err(Error::NotApproved);
            }
            require_checks(policy, facts)?;
        }
        State::Repairing => {
            if proposed.assignee != current.assignee
                || proposed.head_sha != current.head_sha
                || proposed.pull_request.is_some()
                || proposed.validation_passed
            {
                return Ok(false);
            }
        }
        State::Paused | State::Blocked | State::Failed => {
            if proposed.assignee != current.assignee
                || proposed.head_sha != current.head_sha
                || proposed.pull_request != current.pull_request
                || proposed.validation_passed != current.validation_passed
            {
                return Ok(false);
            }
        }
        State::Queued | State::Planning => {
            if proposed.assignee != current.assignee
                || proposed.head_sha != current.head_sha
                || proposed.pull_request != current.pull_request
                || proposed.validation_passed != current.validation_passed
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn allowed(from: State, to: State) -> bool {
    matches!(
        (from, to),
        (State::Queued, State::Planning)
            | (State::Planning, State::Implementing)
            | (State::Implementing, State::Validating)
            | (State::Implementing, State::Repairing)
            | (State::Validating, State::Reviewing)
            | (State::Validating, State::Repairing)
            | (State::Reviewing, State::Merging)
            | (State::Merging, State::Completed)
            | (State::Reviewing, State::Repairing)
            | (State::Repairing, State::Implementing)
            | (State::Repairing, State::Validating)
            | (
                State::Planning
                    | State::Implementing
                    | State::Validating
                    | State::Reviewing
                    | State::Repairing,
                State::Paused | State::Blocked | State::Failed
            )
            | (
                State::Merging,
                State::Paused | State::Blocked | State::Failed
            )
            | (
                State::Paused | State::Blocked,
                State::Planning
                    | State::Implementing
                    | State::Validating
                    | State::Reviewing
                    | State::Repairing
                    | State::Merging
            )
    )
}

pub(crate) fn validate_policy(policy: &TrustedPolicy) -> Result<(), Error> {
    if policy.base_ref.is_empty()
        || !is_sha(&policy.base_sha)
        || policy.allowed_assignee.is_empty()
        || policy.required_checks.is_empty()
        || policy.max_attempts == 0
        || policy.max_runtime.is_zero()
        || policy.max_model_tokens == 0
    {
        return Err(Error::CorruptRecord);
    }
    Ok(())
}

fn require_head(task: &TaskRecord, facts: &ObservedFacts) -> Result<(), Error> {
    let stored = task.head_sha.as_deref().ok_or(Error::StaleHead)?;
    if !is_sha(stored) || stored != facts.head_sha {
        return Err(Error::StaleHead);
    }
    Ok(())
}

fn require_validation(task: &TaskRecord, facts: &ObservedFacts) -> Result<(), Error> {
    if facts.validated_head_sha.as_deref() != task.head_sha.as_deref() {
        return Err(Error::StaleHead);
    }
    Ok(())
}

fn require_pr(
    task: &TaskRecord,
    facts: &ObservedFacts,
    policy: &TrustedPolicy,
) -> Result<(), Error> {
    if task.pull_request.is_none()
        || task.pull_request != facts.pr_number
        || facts.pr_head_sha.as_deref() != task.head_sha.as_deref()
        || facts.pr_base_ref.as_deref() != Some(policy.base_ref.as_str())
        || facts.pr_base_sha.as_deref() != Some(policy.base_sha.as_str())
    {
        return Err(Error::PullRequestMismatch);
    }
    Ok(())
}

fn require_merged_pr(
    task: &TaskRecord,
    facts: &ObservedFacts,
    policy: &TrustedPolicy,
) -> Result<(), Error> {
    if !facts.pr_merged {
        return Err(Error::NotApproved);
    }
    if task.pull_request.is_none()
        || task.pull_request != facts.pr_number
        || task.base_sha != policy.base_sha
        || facts.pr_head_sha.as_deref() != task.head_sha.as_deref()
        || facts.pr_base_ref.as_deref() != Some(policy.base_ref.as_str())
        || !facts.pr_base_sha.as_deref().is_some_and(is_sha)
        || !is_sha(&facts.base_sha)
        || !facts.merge_commit_sha.as_deref().is_some_and(is_sha)
        || !facts.base_contains_merge_commit
    {
        return Err(Error::PullRequestMismatch);
    }
    Ok(())
}

fn require_checks(policy: &TrustedPolicy, facts: &ObservedFacts) -> Result<(), Error> {
    if policy
        .required_checks
        .iter()
        .any(|check| !facts.checks_passed.contains(check))
    {
        return Err(Error::ChecksIncomplete);
    }
    Ok(())
}

fn is_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(state: State) -> (TaskRecord, TrustedPolicy, ObservedFacts) {
        let sha = "0123456789012345678901234567890123456789".to_owned();
        let head = "abcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned();
        let task = TaskRecord {
            task_id: "task-1".into(),
            issue_number: 9,
            base_sha: sha.clone(),
            max_attempts: 3,
            head_sha: Some(head.clone()),
            state,
            attempts: 1,
            assignee: Some("bot".into()),
            implementer: None,
            reviewer: None,
            session_id: None,
            mock_github_journal: None,
            mock_runtime_fingerprint: None,
            validation_passed: true,
            pull_request: Some(4),
            checkpoint: None,
            elapsed: Duration::from_secs(1),
            model_tokens: 1,
            model_budget: 100,
        };
        let policy = TrustedPolicy {
            base_ref: "develop".into(),
            base_sha: sha.clone(),
            allowed_assignee: "bot".into(),
            required_checks: vec!["test".into()],
            max_attempts: 3,
            max_runtime: Duration::from_secs(60),
            max_model_tokens: 100,
        };
        let facts = ObservedFacts {
            policy_base_ref: "develop".into(),
            policy_base_sha: sha.clone(),
            issue_open: true,
            base_sha: sha,
            head_sha: head.clone(),
            validated_head_sha: Some(head.clone()),
            pr_number: Some(4),
            pr_head_sha: Some(head),
            pr_base_ref: Some("develop".into()),
            pr_base_sha: Some(policy.base_sha.clone()),
            pr_merged: false,
            checks_passed: vec!["test".into()],
            reviewer_approved: true,
            approved_assignee: "bot".into(),
            merge_commit_sha: None,
            base_contains_merge_commit: false,
        };
        (task, policy, facts)
    }

    #[test]
    fn corrupt_rows_fail_closed() {
        let (mut task, policy, facts) = setup(State::Reviewing);
        task.validation_passed = false;
        assert_eq!(
            transition(&mut task, State::Merging, &policy, &facts),
            Err(Error::CorruptRecord)
        );
    }

    #[test]
    fn records_can_preserve_usage_that_crossed_the_budget_before_stopping() {
        let (mut task, _, _) = setup(State::Reviewing);
        task.model_tokens = task.model_budget + 1;
        assert_eq!(task.validate(), Ok(()));
    }

    #[test]
    fn mock_journal_must_be_an_array_and_transitions_cannot_rewrite_its_prefix() {
        let (mut current, policy, facts) = setup(State::Reviewing);
        current.mock_github_journal = Some(serde_json::json!([{"operation":"set_check"}]));
        let mut proposed = current.clone();
        proposed.mock_github_journal = Some(serde_json::json!([{"operation":"set_review"}]));
        assert_eq!(
            transition_from(&current, &mut proposed, State::Merging, &policy, &facts),
            Err(Error::InvalidTransition)
        );

        current.mock_github_journal = Some(serde_json::json!({"operation":"set_check"}));
        assert_eq!(current.validate(), Err(Error::CorruptRecord));
    }

    #[test]
    fn stale_sha_blocks_review_and_merge() {
        let (mut task, policy, mut facts) = setup(State::Reviewing);
        facts.head_sha = "ffffffffffffffffffffffffffffffffffffffff".into();
        assert_eq!(
            transition(&mut task, State::Merging, &policy, &facts),
            Err(Error::StaleHead)
        );
    }

    #[test]
    fn merging_is_only_a_verified_handoff_state() {
        let (mut task, policy, mut facts) = setup(State::Reviewing);
        facts.pr_merged = true;
        assert_eq!(
            transition(&mut task, State::Merging, &policy, &facts),
            Err(Error::AlreadyMerged)
        );
    }

    #[test]
    fn completion_needs_external_merge_observation() {
        let (mut task, policy, facts) = setup(State::Merging);
        assert_eq!(
            transition(&mut task, State::Completed, &policy, &facts),
            Err(Error::NotApproved)
        );
    }

    #[test]
    fn merged_pull_request_completes_even_when_issue_is_closed() {
        let (mut task, policy, mut facts) = setup(State::Merging);
        facts.pr_merged = true;
        facts.issue_open = false;
        facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
        facts.base_contains_merge_commit = true;
        assert_eq!(
            transition(&mut task, State::Completed, &policy, &facts),
            Ok(())
        );
        assert_eq!(task.state, State::Completed);
    }

    #[test]
    fn completion_accepts_a_moved_base_only_with_merge_ancestry_evidence() {
        let (mut task, policy, mut facts) = setup(State::Merging);
        let moved_base = "dddddddddddddddddddddddddddddddddddddddd";
        facts.base_sha = moved_base.into();
        facts.pr_merged = true;
        facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
        facts.base_contains_merge_commit = true;
        assert_eq!(policy.base_sha, task.base_sha);
        assert_eq!(
            transition(&mut task, State::Completed, &policy, &facts),
            Ok(())
        );
    }

    #[test]
    fn completion_rejects_missing_base_ancestry_proof() {
        let (mut task, policy, mut facts) = setup(State::Merging);
        facts.pr_merged = true;
        facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
        assert_eq!(
            transition(&mut task, State::Completed, &policy, &facts),
            Err(Error::PullRequestMismatch)
        );
    }

    #[test]
    fn stored_completion_requires_fresh_merge_evidence() {
        let (mut task, policy, mut facts) = setup(State::Merging);
        facts.base_sha = "dddddddddddddddddddddddddddddddddddddddd".into();
        facts.pr_merged = true;
        facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
        facts.base_contains_merge_commit = true;
        transition(&mut task, State::Completed, &policy, &facts).unwrap();
        assert_eq!(validate_completed(&task, &policy, &facts), Ok(()));
        facts.base_contains_merge_commit = false;
        assert_eq!(
            validate_completed(&task, &policy, &facts),
            Err(Error::PullRequestMismatch)
        );
    }

    #[test]
    fn repair_transition_increments_attempt_once_within_policy_limit() {
        let (mut current, policy, facts) = setup(State::Implementing);
        current.pull_request = None;
        current.validation_passed = false;
        let mut proposed = current.clone();
        proposed.attempts += 1;
        transition_from(&current, &mut proposed, State::Repairing, &policy, &facts).unwrap();
        assert_eq!(proposed.state, State::Repairing);
        assert_eq!(proposed.attempts, 2);

        current.attempts = policy.max_attempts;
        proposed = current.clone();
        proposed.attempts += 1;
        assert_eq!(
            transition_from(&current, &mut proposed, State::Repairing, &policy, &facts),
            Err(Error::InvalidTransition)
        );
    }

    #[test]
    fn transition_from_accepts_stage_output_only_when_evidence_matches() {
        let (mut current, policy, mut facts) = setup(State::Planning);
        current.head_sha = None;
        current.pull_request = None;
        current.assignee = None;
        current.validation_passed = false;
        let mut proposed = current.clone();
        proposed.assignee = Some("bot".into());
        transition_from(
            &current,
            &mut proposed,
            State::Implementing,
            &policy,
            &facts,
        )
        .unwrap();
        assert_eq!(proposed.state, State::Implementing);

        current = proposed.clone();
        proposed.state = current.state;
        proposed.head_sha = Some(facts.head_sha.clone());
        transition_from(&current, &mut proposed, State::Validating, &policy, &facts).unwrap();
        assert_eq!(proposed.state, State::Validating);

        current = proposed.clone();
        proposed.state = current.state;
        proposed.pull_request = Some(4);
        proposed.validation_passed = true;
        facts.validated_head_sha = proposed.head_sha.clone();
        transition_from(&current, &mut proposed, State::Reviewing, &policy, &facts).unwrap();
        assert_eq!(proposed.state, State::Reviewing);
    }

    #[test]
    fn transition_from_rejects_immutable_mutations_and_unverified_pr() {
        let (mut current, policy, mut facts) = setup(State::Validating);
        current.pull_request = None;
        current.validation_passed = false;
        let mut proposed = current.clone();
        proposed.issue_number += 1;
        assert_eq!(
            transition_from(&current, &mut proposed, State::Reviewing, &policy, &facts),
            Err(Error::InvalidTransition)
        );

        proposed = current.clone();
        proposed.pull_request = Some(4);
        proposed.validation_passed = true;
        facts.validated_head_sha = proposed.head_sha.clone();
        facts.pr_number = Some(5);
        assert_eq!(
            transition_from(&current, &mut proposed, State::Reviewing, &policy, &facts),
            Err(Error::PullRequestMismatch)
        );

        proposed = current.clone();
        proposed.max_attempts += 1;
        assert_eq!(
            transition_from(&current, &mut proposed, State::Reviewing, &policy, &facts),
            Err(Error::InvalidTransition)
        );

        proposed = current.clone();
        proposed.model_budget += 1;
        assert_eq!(
            transition_from(&current, &mut proposed, State::Reviewing, &policy, &facts),
            Err(Error::InvalidTransition)
        );

        current.mock_runtime_fingerprint = Some("a".repeat(64));
        proposed = current.clone();
        proposed.mock_runtime_fingerprint = Some("b".repeat(64));
        assert_eq!(
            transition_from(&current, &mut proposed, State::Reviewing, &policy, &facts),
            Err(Error::InvalidTransition)
        );
    }

    #[test]
    fn limit_exhaustion_pauses_with_a_checkpoint() {
        let (mut task, mut policy, facts) = setup(State::Implementing);
        task.attempts = 4;
        task.max_attempts = 4;
        task.pull_request = None;
        task.validation_passed = false;
        policy.max_attempts = 3;
        assert_eq!(
            transition(&mut task, State::Validating, &policy, &facts),
            Err(Error::LimitExceeded)
        );
        assert_eq!(task.state, State::Implementing);
        assert_eq!(
            transition(&mut task, State::Paused, &policy, &facts),
            Ok(())
        );
        assert_eq!(task.state, State::Paused);
        assert_eq!(task.checkpoint, Some(State::Implementing));
    }
}
