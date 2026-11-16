CREATE SCHEMA orchestrator;

CREATE TYPE orchestrator.task_state AS ENUM (
    'queued',
    'planning',
    'implementing',
    'validating',
    'reviewing',
    'merging',
    'completed',
    'repairing',
    'paused',
    'blocked',
    'failed'
);

CREATE TABLE orchestrator.tasks (
    id uuid PRIMARY KEY,
    repository text NOT NULL CHECK (repository ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
    issue_number bigint NOT NULL CHECK (issue_number > 0),
    base_sha text NOT NULL CHECK (base_sha ~ '^[0-9a-f]{40}$'),
    head_sha text CHECK (head_sha IS NULL OR head_sha ~ '^[0-9a-f]{40}$'),
    status orchestrator.task_state NOT NULL DEFAULT 'queued',
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL CHECK (max_attempts > 0),
    assigned_worker text,
    validation_result jsonb CHECK (validation_result IS NULL OR jsonb_typeof(validation_result) = 'object'),
    pr_number bigint CHECK (pr_number IS NULL OR pr_number > 0),
    checkpoint jsonb CHECK (checkpoint IS NULL OR jsonb_typeof(checkpoint) = 'object'),
    resume_state orchestrator.task_state,
    execution_timeout_seconds bigint NOT NULL CHECK (execution_timeout_seconds > 0),
    execution_started_at timestamptz,
    execution_deadline timestamptz,
    model_usage bigint NOT NULL DEFAULT 0 CHECK (model_usage >= 0),
    model_budget bigint NOT NULL CHECK (model_budget >= 0),
    idempotency_key uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository, issue_number),
    CHECK (attempt_count <= max_attempts),
    CHECK ((execution_started_at IS NULL) = (execution_deadline IS NULL)),
    CHECK (resume_state IS NULL OR status IN ('paused', 'blocked', 'failed'))
);

CREATE INDEX tasks_ready_idx ON orchestrator.tasks (created_at, id)
    WHERE status = 'queued';

-- One row serializes every worker. An expired lease remains occupied until recovery
-- confirms the old process and its children can no longer perform external work.
CREATE TABLE orchestrator.execution_lease (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    task_id uuid REFERENCES orchestrator.tasks (id),
    owner text,
    fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    expires_at timestamptz,
    CHECK ((task_id IS NULL) = (owner IS NULL)),
    CHECK ((task_id IS NULL) = (expires_at IS NULL))
);

INSERT INTO orchestrator.execution_lease (singleton) VALUES (true);

CREATE SEQUENCE orchestrator.fencing_token_seq AS bigint NO CYCLE;

CREATE TABLE orchestrator.task_operations (
    operation_key uuid PRIMARY KEY,
    task_id uuid NOT NULL REFERENCES orchestrator.tasks (id),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    operation text NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    result jsonb CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE orchestrator.recovery_confirmations (
    confirmation_id uuid PRIMARY KEY,
    task_id uuid NOT NULL REFERENCES orchestrator.tasks (id),
    expired_fencing_token bigint NOT NULL CHECK (expired_fencing_token > 0),
    confirmed_by text NOT NULL,
    evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
    confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (task_id, expired_fencing_token)
);
