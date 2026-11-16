ALTER TABLE orchestrator.tasks
    ADD COLUMN issue_assignee text,
    ADD COLUMN implementer text CHECK (implementer IS NULL OR (btrim(implementer) <> '' AND length(implementer) <= 255)),
    ADD COLUMN reviewer text CHECK (reviewer IS NULL OR (btrim(reviewer) <> '' AND length(reviewer) <= 255)),
    ADD COLUMN session_id text CHECK (session_id IS NULL OR (btrim(session_id) <> '' AND length(session_id) <= 255)),
    ADD COLUMN mock_github_journal jsonb CHECK (
        mock_github_journal IS NULL OR (
            jsonb_typeof(mock_github_journal) = 'array'
            AND octet_length(mock_github_journal::text) <= 65536
        )
    ),
    ADD COLUMN repair_count integer NOT NULL DEFAULT 0;

-- The old counter included the initial claim; preserve only its repair portion.
UPDATE orchestrator.tasks
SET repair_count = GREATEST(attempt_count - 1, 0),
    issue_assignee = assigned_worker;

ALTER TABLE orchestrator.tasks
    ADD CONSTRAINT tasks_issue_assignee_check CHECK (
        issue_assignee IS NULL OR (btrim(issue_assignee) <> '' AND length(issue_assignee) <= 255)
    );

ALTER TABLE orchestrator.tasks
    ADD CONSTRAINT tasks_repair_count_check CHECK (repair_count >= 0 AND repair_count <= max_attempts);
