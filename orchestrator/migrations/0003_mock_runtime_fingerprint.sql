ALTER TABLE orchestrator.tasks
    ADD COLUMN mock_runtime_fingerprint text;

ALTER TABLE orchestrator.tasks
    ADD CONSTRAINT tasks_mock_runtime_fingerprint_check CHECK (
        mock_runtime_fingerprint IS NULL
        OR mock_runtime_fingerprint ~ '^[0-9a-f]{64}$'
    );
