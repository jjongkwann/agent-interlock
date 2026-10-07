-- 0004_control_coverage.sql
--
-- Registers CONTROL_COVERAGE_DECLARED in the ledger's event-type vocabulary.
--
-- The vocabulary lives in four places -- this CHECK constraint, ledger_http._EVENT_TYPES,
-- schemas/event-envelope.schema.json and the EventType component of
-- schemas/ledger-api.openapi.yaml -- and there is no enum in Python to add a member to. The DB is
-- the write-time gate: postgres_ledger.py inserts without its own validation and lets this
-- constraint refuse. A declaration that the HTTP ingest accepts and the table rejects is the
-- failure this migration exists to prevent.
--
-- Idempotent: the runner records applied revisions, but re-running must not fail on a fresh clone
-- that already carries the new constraint name.

-- No BEGIN/COMMIT in the file. PostgreSQLMigrationRunner.apply() already runs the whole batch in
-- one transaction, so a COMMIT here would end it mid-batch and leave this migration committed while
-- a later one rolls back. The psql callers get their atomicity from `--single-transaction` instead;
-- otherwise psql runs each statement on its own and leaves a window, brief but real on a live
-- ledger, where security_events accepts any event_type at all.

ALTER TABLE interlock.security_events
    DROP CONSTRAINT IF EXISTS security_events_event_type_check;

ALTER TABLE interlock.security_events
    ADD CONSTRAINT security_events_event_type_check CHECK (event_type IN (
        'INTERACTION_REQUESTED', 'DATA_FLOW_OBSERVED', 'CONTROL_EVALUATED',
        'CONTROL_COVERAGE_DECLARED', 'ACTION_EXECUTED', 'INTERACTION_COMPLETED',
        'SECURITY_OUTCOME_SET', 'DETECTION_RAISED', 'INCIDENT_UPDATED',
        'CONTROL_HEALTH_CHANGED', 'POLICY_CHANGED', 'TEST_EXECUTED'
    ));
