-- Allow the workflow lifecycle and human approval evidence emitted by Run Control.
-- Keep prior migrations immutable. The migration runner applies this replacement atomically.
ALTER TABLE interlock.security_events
    DROP CONSTRAINT IF EXISTS security_events_event_type_check;

ALTER TABLE interlock.security_events
    ADD CONSTRAINT security_events_event_type_check CHECK (event_type IN (
        'INTERACTION_REQUESTED', 'DATA_FLOW_OBSERVED', 'CONTROL_EVALUATED',
        'CONTROL_COVERAGE_DECLARED', 'ACTION_EXECUTED', 'INTERACTION_COMPLETED',
        'SECURITY_OUTCOME_SET', 'DETECTION_RAISED', 'INCIDENT_UPDATED',
        'CONTROL_HEALTH_CHANGED', 'POLICY_CHANGED', 'TEST_EXECUTED',
        'WORKFLOW_RUN_CREATED', 'WORKFLOW_RUN_STARTED', 'WORKFLOW_RUN_WAITING_APPROVAL',
        'WORKFLOW_RUN_COMPLETED', 'WORKFLOW_RUN_FAILED', 'WORKFLOW_RUN_CANCELED',
        'WORKFLOW_TASK_STATUS_UPDATED', 'WORKFLOW_TASK_APPROVED'
    ));
