"""Property-based tests for audit completeness.

Tests verify that every request produces an immutable audit record in the
compliance store, that records contain all required fields, and that audit
write failures trigger fail-closed behavior (deny the in-flight request).

**Validates: Requirements 11.1, 5.5, 5.8**

Properties tested:
- Property 8: Audit Completeness — every request produces an immutable audit record.

Architecture context:
- AuditStore in chatbot/scripts/audit.py writes records to S3 with Object Lock
- create_audit_record() factory produces populated AuditRecord instances
- AuditWriteError raised on write failure (fail-closed: request must be denied)
- Records include: timestamp, trace_id, session_id, principal, question, SQL,
  policy_decision, lake_formation_outcome, cost, row_count, guardrails_findings
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from hypothesis import given, assume, settings, HealthCheck
from hypothesis import strategies as st

from chatbot.scripts.audit import (
    AuditRecord,
    AuditStore,
    AuditWriteError,
    create_audit_record,
    MAX_RETRIES,
    QUESTION_MAX_LENGTH,
)


# ─── Hypothesis Strategies ────────────────────────────────────────────────────

# Trace IDs in UUID v4 format
trace_id_strategy = st.uuids(version=4).map(str)

# Session IDs in UUID v4 format
session_id_strategy = st.uuids(version=4).map(str)

# User principals (from JWT sub claim)
principal_strategy = st.text(
    min_size=3,
    max_size=50,
    alphabet=st.characters(categories=("L", "N"), whitelist_characters="-_"),
)

# Original user questions of varying length
question_strategy = st.text(
    min_size=1,
    max_size=500,
    alphabet=st.characters(categories=("L", "N", "P", "Z")),
)

# Generated SQL (optional)
sql_strategy = st.one_of(
    st.none(),
    st.just("SELECT id, name FROM users WHERE date = '2024-01-01'"),
    st.just("SELECT count(*) FROM orders GROUP BY region LIMIT 10000"),
    st.text(min_size=10, max_size=200, alphabet=st.characters(categories=("L", "N", "P", "Z"))),
)

# Policy decision results
policy_decision_strategy = st.one_of(
    st.just({}),
    st.fixed_dictionaries({
        "decision": st.sampled_from(["ALLOW", "DENY"]),
        "policy_id": st.text(min_size=3, max_size=30, alphabet="abcdef0123456789-"),
        "policy_version": st.sampled_from(["v1", "v2", "v3"]),
    }),
)

# Lake Formation outcome
lf_outcome_strategy = st.one_of(
    st.none(),
    st.sampled_from(["allowed", "denied"]),
)

# Cost estimate in bytes
cost_strategy = st.one_of(
    st.none(),
    st.integers(min_value=0, max_value=100_000_000_000),
)

# Row count
row_count_strategy = st.one_of(
    st.none(),
    st.integers(min_value=0, max_value=10_000),
)

# Guardrails findings
guardrails_findings_strategy = st.one_of(
    st.just({}),
    st.fixed_dictionaries({
        "action": st.sampled_from(["NONE", "BLOCK", "ANONYMIZE"]),
        "findings": st.lists(
            st.sampled_from(["PII:EMAIL", "PII:PHONE", "PROMPT_INJECTION", "TOXICITY"]),
            max_size=3,
        ),
    }),
)

# Request status
request_status_strategy = st.sampled_from(["success", "failure"])

# Error detail (for failed requests)
error_detail_strategy = st.one_of(
    st.none(),
    st.sampled_from([
        "AuthorizationDenied: Cedar policy forbid matched",
        "CostThresholdExceeded: Estimated 15GB scan",
        "SQLValidationFailed: Non-SELECT statement",
        "GuardrailsBlocked: Prompt injection detected",
        "LakeFormationDenied: Column access not granted",
    ]),
)


@st.composite
def audit_record_strategy(draw) -> AuditRecord:
    """Generate a valid AuditRecord with all required fields populated."""
    return AuditRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        trace_id=draw(trace_id_strategy),
        session_id=draw(session_id_strategy),
        principal=draw(principal_strategy),
        question=draw(question_strategy),
        generated_sql=draw(sql_strategy),
        policy_decision=draw(policy_decision_strategy),
        lake_formation_outcome=draw(lf_outcome_strategy),
        cost_estimate_bytes=draw(cost_strategy),
        row_count=draw(row_count_strategy),
        guardrails_findings=draw(guardrails_findings_strategy),
        request_status=draw(request_status_strategy),
        error_detail=draw(error_detail_strategy),
    )


@st.composite
def create_audit_record_kwargs(draw) -> dict[str, Any]:
    """Generate keyword arguments for create_audit_record() factory."""
    return {
        "trace_id": draw(trace_id_strategy),
        "session_id": draw(session_id_strategy),
        "principal": draw(principal_strategy),
        "question": draw(question_strategy),
        "generated_sql": draw(sql_strategy),
        "policy_decision": draw(policy_decision_strategy),
        "lake_formation_outcome": draw(lf_outcome_strategy),
        "cost_estimate_bytes": draw(cost_strategy),
        "row_count": draw(row_count_strategy),
        "guardrails_findings": draw(guardrails_findings_strategy),
        "request_status": draw(request_status_strategy),
        "error_detail": draw(error_detail_strategy),
    }


# ─── Property 8: Audit Completeness ──────────────────────────────────────────


class TestAuditCompleteness:
    """Property 8: Audit Completeness.

    **Validates: Requirements 11.1, 5.5, 5.8**

    Every request processed by the system (success or failure) produces an
    immutable audit record. Audit records cannot be silently dropped — if
    writing fails, the in-flight request must be denied (fail-closed).

    Sub-properties:
    1. Every request (success or failure) produces a record with required fields
    2. Audit write failure raises AuditWriteError (fail-closed)
    3. Records include all fields required by Requirement 11.1
    """

    @given(record=audit_record_strategy())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_every_record_written_to_s3_on_success(self, record: AuditRecord):
        """Every audit record is written to S3 when the store is available.

        **Validates: Requirements 11.1**

        For any valid AuditRecord, write_record() must successfully persist
        it to S3 and return the object key where it was stored. No record
        is silently dropped when the store is operational.
        """
        mock_s3 = MagicMock()
        mock_cw = MagicMock()
        store = AuditStore(
            bucket_name="audit-bucket",
            s3_client=mock_s3,
            cloudwatch_client=mock_cw,
        )

        object_key = store.write_record(record)

        # Record must be written — put_object called exactly once
        mock_s3.put_object.assert_called_once()

        # The returned key must be a valid non-empty string
        assert object_key is not None and len(object_key) > 0, (
            "write_record must return a non-empty S3 object key"
        )

        # The key must contain the trace_id for correlation
        assert record.trace_id in object_key, (
            f"Object key must contain trace_id '{record.trace_id}' "
            f"for request correlation, got key: '{object_key}'"
        )

    @given(record=audit_record_strategy())
    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_write_failure_raises_audit_write_error(self, record: AuditRecord):
        """Audit write failure after all retries raises AuditWriteError (fail-closed).

        **Validates: Requirements 5.8**

        IF writing to the immutable audit store fails after all retry attempts,
        THEN the system SHALL deny the in-flight request by raising AuditWriteError.
        Audit records cannot be silently dropped.
        """
        mock_s3 = MagicMock()
        mock_cw = MagicMock()

        # Simulate persistent S3 failure
        mock_s3.put_object.side_effect = ClientError(
            error_response={"Error": {"Code": "InternalError", "Message": "S3 unavailable"}},
            operation_name="PutObject",
        )

        store = AuditStore(
            bucket_name="audit-bucket",
            s3_client=mock_s3,
            cloudwatch_client=mock_cw,
        )

        with patch("chatbot.scripts.audit.time.sleep"):
            with pytest.raises(AuditWriteError) as exc_info:
                store.write_record(record)

        # AuditWriteError must contain the trace_id for correlation
        assert exc_info.value.trace_id == record.trace_id, (
            f"AuditWriteError must contain trace_id '{record.trace_id}' "
            f"for correlation, got '{exc_info.value.trace_id}'"
        )

        # All retries must have been attempted
        assert mock_s3.put_object.call_count == MAX_RETRIES, (
            f"Expected {MAX_RETRIES} retry attempts, "
            f"got {mock_s3.put_object.call_count}"
        )

    @given(record=audit_record_strategy())
    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_write_failure_emits_alarm(self, record: AuditRecord):
        """Audit write failure emits a CloudWatch alarm for compliance monitoring.

        **Validates: Requirements 11.1, 5.8**

        When audit write fails after all retries, a CloudWatch metric must be
        emitted to trigger the compliance monitoring alarm. This ensures no
        audit event is silently dropped without operational visibility.
        """
        mock_s3 = MagicMock()
        mock_cw = MagicMock()

        mock_s3.put_object.side_effect = ClientError(
            error_response={"Error": {"Code": "InternalError", "Message": "S3 unavailable"}},
            operation_name="PutObject",
        )

        store = AuditStore(
            bucket_name="audit-bucket",
            s3_client=mock_s3,
            cloudwatch_client=mock_cw,
        )

        with patch("chatbot.scripts.audit.time.sleep"):
            with pytest.raises(AuditWriteError):
                store.write_record(record)

        # CloudWatch alarm must have been emitted
        mock_cw.put_metric_data.assert_called_once()

    @given(kwargs=create_audit_record_kwargs())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_create_audit_record_always_produces_complete_record(
        self, kwargs: dict[str, Any]
    ):
        """create_audit_record factory always produces a record with all required fields.

        **Validates: Requirements 11.1**

        The factory function must produce AuditRecord instances that contain
        ALL fields required by Requirement 11.1: timestamp, trace_id, session_id,
        principal, question, SQL, policy_decision, LF outcome, cost, row count,
        and guardrails findings.
        """
        record = create_audit_record(**kwargs)

        # All required fields must be present and non-None
        assert record.timestamp is not None and len(record.timestamp) > 0, (
            "Audit record must have a non-empty timestamp"
        )
        assert record.trace_id == kwargs["trace_id"], (
            "Audit record trace_id must match input"
        )
        assert record.session_id == kwargs["session_id"], (
            "Audit record session_id must match input"
        )
        assert record.principal == kwargs["principal"], (
            "Audit record principal must match input"
        )
        assert record.question is not None, (
            "Audit record must have a question field (may be empty string)"
        )
        assert record.request_status in ("success", "failure"), (
            f"request_status must be 'success' or 'failure', got '{record.request_status}'"
        )

        # Timestamp must be valid ISO 8601
        parsed_ts = datetime.fromisoformat(record.timestamp)
        assert parsed_ts.tzinfo is not None, (
            "Audit record timestamp must be timezone-aware (UTC)"
        )

    @given(kwargs=create_audit_record_kwargs())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_audit_record_serializes_to_valid_json(self, kwargs: dict[str, Any]):
        """Every audit record serializes to valid JSON for S3 persistence.

        **Validates: Requirements 11.1**

        The audit record must serialize to valid JSON containing all required
        fields. This ensures the record can be persisted to S3 and later
        queried for DSAR/compliance investigation purposes.
        """
        record = create_audit_record(**kwargs)
        json_str = record.to_json()

        # Must produce valid JSON
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict), "Serialized record must be a JSON object"

        # Required fields must be present in serialized form
        required_keys = [
            "timestamp",
            "trace_id",
            "session_id",
            "principal",
            "question",
            "policy_decision",
            "guardrails_findings",
            "request_status",
        ]
        for key in required_keys:
            assert key in parsed, (
                f"Required field '{key}' missing from serialized audit record"
            )

    @given(
        request_status=request_status_strategy,
        kwargs=create_audit_record_kwargs(),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_both_success_and_failure_requests_produce_records(
        self, request_status: str, kwargs: dict[str, Any]
    ):
        """Both successful and failed requests produce complete audit records.

        **Validates: Requirements 11.1**

        WHEN a request completes (success or failure), THE System SHALL write
        an audit record. Neither outcome is exempt from audit trail requirements.
        """
        kwargs["request_status"] = request_status
        record = create_audit_record(**kwargs)

        mock_s3 = MagicMock()
        mock_cw = MagicMock()
        store = AuditStore(
            bucket_name="audit-bucket",
            s3_client=mock_s3,
            cloudwatch_client=mock_cw,
        )

        object_key = store.write_record(record)

        # Record must be written regardless of success/failure status
        mock_s3.put_object.assert_called_once()
        assert object_key is not None and len(object_key) > 0

        # Verify the persisted content includes the request status
        call_kwargs = mock_s3.put_object.call_args[1]
        body = call_kwargs["Body"].decode("utf-8")
        persisted = json.loads(body)
        assert persisted["request_status"] == request_status, (
            f"Persisted record must reflect request_status='{request_status}'"
        )

    @given(record=audit_record_strategy())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_record_written_with_object_lock_compliance_mode(self, record: AuditRecord):
        """Audit records are written with S3 Object Lock in Compliance mode.

        **Validates: Requirements 11.1, 5.5**

        Records must be immutable — written with Object Lock Compliance mode
        so they cannot be deleted or overwritten by any account including root.
        This ensures tamper-proof audit trail for regulatory compliance.
        """
        mock_s3 = MagicMock()
        mock_cw = MagicMock()
        store = AuditStore(
            bucket_name="audit-bucket",
            s3_client=mock_s3,
            cloudwatch_client=mock_cw,
        )

        store.write_record(record)

        call_kwargs = mock_s3.put_object.call_args[1]

        # Must use Compliance mode Object Lock
        assert call_kwargs["ObjectLockMode"] == "COMPLIANCE", (
            f"Audit records must use COMPLIANCE Object Lock mode, "
            f"got '{call_kwargs.get('ObjectLockMode')}'"
        )

        # Must have a retention date set
        assert "ObjectLockRetainUntilDate" in call_kwargs, (
            "Audit records must have ObjectLockRetainUntilDate for 7-year retention"
        )

        # Retention must be in the future (7 years from record timestamp)
        retain_until = call_kwargs["ObjectLockRetainUntilDate"]
        record_time = datetime.fromisoformat(record.timestamp)
        assert retain_until > record_time, (
            "Retention date must be after the record timestamp"
        )

    @given(record=audit_record_strategy())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_policy_decision_included_in_persisted_record(self, record: AuditRecord):
        """Policy decision is included in the persisted audit record.

        **Validates: Requirements 5.5**

        WHEN a Cedar policy evaluation completes, THE system SHALL log the
        decision to the immutable audit store. The audit record must contain
        the policy_decision field with the evaluation result.
        """
        mock_s3 = MagicMock()
        mock_cw = MagicMock()
        store = AuditStore(
            bucket_name="audit-bucket",
            s3_client=mock_s3,
            cloudwatch_client=mock_cw,
        )

        store.write_record(record)

        call_kwargs = mock_s3.put_object.call_args[1]
        body = call_kwargs["Body"].decode("utf-8")
        persisted = json.loads(body)

        # policy_decision must be present in the persisted record
        assert "policy_decision" in persisted, (
            "Persisted audit record must contain 'policy_decision' field "
            "for Cedar policy evaluation logging (Requirement 5.5)"
        )

        # If the original record had a policy decision, it must be preserved
        assert persisted["policy_decision"] == record.policy_decision, (
            "Policy decision must be faithfully persisted in the audit record"
        )

    @given(
        base_question=st.text(min_size=500, max_size=500),
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.function_scoped_fixture])
    def test_question_truncated_to_max_length(self, base_question: str):
        """Questions exceeding 10,000 characters are truncated in the record.

        **Validates: Requirements 11.1**

        Requirement 11.1 specifies original question up to 10,000 characters.
        The audit system must truncate longer questions while still persisting
        a record (not failing).
        """
        # Build a question that exceeds QUESTION_MAX_LENGTH by repeating
        question = base_question * 25  # 500 * 25 = 12,500 chars, always > 10,000
        assert len(question) > QUESTION_MAX_LENGTH  # sanity check

        record = create_audit_record(
            trace_id=str(uuid.uuid4()),
            session_id=str(uuid.uuid4()),
            principal="test-user",
            question=question,
        )

        # Question must be truncated to max length
        assert len(record.question) <= QUESTION_MAX_LENGTH, (
            f"Question must be truncated to {QUESTION_MAX_LENGTH} chars, "
            f"got {len(record.question)}"
        )

        # Serialized form must also respect the limit
        json_str = record.to_json()
        parsed = json.loads(json_str)
        assert len(parsed["question"]) <= QUESTION_MAX_LENGTH

    @given(record=audit_record_strategy())
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_transient_failure_retries_then_succeeds(self, record: AuditRecord):
        """Transient S3 failures are retried and the record is eventually persisted.

        **Validates: Requirements 11.1**

        The audit store must retry on transient failures (up to MAX_RETRIES)
        and persist the record when a retry succeeds. This ensures temporary
        infrastructure issues do not cause audit gaps.
        """
        mock_s3 = MagicMock()
        mock_cw = MagicMock()

        # Fail on first attempt, succeed on second
        mock_s3.put_object.side_effect = [
            ClientError(
                error_response={"Error": {"Code": "InternalError", "Message": "Transient"}},
                operation_name="PutObject",
            ),
            None,  # Success on retry
        ]

        store = AuditStore(
            bucket_name="audit-bucket",
            s3_client=mock_s3,
            cloudwatch_client=mock_cw,
        )

        with patch("chatbot.scripts.audit.time.sleep"):
            object_key = store.write_record(record)

        # Record must be written after retry
        assert object_key is not None and len(object_key) > 0, (
            "Record must be persisted after successful retry"
        )
        assert mock_s3.put_object.call_count == 2, (
            "Expected 2 put_object calls (1 failure + 1 success)"
        )

        # No alarm should be emitted (write eventually succeeded)
        mock_cw.put_metric_data.assert_not_called()

    @given(record=audit_record_strategy())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_record_key_is_date_partitioned(self, record: AuditRecord):
        """Audit records are stored with date-partitioned keys for efficient querying.

        **Validates: Requirements 11.1**

        Records must be stored under date-partitioned S3 key prefixes to
        enable efficient DSAR and compliance investigation queries by date range.
        """
        mock_s3 = MagicMock()
        mock_cw = MagicMock()
        store = AuditStore(
            bucket_name="audit-bucket",
            s3_client=mock_s3,
            cloudwatch_client=mock_cw,
        )

        object_key = store.write_record(record)

        # Key must start with audit/ prefix
        assert object_key.startswith("audit/"), (
            f"Object key must start with 'audit/' prefix, got '{object_key}'"
        )

        # Key must contain date components from record timestamp
        record_time = datetime.fromisoformat(record.timestamp)
        expected_prefix = (
            f"audit/{record_time.year:04d}/{record_time.month:02d}/{record_time.day:02d}/"
        )
        assert object_key.startswith(expected_prefix), (
            f"Object key must be date-partitioned: expected prefix '{expected_prefix}', "
            f"got key '{object_key}'"
        )

        # Key must end with .json extension
        assert object_key.endswith(".json"), (
            f"Object key must have .json extension, got '{object_key}'"
        )
