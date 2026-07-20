"""Unit tests for audit store (chatbot/scripts/audit.py).

Tests audit record creation with all required fields, retry logic on write failure,
alert emission after 3 failed retries, and query_by_principal returns correct results
within SLA.

Requirements: 11.1, 11.4, 11.6
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO
from unittest.mock import MagicMock, call, patch

import pytest
from botocore.exceptions import ClientError

from chatbot.scripts.audit import (
    MAX_RETRIES,
    QUERY_TIMEOUT_SECONDS,
    QUESTION_MAX_LENGTH,
    AuditQueryError,
    AuditQueryTimeoutError,
    AuditRecord,
    AuditStore,
    AuditWriteError,
    create_audit_record,
)


# --- Test Helpers ---


def make_audit_record(**overrides) -> AuditRecord:
    """Create an AuditRecord with sensible defaults for testing."""
    defaults = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "trace_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "principal": "user-abc-123",
        "question": "What are the total sales by region?",
        "generated_sql": "SELECT region, SUM(sales) FROM orders GROUP BY region LIMIT 10000",
        "policy_decision": {"decision": "ALLOW", "policy_id": "policy-123", "version": "v1"},
        "lake_formation_outcome": "allowed",
        "cost_estimate_bytes": 5_000_000_000,
        "row_count": 42,
        "guardrails_findings": {"action": "pass", "findings": []},
        "request_status": "success",
        "error_detail": None,
    }
    defaults.update(overrides)
    return AuditRecord(**defaults)


def make_s3_client_error(code: str = "InternalError", message: str = "Service error") -> ClientError:
    """Create a ClientError for simulating S3 failures."""
    return ClientError(
        error_response={"Error": {"Code": code, "Message": message}},
        operation_name="PutObject",
    )


def make_audit_store(
    s3_client: MagicMock | None = None,
    cloudwatch_client: MagicMock | None = None,
) -> AuditStore:
    """Create an AuditStore with mock AWS clients."""
    return AuditStore(
        bucket_name="test-audit-bucket",
        s3_client=s3_client or MagicMock(),
        cloudwatch_client=cloudwatch_client or MagicMock(),
        alarm_namespace="Test/Audit",
        alarm_metric_name="TestAuditWriteFailure",
    )


# --- Tests: Audit Record Creation (Requirement 11.1) ---


class TestAuditRecordCreation:
    """Test audit record creation with all required fields per Requirement 11.1."""

    def test_audit_record_contains_all_required_fields(self):
        """AuditRecord has all fields required by Requirement 11.1."""
        record = make_audit_record()

        assert record.timestamp is not None
        assert record.trace_id is not None
        assert record.session_id is not None
        assert record.principal is not None
        assert record.question is not None
        assert record.generated_sql is not None
        assert record.policy_decision is not None
        assert record.lake_formation_outcome is not None
        assert record.cost_estimate_bytes is not None
        assert record.row_count is not None
        assert record.guardrails_findings is not None

    def test_audit_record_to_json_includes_all_fields(self):
        """Serialized JSON includes all audit context fields."""
        record = make_audit_record(
            trace_id="trace-abc",
            session_id="session-xyz",
            principal="user-test",
            question="Show me revenue",
            generated_sql="SELECT revenue FROM sales",
            policy_decision={"decision": "ALLOW", "policy_id": "pol-1"},
            lake_formation_outcome="allowed",
            cost_estimate_bytes=1_000_000,
            row_count=10,
            guardrails_findings={"action": "pass"},
        )

        json_str = record.to_json()
        data = json.loads(json_str)

        assert data["trace_id"] == "trace-abc"
        assert data["session_id"] == "session-xyz"
        assert data["principal"] == "user-test"
        assert data["question"] == "Show me revenue"
        assert data["generated_sql"] == "SELECT revenue FROM sales"
        assert data["policy_decision"] == {"decision": "ALLOW", "policy_id": "pol-1"}
        assert data["lake_formation_outcome"] == "allowed"
        assert data["cost_estimate_bytes"] == 1_000_000
        assert data["row_count"] == 10
        assert data["guardrails_findings"] == {"action": "pass"}

    def test_audit_record_truncates_long_question(self):
        """Questions exceeding 10,000 chars are truncated in serialization."""
        long_question = "x" * (QUESTION_MAX_LENGTH + 500)
        record = make_audit_record(question=long_question)

        json_str = record.to_json()
        data = json.loads(json_str)

        assert len(data["question"]) == QUESTION_MAX_LENGTH

    def test_create_audit_record_factory_sets_timestamp(self):
        """create_audit_record() factory sets timestamp to current UTC time."""
        before = datetime.now(timezone.utc)
        record = create_audit_record(
            trace_id="trace-1",
            session_id="session-1",
            principal="user-1",
            question="Test question",
        )
        after = datetime.now(timezone.utc)

        record_time = datetime.fromisoformat(record.timestamp)
        assert before <= record_time <= after

    def test_create_audit_record_factory_defaults(self):
        """create_audit_record() provides sensible defaults for optional fields."""
        record = create_audit_record(
            trace_id="trace-1",
            session_id="session-1",
            principal="user-1",
            question="Test question",
        )

        assert record.generated_sql is None
        assert record.policy_decision == {}
        assert record.lake_formation_outcome is None
        assert record.cost_estimate_bytes is None
        assert record.row_count is None
        assert record.guardrails_findings == {}
        assert record.request_status == "success"
        assert record.error_detail is None

    def test_create_audit_record_truncates_question(self):
        """create_audit_record() truncates question to QUESTION_MAX_LENGTH."""
        long_question = "y" * (QUESTION_MAX_LENGTH + 100)
        record = create_audit_record(
            trace_id="trace-1",
            session_id="session-1",
            principal="user-1",
            question=long_question,
        )

        assert len(record.question) == QUESTION_MAX_LENGTH

    def test_audit_record_with_failure_status(self):
        """AuditRecord captures failure status and error details."""
        record = make_audit_record(
            request_status="failure",
            error_detail="Policy evaluation failed: timeout",
        )

        json_str = record.to_json()
        data = json.loads(json_str)

        assert data["request_status"] == "failure"
        assert data["error_detail"] == "Policy evaluation failed: timeout"


# --- Tests: Write with Retry Logic (Requirement 11.6) ---


class TestAuditWriteRetryLogic:
    """Test retry logic on write failure per Requirement 11.6."""

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_successful_write_on_first_attempt(self, mock_sleep):
        """Write succeeds on first attempt without retries."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)
        record = make_audit_record()

        key = store.write_record(record)

        assert key is not None
        assert mock_s3.put_object.call_count == 1
        mock_sleep.assert_not_called()

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_successful_write_on_second_attempt(self, mock_sleep):
        """Write succeeds on second attempt after first failure."""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = [
            make_s3_client_error(),  # First attempt fails
            None,  # Second attempt succeeds
        ]
        store = make_audit_store(s3_client=mock_s3)
        record = make_audit_record()

        key = store.write_record(record)

        assert key is not None
        assert mock_s3.put_object.call_count == 2
        mock_sleep.assert_called_once()

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_successful_write_on_third_attempt(self, mock_sleep):
        """Write succeeds on third attempt after two failures."""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = [
            make_s3_client_error(),  # First attempt fails
            make_s3_client_error(),  # Second attempt fails
            None,  # Third attempt succeeds
        ]
        store = make_audit_store(s3_client=mock_s3)
        record = make_audit_record()

        key = store.write_record(record)

        assert key is not None
        assert mock_s3.put_object.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_write_fails_after_all_retries_raises_audit_write_error(self, mock_sleep):
        """Write raises AuditWriteError after MAX_RETRIES failures (fail-closed)."""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = make_s3_client_error()
        store = make_audit_store(s3_client=mock_s3)
        record = make_audit_record(trace_id="trace-fail-123")

        with pytest.raises(AuditWriteError) as exc_info:
            store.write_record(record)

        assert exc_info.value.trace_id == "trace-fail-123"
        assert mock_s3.put_object.call_count == MAX_RETRIES

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_exponential_backoff_between_retries(self, mock_sleep):
        """Retry uses exponential backoff (0.5s, 1.0s)."""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = make_s3_client_error()
        mock_cw = MagicMock()
        store = make_audit_store(s3_client=mock_s3, cloudwatch_client=mock_cw)
        record = make_audit_record()

        with pytest.raises(AuditWriteError):
            store.write_record(record)

        # Backoff: 0.5 * 2^0 = 0.5, 0.5 * 2^1 = 1.0
        assert mock_sleep.call_args_list == [call(0.5), call(1.0)]

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_os_error_also_triggers_retry(self, mock_sleep):
        """OSError (network issues) also triggers retry logic."""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = [
            OSError("Connection reset"),
            None,  # Succeeds on second try
        ]
        store = make_audit_store(s3_client=mock_s3)
        record = make_audit_record()

        key = store.write_record(record)

        assert key is not None
        assert mock_s3.put_object.call_count == 2


# --- Tests: Alert Emission After 3 Failed Retries (Requirement 11.6) ---


class TestAuditAlertEmission:
    """Test alert emission after 3 failed retries per Requirement 11.6."""

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_cloudwatch_alarm_emitted_after_all_retries_fail(self, mock_sleep):
        """CloudWatch metric emitted when all retry attempts are exhausted."""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = make_s3_client_error()
        mock_cw = MagicMock()
        store = make_audit_store(s3_client=mock_s3, cloudwatch_client=mock_cw)
        record = make_audit_record(trace_id="trace-alert-test")

        with pytest.raises(AuditWriteError):
            store.write_record(record)

        # Verify CloudWatch put_metric_data was called
        mock_cw.put_metric_data.assert_called_once()
        call_kwargs = mock_cw.put_metric_data.call_args[1]
        assert call_kwargs["Namespace"] == "Test/Audit"
        metric_data = call_kwargs["MetricData"][0]
        assert metric_data["MetricName"] == "TestAuditWriteFailure"
        assert metric_data["Value"] == 1.0
        assert metric_data["Dimensions"][0]["Value"] == "trace-alert-test"

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_no_alert_emitted_on_successful_write(self, mock_sleep):
        """No CloudWatch alarm when write succeeds (even after retries)."""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = [
            make_s3_client_error(),  # First fails
            None,  # Second succeeds
        ]
        mock_cw = MagicMock()
        store = make_audit_store(s3_client=mock_s3, cloudwatch_client=mock_cw)
        record = make_audit_record()

        store.write_record(record)

        mock_cw.put_metric_data.assert_not_called()

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_audit_write_error_raised_even_if_alarm_emission_fails(self, mock_sleep):
        """AuditWriteError still raised even if CloudWatch metric emission fails."""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = make_s3_client_error()
        mock_cw = MagicMock()
        mock_cw.put_metric_data.side_effect = ClientError(
            error_response={"Error": {"Code": "InternalFailure", "Message": "CW down"}},
            operation_name="PutMetricData",
        )
        store = make_audit_store(s3_client=mock_s3, cloudwatch_client=mock_cw)
        record = make_audit_record(trace_id="trace-cw-fail")

        with pytest.raises(AuditWriteError) as exc_info:
            store.write_record(record)

        # Even though CW failed, we still get AuditWriteError (fail-closed)
        assert exc_info.value.trace_id == "trace-cw-fail"


# --- Tests: query_by_principal (Requirements 11.1, 11.4) ---


class TestQueryByPrincipal:
    """Test query_by_principal returns correct results within SLA."""

    def _make_s3_record_body(self, record: AuditRecord) -> bytes:
        """Create S3 GetObject response body from an AuditRecord."""
        return record.to_json().encode("utf-8")

    def test_returns_matching_records_for_principal(self):
        """query_by_principal returns only records matching the specified principal."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)

        now = datetime.now(timezone.utc)
        # Use a same-day range to ensure only 1 prefix is generated
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now

        # Mock paginator — called once per date prefix
        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"Contents": [
                {"Key": "audit/2024/01/15/trace-1-abc.json"},
                {"Key": "audit/2024/01/15/trace-2-def.json"},
            ]}
        ]

        # First record matches principal, second doesn't
        record1 = make_audit_record(
            principal="target-user",
            trace_id="trace-1",
            timestamp=now.isoformat(),
        )
        record2 = make_audit_record(
            principal="other-user",
            trace_id="trace-2",
            timestamp=now.isoformat(),
        )

        mock_s3.get_object.side_effect = [
            {"Body": BytesIO(self._make_s3_record_body(record1))},
            {"Body": BytesIO(self._make_s3_record_body(record2))},
        ]

        results = store.query_by_principal("target-user", (start, end))

        assert len(results) == 1
        assert results[0].principal == "target-user"
        assert results[0].trace_id == "trace-1"

    def test_returns_empty_list_when_no_matches(self):
        """query_by_principal returns empty list when no records match."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)

        now = datetime.now(timezone.utc)
        start = now - timedelta(days=1)
        end = now

        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"Contents": []}]

        results = store.query_by_principal("nonexistent-user", (start, end))

        assert results == []

    def test_results_sorted_by_timestamp_oldest_first(self):
        """Returned records are sorted by timestamp (oldest first)."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)

        now = datetime.now(timezone.utc)
        # Use a range that guarantees both timestamps are within bounds
        ts_old = (now - timedelta(hours=2)).isoformat()
        ts_new = (now - timedelta(hours=1)).isoformat()
        start = now - timedelta(hours=3)
        end = now

        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"Contents": [
                {"Key": "audit/2024/01/15/trace-new.json"},
                {"Key": "audit/2024/01/15/trace-old.json"},
            ]}
        ]

        record_new = make_audit_record(
            principal="user-a", trace_id="trace-new", timestamp=ts_new
        )
        record_old = make_audit_record(
            principal="user-a", trace_id="trace-old", timestamp=ts_old
        )

        mock_s3.get_object.side_effect = [
            {"Body": BytesIO(self._make_s3_record_body(record_new))},
            {"Body": BytesIO(self._make_s3_record_body(record_old))},
        ]

        results = store.query_by_principal("user-a", (start, end))

        assert len(results) == 2
        assert results[0].trace_id == "trace-old"
        assert results[1].trace_id == "trace-new"

    def test_raises_value_error_for_invalid_date_range(self):
        """Raises ValueError when start_date is after end_date."""
        store = make_audit_store()

        now = datetime.now(timezone.utc)
        start = now
        end = now - timedelta(days=5)  # End before start

        with pytest.raises(ValueError, match="Invalid date range"):
            store.query_by_principal("user-1", (start, end))

    def test_raises_value_error_for_span_exceeding_90_days(self):
        """Raises ValueError when date range exceeds 90 days."""
        store = make_audit_store()

        now = datetime.now(timezone.utc)
        start = now - timedelta(days=91)
        end = now

        with pytest.raises(ValueError, match="exceeds maximum"):
            store.query_by_principal("user-1", (start, end))

    def test_raises_audit_query_error_on_s3_failure(self):
        """Raises AuditQueryError when S3 list/get operations fail."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)

        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            operation_name="ListObjectsV2",
        )

        now = datetime.now(timezone.utc)
        start = now - timedelta(days=1)
        end = now

        with pytest.raises(AuditQueryError) as exc_info:
            store.query_by_principal("user-1", (start, end))

        assert exc_info.value.principal == "user-1"

    def test_raises_timeout_error_when_exceeding_sla(self):
        """Raises AuditQueryTimeoutError when query exceeds 60-second SLA."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)

        now = datetime.now(timezone.utc)
        start = now - timedelta(days=30)
        end = now

        # Mock paginator that takes too long by manipulating time
        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator

        # Simulate many pages that would exhaust timeout
        # We patch time.monotonic to simulate elapsed time
        call_count = [0]
        initial_time = time.monotonic()

        def fake_monotonic():
            call_count[0] += 1
            # After a few calls, simulate exceeding timeout
            if call_count[0] > 2:
                return initial_time + QUERY_TIMEOUT_SECONDS + 1
            return initial_time

        # Return multiple prefix pages to force multiple iterations
        mock_paginator.paginate.return_value = [
            {"Contents": [{"Key": f"audit/2024/01/{i:02d}/trace-{i}.json"} for i in range(1, 5)]}
        ]

        with patch("chatbot.scripts.audit.time.monotonic", side_effect=fake_monotonic):
            with pytest.raises(AuditQueryTimeoutError) as exc_info:
                store.query_by_principal("user-1", (start, end))

            assert exc_info.value.principal == "user-1"

    def test_query_within_sla_for_narrow_date_range(self):
        """Query for a single day completes without timeout."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=12)
        end = now

        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"Contents": [{"Key": "audit/2024/01/15/trace-ok.json"}]}
        ]

        record = make_audit_record(
            principal="user-fast",
            trace_id="trace-ok",
            timestamp=now.isoformat(),
        )
        mock_s3.get_object.return_value = {
            "Body": BytesIO(self._make_s3_record_body(record))
        }

        results = store.query_by_principal("user-fast", (start, end))

        assert len(results) == 1
        assert results[0].principal == "user-fast"


# --- Tests: S3 Object Lock and Key Generation ---


class TestAuditStoreObjectLock:
    """Test S3 Object Lock compliance mode is applied correctly."""

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_put_object_applies_compliance_mode(self, mock_sleep):
        """write_record applies COMPLIANCE Object Lock mode."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)
        record = make_audit_record()

        store.write_record(record)

        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["ObjectLockMode"] == "COMPLIANCE"

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_put_object_sets_7_year_retention(self, mock_sleep):
        """write_record sets retention to 7 years from record timestamp."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)

        timestamp = "2024-06-15T10:30:00+00:00"
        record = make_audit_record(timestamp=timestamp)

        store.write_record(record)

        call_kwargs = mock_s3.put_object.call_args[1]
        retain_until = call_kwargs["ObjectLockRetainUntilDate"]
        expected = datetime.fromisoformat(timestamp).replace(year=2024 + 7)
        assert retain_until == expected

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_generated_key_uses_date_partitioning(self, mock_sleep):
        """S3 key follows audit/{year}/{month}/{day}/{trace_id}-{uuid}.json format."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)

        record = make_audit_record(
            timestamp="2024-03-22T14:30:00+00:00",
            trace_id="trace-key-test",
        )

        key = store.write_record(record)

        assert key.startswith("audit/2024/03/22/trace-key-test-")
        assert key.endswith(".json")

    @patch("chatbot.scripts.audit.time.sleep", return_value=None)
    def test_put_object_sets_json_content_type(self, mock_sleep):
        """write_record sets Content-Type to application/json."""
        mock_s3 = MagicMock()
        store = make_audit_store(s3_client=mock_s3)
        record = make_audit_record()

        store.write_record(record)

        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["ContentType"] == "application/json"
