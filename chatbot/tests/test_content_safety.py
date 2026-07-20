"""Unit tests for content safety — PII redaction and session termination logic.

Tests:
- PII redaction based on user role grants (Cedar policy)
- Session termination after 3+ BLOCK actions
- Security event logging to audit store and SIEM
- Re-authentication requirement after terminated session
- Middleware-level enforcement of terminated sessions

Requirements: 8.3, 8.5
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from chatbot.agent.nodes.content_safety import (
    SESSION_BLOCK_THRESHOLD,
    SessionBlockRecord,
    SessionBlockTracker,
    get_block_tracker,
    get_permitted_pii_categories,
    handle_guardrail_block,
    log_session_termination,
    reset_block_tracker,
    should_redact_pii,
    terminate_session_if_needed,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_tracker():
    """Reset the block tracker singleton before each test."""
    reset_block_tracker()
    yield
    reset_block_tracker()


@pytest.fixture
def tracker() -> SessionBlockTracker:
    """Fresh SessionBlockTracker instance."""
    return SessionBlockTracker()


@pytest.fixture
def mock_session_store():
    """Mock session store that tracks invalidation calls."""
    store = MagicMock()
    store.invalidate = MagicMock()
    return store


@pytest.fixture
def mock_audit_store():
    """Mock audit store that records write_record calls."""
    store = MagicMock()
    store.write_record = MagicMock()
    return store


# ---------------------------------------------------------------------------
# Tests: PII redaction via Cedar policy grants (Requirement 8.3)
# ---------------------------------------------------------------------------


class TestPIIRedaction:
    """Tests for PII redaction based on user role grants."""

    def test_analyst_has_no_pii_grants(self):
        """Analysts have no PII viewing grants — all PII is redacted."""
        user_claims = {"role": "analyst", "groups": []}
        permitted = get_permitted_pii_categories(user_claims)
        assert permitted == set()

    def test_manager_can_view_name_email_phone(self):
        """Managers can view NAME, EMAIL, PHONE without redaction."""
        user_claims = {"role": "manager", "groups": []}
        permitted = get_permitted_pii_categories(user_claims)
        assert permitted == {"NAME", "EMAIL", "PHONE"}

    def test_compliance_officer_has_extended_grants(self):
        """Compliance officers can view extended PII categories."""
        user_claims = {"role": "compliance_officer", "groups": []}
        permitted = get_permitted_pii_categories(user_claims)
        assert "SSN" in permitted
        assert "CREDIT_DEBIT_CARD_NUMBER" in permitted
        assert "NAME" in permitted
        assert "EMAIL" in permitted
        assert "PHONE" in permitted
        assert "ADDRESS" in permitted

    def test_hr_director_can_view_hr_pii(self):
        """HR directors can view HR-relevant PII categories."""
        user_claims = {"role": "hr_director", "groups": []}
        permitted = get_permitted_pii_categories(user_claims)
        assert "NAME" in permitted
        assert "SSN" in permitted
        assert "ADDRESS" in permitted

    def test_pii_full_access_group_permits_all(self):
        """Users in pii_full_access group can view all PII types."""
        user_claims = {"role": "analyst", "groups": ["pii_full_access"]}
        permitted = get_permitted_pii_categories(user_claims)
        # Should contain all 31 PII types
        assert len(permitted) == 31
        assert "SSN" in permitted
        assert "CREDIT_DEBIT_CARD_NUMBER" in permitted

    def test_unknown_role_has_no_grants(self):
        """Unknown/empty roles have no PII viewing grants."""
        user_claims = {"role": "unknown_role", "groups": []}
        permitted = get_permitted_pii_categories(user_claims)
        assert permitted == set()

    def test_should_redact_ssn_for_analyst(self):
        """SSN should be redacted for analysts."""
        user_claims = {"role": "analyst", "groups": []}
        assert should_redact_pii("SSN", user_claims) is True

    def test_should_not_redact_name_for_manager(self):
        """NAME should not be redacted for managers."""
        user_claims = {"role": "manager", "groups": []}
        assert should_redact_pii("NAME", user_claims) is False

    def test_should_redact_ssn_for_manager(self):
        """SSN should be redacted for managers (not in their grant set)."""
        user_claims = {"role": "manager", "groups": []}
        assert should_redact_pii("SSN", user_claims) is True

    def test_should_not_redact_ssn_for_compliance_officer(self):
        """SSN should not be redacted for compliance officers."""
        user_claims = {"role": "compliance_officer", "groups": []}
        assert should_redact_pii("SSN", user_claims) is False

    def test_empty_role_redacts_everything(self):
        """Empty role means all PII is redacted."""
        user_claims = {"role": "", "groups": []}
        permitted = get_permitted_pii_categories(user_claims)
        assert permitted == set()
        assert should_redact_pii("EMAIL", user_claims) is True


# ---------------------------------------------------------------------------
# Tests: Session block tracking and termination (Requirement 8.5)
# ---------------------------------------------------------------------------


class TestSessionBlockTracker:
    """Tests for SessionBlockTracker block counting and termination logic."""

    def test_initial_block_count_is_zero(self, tracker: SessionBlockTracker):
        """New sessions start with zero blocks."""
        assert tracker.get_block_count("session-1") == 0

    def test_record_block_increments_count(self, tracker: SessionBlockTracker):
        """Recording a block increments the count."""
        tracker.record_block("session-1")
        assert tracker.get_block_count("session-1") == 1

    def test_multiple_blocks_accumulate(self, tracker: SessionBlockTracker):
        """Multiple blocks accumulate correctly."""
        tracker.record_block("session-1")
        tracker.record_block("session-1")
        assert tracker.get_block_count("session-1") == 2

    def test_should_terminate_at_threshold(self, tracker: SessionBlockTracker):
        """Session should be terminated when block count reaches threshold."""
        for _ in range(SESSION_BLOCK_THRESHOLD):
            tracker.record_block("session-1")
        assert tracker.should_terminate("session-1") is True

    def test_should_not_terminate_below_threshold(self, tracker: SessionBlockTracker):
        """Session should not be terminated below threshold."""
        for _ in range(SESSION_BLOCK_THRESHOLD - 1):
            tracker.record_block("session-1")
        assert tracker.should_terminate("session-1") is False

    def test_terminate_session_marks_terminated(self, tracker: SessionBlockTracker):
        """Terminating a session marks it as terminated."""
        for _ in range(SESSION_BLOCK_THRESHOLD):
            tracker.record_block("session-1")
        tracker.terminate_session("session-1")
        assert tracker.is_terminated("session-1") is True

    def test_is_terminated_false_initially(self, tracker: SessionBlockTracker):
        """Sessions are not terminated initially."""
        assert tracker.is_terminated("session-1") is False

    def test_terminate_sets_timestamp(self, tracker: SessionBlockTracker):
        """Termination records a timestamp."""
        tracker.record_block("session-1")
        tracker.record_block("session-1")
        tracker.record_block("session-1")
        record = tracker.terminate_session("session-1")
        assert record.terminated is True
        assert record.terminated_at is not None
        assert record.terminated_at > 0

    def test_separate_sessions_tracked_independently(self, tracker: SessionBlockTracker):
        """Different sessions are tracked independently."""
        tracker.record_block("session-1")
        tracker.record_block("session-1")
        tracker.record_block("session-1")
        tracker.record_block("session-2")

        assert tracker.get_block_count("session-1") == 3
        assert tracker.get_block_count("session-2") == 1
        assert tracker.should_terminate("session-1") is True
        assert tracker.should_terminate("session-2") is False

    def test_should_terminate_false_after_terminated(self, tracker: SessionBlockTracker):
        """should_terminate returns False once session is already terminated."""
        for _ in range(SESSION_BLOCK_THRESHOLD):
            tracker.record_block("session-1")
        tracker.terminate_session("session-1")
        # Already terminated — should_terminate returns False
        assert tracker.should_terminate("session-1") is False

    def test_clear_session_removes_tracking_data(self, tracker: SessionBlockTracker):
        """Clearing a session removes all tracking data."""
        tracker.record_block("session-1")
        tracker.record_block("session-1")
        tracker.clear_session("session-1")
        assert tracker.get_block_count("session-1") == 0
        assert tracker.is_terminated("session-1") is False

    def test_get_record_returns_none_for_unknown(self, tracker: SessionBlockTracker):
        """get_record returns None for unknown sessions."""
        assert tracker.get_record("unknown-session") is None

    def test_get_record_returns_record_after_block(self, tracker: SessionBlockTracker):
        """get_record returns the record after recording blocks."""
        tracker.record_block("session-1")
        record = tracker.get_record("session-1")
        assert record is not None
        assert record.block_count == 1
        assert record.session_id == "session-1"

    def test_reset_clears_all_sessions(self, tracker: SessionBlockTracker):
        """reset() clears all session tracking data."""
        tracker.record_block("session-1")
        tracker.record_block("session-2")
        tracker.reset()
        assert tracker.get_block_count("session-1") == 0
        assert tracker.get_block_count("session-2") == 0


# ---------------------------------------------------------------------------
# Tests: Session termination integration (Requirement 8.5)
# ---------------------------------------------------------------------------


class TestTerminateSessionIfNeeded:
    """Tests for terminate_session_if_needed integration function."""

    def test_terminates_at_threshold(self, mock_session_store, mock_audit_store):
        """Session is terminated when block count reaches threshold."""
        tracker = get_block_tracker()
        for _ in range(SESSION_BLOCK_THRESHOLD):
            tracker.record_block("session-abc")

        result = terminate_session_if_needed(
            session_id="session-abc",
            principal="user-123",
            trace_id="trace-xyz",
            session_store=mock_session_store,
            audit_store=mock_audit_store,
        )

        assert result is True
        mock_session_store.invalidate.assert_called_once_with("session-abc")

    def test_does_not_terminate_below_threshold(self, mock_session_store, mock_audit_store):
        """Session is not terminated below threshold."""
        tracker = get_block_tracker()
        tracker.record_block("session-abc")
        tracker.record_block("session-abc")

        result = terminate_session_if_needed(
            session_id="session-abc",
            principal="user-123",
            trace_id="trace-xyz",
            session_store=mock_session_store,
            audit_store=mock_audit_store,
        )

        assert result is False
        mock_session_store.invalidate.assert_not_called()

    def test_writes_audit_record_on_termination(self, mock_session_store, mock_audit_store):
        """Audit record is written when session is terminated."""
        tracker = get_block_tracker()
        for _ in range(SESSION_BLOCK_THRESHOLD):
            tracker.record_block("session-abc")

        terminate_session_if_needed(
            session_id="session-abc",
            principal="user-123",
            trace_id="trace-xyz",
            session_store=mock_session_store,
            audit_store=mock_audit_store,
        )

        mock_audit_store.write_record.assert_called_once()
        audit_record = mock_audit_store.write_record.call_args[0][0]
        assert audit_record.session_id == "session-abc"
        assert audit_record.principal == "user-123"
        assert audit_record.request_status == "session_terminated"

    def test_works_without_session_store(self, mock_audit_store):
        """Termination works even without session store (graceful degradation)."""
        tracker = get_block_tracker()
        for _ in range(SESSION_BLOCK_THRESHOLD):
            tracker.record_block("session-abc")

        result = terminate_session_if_needed(
            session_id="session-abc",
            principal="user-123",
            trace_id="trace-xyz",
            session_store=None,
            audit_store=mock_audit_store,
        )

        assert result is True

    def test_works_without_audit_store(self, mock_session_store):
        """Termination works even without audit store (logs warning)."""
        tracker = get_block_tracker()
        for _ in range(SESSION_BLOCK_THRESHOLD):
            tracker.record_block("session-abc")

        result = terminate_session_if_needed(
            session_id="session-abc",
            principal="user-123",
            trace_id="trace-xyz",
            session_store=mock_session_store,
            audit_store=None,
        )

        assert result is True
        mock_session_store.invalidate.assert_called_once_with("session-abc")


# ---------------------------------------------------------------------------
# Tests: Security event logging (Requirement 8.5)
# ---------------------------------------------------------------------------


class TestLogSessionTermination:
    """Tests for security event logging to audit store and SIEM."""

    def test_returns_security_event_dict(self):
        """log_session_termination returns a structured security event."""
        event = log_session_termination(
            session_id="session-abc",
            principal="user-123",
            block_count=3,
            trace_id="trace-xyz",
        )

        assert event["event_type"] == "security_alert"
        assert event["alert_type"] == "session_terminated_excessive_blocks"
        assert event["session_id"] == "session-abc"
        assert event["principal"] == "user-123"
        assert event["block_count"] == 3
        assert event["threshold"] == SESSION_BLOCK_THRESHOLD
        assert event["trace_id"] == "trace-xyz"
        assert "timestamp" in event
        assert event["action_required"] == "User must re-authenticate"

    def test_writes_audit_record_when_store_provided(self, mock_audit_store):
        """Audit record is written when audit store is provided."""
        log_session_termination(
            session_id="session-abc",
            principal="user-123",
            block_count=3,
            trace_id="trace-xyz",
            audit_store=mock_audit_store,
        )

        mock_audit_store.write_record.assert_called_once()
        record = mock_audit_store.write_record.call_args[0][0]
        assert record.principal == "user-123"
        assert record.session_id == "session-abc"
        assert record.trace_id == "trace-xyz"
        assert record.request_status == "session_terminated"

    def test_handles_audit_store_failure_gracefully(self):
        """If audit store write fails, the function still completes."""
        failing_store = MagicMock()
        failing_store.write_record = MagicMock(side_effect=Exception("S3 error"))

        # Should not raise
        event = log_session_termination(
            session_id="session-abc",
            principal="user-123",
            block_count=3,
            trace_id="trace-xyz",
            audit_store=failing_store,
        )

        # Event is still returned
        assert event["event_type"] == "security_alert"

    @patch("chatbot.agent.nodes.content_safety.security_logger")
    def test_emits_siem_log(self, mock_security_logger):
        """Security event is emitted to the SIEM logger."""
        log_session_termination(
            session_id="session-abc",
            principal="user-123",
            block_count=3,
            trace_id="trace-xyz",
        )

        mock_security_logger.warning.assert_called_once()
        call_args = mock_security_logger.warning.call_args
        assert call_args[0][0] == "SESSION_TERMINATED_EXCESSIVE_BLOCKS"
        extra = call_args[1]["extra"]
        assert extra["alert_priority"] == "P2"
        assert extra["session_id"] == "session-abc"


# ---------------------------------------------------------------------------
# Tests: handle_guardrail_block integration (Requirement 8.5)
# ---------------------------------------------------------------------------


class TestHandleGuardrailBlock:
    """Tests for the handle_guardrail_block orchestration function."""

    def test_first_block_does_not_terminate(self):
        """First block does not terminate the session."""
        result = handle_guardrail_block(
            session_id="session-1",
            principal="user-1",
            trace_id="trace-1",
            findings=["CONTENT_FILTER:HATE:BLOCKED:HIGH"],
        )

        assert result["terminated"] is False
        assert result["block_count"] == 1
        assert "I can't help with that request" in result["error_message"]

    def test_second_block_does_not_terminate(self):
        """Second block does not terminate the session."""
        handle_guardrail_block(
            session_id="session-1",
            principal="user-1",
            trace_id="trace-1",
            findings=["finding-1"],
        )
        result = handle_guardrail_block(
            session_id="session-1",
            principal="user-1",
            trace_id="trace-2",
            findings=["finding-2"],
        )

        assert result["terminated"] is False
        assert result["block_count"] == 2

    def test_third_block_terminates_session(self):
        """Third block triggers session termination."""
        handle_guardrail_block(
            session_id="session-1",
            principal="user-1",
            trace_id="trace-1",
            findings=["finding-1"],
        )
        handle_guardrail_block(
            session_id="session-1",
            principal="user-1",
            trace_id="trace-2",
            findings=["finding-2"],
        )
        result = handle_guardrail_block(
            session_id="session-1",
            principal="user-1",
            trace_id="trace-3",
            findings=["finding-3"],
        )

        assert result["terminated"] is True
        assert result["block_count"] == 3
        assert "re-authenticate" in result["error_message"]

    def test_block_after_termination_returns_terminated(self):
        """Blocks after termination return terminated status immediately."""
        # Terminate the session
        for i in range(3):
            handle_guardrail_block(
                session_id="session-1",
                principal="user-1",
                trace_id=f"trace-{i}",
                findings=[f"finding-{i}"],
            )

        # Further block attempt
        result = handle_guardrail_block(
            session_id="session-1",
            principal="user-1",
            trace_id="trace-4",
            findings=["finding-4"],
        )

        assert result["terminated"] is True
        assert "re-authenticate" in result["error_message"]

    def test_invalidates_session_store_on_termination(self, mock_session_store):
        """Session store is invalidated on termination."""
        for i in range(3):
            handle_guardrail_block(
                session_id="session-1",
                principal="user-1",
                trace_id=f"trace-{i}",
                findings=[f"finding-{i}"],
                session_store=mock_session_store,
            )

        mock_session_store.invalidate.assert_called_once_with("session-1")

    def test_error_message_does_not_reveal_detection_category(self):
        """Block error message does not reveal what was detected (Req 8.2)."""
        result = handle_guardrail_block(
            session_id="session-1",
            principal="user-1",
            trace_id="trace-1",
            findings=["CONTENT_FILTER:HATE:BLOCKED:HIGH"],
        )

        msg = result["error_message"]
        # Should not contain internal detection details
        assert "HATE" not in msg
        assert "BLOCKED" not in msg
        assert "CONTENT_FILTER" not in msg
        # Should have a generic helpful message
        assert "I can't help with that request" in msg


# ---------------------------------------------------------------------------
# Tests: Middleware enforcement of terminated sessions (Requirement 8.5)
# ---------------------------------------------------------------------------


class TestMiddlewareSessionTermination:
    """Tests for middleware-level enforcement of terminated sessions."""

    def test_middleware_blocks_terminated_session(self):
        """Middleware returns 401 for requests from terminated sessions."""
        from chatbot.agent.nodes.content_safety import get_block_tracker
        from chatbot.api.middleware import SessionStore, SessionTimeoutMiddleware

        # Set up: terminate a session
        tracker = get_block_tracker()
        for _ in range(SESSION_BLOCK_THRESHOLD):
            tracker.record_block("terminated-session")
        tracker.terminate_session("terminated-session")

        # Create a session store with the session
        session_store = SessionStore()
        session_store.create("terminated-session", "user-1")

        # Verify the middleware's helper method detects termination
        from unittest.mock import AsyncMock

        middleware = SessionTimeoutMiddleware(app=AsyncMock(), session_store=session_store)
        assert middleware._is_session_terminated("terminated-session") is True

    def test_middleware_allows_non_terminated_session(self):
        """Middleware allows requests from non-terminated sessions."""
        from chatbot.api.middleware import SessionStore, SessionTimeoutMiddleware
        from unittest.mock import AsyncMock

        session_store = SessionStore()
        session_store.create("active-session", "user-1")

        middleware = SessionTimeoutMiddleware(app=AsyncMock(), session_store=session_store)
        assert middleware._is_session_terminated("active-session") is False
