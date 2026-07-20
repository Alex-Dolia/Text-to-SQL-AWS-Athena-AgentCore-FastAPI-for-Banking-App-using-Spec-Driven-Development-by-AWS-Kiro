"""Unit tests for the administrative kill switch (chatbot/scripts/kill_switch.py).

Tests:
- Kill switch activation (disable) with proper authorization
- Kill switch re-enablement (enable) with proper authorization
- Unauthorized attempt rejection and audit logging
- Reason field validation (10-500 characters)
- Audit record creation for all operations
- Gateway target disable/enable API calls

Requirements: 14.1, 14.2, 14.3, 14.4, 14.5
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch, call

import pytest

from chatbot.scripts.kill_switch import (
    KillSwitch,
    KillSwitchAction,
    KillSwitchActivationError,
    KillSwitchError,
    KillSwitchRequest,
    KillSwitchResult,
    InvalidReasonError,
    REASON_MAX_LENGTH,
    REASON_MIN_LENGTH,
    SECURITY_OPERATIONS_ROLE,
    UnauthorizedKillSwitchError,
)
from chatbot.scripts.audit import AuditRecord, AuditStore, AuditWriteError


# --- Test Helpers ---


def make_audit_store(**overrides) -> AuditStore:
    """Create an AuditStore with mock S3 and CloudWatch clients."""
    mock_s3 = overrides.get("s3_client", MagicMock())
    mock_cw = overrides.get("cloudwatch_client", MagicMock())
    return AuditStore(
        bucket_name="test-audit-bucket",
        s3_client=mock_s3,
        cloudwatch_client=mock_cw,
    )


def make_kill_switch(
    audit_store: AuditStore | None = None,
    gateway_client: MagicMock | None = None,
    cloudwatch_client: MagicMock | None = None,
) -> KillSwitch:
    """Create a KillSwitch with mock dependencies."""
    if audit_store is None:
        audit_store = make_audit_store()
    if gateway_client is None:
        gateway_client = MagicMock()
    if cloudwatch_client is None:
        cloudwatch_client = MagicMock()
    return KillSwitch(
        audit_store=audit_store,
        gateway_client=gateway_client,
        cloudwatch_client=cloudwatch_client,
    )


def make_disable_request(**overrides) -> KillSwitchRequest:
    """Create a valid kill switch disable request."""
    defaults = {
        "operator_principal": "user-secops-001",
        "operator_role": SECURITY_OPERATIONS_ROLE,
        "target": "api123/integration456",
        "reason": "Security incident detected - containing breach",
        "action": KillSwitchAction.DISABLE,
    }
    defaults.update(overrides)
    return KillSwitchRequest(**defaults)


def make_enable_request(**overrides) -> KillSwitchRequest:
    """Create a valid kill switch enable request."""
    defaults = {
        "operator_principal": "user-secops-001",
        "operator_role": SECURITY_OPERATIONS_ROLE,
        "target": "api123/integration456",
        "reason": "Incident resolved - restoring access",
        "action": KillSwitchAction.ENABLE,
    }
    defaults.update(overrides)
    return KillSwitchRequest(**defaults)


# --- Test Classes ---


class TestKillSwitchAuthorization:
    """Tests for kill switch authorization enforcement (Requirement 14.4)."""

    def test_authorized_security_operations_role_succeeds(self):
        """Operator with security-operations role can invoke kill switch."""
        ks = make_kill_switch()
        request = make_disable_request()

        result = ks.disable(request)

        assert result.success is True
        assert result.action == KillSwitchAction.DISABLE

    def test_unauthorized_analyst_role_rejected(self):
        """Operator with analyst role is rejected with HTTP 403 equivalent."""
        ks = make_kill_switch()
        request = make_disable_request(operator_role="analyst")

        with pytest.raises(UnauthorizedKillSwitchError) as exc_info:
            ks.disable(request)

        assert exc_info.value.principal == "user-secops-001"
        assert exc_info.value.role == "analyst"

    def test_unauthorized_manager_role_rejected(self):
        """Operator with manager role is rejected."""
        ks = make_kill_switch()
        request = make_disable_request(operator_role="manager")

        with pytest.raises(UnauthorizedKillSwitchError):
            ks.disable(request)

    def test_unauthorized_empty_role_rejected(self):
        """Operator with empty role string is rejected."""
        ks = make_kill_switch()
        request = make_disable_request(operator_role="")

        with pytest.raises(UnauthorizedKillSwitchError):
            ks.disable(request)

    def test_unauthorized_attempt_logged_to_audit(self):
        """Unauthorized attempts are logged to the audit store (Req 14.4)."""
        mock_s3 = MagicMock()
        audit_store = make_audit_store(s3_client=mock_s3)
        ks = make_kill_switch(audit_store=audit_store)
        request = make_disable_request(operator_role="analyst")

        with pytest.raises(UnauthorizedKillSwitchError):
            ks.disable(request)

        # Verify an audit record was written for the unauthorized attempt
        assert mock_s3.put_object.called

    def test_enable_also_requires_security_operations_role(self):
        """Re-enablement also requires security-operations role."""
        ks = make_kill_switch()
        request = make_enable_request(operator_role="analyst")

        with pytest.raises(UnauthorizedKillSwitchError):
            ks.enable(request)


class TestKillSwitchReasonValidation:
    """Tests for reason field validation (Requirement 14.3)."""

    def test_valid_reason_within_bounds(self):
        """Reason between 10 and 500 characters is accepted."""
        ks = make_kill_switch()
        request = make_disable_request(reason="Security incident - active breach detected")

        result = ks.disable(request)

        assert result.success is True

    def test_reason_exactly_10_chars_accepted(self):
        """Reason of exactly 10 characters (minimum) is accepted."""
        ks = make_kill_switch()
        request = make_disable_request(reason="A" * 10)

        result = ks.disable(request)

        assert result.success is True

    def test_reason_exactly_500_chars_accepted(self):
        """Reason of exactly 500 characters (maximum) is accepted."""
        ks = make_kill_switch()
        request = make_disable_request(reason="A" * 500)

        result = ks.disable(request)

        assert result.success is True

    def test_reason_too_short_rejected(self):
        """Reason shorter than 10 characters is rejected."""
        ks = make_kill_switch()
        request = make_disable_request(reason="short")

        with pytest.raises(InvalidReasonError) as exc_info:
            ks.disable(request)

        assert exc_info.value.reason_length == 5

    def test_reason_too_long_rejected(self):
        """Reason longer than 500 characters is rejected."""
        ks = make_kill_switch()
        request = make_disable_request(reason="A" * 501)

        with pytest.raises(InvalidReasonError) as exc_info:
            ks.disable(request)

        assert exc_info.value.reason_length == 501

    def test_empty_reason_rejected(self):
        """Empty reason string is rejected."""
        ks = make_kill_switch()
        request = make_disable_request(reason="")

        with pytest.raises(InvalidReasonError):
            ks.disable(request)

    def test_whitespace_only_reason_rejected(self):
        """Whitespace-only reason is rejected (stripped length < 10)."""
        ks = make_kill_switch()
        request = make_disable_request(reason="         ")

        with pytest.raises(InvalidReasonError):
            ks.disable(request)


class TestKillSwitchDisable:
    """Tests for kill switch disable operation (Requirements 14.1, 14.2)."""

    def test_disable_calls_gateway_update_integration(self):
        """Disable updates the Gateway integration to reject requests."""
        mock_gateway = MagicMock()
        ks = make_kill_switch(gateway_client=mock_gateway)
        request = make_disable_request(target="myapi123/integ456")

        result = ks.disable(request)

        mock_gateway.update_integration.assert_called_once()
        call_kwargs = mock_gateway.update_integration.call_args[1]
        assert call_kwargs["ApiId"] == "myapi123"
        assert call_kwargs["IntegrationId"] == "integ456"
        assert call_kwargs["ConnectionState"] == "DISABLED"

    def test_disable_returns_success_result(self):
        """Successful disable returns KillSwitchResult with correct fields."""
        ks = make_kill_switch()
        request = make_disable_request()

        result = ks.disable(request)

        assert result.success is True
        assert result.action == KillSwitchAction.DISABLE
        assert result.target == "api123/integration456"
        assert result.timestamp  # Non-empty ISO 8601 timestamp
        assert result.audit_key  # Non-empty S3 key
        assert "503" in result.message

    def test_disable_writes_audit_record(self):
        """Disable writes an immutable audit record (Req 14.3)."""
        mock_s3 = MagicMock()
        audit_store = make_audit_store(s3_client=mock_s3)
        ks = make_kill_switch(audit_store=audit_store)
        request = make_disable_request(reason="Active security incident")

        result = ks.disable(request)

        # Verify audit record was written with correct content
        assert mock_s3.put_object.called
        call_kwargs = mock_s3.put_object.call_args[1]
        body = call_kwargs["Body"].decode("utf-8")
        assert "Active security incident" in body
        assert "disable" in body
        assert "user-secops-001" in body

    def test_disable_gateway_failure_raises_activation_error(self):
        """Gateway API failure raises KillSwitchActivationError."""
        from botocore.exceptions import ClientError

        mock_gateway = MagicMock()
        mock_gateway.update_integration.side_effect = ClientError(
            {"Error": {"Code": "NotFoundException", "Message": "Integration not found"}},
            "UpdateIntegration",
        )
        ks = make_kill_switch(gateway_client=mock_gateway)
        request = make_disable_request()

        with pytest.raises(KillSwitchActivationError) as exc_info:
            ks.disable(request)

        assert exc_info.value.target == "api123/integration456"
        assert exc_info.value.action == KillSwitchAction.DISABLE

    def test_disable_emits_cloudwatch_metric(self):
        """Disable emits a CloudWatch metric for operational visibility."""
        mock_cw = MagicMock()
        ks = make_kill_switch(cloudwatch_client=mock_cw)
        request = make_disable_request()

        ks.disable(request)

        mock_cw.put_metric_data.assert_called_once()
        call_kwargs = mock_cw.put_metric_data.call_args[1]
        assert call_kwargs["Namespace"] == "Chatbot/KillSwitch"


class TestKillSwitchEnable:
    """Tests for kill switch re-enablement (Requirement 14.5)."""

    def test_enable_calls_gateway_update_integration(self):
        """Enable updates the Gateway integration to resume requests."""
        mock_gateway = MagicMock()
        ks = make_kill_switch(gateway_client=mock_gateway)
        request = make_enable_request(target="myapi123/integ456")

        result = ks.enable(request)

        mock_gateway.update_integration.assert_called_once()
        call_kwargs = mock_gateway.update_integration.call_args[1]
        assert call_kwargs["ApiId"] == "myapi123"
        assert call_kwargs["IntegrationId"] == "integ456"
        assert call_kwargs["ConnectionState"] == "AVAILABLE"

    def test_enable_returns_success_result(self):
        """Successful enable returns KillSwitchResult with correct fields."""
        ks = make_kill_switch()
        request = make_enable_request()

        result = ks.enable(request)

        assert result.success is True
        assert result.action == KillSwitchAction.ENABLE
        assert result.target == "api123/integration456"
        assert "re-enabled" in result.message

    def test_enable_writes_audit_record(self):
        """Enable writes an immutable audit record (Req 14.5)."""
        mock_s3 = MagicMock()
        audit_store = make_audit_store(s3_client=mock_s3)
        ks = make_kill_switch(audit_store=audit_store)
        request = make_enable_request(reason="Incident resolved - all clear")

        result = ks.enable(request)

        assert mock_s3.put_object.called
        call_kwargs = mock_s3.put_object.call_args[1]
        body = call_kwargs["Body"].decode("utf-8")
        assert "Incident resolved" in body
        assert "enable" in body

    def test_enable_gateway_failure_raises_activation_error(self):
        """Gateway API failure during enable raises KillSwitchActivationError."""
        from botocore.exceptions import ClientError

        mock_gateway = MagicMock()
        mock_gateway.update_integration.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": "Service unavailable"}},
            "UpdateIntegration",
        )
        ks = make_kill_switch(gateway_client=mock_gateway)
        request = make_enable_request()

        with pytest.raises(KillSwitchActivationError) as exc_info:
            ks.enable(request)

        assert exc_info.value.action == KillSwitchAction.ENABLE


class TestKillSwitchAuditIntegration:
    """Tests for audit record correctness and content."""

    def test_audit_record_contains_operator_identity(self):
        """Audit record includes operator identity (Req 14.3)."""
        mock_s3 = MagicMock()
        audit_store = make_audit_store(s3_client=mock_s3)
        ks = make_kill_switch(audit_store=audit_store)
        request = make_disable_request(operator_principal="secops-jane-doe")

        ks.disable(request)

        call_kwargs = mock_s3.put_object.call_args[1]
        body = call_kwargs["Body"].decode("utf-8")
        assert "secops-jane-doe" in body

    def test_audit_record_contains_reason(self):
        """Audit record includes the mandatory reason field (Req 14.3)."""
        mock_s3 = MagicMock()
        audit_store = make_audit_store(s3_client=mock_s3)
        ks = make_kill_switch(audit_store=audit_store)
        request = make_disable_request(reason="Compromised credentials detected for user X")

        ks.disable(request)

        call_kwargs = mock_s3.put_object.call_args[1]
        body = call_kwargs["Body"].decode("utf-8")
        assert "Compromised credentials detected for user X" in body

    def test_audit_record_contains_target(self):
        """Audit record includes the target identifier (Req 14.3)."""
        mock_s3 = MagicMock()
        audit_store = make_audit_store(s3_client=mock_s3)
        ks = make_kill_switch(audit_store=audit_store)
        request = make_disable_request(target="prod-api/gateway-integ-789")

        ks.disable(request)

        call_kwargs = mock_s3.put_object.call_args[1]
        body = call_kwargs["Body"].decode("utf-8")
        assert "prod-api/gateway-integ-789" in body

    def test_audit_record_contains_timestamp(self):
        """Audit record includes ISO 8601 timestamp (Req 14.3)."""
        mock_s3 = MagicMock()
        audit_store = make_audit_store(s3_client=mock_s3)
        ks = make_kill_switch(audit_store=audit_store)
        request = make_disable_request()

        ks.disable(request)

        call_kwargs = mock_s3.put_object.call_args[1]
        body = call_kwargs["Body"].decode("utf-8")
        # ISO 8601 timestamps contain 'T' and timezone info
        assert "T" in body
        assert "+00:00" in body or "Z" in body

    def test_audit_write_failure_prevents_operation(self):
        """If audit write fails, the operation fails (fail-closed semantics)."""
        mock_s3 = MagicMock()
        # First call (for the successful gateway disable) then audit write fails
        from botocore.exceptions import ClientError

        mock_s3.put_object.side_effect = ClientError(
            {"Error": {"Code": "InternalError", "Message": "S3 unavailable"}},
            "PutObject",
        )
        mock_cw = MagicMock()
        audit_store = AuditStore(
            bucket_name="test-bucket",
            s3_client=mock_s3,
            cloudwatch_client=mock_cw,
        )
        ks = make_kill_switch(audit_store=audit_store)
        request = make_disable_request()

        with pytest.raises(AuditWriteError):
            ks.disable(request)


class TestKillSwitchTargetParsing:
    """Tests for target identifier parsing."""

    def test_target_with_api_and_integration_id(self):
        """Target format 'api_id/integration_id' is parsed correctly."""
        mock_gateway = MagicMock()
        ks = make_kill_switch(gateway_client=mock_gateway)
        request = make_disable_request(target="abc123/xyz789")

        ks.disable(request)

        call_kwargs = mock_gateway.update_integration.call_args[1]
        assert call_kwargs["ApiId"] == "abc123"
        assert call_kwargs["IntegrationId"] == "xyz789"

    def test_target_with_single_id(self):
        """Target with single ID uses it for both api_id and integration_id."""
        mock_gateway = MagicMock()
        ks = make_kill_switch(gateway_client=mock_gateway)
        request = make_disable_request(target="singleid")

        ks.disable(request)

        call_kwargs = mock_gateway.update_integration.call_args[1]
        assert call_kwargs["ApiId"] == "singleid"
        assert call_kwargs["IntegrationId"] == "singleid"
