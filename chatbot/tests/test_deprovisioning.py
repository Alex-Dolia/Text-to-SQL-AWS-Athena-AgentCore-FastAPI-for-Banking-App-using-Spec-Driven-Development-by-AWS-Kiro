"""Unit tests for user deprovisioning webhook (chatbot/scripts/deprovisioning.py).

Tests the complete deprovisioning flow: successful revocation, retry on failure,
P1 alert on exhaustion, and audit record writing.

Requirements: 15.1, 15.2, 15.3, 15.4
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from chatbot.scripts.deprovisioning import (
    MAX_RETRIES,
    OBO_TOKEN_SECRET_PREFIX,
    P1_ALERT_METRIC_NAME,
    P1_ALERT_NAMESPACE,
    SLA_SECONDS,
    DeprovisioningEvent,
    DeprovisioningHandler,
    DeprovisioningResult,
    DeprovisioningStatus,
    lambda_handler,
)


# --- Test Helpers ---


def make_cognito_client_error(
    code: str = "InternalErrorException", message: str = "Service error"
) -> ClientError:
    """Create a ClientError simulating a Cognito failure."""
    return ClientError(
        error_response={"Error": {"Code": code, "Message": message}},
        operation_name="AdminUserGlobalSignOut",
    )


def make_secrets_client_error(
    code: str = "InternalServiceError", message: str = "Service error"
) -> ClientError:
    """Create a ClientError simulating a Secrets Manager failure."""
    return ClientError(
        error_response={"Error": {"Code": code, "Message": message}},
        operation_name="DeleteSecret",
    )


def make_deprovisioning_event(**overrides) -> DeprovisioningEvent:
    """Create a DeprovisioningEvent with sensible defaults for testing."""
    defaults = {
        "user_id": "user-123-abc",
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "idp_event_id": str(uuid.uuid4()),
        "reason": "user_deprovisioned",
    }
    defaults.update(overrides)
    return DeprovisioningEvent(**defaults)


def make_handler(
    cognito_client: MagicMock | None = None,
    secrets_client: MagicMock | None = None,
    cloudwatch_client: MagicMock | None = None,
    audit_store: MagicMock | None = None,
) -> DeprovisioningHandler:
    """Create a DeprovisioningHandler with mock AWS clients."""
    return DeprovisioningHandler(
        user_pool_id="us-east-1_TestPool",
        cognito_client=cognito_client or MagicMock(),
        secrets_client=secrets_client or MagicMock(),
        cloudwatch_client=cloudwatch_client or MagicMock(),
        audit_store=audit_store,
    )


# --- Tests: Successful Deprovisioning Flow (Requirements 15.1, 15.2) ---


class TestSuccessfulDeprovisioning:
    """Test successful deprovisioning completes all steps."""

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_full_success_revokes_cognito_and_deletes_obo(self, mock_sleep):
        """Successful flow revokes Cognito tokens and deletes OBO token."""
        mock_cognito = MagicMock()
        mock_secrets = MagicMock()
        handler = make_handler(cognito_client=mock_cognito, secrets_client=mock_secrets)
        event = make_deprovisioning_event(user_id="user-success")

        result = handler.handle_event(event)

        assert result.status == DeprovisioningStatus.SUCCESS.value
        assert result.cognito_revoked is True
        assert result.obo_token_deleted is True
        assert result.cognito_revocation_timestamp is not None
        assert result.secrets_manager_deletion_timestamp is not None
        assert result.error_detail is None

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_cognito_global_sign_out_called_with_correct_params(self, mock_sleep):
        """Cognito AdminUserGlobalSignOut called with correct UserPoolId and Username."""
        mock_cognito = MagicMock()
        handler = make_handler(cognito_client=mock_cognito)
        event = make_deprovisioning_event(user_id="user-signout")

        handler.handle_event(event)

        mock_cognito.admin_user_global_sign_out.assert_called_once_with(
            UserPoolId="us-east-1_TestPool",
            Username="user-signout",
        )

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_obo_token_deleted_with_force_and_correct_secret_id(self, mock_sleep):
        """Secrets Manager delete_secret called with ForceDeleteWithoutRecovery=True."""
        mock_secrets = MagicMock()
        handler = make_handler(secrets_client=mock_secrets)
        event = make_deprovisioning_event(user_id="user-obo-del")

        handler.handle_event(event)

        mock_secrets.delete_secret.assert_called_once_with(
            SecretId=f"{OBO_TOKEN_SECRET_PREFIX}user-obo-del",
            ForceDeleteWithoutRecovery=True,
        )

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_obo_token_not_found_treated_as_success(self, mock_sleep):
        """ResourceNotFoundException for OBO token treated as success (already deleted)."""
        mock_secrets = MagicMock()
        mock_secrets.delete_secret.side_effect = ClientError(
            error_response={"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}},
            operation_name="DeleteSecret",
        )
        handler = make_handler(secrets_client=mock_secrets)
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        assert result.status == DeprovisioningStatus.SUCCESS.value
        assert result.obo_token_deleted is True

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_no_p1_alert_on_success(self, mock_sleep):
        """No P1 alert emitted when deprovisioning succeeds."""
        mock_cw = MagicMock()
        handler = make_handler(cloudwatch_client=mock_cw)
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        assert result.status == DeprovisioningStatus.SUCCESS.value
        mock_cw.put_metric_data.assert_not_called()


# --- Tests: Retry Logic (Requirement 15.4) ---


class TestDeprovisioningRetryLogic:
    """Test retry logic: 3 retries within SLA, P1 alert if all exhausted."""

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_cognito_retry_succeeds_on_second_attempt(self, mock_sleep):
        """Cognito revocation retries and succeeds on second attempt."""
        mock_cognito = MagicMock()
        mock_cognito.admin_user_global_sign_out.side_effect = [
            make_cognito_client_error(),  # First attempt fails
            None,  # Second attempt succeeds
        ]
        handler = make_handler(cognito_client=mock_cognito)
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        assert result.cognito_revoked is True
        assert result.retry_count >= 1
        assert mock_cognito.admin_user_global_sign_out.call_count == 2

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_secrets_retry_succeeds_on_third_attempt(self, mock_sleep):
        """Secrets Manager deletion retries and succeeds on third attempt."""
        mock_secrets = MagicMock()
        mock_secrets.delete_secret.side_effect = [
            make_secrets_client_error(),  # First fails
            make_secrets_client_error(),  # Second fails
            None,  # Third succeeds
        ]
        handler = make_handler(secrets_client=mock_secrets)
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        assert result.obo_token_deleted is True
        assert result.retry_count >= 2
        assert mock_secrets.delete_secret.call_count == 3

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_cognito_all_retries_exhausted_triggers_p1_alert(self, mock_sleep):
        """P1 alert emitted when Cognito revocation fails after all retries."""
        mock_cognito = MagicMock()
        mock_cognito.admin_user_global_sign_out.side_effect = make_cognito_client_error()
        mock_cw = MagicMock()
        handler = make_handler(cognito_client=mock_cognito, cloudwatch_client=mock_cw)
        event = make_deprovisioning_event(user_id="user-fail")

        result = handler.handle_event(event)

        assert result.cognito_revoked is False
        assert result.status in (
            DeprovisioningStatus.PARTIAL_FAILURE.value,
            DeprovisioningStatus.FAILURE.value,
        )
        mock_cw.put_metric_data.assert_called_once()
        call_kwargs = mock_cw.put_metric_data.call_args[1]
        assert call_kwargs["Namespace"] == P1_ALERT_NAMESPACE
        metric_data = call_kwargs["MetricData"][0]
        assert metric_data["MetricName"] == P1_ALERT_METRIC_NAME

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_both_steps_fail_results_in_failure_status(self, mock_sleep):
        """Full failure status when both Cognito and Secrets Manager fail."""
        mock_cognito = MagicMock()
        mock_cognito.admin_user_global_sign_out.side_effect = make_cognito_client_error()
        mock_secrets = MagicMock()
        mock_secrets.delete_secret.side_effect = make_secrets_client_error()
        mock_cw = MagicMock()
        handler = make_handler(
            cognito_client=mock_cognito,
            secrets_client=mock_secrets,
            cloudwatch_client=mock_cw,
        )
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        assert result.status == DeprovisioningStatus.FAILURE.value
        assert result.cognito_revoked is False
        assert result.obo_token_deleted is False
        mock_cw.put_metric_data.assert_called_once()

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_partial_failure_when_cognito_succeeds_but_secrets_fails(self, mock_sleep):
        """Partial failure when Cognito revokes but Secrets Manager deletion fails."""
        mock_cognito = MagicMock()
        mock_secrets = MagicMock()
        mock_secrets.delete_secret.side_effect = make_secrets_client_error()
        mock_cw = MagicMock()
        handler = make_handler(
            cognito_client=mock_cognito,
            secrets_client=mock_secrets,
            cloudwatch_client=mock_cw,
        )
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        assert result.status == DeprovisioningStatus.PARTIAL_FAILURE.value
        assert result.cognito_revoked is True
        assert result.obo_token_deleted is False
        mock_cw.put_metric_data.assert_called_once()

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_retry_count_tracks_total_retries(self, mock_sleep):
        """retry_count in result tracks total retry attempts across both steps."""
        mock_cognito = MagicMock()
        mock_cognito.admin_user_global_sign_out.side_effect = [
            make_cognito_client_error(),
            None,
        ]
        mock_secrets = MagicMock()
        mock_secrets.delete_secret.side_effect = [
            make_secrets_client_error(),
            None,
        ]
        handler = make_handler(cognito_client=mock_cognito, secrets_client=mock_secrets)
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        assert result.retry_count == 2  # 1 retry for each step


# --- Tests: SLA Enforcement ---


class TestDeprovisioningSLA:
    """Test that deprovisioning respects the 5-minute SLA."""

    def test_sla_constant_is_5_minutes(self):
        """SLA constant is configured as 300 seconds (5 minutes)."""
        assert SLA_SECONDS == 300

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    @patch("chatbot.scripts.deprovisioning.time.monotonic")
    def test_sla_breach_stops_retries(self, mock_monotonic, mock_sleep):
        """Retries stop when SLA would be breached."""
        # Simulate time progressing past SLA on first retry check
        mock_monotonic.side_effect = [
            0,    # start_time
            0,    # first attempt check for cognito
            301,  # SLA check before second attempt — breached
            301,  # start_time already captured, step 2 check
            301,  # step 2 first check
        ]
        mock_cognito = MagicMock()
        mock_cognito.admin_user_global_sign_out.side_effect = make_cognito_client_error()
        handler = make_handler(cognito_client=mock_cognito)
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        # Should have attempted cognito once before SLA breach stopped it
        assert result.cognito_revoked is False
        assert "SLA" in (result.error_detail or "")


# --- Tests: Audit Record Writing (Requirement 15.3) ---


class TestDeprovisioningAuditRecord:
    """Test audit record written with all required timestamps."""

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_audit_record_written_on_success(self, mock_sleep):
        """Audit record written with timestamps on successful deprovisioning."""
        mock_audit = MagicMock()
        handler = make_handler(audit_store=mock_audit)
        event = make_deprovisioning_event(
            user_id="user-audit-test",
            event_timestamp="2024-06-15T10:00:00+00:00",
        )

        handler.handle_event(event)

        mock_audit.write_record.assert_called_once()
        audit_record = mock_audit.write_record.call_args[0][0]

        # Verify the audit record contains required deprovisioning fields
        assert audit_record.principal == "user-audit-test"
        assert "[DEPROVISIONING]" in audit_record.question
        assert audit_record.policy_decision["action"] == "user_deprovisioning"
        assert audit_record.policy_decision["idp_event_timestamp"] == "2024-06-15T10:00:00+00:00"
        assert audit_record.policy_decision["cognito_revocation_timestamp"] is not None
        assert audit_record.policy_decision["secrets_manager_deletion_timestamp"] is not None
        assert audit_record.policy_decision["status"] == "success"

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_audit_record_written_on_failure(self, mock_sleep):
        """Audit record written even when deprovisioning fails."""
        mock_cognito = MagicMock()
        mock_cognito.admin_user_global_sign_out.side_effect = make_cognito_client_error()
        mock_secrets = MagicMock()
        mock_secrets.delete_secret.side_effect = make_secrets_client_error()
        mock_audit = MagicMock()
        handler = make_handler(
            cognito_client=mock_cognito,
            secrets_client=mock_secrets,
            audit_store=mock_audit,
        )
        event = make_deprovisioning_event(user_id="user-fail-audit")

        handler.handle_event(event)

        mock_audit.write_record.assert_called_once()
        audit_record = mock_audit.write_record.call_args[0][0]
        assert audit_record.request_status == "failure"
        assert audit_record.error_detail is not None

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_audit_failure_does_not_change_result(self, mock_sleep):
        """Audit write failure doesn't change the deprovisioning result."""
        mock_audit = MagicMock()
        mock_audit.write_record.side_effect = Exception("Audit write failed")
        handler = make_handler(audit_store=mock_audit)
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        # Deprovisioning still succeeds even if audit write fails
        assert result.status == DeprovisioningStatus.SUCCESS.value

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_no_audit_store_configured_skips_write(self, mock_sleep):
        """No error when audit store is not configured (logs warning)."""
        handler = make_handler(audit_store=None)
        event = make_deprovisioning_event()

        result = handler.handle_event(event)

        # Should complete without error
        assert result.status == DeprovisioningStatus.SUCCESS.value


# --- Tests: Event Parsing ---


class TestDeprovisioningEventParsing:
    """Test DeprovisioningEvent parsing from Lambda event payloads."""

    def test_parse_direct_invocation_event(self):
        """Parse a direct Lambda invocation event."""
        raw_event = {
            "user_id": "user-direct",
            "event_timestamp": "2024-06-15T10:00:00+00:00",
            "idp_event_id": "evt-123",
            "reason": "employment_terminated",
        }

        event = DeprovisioningEvent.from_lambda_event(raw_event)

        assert event.user_id == "user-direct"
        assert event.event_timestamp == "2024-06-15T10:00:00+00:00"
        assert event.idp_event_id == "evt-123"
        assert event.reason == "employment_terminated"

    def test_parse_api_gateway_proxy_event(self):
        """Parse an API Gateway proxy formatted event (body as JSON string)."""
        raw_event = {
            "body": json.dumps({
                "user_id": "user-apigw",
                "event_timestamp": "2024-06-15T11:00:00+00:00",
            }),
            "headers": {"Content-Type": "application/json"},
        }

        event = DeprovisioningEvent.from_lambda_event(raw_event)

        assert event.user_id == "user-apigw"
        assert event.event_timestamp == "2024-06-15T11:00:00+00:00"

    def test_parse_event_with_defaults(self):
        """Defaults applied for optional fields."""
        raw_event = {"user_id": "user-minimal"}

        event = DeprovisioningEvent.from_lambda_event(raw_event)

        assert event.user_id == "user-minimal"
        assert event.event_timestamp is not None  # Defaults to now
        assert event.idp_event_id is not None  # Defaults to UUID
        assert event.reason == "user_deprovisioned"

    def test_parse_event_missing_user_id_raises_key_error(self):
        """Missing user_id raises KeyError."""
        raw_event = {"event_timestamp": "2024-06-15T10:00:00+00:00"}

        with pytest.raises(KeyError):
            DeprovisioningEvent.from_lambda_event(raw_event)


# --- Tests: Lambda Handler ---


class TestLambdaHandler:
    """Test the lambda_handler entry point."""

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    @patch.dict("os.environ", {"COGNITO_USER_POOL_ID": "us-east-1_Test", "AUDIT_BUCKET_NAME": ""})
    @patch("chatbot.scripts.deprovisioning.boto3.client")
    def test_lambda_handler_success_returns_200(self, mock_boto3_client, mock_sleep):
        """Lambda handler returns 200 on successful deprovisioning."""
        mock_client = MagicMock()
        mock_boto3_client.return_value = mock_client

        event = {
            "user_id": "user-lambda-test",
            "event_timestamp": "2024-06-15T10:00:00+00:00",
        }

        response = lambda_handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "success"

    @patch.dict("os.environ", {"COGNITO_USER_POOL_ID": "", "AUDIT_BUCKET_NAME": ""})
    def test_lambda_handler_missing_pool_id_returns_500(self):
        """Lambda handler returns 500 when COGNITO_USER_POOL_ID is not set."""
        response = lambda_handler({"user_id": "test"}, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert "Configuration error" in body["error"]

    @patch.dict("os.environ", {"COGNITO_USER_POOL_ID": "us-east-1_Test", "AUDIT_BUCKET_NAME": ""})
    @patch("chatbot.scripts.deprovisioning.boto3.client")
    def test_lambda_handler_invalid_payload_returns_400(self, mock_boto3_client):
        """Lambda handler returns 400 for invalid event payload."""
        response = lambda_handler({"invalid": "no user_id"}, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert "Invalid event payload" in body["error"]

    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    @patch.dict("os.environ", {"COGNITO_USER_POOL_ID": "us-east-1_Test", "AUDIT_BUCKET_NAME": ""})
    @patch("chatbot.scripts.deprovisioning.boto3.client")
    def test_lambda_handler_partial_failure_returns_207(self, mock_boto3_client, mock_sleep):
        """Lambda handler returns 207 on partial failure."""
        mock_client = MagicMock()
        # Cognito succeeds, but Secrets Manager fails
        mock_client.admin_user_global_sign_out.return_value = None
        mock_client.delete_secret.side_effect = make_secrets_client_error()
        mock_boto3_client.return_value = mock_client

        event = {"user_id": "user-partial"}

        response = lambda_handler(event, None)

        assert response["statusCode"] == 207
        body = json.loads(response["body"])
        assert body["status"] == "partial_failure"
