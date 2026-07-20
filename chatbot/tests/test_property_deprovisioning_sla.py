"""Property-based tests for deprovisioning SLA.

Tests verify that token revocation completes within 5 minutes (300 seconds)
of the IdP deprovisioning event, that both Cognito tokens and OBO tokens
are revoked, and that retry logic stays within SLA bounds.

**Validates: Requirements 15.1, 15.2, 7.3**

Properties tested:
- Property 12: Deprovisioning SLA — token revocation completes within 5 minutes of IdP event
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from chatbot.scripts.deprovisioning import (
    MAX_RETRIES,
    SLA_SECONDS,
    DeprovisioningEvent,
    DeprovisioningHandler,
    DeprovisioningStatus,
)


# ─── Constants ────────────────────────────────────────────────────────────────

# The SLA threshold: 5 minutes = 300 seconds
DEPROVISIONING_SLA_SECONDS = 300


# ─── Hypothesis Strategies ────────────────────────────────────────────────────

# Strategy for user IDs: realistic alphanumeric strings
user_id_strategy = st.from_regex(r"[a-z0-9\-]{5,40}", fullmatch=True)

# Strategy for IdP event timestamps (ISO 8601 strings within a realistic range)
event_timestamp_strategy = st.datetimes(
    min_value=datetime(2024, 1, 1),
    max_value=datetime(2030, 12, 31),
    timezones=st.just(timezone.utc),
).map(lambda dt: dt.isoformat())

# Strategy for number of failures before success (0 = immediate success, up to MAX_RETRIES)
failures_before_success = st.integers(min_value=0, max_value=MAX_RETRIES)

# Strategy for simulating elapsed time per operation attempt (in seconds)
# Each AWS API call typically takes between 0.05s and 2s
operation_duration_seconds = st.floats(min_value=0.05, max_value=2.0)


# ─── Helpers ──────────────────────────────────────────────────────────────────


def make_client_error(operation: str = "TestOp") -> ClientError:
    """Create a ClientError for testing retries."""
    return ClientError(
        error_response={"Error": {"Code": "InternalErrorException", "Message": "Transient"}},
        operation_name=operation,
    )


def make_handler(
    cognito_side_effect=None,
    secrets_side_effect=None,
) -> DeprovisioningHandler:
    """Create a DeprovisioningHandler with configurable mock behavior."""
    mock_cognito = MagicMock()
    mock_secrets = MagicMock()
    mock_cloudwatch = MagicMock()

    if cognito_side_effect is not None:
        mock_cognito.admin_user_global_sign_out.side_effect = cognito_side_effect

    if secrets_side_effect is not None:
        mock_secrets.delete_secret.side_effect = secrets_side_effect

    return DeprovisioningHandler(
        user_pool_id="us-east-1_TestPool",
        cognito_client=mock_cognito,
        secrets_client=mock_secrets,
        cloudwatch_client=mock_cloudwatch,
        audit_store=None,
    )


# ─── Property 12: Deprovisioning SLA ─────────────────────────────────────────


class TestDeprovisioningSLAProperty:
    """Property 12: Deprovisioning SLA.

    **Validates: Requirements 15.1, 15.2, 7.3**

    Token revocation (both Cognito tokens and OBO tokens) completes within
    5 minutes (300 seconds) of the IdP deprovisioning event. This property
    holds regardless of user ID, event timestamp, or number of retries needed.
    """

    @given(
        user_id=user_id_strategy,
        event_timestamp=event_timestamp_strategy,
    )
    @settings(max_examples=200)
    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_successful_deprovisioning_completes_within_sla(
        self, mock_sleep, user_id: str, event_timestamp: str
    ):
        """When both revocation steps succeed immediately, total elapsed time is within SLA.

        For any user_id and event_timestamp, if both Cognito revocation and
        OBO token deletion succeed on the first attempt, the total operation
        completes well within the 5-minute SLA.

        **Validates: Requirements 15.1, 15.2**
        """
        handler = make_handler()
        event = DeprovisioningEvent(
            user_id=user_id,
            event_timestamp=event_timestamp,
            idp_event_id=str(uuid.uuid4()),
        )

        result = handler.handle_event(event)

        # Core property: elapsed time within SLA
        assert result.total_elapsed_seconds <= DEPROVISIONING_SLA_SECONDS, (
            f"Deprovisioning for user '{user_id}' took {result.total_elapsed_seconds:.1f}s, "
            f"exceeding SLA of {DEPROVISIONING_SLA_SECONDS}s"
        )
        # Both token types must be revoked
        assert result.cognito_revoked is True, (
            f"Cognito tokens not revoked for user '{user_id}'"
        )
        assert result.obo_token_deleted is True, (
            f"OBO token not deleted for user '{user_id}'"
        )
        assert result.status == DeprovisioningStatus.SUCCESS.value

    @given(
        user_id=user_id_strategy,
        cognito_failures=st.integers(min_value=0, max_value=MAX_RETRIES - 1),
        obo_failures=st.integers(min_value=0, max_value=MAX_RETRIES - 1),
    )
    @settings(max_examples=200)
    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_retries_within_sla_still_revoke_both_token_types(
        self,
        mock_sleep,
        user_id: str,
        cognito_failures: int,
        obo_failures: int,
    ):
        """Even with transient failures, if retries succeed the SLA is met and both tokens revoked.

        For any combination of transient failures (less than MAX_RETRIES), when
        the operation eventually succeeds, both Cognito tokens and OBO tokens
        are revoked within the 5-minute SLA.

        **Validates: Requirements 15.1, 15.2, 7.3**
        """
        # Build side effects: N failures then success
        cognito_effects = [make_client_error("AdminUserGlobalSignOut")] * cognito_failures + [None]
        obo_effects = [make_client_error("DeleteSecret")] * obo_failures + [None]

        handler = make_handler(
            cognito_side_effect=cognito_effects,
            secrets_side_effect=obo_effects,
        )
        event = DeprovisioningEvent(
            user_id=user_id,
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            idp_event_id=str(uuid.uuid4()),
        )

        result = handler.handle_event(event)

        # Property: even after retries, SLA is still met
        assert result.total_elapsed_seconds <= DEPROVISIONING_SLA_SECONDS, (
            f"Deprovisioning with retries ({cognito_failures} cognito, {obo_failures} obo) "
            f"took {result.total_elapsed_seconds:.1f}s, exceeding SLA of {DEPROVISIONING_SLA_SECONDS}s"
        )
        # Both token types MUST be revoked when retries eventually succeed
        assert result.cognito_revoked is True, (
            f"Cognito tokens not revoked after {cognito_failures} retries"
        )
        assert result.obo_token_deleted is True, (
            f"OBO token not deleted after {obo_failures} retries"
        )
        assert result.status == DeprovisioningStatus.SUCCESS.value

    @given(
        user_id=user_id_strategy,
        event_timestamp=event_timestamp_strategy,
    )
    @settings(max_examples=200)
    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    @patch("chatbot.scripts.deprovisioning.time.monotonic")
    def test_sla_breach_halts_retries_and_emits_alert(
        self,
        mock_monotonic,
        mock_sleep,
        user_id: str,
        event_timestamp: str,
    ):
        """When SLA is about to be breached, the handler stops retrying rather than exceeding it.

        The retry logic checks remaining time before each attempt. If continuing
        would exceed the 5-minute SLA, it stops and reports failure. This ensures
        the handler never runs unbounded.

        **Validates: Requirements 15.1, 15.2, 7.3**
        """
        # Simulate time jumping past SLA after first failed attempt
        # time.monotonic calls: start_time, check1 (ok), check2 (past SLA), ...
        mock_monotonic.side_effect = [
            0.0,    # start_time in handle_event
            0.0,    # first check in _retry_step (cognito) — within SLA
            301.0,  # second check — past SLA, should stop
            301.0,  # start check for OBO step
            301.0,  # first check in _retry_step (obo) — past SLA
            301.0,  # total_elapsed computation
        ]

        # Both operations always fail (forcing retries)
        handler = make_handler(
            cognito_side_effect=make_client_error("AdminUserGlobalSignOut"),
            secrets_side_effect=make_client_error("DeleteSecret"),
        )
        event = DeprovisioningEvent(
            user_id=user_id,
            event_timestamp=event_timestamp,
            idp_event_id=str(uuid.uuid4()),
        )

        result = handler.handle_event(event)

        # Property: when SLA is breached, retries stop and failure is reported
        assert result.status in (
            DeprovisioningStatus.FAILURE.value,
            DeprovisioningStatus.PARTIAL_FAILURE.value,
        ), f"Expected failure/partial_failure status when SLA breached, got '{result.status}'"
        # The error detail should reference SLA
        assert result.error_detail is not None
        assert "SLA" in result.error_detail or "Insufficient time" in result.error_detail

    @given(user_id=user_id_strategy)
    @settings(max_examples=100)
    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_max_retries_bounded_to_3_per_step(self, mock_sleep, user_id: str):
        """Retry logic never exceeds MAX_RETRIES (3) attempts per step.

        This ensures the retry mechanism is bounded, preventing infinite loops
        that would breach the SLA.

        **Validates: Requirements 15.1, 15.2**
        """
        mock_cognito = MagicMock()
        mock_cognito.admin_user_global_sign_out.side_effect = make_client_error(
            "AdminUserGlobalSignOut"
        )
        mock_secrets = MagicMock()
        mock_secrets.delete_secret.side_effect = make_client_error("DeleteSecret")

        handler = DeprovisioningHandler(
            user_pool_id="us-east-1_TestPool",
            cognito_client=mock_cognito,
            secrets_client=mock_secrets,
            cloudwatch_client=MagicMock(),
            audit_store=None,
        )
        event = DeprovisioningEvent(
            user_id=user_id,
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            idp_event_id=str(uuid.uuid4()),
        )

        result = handler.handle_event(event)

        # Property: each step tried at most MAX_RETRIES times
        assert mock_cognito.admin_user_global_sign_out.call_count <= MAX_RETRIES
        assert mock_secrets.delete_secret.call_count <= MAX_RETRIES
        # Total retry_count is bounded
        assert result.retry_count <= MAX_RETRIES * 2  # At most 3 retries per step × 2 steps

    @given(user_id=user_id_strategy)
    @settings(max_examples=100)
    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_both_cognito_and_obo_tokens_always_attempted(self, mock_sleep, user_id: str):
        """Deprovisioning always attempts both Cognito revocation AND OBO token deletion.

        Even if one step fails, the other must still be attempted. Both token types
        must be targeted for revocation to fully deprovision a user.

        **Validates: Requirements 15.1, 15.2, 7.3**
        """
        mock_cognito = MagicMock()
        mock_secrets = MagicMock()

        handler = DeprovisioningHandler(
            user_pool_id="us-east-1_TestPool",
            cognito_client=mock_cognito,
            secrets_client=mock_secrets,
            cloudwatch_client=MagicMock(),
            audit_store=None,
        )
        event = DeprovisioningEvent(
            user_id=user_id,
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            idp_event_id=str(uuid.uuid4()),
        )

        handler.handle_event(event)

        # Property: both revocation operations were attempted
        assert mock_cognito.admin_user_global_sign_out.call_count >= 1, (
            "Cognito token revocation was never attempted"
        )
        assert mock_secrets.delete_secret.call_count >= 1, (
            "OBO token deletion was never attempted"
        )

    @given(user_id=user_id_strategy)
    @settings(max_examples=100)
    @patch("chatbot.scripts.deprovisioning.time.sleep", return_value=None)
    def test_cognito_failure_does_not_prevent_obo_revocation(self, mock_sleep, user_id: str):
        """Even when Cognito revocation fails completely, OBO token deletion is still attempted.

        The deprovisioning handler must not short-circuit — both token types need
        independent revocation attempts to maximize the chance of full deprovisioning.

        **Validates: Requirements 15.2, 7.3**
        """
        mock_cognito = MagicMock()
        mock_cognito.admin_user_global_sign_out.side_effect = make_client_error(
            "AdminUserGlobalSignOut"
        )
        mock_secrets = MagicMock()

        handler = DeprovisioningHandler(
            user_pool_id="us-east-1_TestPool",
            cognito_client=mock_cognito,
            secrets_client=mock_secrets,
            cloudwatch_client=MagicMock(),
            audit_store=None,
        )
        event = DeprovisioningEvent(
            user_id=user_id,
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            idp_event_id=str(uuid.uuid4()),
        )

        result = handler.handle_event(event)

        # Cognito failed but OBO should still succeed
        assert result.cognito_revoked is False
        assert result.obo_token_deleted is True, (
            "OBO token deletion should proceed even when Cognito revocation fails"
        )
        # OBO deletion was attempted
        mock_secrets.delete_secret.assert_called()


class TestSLAConstantProperty:
    """Verify the SLA constant matches the 5-minute requirement.

    **Validates: Requirements 15.1, 15.2**
    """

    def test_sla_constant_equals_300_seconds(self):
        """The deprovisioning SLA constant is exactly 5 minutes (300 seconds).

        **Validates: Requirements 15.1, 15.2**
        """
        assert SLA_SECONDS == 300, (
            f"SLA_SECONDS is {SLA_SECONDS}, expected 300 (5 minutes)"
        )
        assert DEPROVISIONING_SLA_SECONDS == 300
