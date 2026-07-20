"""User deprovisioning webhook Lambda handler.

When a user is deprovisioned from the corporate IdP, this Lambda ensures all
chatbot access is revoked within 5 minutes of the IdP event:

1. Revoke all Cognito tokens (access + refresh)
2. Delete OBO token vault entry in Secrets Manager
3. Write audit record with all timestamps
4. Retry up to 3 times within SLA; emit P1 alert if all retries exhausted

Requirements: 15.1, 15.2, 15.3, 15.4
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Constants
MAX_RETRIES = 3
RETRY_INTERVAL_SECONDS = 60
SLA_SECONDS = 300  # 5 minutes
OBO_TOKEN_SECRET_PREFIX = "chatbot/obo-token/"
P1_ALERT_NAMESPACE = "Chatbot/Security"
P1_ALERT_METRIC_NAME = "DeprovisioningFailure"


class DeprovisioningStatus(Enum):
    """Final status of a deprovisioning operation."""

    SUCCESS = "success"
    PARTIAL_FAILURE = "partial_failure"
    FAILURE = "failure"


class DeprovisioningError(Exception):
    """Raised when deprovisioning cannot complete within SLA."""

    def __init__(self, user_id: str, message: str, step: str):
        self.user_id = user_id
        self.step = step
        super().__init__(f"Deprovisioning failed for {user_id} at step '{step}': {message}")


@dataclass
class DeprovisioningEvent:
    """Parsed IdP deprovisioning webhook event."""

    user_id: str
    event_timestamp: str  # ISO 8601 from IdP
    idp_event_id: str
    reason: str = "user_deprovisioned"

    @classmethod
    def from_lambda_event(cls, event: dict[str, Any]) -> "DeprovisioningEvent":
        """Parse a Lambda event payload into a DeprovisioningEvent.

        Supports both direct invocation and API Gateway proxy formats.
        """
        # Handle API Gateway proxy format
        body = event
        if "body" in event:
            body = json.loads(event["body"]) if isinstance(event["body"], str) else event["body"]

        return cls(
            user_id=body["user_id"],
            event_timestamp=body.get(
                "event_timestamp", datetime.now(timezone.utc).isoformat()
            ),
            idp_event_id=body.get("idp_event_id", str(uuid.uuid4())),
            reason=body.get("reason", "user_deprovisioned"),
        )


@dataclass
class DeprovisioningResult:
    """Complete result of a deprovisioning operation with all timestamps."""

    user_id: str
    idp_event_timestamp: str
    cognito_revocation_timestamp: str | None = None
    secrets_manager_deletion_timestamp: str | None = None
    status: str = DeprovisioningStatus.SUCCESS.value
    cognito_revoked: bool = False
    obo_token_deleted: bool = False
    error_detail: str | None = None
    retry_count: int = 0
    total_elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for audit logging."""
        return asdict(self)


class DeprovisioningHandler:
    """Handles user deprovisioning from IdP webhook events.

    Revokes all Cognito tokens and deletes OBO token vault entries
    within 5 minutes of the IdP event. Implements retry logic (3 retries)
    and emits P1 alert if all retries are exhausted.

    Requirements: 15.1, 15.2, 15.3, 15.4
    """

    def __init__(
        self,
        user_pool_id: str,
        *,
        cognito_client: Any | None = None,
        secrets_client: Any | None = None,
        cloudwatch_client: Any | None = None,
        audit_store: Any | None = None,
    ):
        """Initialize the deprovisioning handler.

        Args:
            user_pool_id: Cognito User Pool ID for token revocation.
            cognito_client: Optional boto3 Cognito IDP client (for testing).
            secrets_client: Optional boto3 Secrets Manager client (for testing).
            cloudwatch_client: Optional boto3 CloudWatch client (for testing).
            audit_store: Optional AuditStore instance for writing audit records.
        """
        self._user_pool_id = user_pool_id
        self._cognito = cognito_client or boto3.client("cognito-idp")
        self._secrets = secrets_client or boto3.client("secretsmanager")
        self._cloudwatch = cloudwatch_client or boto3.client("cloudwatch")
        self._audit_store = audit_store

    def handle_event(self, event: DeprovisioningEvent) -> DeprovisioningResult:
        """Process a deprovisioning event with retry logic.

        Attempts to revoke all access within the 5-minute SLA. Retries
        failed steps up to 3 times. Emits P1 alert if all retries exhausted.

        Args:
            event: Parsed deprovisioning event from the IdP webhook.

        Returns:
            DeprovisioningResult with all timestamps and final status.
        """
        start_time = time.monotonic()
        event_received_at = datetime.now(timezone.utc)

        result = DeprovisioningResult(
            user_id=event.user_id,
            idp_event_timestamp=event.event_timestamp,
        )

        # Step 1: Revoke Cognito tokens with retry
        cognito_success = self._retry_step(
            step_name="cognito_revocation",
            operation=lambda: self._revoke_cognito_tokens(event.user_id),
            start_time=start_time,
            result=result,
        )

        if cognito_success:
            result.cognito_revoked = True
            result.cognito_revocation_timestamp = datetime.now(timezone.utc).isoformat()

        # Step 2: Delete OBO token vault entry with retry
        obo_success = self._retry_step(
            step_name="obo_token_deletion",
            operation=lambda: self._delete_obo_token(event.user_id),
            start_time=start_time,
            result=result,
        )

        if obo_success:
            result.obo_token_deleted = True
            result.secrets_manager_deletion_timestamp = datetime.now(timezone.utc).isoformat()

        # Determine final status
        result.total_elapsed_seconds = time.monotonic() - start_time

        if cognito_success and obo_success:
            result.status = DeprovisioningStatus.SUCCESS.value
        elif cognito_success or obo_success:
            result.status = DeprovisioningStatus.PARTIAL_FAILURE.value
            self._emit_p1_alert(event.user_id, result)
        else:
            result.status = DeprovisioningStatus.FAILURE.value
            self._emit_p1_alert(event.user_id, result)

        # Step 3: Write audit record
        self._write_audit_record(event, result)

        return result

    def _retry_step(
        self,
        step_name: str,
        operation: callable,
        start_time: float,
        result: DeprovisioningResult,
    ) -> bool:
        """Retry an operation up to MAX_RETRIES times within the SLA.

        Args:
            step_name: Name of the step for logging.
            operation: Callable to execute.
            start_time: Monotonic start time for SLA tracking.
            result: DeprovisioningResult to update retry count.

        Returns:
            True if the operation succeeded, False if all retries exhausted.
        """
        for attempt in range(1, MAX_RETRIES + 1):
            # Check SLA before attempting
            elapsed = time.monotonic() - start_time
            if elapsed >= SLA_SECONDS:
                logger.error(
                    "SLA breached for step %s after %.1fs (attempt %d/%d)",
                    step_name,
                    elapsed,
                    attempt,
                    MAX_RETRIES,
                )
                result.error_detail = (
                    f"SLA breached at step '{step_name}' "
                    f"after {elapsed:.1f}s (limit: {SLA_SECONDS}s)"
                )
                return False

            try:
                operation()
                logger.info(
                    "Step %s succeeded on attempt %d/%d",
                    step_name,
                    attempt,
                    MAX_RETRIES,
                )
                return True
            except (ClientError, OSError) as exc:
                result.retry_count += 1
                logger.warning(
                    "Step %s attempt %d/%d failed: %s",
                    step_name,
                    attempt,
                    MAX_RETRIES,
                    str(exc),
                )
                if attempt < MAX_RETRIES:
                    # Wait before retry, but check we won't exceed SLA
                    remaining_time = SLA_SECONDS - (time.monotonic() - start_time)
                    wait_time = min(RETRY_INTERVAL_SECONDS, remaining_time - 10)
                    if wait_time > 0:
                        time.sleep(wait_time)
                    else:
                        # Not enough time for another retry
                        result.error_detail = (
                            f"Insufficient time for retry at step '{step_name}': "
                            f"{remaining_time:.1f}s remaining"
                        )
                        return False
                else:
                    result.error_detail = (
                        f"All {MAX_RETRIES} retries exhausted for step '{step_name}': "
                        f"{str(exc)}"
                    )

        return False

    def _revoke_cognito_tokens(self, user_id: str) -> None:
        """Revoke all Cognito tokens (access + refresh) for the user.

        Uses AdminUserGlobalSignOut to invalidate all tokens issued to the user,
        including access tokens and refresh tokens across all sessions.

        Args:
            user_id: The Cognito user ID (sub claim) to revoke.

        Raises:
            ClientError: If the Cognito API call fails.

        Requirements: 15.1
        """
        self._cognito.admin_user_global_sign_out(
            UserPoolId=self._user_pool_id,
            Username=user_id,
        )
        logger.info(
            "Cognito tokens revoked for user %s (global sign-out)",
            user_id,
        )

    def _delete_obo_token(self, user_id: str) -> None:
        """Delete the user's OBO token vault entry from Secrets Manager.

        Removes the token so no further Athena queries can execute as this user's
        federated identity.

        Args:
            user_id: The user ID used as part of the secret name/key.

        Raises:
            ClientError: If the Secrets Manager API call fails.

        Requirements: 15.2
        """
        secret_id = f"{OBO_TOKEN_SECRET_PREFIX}{user_id}"

        try:
            self._secrets.delete_secret(
                SecretId=secret_id,
                ForceDeleteWithoutRecovery=True,
            )
            logger.info(
                "OBO token vault entry deleted for user %s (secret: %s)",
                user_id,
                secret_id,
            )
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "ResourceNotFoundException":
                # Token already deleted or never existed — treat as success
                logger.info(
                    "OBO token vault entry not found for user %s (already deleted)",
                    user_id,
                )
            else:
                raise

    def _emit_p1_alert(self, user_id: str, result: DeprovisioningResult) -> None:
        """Emit a P1 alert when deprovisioning fails or partially fails.

        Triggers CloudWatch alarm for security operations team notification.

        Args:
            user_id: The user whose deprovisioning failed.
            result: The deprovisioning result with failure details.

        Requirements: 15.4
        """
        try:
            self._cloudwatch.put_metric_data(
                Namespace=P1_ALERT_NAMESPACE,
                MetricData=[
                    {
                        "MetricName": P1_ALERT_METRIC_NAME,
                        "Value": 1.0,
                        "Unit": "Count",
                        "Dimensions": [
                            {"Name": "UserId", "Value": user_id},
                            {"Name": "Status", "Value": result.status},
                        ],
                    }
                ],
            )
            logger.error(
                "P1 ALERT: Deprovisioning %s for user %s — %s",
                result.status,
                user_id,
                result.error_detail or "unknown error",
            )
        except (ClientError, OSError) as exc:
            # Alert emission failure is logged but doesn't change the result
            logger.critical(
                "Failed to emit P1 alert for user %s deprovisioning failure: %s",
                user_id,
                str(exc),
            )

    def _write_audit_record(
        self, event: DeprovisioningEvent, result: DeprovisioningResult
    ) -> None:
        """Write deprovisioning audit record with all timestamps.

        Records the full timeline: IdP event, revocation, deletion, and status.

        Args:
            event: The original IdP deprovisioning event.
            result: The deprovisioning result with all timestamps.

        Requirements: 15.3
        """
        if self._audit_store is None:
            logger.warning(
                "No audit store configured — skipping audit record for user %s",
                event.user_id,
            )
            return

        from chatbot.scripts.audit import AuditRecord

        audit_record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            trace_id=str(uuid.uuid4()),
            session_id=event.idp_event_id,
            principal=event.user_id,
            question=f"[DEPROVISIONING] {event.reason}",
            generated_sql=None,
            policy_decision={
                "action": "user_deprovisioning",
                "idp_event_timestamp": event.event_timestamp,
                "cognito_revocation_timestamp": result.cognito_revocation_timestamp,
                "secrets_manager_deletion_timestamp": result.secrets_manager_deletion_timestamp,
                "status": result.status,
                "retry_count": result.retry_count,
                "total_elapsed_seconds": result.total_elapsed_seconds,
            },
            lake_formation_outcome=None,
            cost_estimate_bytes=None,
            row_count=None,
            guardrails_findings={},
            request_status=result.status,
            error_detail=result.error_detail,
        )

        try:
            self._audit_store.write_record(audit_record)
            logger.info(
                "Audit record written for deprovisioning of user %s (status: %s)",
                event.user_id,
                result.status,
            )
        except Exception as exc:
            # Audit write failure is critical but doesn't change deprovisioning outcome
            logger.critical(
                "Failed to write audit record for deprovisioning of user %s: %s",
                event.user_id,
                str(exc),
            )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda entry point for the deprovisioning webhook.

    This function is triggered by the corporate IdP when a user is deprovisioned.
    It orchestrates token revocation and OBO token deletion within the 5-minute SLA.

    Environment variables required:
        COGNITO_USER_POOL_ID: The Cognito User Pool ID.
        AUDIT_BUCKET_NAME: S3 bucket for audit records (optional).

    Args:
        event: Lambda event payload (API Gateway proxy or direct invocation).
        context: Lambda context object.

    Returns:
        Response dict with statusCode and body.
    """
    import os

    user_pool_id = os.environ.get("COGNITO_USER_POOL_ID", "")
    audit_bucket = os.environ.get("AUDIT_BUCKET_NAME", "")

    if not user_pool_id:
        logger.error("COGNITO_USER_POOL_ID environment variable not set")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Configuration error: missing user pool ID"}),
        }

    # Initialize audit store if bucket configured
    audit_store = None
    if audit_bucket:
        from chatbot.scripts.audit import AuditStore

        audit_store = AuditStore(bucket_name=audit_bucket)

    handler = DeprovisioningHandler(
        user_pool_id=user_pool_id,
        audit_store=audit_store,
    )

    try:
        deprovisioning_event = DeprovisioningEvent.from_lambda_event(event)
    except (KeyError, json.JSONDecodeError, TypeError) as exc:
        logger.error("Failed to parse deprovisioning event: %s", str(exc))
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"Invalid event payload: {str(exc)}"}),
        }

    result = handler.handle_event(deprovisioning_event)

    # Determine HTTP status code based on result
    if result.status == DeprovisioningStatus.SUCCESS.value:
        status_code = 200
    elif result.status == DeprovisioningStatus.PARTIAL_FAILURE.value:
        status_code = 207  # Multi-Status
    else:
        status_code = 500

    return {
        "statusCode": status_code,
        "body": json.dumps(result.to_dict(), default=str),
    }
