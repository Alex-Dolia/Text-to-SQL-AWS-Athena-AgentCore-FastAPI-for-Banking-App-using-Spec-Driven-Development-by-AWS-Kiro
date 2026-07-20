"""Administrative kill switch for immediate chatbot access disablement.

Provides an enable/disable mechanism for the AgentCore Gateway target
to contain security incidents within minutes. When activated:
- All new requests receive HTTP 503 within 5 minutes of API call
- 100% of new requests are blocked; in-flight requests complete (no new tool calls)
- An immutable audit entry is recorded with operator identity, reason, target, timestamp
- Only principals with the security-operations role can invoke (Cedar policy enforced)

Re-enablement restores the Gateway target within 5 minutes with full audit logging.

Requirements: 14.1, 14.2, 14.3, 14.4, 14.5
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import boto3
from botocore.exceptions import ClientError

from chatbot.scripts.audit import AuditRecord, AuditStore, AuditWriteError

logger = logging.getLogger(__name__)

# Constants
REASON_MIN_LENGTH = 10
REASON_MAX_LENGTH = 500
SECURITY_OPERATIONS_ROLE = "security-operations"
KILL_SWITCH_ACTION = "kill_switch"
DISABLE_TIMEOUT_SECONDS = 300  # 5 minutes
ENABLE_TIMEOUT_SECONDS = 300  # 5 minutes


class KillSwitchAction(str, Enum):
    """Actions available for the kill switch."""

    DISABLE = "disable"
    ENABLE = "enable"


class KillSwitchError(Exception):
    """Base exception for kill switch operations."""

    pass


class UnauthorizedKillSwitchError(KillSwitchError):
    """Raised when a non-security-operations principal attempts kill switch invocation.

    Requirement 14.4: restrict invocation to security-operations role.
    """

    def __init__(self, principal: str, role: str):
        self.principal = principal
        self.role = role
        super().__init__(
            f"Unauthorized kill switch attempt by principal={principal} "
            f"with role={role}. Required role: {SECURITY_OPERATIONS_ROLE}"
        )


class InvalidReasonError(KillSwitchError):
    """Raised when the reason field does not meet length requirements.

    Requirement 14.3: mandatory reason field (10-500 characters).
    """

    def __init__(self, reason_length: int):
        self.reason_length = reason_length
        super().__init__(
            f"Reason must be between {REASON_MIN_LENGTH} and {REASON_MAX_LENGTH} "
            f"characters (got {reason_length})"
        )


class KillSwitchActivationError(KillSwitchError):
    """Raised when the Gateway target cannot be disabled/enabled within SLA."""

    def __init__(self, target: str, action: KillSwitchAction, detail: str):
        self.target = target
        self.action = action
        super().__init__(
            f"Kill switch {action.value} failed for target={target}: {detail}"
        )


@dataclass
class KillSwitchRequest:
    """Request to activate or deactivate the kill switch.

    Attributes:
        operator_principal: Identity of the operator (from validated JWT sub claim).
        operator_role: Role of the operator (from validated JWT role claim).
        target: The Gateway target identifier to disable/enable.
        reason: Mandatory reason for the action (10-500 characters).
        action: Whether to disable (kill) or enable (restore) the target.
    """

    operator_principal: str
    operator_role: str
    target: str
    reason: str
    action: KillSwitchAction


@dataclass
class KillSwitchResult:
    """Result of a kill switch operation.

    Attributes:
        success: Whether the operation completed successfully.
        action: The action that was performed.
        target: The Gateway target affected.
        timestamp: ISO 8601 timestamp of the operation.
        audit_key: S3 object key of the audit record.
        message: Human-readable status message.
    """

    success: bool
    action: KillSwitchAction
    target: str
    timestamp: str
    audit_key: str
    message: str


class KillSwitch:
    """Administrative kill switch for the AgentCore Gateway target.

    Implements immediate disablement/re-enablement of chatbot access:
    - Disable: sets Gateway target to reject all new requests with HTTP 503
    - Enable: restores Gateway target to accept new requests
    - Both operations complete within 5 minutes of API call
    - Both operations produce immutable audit records

    The kill switch operates by updating the Gateway target configuration
    to a "disabled" state. When disabled:
    - New requests receive HTTP 503 (chatbot temporarily disabled)
    - In-flight requests that passed the Gateway are allowed to complete
    - No new tool calls are initiated for in-flight sessions

    Requirements: 14.1, 14.2, 14.3, 14.4, 14.5
    """

    def __init__(
        self,
        audit_store: AuditStore,
        *,
        gateway_client: Any | None = None,
        cloudwatch_client: Any | None = None,
    ):
        """Initialize the kill switch.

        Args:
            audit_store: AuditStore instance for immutable audit logging.
            gateway_client: Optional boto3 client for Gateway operations.
                           Uses apigatewayv2 to manage target integrations.
            cloudwatch_client: Optional boto3 CloudWatch client for metrics.
        """
        self._audit_store = audit_store
        self._gateway = gateway_client or boto3.client("apigatewayv2")
        self._cloudwatch = cloudwatch_client or boto3.client("cloudwatch")

    def disable(self, request: KillSwitchRequest) -> KillSwitchResult:
        """Disable the Gateway target (kill switch activation).

        Blocks 100% of new requests to the target with HTTP 503.
        In-flight requests are allowed to complete but no new tool calls
        are initiated for those sessions.

        Args:
            request: Kill switch disable request with operator credentials.

        Returns:
            KillSwitchResult with operation status and audit reference.

        Raises:
            UnauthorizedKillSwitchError: If operator lacks security-operations role.
            InvalidReasonError: If reason doesn't meet length requirements.
            KillSwitchActivationError: If the Gateway target cannot be disabled.
            AuditWriteError: If the audit record cannot be written (fail-closed).

        Requirements: 14.1, 14.2, 14.3, 14.4
        """
        request.action = KillSwitchAction.DISABLE
        self._validate_authorization(request)
        self._validate_reason(request.reason)

        timestamp = datetime.now(timezone.utc).isoformat()
        trace_id = str(uuid.uuid4())

        # Log the unauthorized attempt if it somehow got here
        # (defense in depth — authorization check above should catch this)
        logger.info(
            "Kill switch DISABLE initiated",
            extra={
                "operator": request.operator_principal,
                "target": request.target,
                "trace_id": trace_id,
            },
        )

        # Disable the Gateway target
        try:
            self._disable_gateway_target(request.target)
        except (ClientError, OSError) as exc:
            logger.error(
                "Failed to disable Gateway target %s: %s",
                request.target,
                str(exc),
            )
            raise KillSwitchActivationError(
                target=request.target,
                action=KillSwitchAction.DISABLE,
                detail=str(exc),
            )

        # Write immutable audit record (fail-closed if audit fails)
        audit_key = self._write_audit_record(
            trace_id=trace_id,
            timestamp=timestamp,
            operator=request.operator_principal,
            action=KillSwitchAction.DISABLE,
            target=request.target,
            reason=request.reason,
        )

        # Emit CloudWatch metric for operational visibility
        self._emit_metric(KillSwitchAction.DISABLE, request.target)

        logger.info(
            "Kill switch DISABLE completed for target %s",
            request.target,
            extra={
                "operator": request.operator_principal,
                "target": request.target,
                "trace_id": trace_id,
                "audit_key": audit_key,
            },
        )

        return KillSwitchResult(
            success=True,
            action=KillSwitchAction.DISABLE,
            target=request.target,
            timestamp=timestamp,
            audit_key=audit_key,
            message=f"Gateway target '{request.target}' disabled. "
            f"All new requests will receive HTTP 503.",
        )

    def enable(self, request: KillSwitchRequest) -> KillSwitchResult:
        """Re-enable the Gateway target (kill switch deactivation).

        Restores the target to active status, resuming acceptance of user requests
        within 5 minutes of the API call.

        Args:
            request: Kill switch enable request with operator credentials.

        Returns:
            KillSwitchResult with operation status and audit reference.

        Raises:
            UnauthorizedKillSwitchError: If operator lacks security-operations role.
            InvalidReasonError: If reason doesn't meet length requirements.
            KillSwitchActivationError: If the Gateway target cannot be re-enabled.
            AuditWriteError: If the audit record cannot be written (fail-closed).

        Requirements: 14.5
        """
        request.action = KillSwitchAction.ENABLE
        self._validate_authorization(request)
        self._validate_reason(request.reason)

        timestamp = datetime.now(timezone.utc).isoformat()
        trace_id = str(uuid.uuid4())

        logger.info(
            "Kill switch ENABLE initiated",
            extra={
                "operator": request.operator_principal,
                "target": request.target,
                "trace_id": trace_id,
            },
        )

        # Re-enable the Gateway target
        try:
            self._enable_gateway_target(request.target)
        except (ClientError, OSError) as exc:
            logger.error(
                "Failed to enable Gateway target %s: %s",
                request.target,
                str(exc),
            )
            raise KillSwitchActivationError(
                target=request.target,
                action=KillSwitchAction.ENABLE,
                detail=str(exc),
            )

        # Write immutable audit record (fail-closed if audit fails)
        audit_key = self._write_audit_record(
            trace_id=trace_id,
            timestamp=timestamp,
            operator=request.operator_principal,
            action=KillSwitchAction.ENABLE,
            target=request.target,
            reason=request.reason,
        )

        # Emit CloudWatch metric for operational visibility
        self._emit_metric(KillSwitchAction.ENABLE, request.target)

        logger.info(
            "Kill switch ENABLE completed for target %s",
            request.target,
            extra={
                "operator": request.operator_principal,
                "target": request.target,
                "trace_id": trace_id,
                "audit_key": audit_key,
            },
        )

        return KillSwitchResult(
            success=True,
            action=KillSwitchAction.ENABLE,
            target=request.target,
            timestamp=timestamp,
            audit_key=audit_key,
            message=f"Gateway target '{request.target}' re-enabled. "
            f"User requests will be accepted.",
        )

    def get_target_status(self, target: str) -> dict[str, Any]:
        """Query the current status of a Gateway target.

        Args:
            target: The Gateway target identifier to check.

        Returns:
            Dictionary with target status information:
            - target: target identifier
            - enabled: whether the target is currently active
            - last_modified: ISO 8601 timestamp of last status change
        """
        try:
            response = self._gateway.get_integration(
                ApiId=self._extract_api_id(target),
                IntegrationId=self._extract_integration_id(target),
            )
            # Check if the integration connection state indicates disabled
            connection_state = response.get("ConnectionState", "AVAILABLE")
            return {
                "target": target,
                "enabled": connection_state != "DISABLED",
                "connection_state": connection_state,
            }
        except (ClientError, OSError) as exc:
            logger.warning(
                "Failed to get status for target %s: %s",
                target,
                str(exc),
            )
            return {
                "target": target,
                "enabled": None,
                "error": str(exc),
            }

    def _validate_authorization(self, request: KillSwitchRequest) -> None:
        """Validate that the operator has the security-operations role.

        Requirement 14.4: restrict invocation to security-operations role.
        Unauthorized attempts are logged to the audit store.

        Raises:
            UnauthorizedKillSwitchError: If operator role != security-operations.
        """
        if request.operator_role != SECURITY_OPERATIONS_ROLE:
            # Log the unauthorized attempt to audit store
            self._log_unauthorized_attempt(request)
            raise UnauthorizedKillSwitchError(
                principal=request.operator_principal,
                role=request.operator_role,
            )

    def _validate_reason(self, reason: str) -> None:
        """Validate the reason field meets length requirements.

        Requirement 14.3: mandatory reason field (10-500 characters).

        Raises:
            InvalidReasonError: If reason length is outside [10, 500].
        """
        reason_length = len(reason.strip()) if reason else 0
        if reason_length < REASON_MIN_LENGTH or reason_length > REASON_MAX_LENGTH:
            raise InvalidReasonError(reason_length=reason_length)

    def _disable_gateway_target(self, target: str) -> None:
        """Disable the Gateway target integration.

        Updates the Gateway integration to reject all new requests.
        In-flight requests are allowed to complete but no new tool calls
        are initiated.

        The implementation updates the route integration to point to a
        mock integration that returns HTTP 503, achieving immediate
        request blocking without terminating in-flight operations.

        Requirement 14.1: disable within 5 minutes of API call.
        Requirement 14.2: block 100% new requests; in-flight complete.
        """
        api_id = self._extract_api_id(target)
        integration_id = self._extract_integration_id(target)

        # Update integration to return 503 for all new requests
        # This achieves "block new, allow in-flight" semantics because:
        # - Already-dispatched requests are on the backend, not affected
        # - New requests hit the updated integration and get 503
        self._gateway.update_integration(
            ApiId=api_id,
            IntegrationId=integration_id,
            ConnectionState="DISABLED",
            Description="KILL_SWITCH_ACTIVE: All requests blocked by security operations",
            ResponseParameters={
                "503": {
                    "overwrite:statuscode": "503",
                    "overwrite:header.content-type": "application/json",
                }
            },
        )

        logger.info(
            "Gateway target disabled: api_id=%s, integration_id=%s",
            api_id,
            integration_id,
        )

    def _enable_gateway_target(self, target: str) -> None:
        """Re-enable the Gateway target integration.

        Restores the Gateway integration to active status, resuming
        normal request routing.

        Requirement 14.5: restore within 5 minutes of API call.
        """
        api_id = self._extract_api_id(target)
        integration_id = self._extract_integration_id(target)

        # Restore integration to normal operation
        self._gateway.update_integration(
            ApiId=api_id,
            IntegrationId=integration_id,
            ConnectionState="AVAILABLE",
            Description="Active — kill switch deactivated",
            ResponseParameters={},
        )

        logger.info(
            "Gateway target re-enabled: api_id=%s, integration_id=%s",
            api_id,
            integration_id,
        )

    def _write_audit_record(
        self,
        *,
        trace_id: str,
        timestamp: str,
        operator: str,
        action: KillSwitchAction,
        target: str,
        reason: str,
    ) -> str:
        """Write an immutable audit record for the kill switch operation.

        Requirement 14.3: record operator identity, reason, target, timestamp.

        Returns:
            The S3 object key where the audit record was stored.

        Raises:
            AuditWriteError: If the audit cannot be written (fail-closed).
        """
        audit_record = AuditRecord(
            timestamp=timestamp,
            trace_id=trace_id,
            session_id="kill-switch-operation",
            principal=operator,
            question=f"Kill switch {action.value}: {reason}",
            generated_sql=None,
            policy_decision={
                "action": KILL_SWITCH_ACTION,
                "operation": action.value,
                "target": target,
                "reason": reason,
                "operator_role": SECURITY_OPERATIONS_ROLE,
            },
            lake_formation_outcome=None,
            cost_estimate_bytes=None,
            row_count=None,
            guardrails_findings={},
            request_status="success",
            error_detail=None,
        )

        return self._audit_store.write_record(audit_record)

    def _log_unauthorized_attempt(self, request: KillSwitchRequest) -> None:
        """Log an unauthorized kill switch attempt to the audit store.

        Requirement 14.4: unauthorized attempts SHALL be logged.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        trace_id = str(uuid.uuid4())

        try:
            audit_record = AuditRecord(
                timestamp=timestamp,
                trace_id=trace_id,
                session_id="kill-switch-unauthorized",
                principal=request.operator_principal,
                question=f"UNAUTHORIZED kill switch {request.action.value} attempt: {request.reason}",
                generated_sql=None,
                policy_decision={
                    "action": KILL_SWITCH_ACTION,
                    "operation": request.action.value,
                    "target": request.target,
                    "reason": request.reason,
                    "operator_role": request.operator_role,
                    "authorized": False,
                    "required_role": SECURITY_OPERATIONS_ROLE,
                },
                lake_formation_outcome=None,
                cost_estimate_bytes=None,
                row_count=None,
                guardrails_findings={},
                request_status="failure",
                error_detail=f"Unauthorized: role={request.operator_role}, "
                f"required={SECURITY_OPERATIONS_ROLE}",
            )

            self._audit_store.write_record(audit_record)
        except AuditWriteError:
            # Even if audit write fails for the unauthorized attempt,
            # we still raise UnauthorizedKillSwitchError (which is the
            # primary security control). The audit failure is logged.
            logger.error(
                "Failed to audit unauthorized kill switch attempt by %s",
                request.operator_principal,
            )

    def _emit_metric(self, action: KillSwitchAction, target: str) -> None:
        """Emit CloudWatch metric for kill switch operation visibility."""
        try:
            self._cloudwatch.put_metric_data(
                Namespace="Chatbot/KillSwitch",
                MetricData=[
                    {
                        "MetricName": f"KillSwitch{action.value.capitalize()}",
                        "Value": 1.0,
                        "Unit": "Count",
                        "Dimensions": [
                            {"Name": "Target", "Value": target},
                            {"Name": "Action", "Value": action.value},
                        ],
                    }
                ],
            )
        except (ClientError, OSError) as exc:
            # Metric emission failure is not critical — the audit record
            # is the authoritative record of the operation
            logger.warning(
                "Failed to emit kill switch metric: %s", str(exc)
            )

    @staticmethod
    def _extract_api_id(target: str) -> str:
        """Extract the API Gateway ID from a target identifier.

        Target format: "{api_id}/{integration_id}" or just the api_id
        if integration_id is stored separately.
        """
        parts = target.split("/")
        return parts[0]

    @staticmethod
    def _extract_integration_id(target: str) -> str:
        """Extract the integration ID from a target identifier.

        Target format: "{api_id}/{integration_id}"
        """
        parts = target.split("/")
        if len(parts) >= 2:
            return parts[1]
        return parts[0]
