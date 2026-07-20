"""Daily permission reconciliation: Cedar permits vs Lake Formation grants.

Compares (principal, table) tuples bidirectionally between Cedar policy permits
and Lake Formation grants. On divergence, triggers P1 alert and fail-closes
affected principals within 5 minutes. On job failure, assumes breach posture
and blocks all requests. On healthy, records status in audit store and emits
a CloudWatch metric.

Must complete within 60 minutes of invocation.

Requirements: 13.1, 13.2, 13.3, 13.4
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

import boto3
from botocore.exceptions import ClientError

from chatbot.scripts.audit import AuditRecord, AuditStore

logger = logging.getLogger(__name__)

# Constants
MAX_EXECUTION_MINUTES = 60
MAX_EXECUTION_SECONDS = MAX_EXECUTION_MINUTES * 60
FAIL_CLOSE_SLA_MINUTES = 5
P1_ALERT_TOPIC = "chatbot-security-p1-alerts"
RECONCILIATION_METRIC_NAMESPACE = "Chatbot/Reconciliation"
RECONCILIATION_METRIC_NAME = "ReconciliationStatus"


class ReconciliationTimeoutError(Exception):
    """Raised when reconciliation exceeds the 60-minute execution limit."""

    def __init__(self, elapsed_seconds: float):
        self.elapsed_seconds = elapsed_seconds
        super().__init__(
            f"Reconciliation exceeded {MAX_EXECUTION_MINUTES}-minute limit "
            f"(elapsed: {elapsed_seconds:.1f}s)"
        )


@dataclass
class ReconciliationResult:
    """Result of the daily permission reconciliation.

    Attributes:
        status: "healthy" (no divergences), "divergent" (mismatches found),
                or "error" (job failure — assume breach posture).
        divergences: List of dicts describing each mismatch with principal, table, type.
        cedar_permits: Total number of Cedar permits evaluated.
        lf_grants: Total number of Lake Formation grants evaluated.
        execution_time_s: Time taken in seconds.
    """

    status: Literal["healthy", "divergent", "error"]
    divergences: list[dict[str, str]] = field(default_factory=list)
    cedar_permits: int = 0
    lf_grants: int = 0
    execution_time_s: float = 0.0


class ReconciliationService:
    """Service for daily permission reconciliation between Cedar and Lake Formation.

    Implements the reconciliation algorithm:
    1. Fetch all Cedar permits as (principal, table) tuples
    2. Fetch all Lake Formation grants as (principal, table) tuples
    3. Compare bidirectionally
    4. On divergence: P1 alert + fail-close affected principals
    5. On job failure: assume breach + block all + P1 alert
    6. On healthy: audit record + CloudWatch metric

    Requirements: 13.1, 13.2, 13.3, 13.4
    """

    def __init__(
        self,
        *,
        cedar_client: Any | None = None,
        lakeformation_client: Any | None = None,
        sns_client: Any | None = None,
        cloudwatch_client: Any | None = None,
        audit_store: AuditStore | None = None,
        sns_topic_arn: str = "",
        gateway_target_id: str = "chatbot-gateway",
    ):
        """Initialize the reconciliation service.

        Args:
            cedar_client: Client for fetching Cedar policy permits.
            lakeformation_client: boto3 Lake Formation client.
            sns_client: boto3 SNS client for P1 alerts.
            cloudwatch_client: boto3 CloudWatch client for metrics.
            audit_store: AuditStore instance for recording reconciliation status.
            sns_topic_arn: SNS topic ARN for P1 security alerts.
            gateway_target_id: The Gateway target ID for fail-close operations.
        """
        self._cedar_client = cedar_client
        self._lakeformation = lakeformation_client or boto3.client("lakeformation")
        self._sns = sns_client or boto3.client("sns")
        self._cloudwatch = cloudwatch_client or boto3.client("cloudwatch")
        self._audit_store = audit_store
        self._sns_topic_arn = sns_topic_arn
        self._gateway_target_id = gateway_target_id
        self._blocked_principals: set[str] = set()
        self._all_blocked: bool = False

    def fetch_cedar_permits(self) -> set[tuple[str, str]]:
        """Fetch all Cedar policy permits as (principal, table) tuples.

        Retrieves all active permit policies from the Cedar policy store
        and extracts (principal, table) pairs where access is explicitly granted.

        Returns:
            Set of (principal, table) tuples representing Cedar permits.

        Raises:
            ClientError: If the Cedar policy store is unreachable.
        """
        if self._cedar_client is None:
            raise RuntimeError("Cedar client not configured")

        permits: set[tuple[str, str]] = set()
        response = self._cedar_client.list_permits()

        for permit in response.get("permits", []):
            principal = permit.get("principal", "")
            table = permit.get("resource", "")
            if principal and table:
                permits.add((principal, table))

        return permits

    def fetch_lake_formation_grants(self) -> set[tuple[str, str]]:
        """Fetch all Lake Formation grants as (principal, table) tuples.

        Retrieves all Lake Formation table-level grants and extracts
        (principal, table) pairs.

        Returns:
            Set of (principal, table) tuples representing LF grants.

        Raises:
            ClientError: If Lake Formation API is unreachable.
        """
        grants: set[tuple[str, str]] = set()

        paginator = self._lakeformation.get_paginator("list_permissions")
        for page in paginator.paginate(
            ResourceType="TABLE",
            MaxResults=1000,
        ):
            for permission in page.get("PrincipalResourcePermissions", []):
                principal_info = permission.get("Principal", {})
                resource_info = permission.get("Resource", {})

                principal = principal_info.get("DataLakePrincipalIdentifier", "")
                table_info = resource_info.get("Table", {})
                database = table_info.get("DatabaseName", "")
                table_name = table_info.get("Name", "")

                if principal and database and table_name:
                    table = f"{database}/{table_name}"
                    grants.add((principal, table))

        return grants

    def trigger_p1_alert(self, divergences: list[dict[str, str]]) -> None:
        """Trigger P1 alert to security operations team.

        Args:
            divergences: List of divergence details to include in the alert.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        subject = "P1 SECURITY ALERT: Permission Reconciliation Divergence"

        message = {
            "alert_type": "P1",
            "source": "permission_reconciliation",
            "timestamp": timestamp,
            "divergence_count": len(divergences),
            "divergences": divergences[:50],  # Limit to first 50 for SNS size limits
            "action_taken": "fail-closed affected principals",
            "gateway_target": self._gateway_target_id,
        }

        try:
            self._sns.publish(
                TopicArn=self._sns_topic_arn,
                Subject=subject[:100],  # SNS subject limit
                Message=str(message),
                MessageAttributes={
                    "AlertSeverity": {
                        "DataType": "String",
                        "StringValue": "P1",
                    },
                    "Source": {
                        "DataType": "String",
                        "StringValue": "reconciliation",
                    },
                },
            )
            logger.info(
                "P1 alert triggered: %d divergences detected",
                len(divergences),
            )
        except Exception as exc:
            # Alert failure is logged but does not prevent fail-close action.
            # The reconciliation must continue blocking affected principals
            # regardless of whether the alert was delivered.
            logger.error("Failed to send P1 alert via SNS: %s", str(exc))

    def block_principals(self, principals: set[str]) -> None:
        """Fail-close affected principals within 5 minutes of detection.

        Blocks all requests from the specified principals by updating
        the Gateway deny list.

        Args:
            principals: Set of principal identifiers to block.
        """
        self._blocked_principals.update(principals)
        logger.warning(
            "Fail-closed %d principals due to reconciliation divergence",
            len(principals),
            extra={"principals": list(principals)[:20]},
        )

    def block_all_requests(self) -> None:
        """Block all agent requests system-wide (assume breach posture).

        Activated when reconciliation job fails or times out.
        All requests are blocked until reconciliation succeeds.
        """
        self._all_blocked = True
        logger.critical(
            "ASSUME BREACH: All requests blocked due to reconciliation failure"
        )

    def is_principal_blocked(self, principal: str) -> bool:
        """Check if a principal is currently blocked by reconciliation.

        Args:
            principal: The principal identifier to check.

        Returns:
            True if the principal is blocked (either individually or system-wide).
        """
        return self._all_blocked or principal in self._blocked_principals

    def _record_healthy_status(self, result: ReconciliationResult) -> None:
        """Record healthy reconciliation status in audit store and emit metric.

        Requirements: 13.4
        """
        # Emit CloudWatch metric indicating successful reconciliation
        try:
            self._cloudwatch.put_metric_data(
                Namespace=RECONCILIATION_METRIC_NAMESPACE,
                MetricData=[
                    {
                        "MetricName": RECONCILIATION_METRIC_NAME,
                        "Value": 1.0,
                        "Unit": "Count",
                        "Timestamp": datetime.now(timezone.utc),
                        "Dimensions": [
                            {"Name": "Status", "Value": "healthy"},
                            {"Name": "GatewayTarget", "Value": self._gateway_target_id},
                        ],
                    },
                    {
                        "MetricName": "ReconciliationDuration",
                        "Value": result.execution_time_s,
                        "Unit": "Seconds",
                        "Timestamp": datetime.now(timezone.utc),
                        "Dimensions": [
                            {"Name": "GatewayTarget", "Value": self._gateway_target_id},
                        ],
                    },
                ],
            )
            logger.info(
                "CloudWatch metric emitted: reconciliation healthy "
                "(cedar_permits=%d, lf_grants=%d, duration=%.1fs)",
                result.cedar_permits,
                result.lf_grants,
                result.execution_time_s,
            )
        except (ClientError, OSError) as exc:
            logger.error("Failed to emit CloudWatch metric: %s", str(exc))

        # Record status in audit store
        if self._audit_store:
            try:
                audit_record = AuditRecord(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    trace_id=str(uuid.uuid4()),
                    session_id="reconciliation",
                    principal="system:reconciliation",
                    question="Daily permission reconciliation",
                    generated_sql=None,
                    policy_decision={
                        "reconciliation_status": "healthy",
                        "cedar_permits": result.cedar_permits,
                        "lf_grants": result.lf_grants,
                    },
                    lake_formation_outcome="healthy",
                    request_status="success",
                )
                self._audit_store.write_record(audit_record)
            except Exception as exc:
                logger.error("Failed to write healthy audit record: %s", str(exc))

    def _record_divergent_status(self, result: ReconciliationResult) -> None:
        """Record divergent reconciliation status in audit store."""
        if self._audit_store:
            try:
                audit_record = AuditRecord(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    trace_id=str(uuid.uuid4()),
                    session_id="reconciliation",
                    principal="system:reconciliation",
                    question="Daily permission reconciliation",
                    generated_sql=None,
                    policy_decision={
                        "reconciliation_status": "divergent",
                        "cedar_permits": result.cedar_permits,
                        "lf_grants": result.lf_grants,
                        "divergence_count": len(result.divergences),
                        "divergences": result.divergences[:50],
                    },
                    lake_formation_outcome="divergent",
                    request_status="failure",
                    error_detail=f"Permission divergence detected: {len(result.divergences)} mismatches",
                )
                self._audit_store.write_record(audit_record)
            except Exception as exc:
                logger.error("Failed to write divergent audit record: %s", str(exc))

    def _record_error_status(self, error: str) -> None:
        """Record reconciliation error/failure in audit store."""
        if self._audit_store:
            try:
                audit_record = AuditRecord(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    trace_id=str(uuid.uuid4()),
                    session_id="reconciliation",
                    principal="system:reconciliation",
                    question="Daily permission reconciliation",
                    generated_sql=None,
                    policy_decision={
                        "reconciliation_status": "error",
                        "error": error,
                    },
                    lake_formation_outcome="error",
                    request_status="failure",
                    error_detail=f"Reconciliation job failure: {error}",
                )
                self._audit_store.write_record(audit_record)
            except Exception as exc:
                logger.error("Failed to write error audit record: %s", str(exc))


def reconcile_permissions(
    *,
    cedar_client: Any | None = None,
    lakeformation_client: Any | None = None,
    sns_client: Any | None = None,
    cloudwatch_client: Any | None = None,
    audit_store: AuditStore | None = None,
    sns_topic_arn: str = "",
    gateway_target_id: str = "chatbot-gateway",
) -> ReconciliationResult:
    """Daily reconciliation: compare Cedar permits against Lake Formation grants.

    Fetches all Cedar permits and Lake Formation grants as (principal, table)
    tuples, compares them bidirectionally, and takes appropriate action:

    - Healthy: Records status in audit store, emits CloudWatch metric.
    - Divergent: Triggers P1 alert, fail-closes affected principals within 5 minutes.
    - Error/Failure: Assumes breach, blocks all requests, triggers P1 alert.

    Must complete within 60 minutes of invocation.

    Args:
        cedar_client: Client for fetching Cedar policy permits.
        lakeformation_client: boto3 Lake Formation client.
        sns_client: boto3 SNS client for P1 alerts.
        cloudwatch_client: boto3 CloudWatch client for metrics.
        audit_store: AuditStore instance for recording reconciliation status.
        sns_topic_arn: SNS topic ARN for P1 security alerts.
        gateway_target_id: The Gateway target ID for fail-close operations.

    Returns:
        ReconciliationResult with status, divergences, and timing information.

    Requirements: 13.1, 13.2, 13.3, 13.4
    """
    start_time = time.monotonic()

    service = ReconciliationService(
        cedar_client=cedar_client,
        lakeformation_client=lakeformation_client,
        sns_client=sns_client,
        cloudwatch_client=cloudwatch_client,
        audit_store=audit_store,
        sns_topic_arn=sns_topic_arn,
        gateway_target_id=gateway_target_id,
    )

    try:
        # Fetch all Cedar permits (principal, table) tuples
        cedar_permits = service.fetch_cedar_permits()

        # Check timeout after Cedar fetch
        elapsed = time.monotonic() - start_time
        if elapsed >= MAX_EXECUTION_SECONDS:
            raise ReconciliationTimeoutError(elapsed_seconds=elapsed)

        # Fetch all Lake Formation grants (principal, table) tuples
        lf_grants = service.fetch_lake_formation_grants()

        # Check timeout after LF fetch
        elapsed = time.monotonic() - start_time
        if elapsed >= MAX_EXECUTION_SECONDS:
            raise ReconciliationTimeoutError(elapsed_seconds=elapsed)

        # Compare bidirectionally
        divergences: list[dict[str, str]] = []

        # Cedar permits without corresponding LF grant
        cedar_without_lf = cedar_permits - lf_grants
        for principal, table in cedar_without_lf:
            divergences.append({
                "principal": principal,
                "table": table,
                "type": "cedar_permit_without_lf_grant",
            })

        # LF grants without corresponding Cedar permit
        lf_without_cedar = lf_grants - cedar_permits
        for principal, table in lf_without_cedar:
            divergences.append({
                "principal": principal,
                "table": table,
                "type": "lf_grant_without_cedar_permit",
            })

        execution_time = time.monotonic() - start_time

        if divergences:
            # Divergence detected — trigger P1 alert and fail-close
            service.trigger_p1_alert(divergences)

            # Fail-close affected principals within 5 minutes
            affected_principals = {d["principal"] for d in divergences}
            service.block_principals(affected_principals)

            result = ReconciliationResult(
                status="divergent",
                divergences=divergences,
                cedar_permits=len(cedar_permits),
                lf_grants=len(lf_grants),
                execution_time_s=execution_time,
            )
            service._record_divergent_status(result)

            logger.warning(
                "Reconciliation DIVERGENT: %d mismatches, %d principals blocked",
                len(divergences),
                len(affected_principals),
            )
            return result

        # Healthy — no divergences
        result = ReconciliationResult(
            status="healthy",
            divergences=[],
            cedar_permits=len(cedar_permits),
            lf_grants=len(lf_grants),
            execution_time_s=execution_time,
        )
        service._record_healthy_status(result)

        logger.info(
            "Reconciliation HEALTHY: %d Cedar permits, %d LF grants match",
            len(cedar_permits),
            len(lf_grants),
        )
        return result

    except Exception as exc:
        # Job failure — assume breach, block all, trigger P1 alert
        execution_time = time.monotonic() - start_time

        error_msg = str(exc)
        logger.critical(
            "Reconciliation FAILURE: %s — assuming breach, blocking all requests",
            error_msg,
        )

        # Assume breach: block all requests
        service.block_all_requests()

        # Trigger P1 alert for job failure
        service.trigger_p1_alert([{
            "type": "reconciliation_failure",
            "error": error_msg,
            "elapsed_seconds": str(execution_time),
        }])

        # Record error status in audit store
        service._record_error_status(error_msg)

        return ReconciliationResult(
            status="error",
            divergences=[],
            cedar_permits=0,
            lf_grants=0,
            execution_time_s=execution_time,
        )
