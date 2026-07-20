"""Immutable audit record writer and query capability for compliance trail.

Writes audit records to S3 with Object Lock (Compliance mode, 7-year retention).
Implements fail-closed semantics: if audit cannot be written after 3 retries,
the in-flight request is denied rather than proceeding without an audit record.

Provides query_by_principal() for DSAR response and compliance investigations,
supporting date range queries with results within 60 seconds for 90-day spans.

Configures cross-region replication with RPO ≤15 minutes for disaster recovery.

Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 5.8
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Constants
MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 0.5
RETENTION_YEARS = 7
QUESTION_MAX_LENGTH = 10_000
QUERY_TIMEOUT_SECONDS = 60
MAX_QUERY_SPAN_DAYS = 90
REPLICATION_RPO_MINUTES = 15


class AuditWriteError(Exception):
    """Raised when audit record cannot be written after all retry attempts.

    This exception signals fail-closed behavior: the in-flight request
    must be denied because the audit trail cannot be maintained.
    """

    def __init__(self, trace_id: str, message: str = "Audit write failed after all retries"):
        self.trace_id = trace_id
        super().__init__(f"{message} [trace_id={trace_id}]")


class AuditQueryError(Exception):
    """Raised when an audit query fails or times out.

    Used for DSAR response and compliance investigation query failures.
    """

    def __init__(self, principal: str, message: str = "Audit query failed"):
        self.principal = principal
        super().__init__(f"{message} [principal={principal}]")


class AuditQueryTimeoutError(AuditQueryError):
    """Raised when an audit query exceeds the 60-second SLA."""

    def __init__(self, principal: str, elapsed_seconds: float):
        self.elapsed_seconds = elapsed_seconds
        super().__init__(
            principal,
            f"Audit query exceeded {QUERY_TIMEOUT_SECONDS}s SLA "
            f"(elapsed: {elapsed_seconds:.1f}s)",
        )


@dataclass
class AuditRecord:
    """Full audit context for a chatbot request.

    All fields required by Requirement 11.1:
    timestamp, trace_id, session_id, principal, question, SQL,
    policy decision, LF outcome, cost, row count, guardrails findings.
    """

    timestamp: str
    trace_id: str
    session_id: str
    principal: str
    question: str
    generated_sql: str | None = None
    policy_decision: dict[str, Any] = field(default_factory=dict)
    lake_formation_outcome: str | None = None
    cost_estimate_bytes: int | None = None
    row_count: int | None = None
    guardrails_findings: dict[str, Any] = field(default_factory=dict)
    request_status: str = "success"
    error_detail: str | None = None

    def to_json(self) -> str:
        """Serialize audit record to JSON string."""
        data = asdict(self)
        # Truncate question to max length per requirement 11.1
        if data["question"] and len(data["question"]) > QUESTION_MAX_LENGTH:
            data["question"] = data["question"][:QUESTION_MAX_LENGTH]
        return json.dumps(data, default=str, ensure_ascii=False)


class AuditStore:
    """Immutable audit record writer backed by S3 Object Lock.

    Writes audit records to S3 with:
    - Object Lock in Compliance mode (cannot be deleted, even by root)
    - 7-year retention period
    - Retry logic (3 attempts) with exponential backoff
    - CloudWatch alarm on failure
    - Fail-closed: raises AuditWriteError if write fails (denying in-flight request)

    Requirements: 11.1, 11.2, 11.5, 11.6, 5.8
    """

    def __init__(
        self,
        bucket_name: str,
        *,
        s3_client: Any | None = None,
        cloudwatch_client: Any | None = None,
        alarm_namespace: str = "Chatbot/Audit",
        alarm_metric_name: str = "AuditWriteFailure",
    ):
        """Initialize AuditStore.

        Args:
            bucket_name: S3 bucket with Object Lock enabled (Compliance mode).
            s3_client: Optional boto3 S3 client (for testing/injection).
            cloudwatch_client: Optional boto3 CloudWatch client (for testing/injection).
            alarm_namespace: CloudWatch namespace for failure metrics.
            alarm_metric_name: CloudWatch metric name for write failures.
        """
        self._bucket_name = bucket_name
        self._s3 = s3_client or boto3.client("s3")
        self._cloudwatch = cloudwatch_client or boto3.client("cloudwatch")
        self._alarm_namespace = alarm_namespace
        self._alarm_metric_name = alarm_metric_name

    def write_record(self, record: AuditRecord) -> str:
        """Write an immutable audit record to S3.

        Attempts up to 3 writes with exponential backoff. On complete failure,
        emits a CloudWatch metric/alarm and raises AuditWriteError to fail-close
        the in-flight request.

        Args:
            record: The audit record to persist.

        Returns:
            The S3 object key where the record was stored.

        Raises:
            AuditWriteError: If all retry attempts fail. The caller MUST
                deny the in-flight request when this is raised.
        """
        object_key = self._generate_key(record)
        record_json = record.to_json()
        last_error: Exception | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._put_object(object_key, record_json, record.timestamp)
                logger.info(
                    "Audit record written successfully",
                    extra={
                        "trace_id": record.trace_id,
                        "object_key": object_key,
                        "attempt": attempt,
                    },
                )
                return object_key
            except (ClientError, OSError) as exc:
                last_error = exc
                logger.warning(
                    "Audit write attempt %d/%d failed: %s",
                    attempt,
                    MAX_RETRIES,
                    str(exc),
                    extra={"trace_id": record.trace_id, "attempt": attempt},
                )
                if attempt < MAX_RETRIES:
                    backoff = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
                    time.sleep(backoff)

        # All retries exhausted — emit alarm and fail-closed
        self._emit_failure_alarm(record.trace_id)
        logger.error(
            "Audit write FAILED after %d attempts — failing request (fail-closed)",
            MAX_RETRIES,
            extra={"trace_id": record.trace_id, "session_id": record.session_id},
        )
        raise AuditWriteError(trace_id=record.trace_id)

    def _put_object(self, key: str, body: str, timestamp: str) -> None:
        """Write object to S3 with Object Lock retention.

        Applies Compliance mode retention for 7 years from the record timestamp.
        """
        # Calculate retention expiry: 7 years from record timestamp
        record_time = datetime.fromisoformat(timestamp)
        retain_until = record_time.replace(year=record_time.year + RETENTION_YEARS)

        self._s3.put_object(
            Bucket=self._bucket_name,
            Key=key,
            Body=body.encode("utf-8"),
            ContentType="application/json",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
        )

    def _generate_key(self, record: AuditRecord) -> str:
        """Generate a partitioned S3 key for the audit record.

        Format: audit/{year}/{month}/{day}/{trace_id}-{uuid}.json
        Partitioning by date enables efficient DSAR/investigation queries.
        """
        record_time = datetime.fromisoformat(record.timestamp)
        unique_suffix = uuid.uuid4().hex[:8]
        return (
            f"audit/{record_time.year:04d}/{record_time.month:02d}/{record_time.day:02d}/"
            f"{record.trace_id}-{unique_suffix}.json"
        )

    def _emit_failure_alarm(self, trace_id: str) -> None:
        """Emit CloudWatch metric for audit write failure.

        This triggers the compliance monitoring alarm configured in the
        observability stack, alerting security operations that an audit
        record could not be persisted.
        """
        try:
            self._cloudwatch.put_metric_data(
                Namespace=self._alarm_namespace,
                MetricData=[
                    {
                        "MetricName": self._alarm_metric_name,
                        "Value": 1.0,
                        "Unit": "Count",
                        "Dimensions": [
                            {"Name": "TraceId", "Value": trace_id},
                        ],
                    }
                ],
            )
            logger.info(
                "CloudWatch alarm emitted for audit write failure",
                extra={"trace_id": trace_id},
            )
        except (ClientError, OSError) as exc:
            # Even if alarm emission fails, we still raise AuditWriteError
            # to maintain fail-closed semantics
            logger.error(
                "Failed to emit CloudWatch alarm: %s",
                str(exc),
                extra={"trace_id": trace_id},
            )

    def query_by_principal(
        self,
        principal: str,
        date_range: tuple[datetime, datetime],
    ) -> list[AuditRecord]:
        """Query audit records by principal and date range for DSAR/investigation.

        Supports compliance investigations and GDPR/UK GDPR DSAR responses.
        Returns results within 60 seconds for queries spanning up to 90 days.

        The implementation uses S3 ListObjectsV2 with date-partitioned prefix
        filtering to efficiently locate relevant records without full bucket scans.

        Args:
            principal: The user principal to search for (from JWT sub claim).
            date_range: Tuple of (start_date, end_date) as timezone-aware datetimes.
                        Maximum span of 90 days supported within 60-second SLA.

        Returns:
            List of AuditRecord objects matching the principal within the date range,
            ordered by timestamp (oldest first).

        Raises:
            AuditQueryError: If the query fails due to S3 errors.
            AuditQueryTimeoutError: If the query exceeds 60-second SLA.
            ValueError: If date_range is invalid (start > end or span > 90 days).

        Requirements: 11.3, 11.4
        """
        start_date, end_date = date_range

        # Validate date range
        if start_date > end_date:
            raise ValueError(
                f"Invalid date range: start ({start_date.isoformat()}) "
                f"is after end ({end_date.isoformat()})"
            )

        span_days = (end_date - start_date).days
        if span_days > MAX_QUERY_SPAN_DAYS:
            raise ValueError(
                f"Date range span ({span_days} days) exceeds maximum "
                f"of {MAX_QUERY_SPAN_DAYS} days for 60-second SLA"
            )

        query_start_time = time.monotonic()
        matching_records: list[AuditRecord] = []

        try:
            # Generate date-partitioned prefixes to search
            prefixes = self._generate_date_prefixes(start_date, end_date)

            for prefix in prefixes:
                # Check timeout before each prefix scan
                elapsed = time.monotonic() - query_start_time
                if elapsed >= QUERY_TIMEOUT_SECONDS:
                    raise AuditQueryTimeoutError(
                        principal=principal, elapsed_seconds=elapsed
                    )

                # List objects under this date prefix
                objects = self._list_objects_with_prefix(prefix)

                for obj_key in objects:
                    # Check timeout periodically during record retrieval
                    elapsed = time.monotonic() - query_start_time
                    if elapsed >= QUERY_TIMEOUT_SECONDS:
                        raise AuditQueryTimeoutError(
                            principal=principal, elapsed_seconds=elapsed
                        )

                    # Retrieve and filter by principal
                    record = self._get_and_parse_record(obj_key)
                    if record and record.principal == principal:
                        # Verify record falls within the requested date range
                        record_time = datetime.fromisoformat(record.timestamp)
                        if start_date <= record_time <= end_date:
                            matching_records.append(record)

        except AuditQueryTimeoutError:
            raise
        except (ClientError, OSError) as exc:
            logger.error(
                "Audit query failed for principal %s: %s",
                principal,
                str(exc),
            )
            raise AuditQueryError(
                principal=principal,
                message=f"Audit query failed: {str(exc)}",
            )

        # Sort by timestamp (oldest first)
        matching_records.sort(key=lambda r: r.timestamp)

        elapsed = time.monotonic() - query_start_time
        logger.info(
            "Audit query completed for principal %s: %d records in %.1fs",
            principal,
            len(matching_records),
            elapsed,
        )

        return matching_records

    def _generate_date_prefixes(
        self, start_date: datetime, end_date: datetime
    ) -> list[str]:
        """Generate S3 key prefixes for each day in the date range.

        Uses the partitioned key structure: audit/{year}/{month}/{day}/
        to enable efficient prefix-based listing.
        """
        prefixes: list[str] = []
        current = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)

        while current <= end:
            prefix = f"audit/{current.year:04d}/{current.month:02d}/{current.day:02d}/"
            prefixes.append(prefix)
            current += timedelta(days=1)

        return prefixes

    def _list_objects_with_prefix(self, prefix: str) -> list[str]:
        """List all object keys under a given S3 prefix.

        Uses pagination to handle large result sets.
        """
        keys: list[str] = []
        paginator = self._s3.get_paginator("list_objects_v2")

        for page in paginator.paginate(Bucket=self._bucket_name, Prefix=prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])

        return keys

    def _get_and_parse_record(self, key: str) -> AuditRecord | None:
        """Retrieve and parse a single audit record from S3.

        Returns None if the record cannot be parsed (logs warning).
        """
        try:
            response = self._s3.get_object(Bucket=self._bucket_name, Key=key)
            body = response["Body"].read().decode("utf-8")
            data = json.loads(body)

            return AuditRecord(
                timestamp=data["timestamp"],
                trace_id=data["trace_id"],
                session_id=data["session_id"],
                principal=data["principal"],
                question=data["question"],
                generated_sql=data.get("generated_sql"),
                policy_decision=data.get("policy_decision", {}),
                lake_formation_outcome=data.get("lake_formation_outcome"),
                cost_estimate_bytes=data.get("cost_estimate_bytes"),
                row_count=data.get("row_count"),
                guardrails_findings=data.get("guardrails_findings", {}),
                request_status=data.get("request_status", "success"),
                error_detail=data.get("error_detail"),
            )
        except (ClientError, json.JSONDecodeError, KeyError) as exc:
            logger.warning(
                "Failed to parse audit record at %s: %s",
                key,
                str(exc),
            )
            return None


class CrossRegionReplicationConfig:
    """Configuration for cross-region replication of audit records.

    Ensures RPO ≤15 minutes by configuring S3 Cross-Region Replication (CRR)
    with S3 Replication Time Control (S3 RTC) which guarantees 99.99% of objects
    are replicated within 15 minutes.

    Requirements: 11.3
    """

    def __init__(
        self,
        source_bucket: str,
        destination_bucket: str,
        destination_region: str,
        *,
        s3_client: Any | None = None,
        iam_client: Any | None = None,
        role_arn: str | None = None,
    ):
        """Initialize cross-region replication configuration.

        Args:
            source_bucket: Primary audit bucket name (Object Lock enabled).
            destination_bucket: Replica audit bucket name in secondary region.
            destination_region: AWS region for the replica bucket.
            s3_client: Optional boto3 S3 client (for testing/injection).
            iam_client: Optional boto3 IAM client (for testing/injection).
            role_arn: IAM role ARN for S3 replication. If None, a default
                      naming convention is used.
        """
        self._source_bucket = source_bucket
        self._destination_bucket = destination_bucket
        self._destination_region = destination_region
        self._s3 = s3_client or boto3.client("s3")
        self._iam = iam_client or boto3.client("iam")
        self._role_arn = role_arn

    @property
    def replication_config(self) -> dict[str, Any]:
        """Generate the S3 replication configuration.

        Configures:
        - S3 Replication Time Control (RTC) for RPO ≤15 minutes
        - Replica Object Lock retention replication
        - All audit prefix objects replicated
        - Delete marker replication enabled for consistency
        """
        return {
            "Role": self._role_arn or "",
            "Rules": [
                {
                    "ID": "audit-cross-region-replication",
                    "Status": "Enabled",
                    "Priority": 1,
                    "Filter": {
                        "Prefix": "audit/",
                    },
                    "Destination": {
                        "Bucket": f"arn:aws:s3:::{self._destination_bucket}",
                        "StorageClass": "STANDARD",
                        "ReplicationTime": {
                            "Status": "Enabled",
                            "Time": {
                                "Minutes": REPLICATION_RPO_MINUTES,
                            },
                        },
                        "Metrics": {
                            "Status": "Enabled",
                            "EventThreshold": {
                                "Minutes": REPLICATION_RPO_MINUTES,
                            },
                        },
                    },
                    "DeleteMarkerReplication": {
                        "Status": "Enabled",
                    },
                    "SourceSelectionCriteria": {
                        "ReplicaModifications": {
                            "Status": "Enabled",
                        },
                    },
                }
            ],
        }

    def apply_replication(self) -> dict[str, Any]:
        """Apply the cross-region replication configuration to the source bucket.

        Configures S3 CRR with Replication Time Control (RTC) which
        guarantees 99.99% of objects replicated within 15 minutes (RPO ≤15 min).

        Returns:
            The replication configuration that was applied.

        Raises:
            ClientError: If the S3 API call fails.
        """
        config = self.replication_config

        self._s3.put_bucket_replication(
            Bucket=self._source_bucket,
            ReplicationConfiguration=config,
        )

        logger.info(
            "Cross-region replication configured: %s → %s (RPO ≤%d minutes)",
            self._source_bucket,
            self._destination_bucket,
            REPLICATION_RPO_MINUTES,
        )

        return config

    def verify_replication_status(self) -> dict[str, Any]:
        """Verify the replication configuration is active and healthy.

        Returns:
            Dictionary with replication status details including:
            - configured: Whether replication is configured
            - rules_enabled: Number of enabled replication rules
            - rpo_minutes: Configured RPO in minutes
            - destination_region: Target region for replicas
        """
        try:
            response = self._s3.get_bucket_replication(Bucket=self._source_bucket)
            config = response.get("ReplicationConfiguration", {})
            rules = config.get("Rules", [])
            enabled_rules = [r for r in rules if r.get("Status") == "Enabled"]

            # Extract RPO from first enabled rule with RTC
            rpo_minutes = None
            for rule in enabled_rules:
                dest = rule.get("Destination", {})
                rtime = dest.get("ReplicationTime", {})
                if rtime.get("Status") == "Enabled":
                    rpo_minutes = rtime.get("Time", {}).get("Minutes")
                    break

            return {
                "configured": True,
                "rules_enabled": len(enabled_rules),
                "rpo_minutes": rpo_minutes,
                "destination_bucket": self._destination_bucket,
                "destination_region": self._destination_region,
            }
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "ReplicationConfigurationNotFoundError":
                return {
                    "configured": False,
                    "rules_enabled": 0,
                    "rpo_minutes": None,
                    "destination_bucket": self._destination_bucket,
                    "destination_region": self._destination_region,
                }
            raise


def create_audit_record(
    trace_id: str,
    session_id: str,
    principal: str,
    question: str,
    *,
    generated_sql: str | None = None,
    policy_decision: dict[str, Any] | None = None,
    lake_formation_outcome: str | None = None,
    cost_estimate_bytes: int | None = None,
    row_count: int | None = None,
    guardrails_findings: dict[str, Any] | None = None,
    request_status: str = "success",
    error_detail: str | None = None,
) -> AuditRecord:
    """Factory function to create an AuditRecord with current timestamp.

    Convenience wrapper that sets the timestamp to now (UTC) and provides
    sensible defaults for optional fields.

    Args:
        trace_id: UUID v4 request correlation ID.
        session_id: UUID v4 session identifier.
        principal: Authenticated user principal (from JWT).
        question: Original user question (truncated to 10,000 chars).
        generated_sql: SQL generated by the agent, if any.
        policy_decision: Cedar policy evaluation result dict.
        lake_formation_outcome: Lake Formation access check result.
        cost_estimate_bytes: Estimated bytes scanned by Athena.
        row_count: Number of rows returned, if query executed.
        guardrails_findings: Bedrock Guardrails scan results.
        request_status: "success" or "failure".
        error_detail: Error description if request failed.

    Returns:
        Populated AuditRecord ready for writing.
    """
    return AuditRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        trace_id=trace_id,
        session_id=session_id,
        principal=principal,
        question=question[:QUESTION_MAX_LENGTH] if question else "",
        generated_sql=generated_sql,
        policy_decision=policy_decision or {},
        lake_formation_outcome=lake_formation_outcome,
        cost_estimate_bytes=cost_estimate_bytes,
        row_count=row_count,
        guardrails_findings=guardrails_findings or {},
        request_status=request_status,
        error_detail=error_detail,
    )
