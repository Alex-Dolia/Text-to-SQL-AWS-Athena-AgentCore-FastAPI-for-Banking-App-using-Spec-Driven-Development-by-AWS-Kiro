"""Structured error handling for the chatbot security architecture.

Defines classified error types and handlers that produce user-friendly
error responses without leaking security internals.

Error Classification:
- AuthorizationDeniedError: Cedar/Lake Formation policy denial
- CostThresholdExceededError: Query cost exceeds threshold
- GuardrailsBlockError: Bedrock Guardrails blocked the request
- SQLFailureError: SQL generation/validation/execution failure
- UnclassifiedError: Catch-all for unexpected errors

All error responses:
- Include trace_id for end-to-end correlation
- Return within 5 seconds of detection
- Never expose policy IDs, rule identifiers, or internal details

Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("chatbot.security")

# Maximum allowed time (seconds) between error detection and response delivery
ERROR_RESPONSE_DEADLINE_SECONDS = 5.0


# ---------------------------------------------------------------------------
# Error Classes
# ---------------------------------------------------------------------------


class AuthorizationDeniedError(Exception):
    """Raised when Cedar or Lake Formation denies access.

    User-facing message directs to Data Governance portal without
    revealing policy IDs, Cedar policy source, rule identifiers,
    or Lake Formation grant details.

    Requirement 17.1
    """

    def __init__(
        self,
        *,
        principal: str = "",
        resource: str = "",
        layer: str = "policy",  # "cedar", "lake_formation", or "policy" (generic)
        policy_id: str = "",  # Internal only — never exposed to user
        trace_id: str = "",
    ):
        self.principal = principal
        self.resource = resource
        self.layer = layer
        self.policy_id = policy_id  # Logged to audit, never in response
        self.trace_id = trace_id
        self.detected_at = time.monotonic()
        super().__init__(
            f"Authorization denied for {principal} on {resource} by {layer}"
        )


class CostThresholdExceededError(Exception):
    """Raised when estimated query cost exceeds the configured threshold.

    User-facing message includes estimated GB, the limit, and a
    suggestion to add date or partition filters.

    Requirement 17.2
    """

    def __init__(
        self,
        *,
        estimated_bytes: int,
        threshold_bytes: int,
        trace_id: str = "",
        filter_suggestions: list[str] | None = None,
    ):
        self.estimated_bytes = estimated_bytes
        self.threshold_bytes = threshold_bytes
        self.trace_id = trace_id
        self.filter_suggestions = filter_suggestions or [
            "Add a date range filter (e.g., WHERE date >= '2024-01-01')",
            "Add partition key filters to reduce scan scope",
            "Select fewer columns instead of SELECT *",
        ]
        self.detected_at = time.monotonic()
        estimated_gb = estimated_bytes / (1024**3)
        threshold_gb = threshold_bytes / (1024**3)
        super().__init__(
            f"Cost threshold exceeded: estimated {estimated_gb:.1f} GB "
            f"exceeds {threshold_gb:.1f} GB limit"
        )

    @property
    def estimated_gb(self) -> float:
        """Estimated scan size in GB."""
        return self.estimated_bytes / (1024**3)

    @property
    def threshold_gb(self) -> float:
        """Configured threshold in GB."""
        return self.threshold_bytes / (1024**3)


class GuardrailsBlockError(Exception):
    """Raised when Bedrock Guardrails blocks a request.

    Returns a fixed response without revealing the guardrail rule
    triggered, the detection category, or the content that caused the block.

    Requirement 17.3
    """

    # Fixed user-facing message — never varies regardless of block reason
    FIXED_RESPONSE = (
        "I can't help with that request. "
        "Please rephrase your question about the data."
    )

    def __init__(
        self,
        *,
        trace_id: str = "",
        # Internal details for audit logging only — never exposed to user
        detection_category: str = "",
        scan_direction: str = "",
        confidence_score: float = 0.0,
        content_hash: str = "",
        session_id: str = "",
    ):
        self.trace_id = trace_id
        self.detection_category = detection_category
        self.scan_direction = scan_direction
        self.confidence_score = confidence_score
        self.content_hash = content_hash
        self.session_id = session_id
        self.detected_at = time.monotonic()
        super().__init__("Guardrails block triggered")


class SQLFailureError(Exception):
    """Raised when SQL generation/validation/execution fails after retries.

    User-facing message suggests rephrasing. Full failure chain is
    logged to the audit store for investigation.

    Requirement 17.4
    """

    def __init__(
        self,
        *,
        trace_id: str = "",
        original_question: str = "",
        sql_attempts: list[str] | None = None,
        error_details: list[str] | None = None,
        session_id: str = "",
        principal: str = "",
    ):
        self.trace_id = trace_id
        self.original_question = original_question
        self.sql_attempts = sql_attempts or []
        self.error_details = error_details or []
        self.session_id = session_id
        self.principal = principal
        self.detected_at = time.monotonic()
        super().__init__(
            f"SQL failure after {len(self.sql_attempts)} attempts"
        )


# ---------------------------------------------------------------------------
# Error Response Builders
# ---------------------------------------------------------------------------


def build_authorization_denied_response(
    trace_id: str,
) -> dict[str, Any]:
    """Build user-facing response for authorization denial.

    Requirement 17.1: Actionable message directing to Data Governance portal
    without policy IDs, rule identifiers, or grant details.
    """
    return {
        "error_type": "auth_denied",
        "message": (
            "Access to the requested data is not available for your account. "
            "Please visit the Data Governance portal to request access or "
            "contact your manager to review your data permissions."
        ),
        "trace_id": trace_id,
        "retry_after": None,
    }


def build_cost_threshold_response(
    trace_id: str,
    estimated_gb: float,
    threshold_gb: float,
    filter_suggestions: list[str],
) -> dict[str, Any]:
    """Build user-facing response for cost threshold exceeded.

    Requirement 17.2: Include estimated GB, limit, and filter suggestions.
    """
    suggestion_text = " ".join(
        f"({i+1}) {s}" for i, s in enumerate(filter_suggestions[:3])
    )
    return {
        "error_type": "cost_exceeded",
        "message": (
            f"Your query would scan approximately {estimated_gb:.1f} GB of data, "
            f"which exceeds the {threshold_gb:.1f} GB limit. "
            f"To reduce the scan size, try: {suggestion_text}"
        ),
        "trace_id": trace_id,
        "retry_after": None,
    }


def build_guardrails_block_response(
    trace_id: str,
) -> dict[str, Any]:
    """Build user-facing response for guardrails block.

    Requirement 17.3: Fixed response, never reveals detection category or rule.
    """
    return {
        "error_type": "out_of_scope",
        "message": GuardrailsBlockError.FIXED_RESPONSE,
        "trace_id": trace_id,
        "retry_after": None,
    }


def build_sql_failure_response(
    trace_id: str,
) -> dict[str, Any]:
    """Build user-facing response for SQL failure.

    Requirement 17.4: Suggest rephrasing without revealing SQL internals.
    """
    return {
        "error_type": "sql_failed",
        "message": (
            "I wasn't able to generate a valid query for your question. "
            "Please try rephrasing your question or asking a simpler version. "
            f"If the issue persists, contact support with reference: {trace_id}"
        ),
        "trace_id": trace_id,
        "retry_after": None,
    }


def build_unclassified_error_response(
    trace_id: str,
) -> dict[str, Any]:
    """Build user-facing response for unclassified/unexpected errors.

    Requirement 17.6: Generic message with trace_id, no internal details.
    """
    return {
        "error_type": "internal_error",
        "message": (
            "An unexpected error occurred while processing your request. "
            f"Please try again or contact support with reference: {trace_id}"
        ),
        "trace_id": trace_id,
        "retry_after": None,
    }


# ---------------------------------------------------------------------------
# Audit Logging Helpers
# ---------------------------------------------------------------------------


def log_sql_failure_to_audit(error: SQLFailureError) -> None:
    """Log the full SQL failure chain to the audit store.

    Requirement 17.4: Log original question, generated SQL attempts,
    and error details for investigation.
    """
    logger.error(
        "SQL_FAILURE_CHAIN",
        extra={
            "event_type": "sql_failure",
            "trace_id": error.trace_id,
            "session_id": error.session_id,
            "principal": error.principal,
            "original_question": error.original_question[:10_000],
            "sql_attempts": error.sql_attempts,
            "error_details": error.error_details,
            "attempt_count": len(error.sql_attempts),
        },
    )


def log_authorization_denied_to_audit(error: AuthorizationDeniedError) -> None:
    """Log authorization denial details to audit (internal details safe here).

    Policy IDs and layer info are logged for investigation but never
    exposed in the user-facing response.
    """
    security_logger.warning(
        "AUTHORIZATION_DENIED",
        extra={
            "event_type": "authorization_denied",
            "trace_id": error.trace_id,
            "principal": error.principal,
            "resource": error.resource,
            "layer": error.layer,
            "policy_id": error.policy_id,
        },
    )


def log_guardrails_block_to_audit(error: GuardrailsBlockError) -> None:
    """Log guardrails block details to audit store.

    Full detection details are logged for security review but never
    exposed in the user-facing response.
    """
    security_logger.warning(
        "GUARDRAILS_BLOCK",
        extra={
            "event_type": "guardrails_block",
            "trace_id": error.trace_id,
            "session_id": error.session_id,
            "detection_category": error.detection_category,
            "scan_direction": error.scan_direction,
            "confidence_score": error.confidence_score,
            "content_hash": error.content_hash,
        },
    )
