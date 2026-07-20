"""Content safety enforcement — PII redaction and session termination logic.

Implements:
- PII redaction unless user's role permits viewing that PII category (via Cedar policy)
- Session termination after 3+ BLOCK actions in a single session
- Security event logging to audit store and SIEM on session termination
- Re-authentication requirement after terminated session

Requirements: 8.3, 8.5
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Structured security logger for SIEM-bound alerts
security_logger = logging.getLogger("chatbot.security")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Number of BLOCK actions in a session before termination (Requirement 8.5)
SESSION_BLOCK_THRESHOLD: int = 3


# ---------------------------------------------------------------------------
# Cedar-based PII role grants
# ---------------------------------------------------------------------------

# PII categories that specific roles are permitted to view without redaction.
# These map to Cedar policy grants: the Cedar policy set defines which roles
# have explicit permits for specific PII entity types.
#
# In production this would be evaluated dynamically via the Cedar policy engine;
# here we maintain a static mapping that mirrors the deployed Cedar policies.
ROLE_PII_GRANTS: dict[str, set[str]] = {
    "manager": {"NAME", "EMAIL", "PHONE"},
    "compliance_officer": {
        "NAME", "EMAIL", "PHONE", "ADDRESS",
        "SSN", "CREDIT_DEBIT_CARD_NUMBER",
    },
    "hr_director": {"NAME", "EMAIL", "PHONE", "ADDRESS", "SSN"},
    # Default: no PII grants (analysts, regular users, etc.)
}


def get_permitted_pii_categories(user_claims: dict[str, Any]) -> set[str]:
    """Determine PII categories the user may view without redaction.

    Evaluates Cedar policy grants for the user's role to determine which
    PII entity types should NOT be redacted in output.

    Args:
        user_claims: Validated JWT claims dict with at least 'role' key.

    Returns:
        Set of PII category names (e.g., "NAME", "EMAIL") the user may view.
    """
    role = user_claims.get("role", "")
    # Check direct role grants
    permitted = set(ROLE_PII_GRANTS.get(role, set()))

    # Check group-based grants (e.g., "pii_viewer" group)
    groups = user_claims.get("groups", [])
    if "pii_full_access" in groups:
        # Full PII access group — all categories permitted
        from chatbot.agent.nodes.output_scan import ALL_PII_ENTITY_TYPES
        permitted = set(ALL_PII_ENTITY_TYPES)

    return permitted


def should_redact_pii(
    pii_type: str,
    user_claims: dict[str, Any],
) -> bool:
    """Determine if a specific PII type should be redacted for this user.

    Args:
        pii_type: The PII entity type (e.g., "SSN", "EMAIL").
        user_claims: Validated JWT claims.

    Returns:
        True if the PII should be redacted, False if user may view it.
    """
    permitted = get_permitted_pii_categories(user_claims)
    return pii_type not in permitted


# ---------------------------------------------------------------------------
# Session Block Tracker — tracks BLOCK actions per session
# ---------------------------------------------------------------------------

@dataclass
class SessionBlockRecord:
    """Tracks BLOCK actions for a single session."""

    session_id: str
    block_count: int = 0
    block_timestamps: list[float] = field(default_factory=list)
    terminated: bool = False
    terminated_at: float | None = None


class SessionBlockTracker:
    """Tracks guardrails BLOCK actions per session and enforces termination.

    After 3+ BLOCK actions in a single session, the session is terminated
    and the user must re-authenticate (Requirement 8.5).

    Thread safety: In production, this would be backed by a distributed store
    (e.g., DynamoDB or Redis). The in-memory implementation is suitable for
    single-process deployments and testing.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionBlockRecord] = {}

    def record_block(self, session_id: str) -> SessionBlockRecord:
        """Record a BLOCK action for the given session.

        Args:
            session_id: The session identifier (UUID v4).

        Returns:
            Updated SessionBlockRecord after recording the block.
        """
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionBlockRecord(session_id=session_id)

        record = self._sessions[session_id]
        record.block_count += 1
        record.block_timestamps.append(time.time())

        logger.info(
            "Session %s: BLOCK action recorded (count: %d/%d)",
            session_id,
            record.block_count,
            SESSION_BLOCK_THRESHOLD,
        )

        return record

    def should_terminate(self, session_id: str) -> bool:
        """Check if a session should be terminated due to excessive BLOCKs.

        Args:
            session_id: The session identifier.

        Returns:
            True if block count >= threshold and session not yet terminated.
        """
        record = self._sessions.get(session_id)
        if record is None:
            return False
        return record.block_count >= SESSION_BLOCK_THRESHOLD and not record.terminated

    def is_terminated(self, session_id: str) -> bool:
        """Check if a session has already been terminated.

        Args:
            session_id: The session identifier.

        Returns:
            True if the session was previously terminated.
        """
        record = self._sessions.get(session_id)
        if record is None:
            return False
        return record.terminated

    def terminate_session(self, session_id: str) -> SessionBlockRecord:
        """Mark a session as terminated.

        Args:
            session_id: The session identifier.

        Returns:
            The terminated SessionBlockRecord.
        """
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionBlockRecord(session_id=session_id)

        record = self._sessions[session_id]
        record.terminated = True
        record.terminated_at = time.time()

        logger.warning(
            "Session %s TERMINATED: %d BLOCK actions exceeded threshold (%d)",
            session_id,
            record.block_count,
            SESSION_BLOCK_THRESHOLD,
        )

        return record

    def get_block_count(self, session_id: str) -> int:
        """Get current block count for a session.

        Args:
            session_id: The session identifier.

        Returns:
            Number of BLOCK actions recorded for this session.
        """
        record = self._sessions.get(session_id)
        return record.block_count if record else 0

    def get_record(self, session_id: str) -> SessionBlockRecord | None:
        """Get the full block record for a session.

        Args:
            session_id: The session identifier.

        Returns:
            SessionBlockRecord or None if no blocks recorded.
        """
        return self._sessions.get(session_id)

    def clear_session(self, session_id: str) -> None:
        """Remove tracking data for a session (e.g., after re-auth)."""
        self._sessions.pop(session_id, None)

    def reset(self) -> None:
        """Reset all tracking data (for testing)."""
        self._sessions.clear()


# Module-level singleton
_block_tracker: SessionBlockTracker | None = None


def get_block_tracker() -> SessionBlockTracker:
    """Get or create the module-level SessionBlockTracker singleton."""
    global _block_tracker
    if _block_tracker is None:
        _block_tracker = SessionBlockTracker()
    return _block_tracker


def reset_block_tracker() -> None:
    """Reset the block tracker singleton (for testing)."""
    global _block_tracker
    _block_tracker = None


# ---------------------------------------------------------------------------
# Security event logging — audit store + SIEM
# ---------------------------------------------------------------------------

def log_session_termination(
    session_id: str,
    principal: str,
    block_count: int,
    trace_id: str,
    *,
    audit_store: Any | None = None,
) -> dict[str, Any]:
    """Log a session termination security event to audit store and SIEM.

    This function:
    1. Emits a structured security event to the SIEM logger
    2. Writes an audit record to the immutable audit store (if provided)

    Args:
        session_id: The terminated session ID.
        principal: User principal (from JWT sub claim).
        block_count: Number of BLOCK actions that triggered termination.
        trace_id: Request trace ID for correlation.
        audit_store: Optional AuditStore instance for writing audit record.

    Returns:
        Dict containing the security event details logged.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    security_event = {
        "event_type": "security_alert",
        "alert_type": "session_terminated_excessive_blocks",
        "alert_priority": "P2",
        "session_id": session_id,
        "principal": principal,
        "block_count": block_count,
        "threshold": SESSION_BLOCK_THRESHOLD,
        "trace_id": trace_id,
        "timestamp": timestamp,
        "action_required": "User must re-authenticate",
        "reason": (
            f"Session terminated: {block_count} guardrails BLOCK actions "
            f"exceeded threshold of {SESSION_BLOCK_THRESHOLD}"
        ),
    }

    # Log to SIEM via structured security logger
    security_logger.warning(
        "SESSION_TERMINATED_EXCESSIVE_BLOCKS",
        extra=security_event,
    )

    # Write to immutable audit store if available
    if audit_store is not None:
        try:
            from chatbot.scripts.audit import AuditRecord
            audit_record = AuditRecord(
                timestamp=timestamp,
                trace_id=trace_id,
                session_id=session_id,
                principal=principal,
                question="[SESSION_TERMINATED]",
                generated_sql=None,
                policy_decision={
                    "event": "session_termination",
                    "reason": "excessive_guardrails_blocks",
                    "block_count": block_count,
                },
                lake_formation_outcome=None,
                cost_estimate_bytes=None,
                row_count=None,
                guardrails_findings={
                    "action": "SESSION_TERMINATE",
                    "block_count": block_count,
                    "threshold": SESSION_BLOCK_THRESHOLD,
                },
                request_status="session_terminated",
                error_detail=f"Session terminated after {block_count} BLOCK actions",
            )
            audit_store.write_record(audit_record)
            logger.info(
                "Audit record written for session termination: %s",
                session_id,
            )
        except Exception as e:
            # Log but don't fail — the session is already terminated
            logger.error(
                "Failed to write audit record for session termination: %s",
                str(e),
                extra={"session_id": session_id, "trace_id": trace_id},
            )

    return security_event


# ---------------------------------------------------------------------------
# Session termination check — integrated with session store
# ---------------------------------------------------------------------------

def terminate_session_if_needed(
    session_id: str,
    principal: str,
    trace_id: str,
    *,
    session_store: Any | None = None,
    audit_store: Any | None = None,
) -> bool:
    """Check if session should be terminated and perform termination if so.

    This function checks the block tracker, and if the threshold is met:
    1. Marks the session as terminated in the block tracker
    2. Invalidates the session in the session store (requiring re-auth)
    3. Logs the security event to audit store and SIEM

    Args:
        session_id: Session identifier.
        principal: User principal from JWT.
        trace_id: Request correlation ID.
        session_store: Optional SessionStore for invalidation.
        audit_store: Optional AuditStore for audit logging.

    Returns:
        True if session was terminated, False otherwise.
    """
    tracker = get_block_tracker()

    if not tracker.should_terminate(session_id):
        return False

    # Terminate the session
    record = tracker.terminate_session(session_id)

    # Invalidate in session store (forces re-authentication)
    if session_store is not None:
        session_store.invalidate(session_id)
        logger.info(
            "Session %s invalidated in session store (re-auth required)",
            session_id,
        )

    # Log security event to audit + SIEM
    log_session_termination(
        session_id=session_id,
        principal=principal,
        block_count=record.block_count,
        trace_id=trace_id,
        audit_store=audit_store,
    )

    return True


# ---------------------------------------------------------------------------
# Enhanced output scan with session termination
# ---------------------------------------------------------------------------

def handle_guardrail_block(
    session_id: str,
    principal: str,
    trace_id: str,
    findings: list[str],
    *,
    session_store: Any | None = None,
    audit_store: Any | None = None,
) -> dict[str, Any]:
    """Handle a guardrails BLOCK action with session tracking.

    Records the block, checks termination threshold, and returns
    appropriate response state.

    Args:
        session_id: Session identifier.
        principal: User principal.
        trace_id: Request correlation ID.
        findings: Guardrails findings from the scan.
        session_store: Optional SessionStore for invalidation.
        audit_store: Optional AuditStore for audit logging.

    Returns:
        Dict with response information:
        - "terminated": bool — whether session was terminated
        - "error_message": str — user-facing error message
        - "block_count": int — current block count for session
    """
    tracker = get_block_tracker()

    # Check if session already terminated
    if tracker.is_terminated(session_id):
        return {
            "terminated": True,
            "error_message": (
                "Your session has been terminated due to repeated policy violations. "
                "Please re-authenticate to continue."
            ),
            "block_count": tracker.get_block_count(session_id),
        }

    # Record the new block
    record = tracker.record_block(session_id)

    # Check if termination threshold is now reached
    terminated = terminate_session_if_needed(
        session_id=session_id,
        principal=principal,
        trace_id=trace_id,
        session_store=session_store,
        audit_store=audit_store,
    )

    if terminated:
        error_message = (
            "Your session has been terminated due to repeated policy violations. "
            "Please re-authenticate to continue."
        )
    else:
        # Standard block response (no detection category revealed per Req 8.2)
        error_message = (
            "I can't help with that request. "
            "Please rephrase your question about the data."
        )

    return {
        "terminated": terminated,
        "error_message": error_message,
        "block_count": record.block_count,
    }
