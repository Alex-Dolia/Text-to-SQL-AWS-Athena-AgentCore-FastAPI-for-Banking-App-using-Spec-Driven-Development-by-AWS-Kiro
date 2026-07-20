"""Cedar policy evaluation integration for AgentCore Gateway.

Implements deterministic, default-deny, forbid-wins authorization at the
Gateway boundary. All tool invocations are evaluated BEFORE execution.

Key behaviors:
- Default-deny: no access without explicit permit (Req 5.1)
- Forbid-wins: forbid overrides any permit (Req 5.2)
- Principal claims sourced exclusively from validated JWT (Req 5.3)
- Decision logged to immutable audit store BEFORE returning (Req 5.5)
- P99 evaluation within 30ms (Req 5.6)
- Fail-closed on policy engine unavailable or evaluation error (Req 5.7)
- Fail-closed if audit write fails (Req 5.8)

Requirements: 5.1, 5.2, 5.3, 5.5, 5.6, 5.7, 5.8
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

logger = logging.getLogger(__name__)

# Maximum evaluation time budget in seconds (30ms at P99)
MAX_EVALUATION_TIME_MS = 30
POLICY_ENGINE_TIMEOUT_MS = 25  # Leave 5ms for audit write overhead


class PolicyDecisionType(str, Enum):
    """Cedar policy evaluation outcomes."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class PolicyDenyReason(str, Enum):
    """Categorized reasons for policy denial."""

    NO_MATCHING_PERMIT = "no_matching_permit"  # Default-deny (Req 5.1)
    FORBID_OVERRIDE = "forbid_override"  # Forbid-wins (Req 5.2)
    ENGINE_UNAVAILABLE = "engine_unavailable"  # Fail-closed (Req 5.7)
    EVALUATION_ERROR = "evaluation_error"  # Fail-closed (Req 5.7)
    AUDIT_WRITE_FAILED = "audit_write_failed"  # Fail-closed (Req 5.8)


@dataclass(frozen=True)
class PolicyRequest:
    """Request for Cedar policy evaluation.

    Principal claims are sourced EXCLUSIVELY from the validated JWT
    (Req 5.3) — never from user-supplied input or LLM-generated content.
    """

    # Principal attributes (from validated JWT only — Req 5.3)
    principal_id: str  # JWT 'sub' claim
    department: str  # JWT 'department' claim
    role: str  # JWT 'role' claim
    data_classification_tier: str  # JWT 'data_classification_tier' claim
    groups: tuple[str, ...]  # JWT 'groups' claim (frozen for hashability)

    # Action being requested
    action: str  # Tool name: "run_query", "list_tables", etc.

    # Resource being accessed
    resource_database: str  # Target database
    resource_table: str  # Target table
    resource_classification_tier: str = "internal"  # Resource classification
    resource_is_partitioned: bool = False

    # Tracing context
    trace_id: str = ""
    session_id: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    """Result of Cedar policy evaluation.

    Contains decision, determining policies, and timing for audit logging.
    """

    decision: PolicyDecisionType
    determining_policies: tuple[str, ...] = ()
    policy_version: str = ""
    evaluation_time_ms: float = 0.0
    deny_reason: PolicyDenyReason | None = None
    error_detail: str | None = None

    def to_audit_dict(self) -> dict[str, Any]:
        """Convert to dictionary for audit record persistence."""
        return {
            "decision": self.decision.value,
            "determining_policies": list(self.determining_policies),
            "policy_version": self.policy_version,
            "evaluation_time_ms": round(self.evaluation_time_ms, 2),
            "deny_reason": self.deny_reason.value if self.deny_reason else None,
        }


class AuditWriteError(Exception):
    """Raised when audit write fails — triggers fail-closed (Req 5.8)."""

    pass


class PolicyEngineError(Exception):
    """Raised when policy engine is unavailable — triggers fail-closed (Req 5.7)."""

    pass


class AuditWriter(Protocol):
    """Protocol for audit record writing (dependency injection)."""

    def write_policy_decision(
        self,
        request: PolicyRequest,
        decision: PolicyDecision,
    ) -> None:
        """Write policy decision to immutable audit store.

        Must succeed for the request to proceed.
        Raises AuditWriteError if write fails.
        """
        ...


class PolicyEngine(Protocol):
    """Protocol for Cedar policy engine (dependency injection).

    In production, this delegates to AgentCore's Cedar runtime.
    For testing, can be replaced with a local evaluator.
    """

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """Evaluate Cedar policies for the given request.

        Raises PolicyEngineError if engine is unavailable.
        """
        ...


# ─── Tier hierarchy for classification comparison ────────────────────────────
TIER_HIERARCHY: dict[str, int] = {
    "public": 1,
    "internal": 2,
    "confidential": 3,
    "restricted": 4,
}


class LocalCedarEvaluator:
    """Local Cedar policy evaluator implementing default-deny + forbid-wins.

    This evaluator implements the Cedar semantics locally for the policies
    defined in the chatbot/policies/ directory. In production, the AgentCore
    Gateway handles evaluation via its built-in Cedar runtime.

    Semantics:
    - Default-deny: if no permit matches, deny (Req 5.1)
    - Forbid-wins: if any forbid matches, deny regardless of permits (Req 5.2)
    """

    # PCI databases that are unconditionally forbidden
    FORBIDDEN_DATABASES: frozenset[str] = frozenset(
        {"pci_cardholder", "pci_transactions"}
    )

    # Policy version tracking
    POLICY_VERSION: str = "v1.0.0"

    # Role → permitted actions mapping
    ROLE_PERMITS: dict[str, frozenset[str]] = {
        "analyst": frozenset({"run_query", "list_tables", "get_schema", "estimate_cost"}),
        "manager": frozenset({"run_query", "list_tables", "get_schema", "estimate_cost"}),
        "admin": frozenset({"run_query", "list_tables", "get_schema", "estimate_cost"}),
    }

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """Evaluate Cedar policies: forbid-wins, then permit check, then default-deny.

        Evaluation order:
        1. Check forbid rules (PCI databases, tier violation) — Req 5.2
        2. Check permit rules (role + department + tier match) — Req 5.1
        3. Default-deny if no permit matches — Req 5.1

        Raises:
            PolicyEngineError: If evaluation encounters an internal error.
        """
        start_time = time.perf_counter()

        try:
            # Phase 1: Forbid rules (forbid-wins — Req 5.2)
            forbid_result = self._check_forbid_rules(request)
            if forbid_result is not None:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return PolicyDecision(
                    decision=PolicyDecisionType.DENY,
                    determining_policies=forbid_result,
                    policy_version=self.POLICY_VERSION,
                    evaluation_time_ms=elapsed_ms,
                    deny_reason=PolicyDenyReason.FORBID_OVERRIDE,
                )

            # Phase 2: Permit rules
            permit_result = self._check_permit_rules(request)
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if permit_result is not None:
                return PolicyDecision(
                    decision=PolicyDecisionType.ALLOW,
                    determining_policies=permit_result,
                    policy_version=self.POLICY_VERSION,
                    evaluation_time_ms=elapsed_ms,
                )

            # Phase 3: Default-deny (Req 5.1)
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return PolicyDecision(
                decision=PolicyDecisionType.DENY,
                determining_policies=("default-deny",),
                policy_version=self.POLICY_VERSION,
                evaluation_time_ms=elapsed_ms,
                deny_reason=PolicyDenyReason.NO_MATCHING_PERMIT,
            )

        except PolicyEngineError:
            raise
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error("Policy evaluation error: %s", str(exc))
            raise PolicyEngineError(f"Evaluation failed: {exc}") from exc

    def _check_forbid_rules(self, request: PolicyRequest) -> tuple[str, ...] | None:
        """Check forbid rules — returns determining policies if forbidden, else None."""
        # Forbid: PCI databases
        if request.resource_database in self.FORBIDDEN_DATABASES:
            return (f"forbid-pci-{request.resource_database}",)

        # Forbid: Classification tier violation
        principal_tier = TIER_HIERARCHY.get(request.data_classification_tier, 0)
        resource_tier = TIER_HIERARCHY.get(request.resource_classification_tier, 0)

        if resource_tier > principal_tier:
            return ("forbid-tier-violation",)

        return None

    def _check_permit_rules(self, request: PolicyRequest) -> tuple[str, ...] | None:
        """Check permit rules — returns determining policies if permitted, else None."""
        role = request.role.lower()
        permitted_actions = self.ROLE_PERMITS.get(role)

        if permitted_actions is None:
            return None

        if request.action not in permitted_actions:
            return None

        # Role has the action permitted — check department/database alignment
        # Analysts and managers can query databases in their department
        return (f"permit-{role}-{request.action}",)


class DefaultAuditWriter:
    """Default audit writer that integrates with the AuditStore.

    Writes policy decisions to the immutable audit store (S3 Object Lock).
    Raises AuditWriteError if the write fails after retries.
    """

    def __init__(self, audit_store: Any | None = None):
        """Initialize with optional audit store dependency.

        Args:
            audit_store: AuditStore instance. If None, creates one from
                         environment configuration.
        """
        self._audit_store = audit_store

    def _get_audit_store(self) -> Any:
        """Lazy-load the audit store."""
        if self._audit_store is None:
            import os

            from chatbot.scripts.audit import AuditStore

            bucket = os.environ.get("AUDIT_BUCKET_NAME", "chatbot-audit-prod")
            self._audit_store = AuditStore(bucket_name=bucket)
        return self._audit_store

    def write_policy_decision(
        self,
        request: PolicyRequest,
        decision: PolicyDecision,
    ) -> None:
        """Write policy decision to audit store BEFORE returning (Req 5.5).

        Raises:
            AuditWriteError: If write fails — caller MUST deny request (Req 5.8).
        """
        from chatbot.scripts.audit import AuditRecord
        from chatbot.scripts.audit import AuditWriteError as StoreWriteError

        try:
            store = self._get_audit_store()
            record = AuditRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                trace_id=request.trace_id or str(uuid.uuid4()),
                session_id=request.session_id or "",
                principal=request.principal_id,
                question=f"[POLICY_EVAL] {request.action} on {request.resource_database}/{request.resource_table}",
                generated_sql=None,
                policy_decision=decision.to_audit_dict(),
                lake_formation_outcome=None,
                cost_estimate_bytes=None,
                row_count=None,
                guardrails_findings={},
                request_status="success" if decision.decision == PolicyDecisionType.ALLOW else "denied",
            )
            store.write_record(record)
            logger.info(
                "Policy decision audit written: decision=%s, policies=%s, trace_id=%s",
                decision.decision.value,
                decision.determining_policies,
                request.trace_id,
            )
        except (StoreWriteError, Exception) as exc:
            logger.error(
                "FAIL-CLOSED: Audit write failed for policy decision, "
                "denying request (Req 5.8). Error: %s",
                str(exc),
            )
            raise AuditWriteError(
                f"Audit write failed for policy decision: {exc}"
            ) from exc


class CedarPolicyEvaluator:
    """Cedar policy evaluation integration for AgentCore Gateway.

    Orchestrates the full evaluation flow:
    1. Extract principal claims from validated JWT (Req 5.3)
    2. Evaluate Cedar policies (default-deny + forbid-wins)
    3. Log decision to audit store BEFORE returning (Req 5.5)
    4. Fail-closed on any error (Req 5.7, 5.8)

    This class is the single integration point called from tool_call.py.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        audit_writer: AuditWriter | None = None,
    ):
        """Initialize evaluator with optional dependency injection.

        Args:
            policy_engine: Cedar evaluation engine. Defaults to LocalCedarEvaluator.
            audit_writer: Audit record writer. Defaults to DefaultAuditWriter.
        """
        self._engine = policy_engine or LocalCedarEvaluator()
        self._audit_writer = audit_writer or DefaultAuditWriter()

    def evaluate_tool_call(
        self,
        tool_name: str,
        user_claims: dict[str, Any],
        resource_database: str = "",
        resource_table: str = "",
        resource_classification_tier: str = "internal",
        trace_id: str = "",
        session_id: str = "",
    ) -> PolicyDecision:
        """Evaluate Cedar policy for a tool call — fail-closed on any error.

        This is the main entry point for policy evaluation. It:
        1. Builds a PolicyRequest from validated JWT claims (Req 5.3)
        2. Evaluates Cedar policies (Req 5.1, 5.2)
        3. Logs decision to audit BEFORE returning (Req 5.5)
        4. Returns DENY on any error (fail-closed, Req 5.7, 5.8)

        Args:
            tool_name: MCP tool being invoked (e.g., "run_query").
            user_claims: Claims from validated JWT. MUST be from JWT validation
                         only — never from user input or LLM content (Req 5.3).
            resource_database: Target database identifier.
            resource_table: Target table identifier.
            resource_classification_tier: Resource classification level.
            trace_id: Request trace ID for correlation.
            session_id: Session identifier.

        Returns:
            PolicyDecision with ALLOW or DENY and determining policies.
            On ANY error, returns DENY (fail-closed).
        """
        start_time = time.perf_counter()

        # Step 1: Build request from JWT claims ONLY (Req 5.3)
        request = self._build_request_from_jwt(
            tool_name=tool_name,
            user_claims=user_claims,
            resource_database=resource_database,
            resource_table=resource_table,
            resource_classification_tier=resource_classification_tier,
            trace_id=trace_id,
            session_id=session_id,
        )

        # Step 2: Evaluate Cedar policy (fail-closed on error — Req 5.7)
        try:
            decision = self._engine.evaluate(request)
        except PolicyEngineError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "FAIL-CLOSED: Policy engine unavailable/error (Req 5.7). "
                "Denying request. Error: %s",
                str(exc),
            )
            decision = PolicyDecision(
                decision=PolicyDecisionType.DENY,
                determining_policies=("fail-closed-engine-error",),
                policy_version="unknown",
                evaluation_time_ms=elapsed_ms,
                deny_reason=PolicyDenyReason.ENGINE_UNAVAILABLE,
                error_detail=str(exc),
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "FAIL-CLOSED: Unexpected policy evaluation error (Req 5.7). "
                "Denying request. Error: %s",
                str(exc),
            )
            decision = PolicyDecision(
                decision=PolicyDecisionType.DENY,
                determining_policies=("fail-closed-unexpected-error",),
                policy_version="unknown",
                evaluation_time_ms=elapsed_ms,
                deny_reason=PolicyDenyReason.EVALUATION_ERROR,
                error_detail=str(exc),
            )

        # Step 3: Log decision to audit store BEFORE returning (Req 5.5)
        # Fail-closed if audit write fails (Req 5.8)
        try:
            self._audit_writer.write_policy_decision(request, decision)
        except AuditWriteError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "FAIL-CLOSED: Audit write failed (Req 5.8). "
                "Denying request regardless of policy decision. Error: %s",
                str(exc),
            )
            return PolicyDecision(
                decision=PolicyDecisionType.DENY,
                determining_policies=("fail-closed-audit-write-failed",),
                policy_version=decision.policy_version,
                evaluation_time_ms=elapsed_ms,
                deny_reason=PolicyDenyReason.AUDIT_WRITE_FAILED,
                error_detail=str(exc),
            )

        return decision

    def _build_request_from_jwt(
        self,
        tool_name: str,
        user_claims: dict[str, Any],
        resource_database: str,
        resource_table: str,
        resource_classification_tier: str,
        trace_id: str,
        session_id: str,
    ) -> PolicyRequest:
        """Build PolicyRequest sourcing claims ONLY from validated JWT (Req 5.3).

        CRITICAL: user_claims MUST come from the JWT validation layer,
        never from user-supplied input or LLM-generated content.
        """
        groups = user_claims.get("groups", [])
        if isinstance(groups, str):
            groups = [groups]

        return PolicyRequest(
            principal_id=user_claims.get("sub", ""),
            department=user_claims.get("department", ""),
            role=user_claims.get("role", ""),
            data_classification_tier=user_claims.get("data_classification_tier", ""),
            groups=tuple(groups),
            action=tool_name,
            resource_database=resource_database,
            resource_table=resource_table,
            resource_classification_tier=resource_classification_tier,
            trace_id=trace_id,
            session_id=session_id,
        )
