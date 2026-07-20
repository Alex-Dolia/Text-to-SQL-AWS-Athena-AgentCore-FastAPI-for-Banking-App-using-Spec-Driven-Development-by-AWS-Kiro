"""Integration tests for Cedar policy evaluation wiring in tool_call node.

Task 16.2: Implement Cedar policy evaluation integration
- Wire AgentCore Gateway policy evaluation for all tool calls
- Source principal claims exclusively from validated JWT (never user input or LLM content)
- Log decision (permit/deny), policy ID, version to audit store before returning
- Fail-closed on policy engine unavailable or evaluation error
- Fail-closed if audit write fails (deny in-flight request)

Requirements: 5.1, 5.2, 5.3, 5.5, 5.6, 5.7, 5.8
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from chatbot.agent.nodes.tool_call import (
    _extract_resource_from_sql,
    get_policy_evaluator,
    set_policy_evaluator,
    tool_call,
)
from chatbot.policies.evaluator import (
    AuditWriteError,
    AuditWriter,
    CedarPolicyEvaluator,
    DefaultAuditWriter,
    LocalCedarEvaluator,
    PolicyDecision,
    PolicyDecisionType,
    PolicyDenyReason,
    PolicyEngine,
    PolicyEngineError,
    PolicyRequest,
)


# ─── Test Helpers ─────────────────────────────────────────────────────────────


def _analyst_claims() -> dict:
    """Return valid analyst JWT claims."""
    return {
        "sub": "user-analyst-001",
        "department": "analytics",
        "role": "analyst",
        "data_classification_tier": "confidential",
        "groups": ["data-users", "elevated_cost"],
    }


def _viewer_claims() -> dict:
    """Return viewer claims (no permit exists for viewer role)."""
    return {
        "sub": "user-viewer-001",
        "department": "marketing",
        "role": "viewer",
        "data_classification_tier": "internal",
        "groups": ["basic-users"],
    }


def _make_state(
    sql: str = "SELECT * FROM analytics_db.events LIMIT 10",
    user_claims: dict | None = None,
    sql_valid: bool = True,
    trace_id: str = "trace-001",
    session_id: str = "session-001",
) -> dict:
    """Create a minimal tool_call state."""
    return {
        "generated_sql": sql,
        "user_claims": user_claims or _analyst_claims(),
        "sql_valid": sql_valid,
        "trace_id": trace_id,
        "session_id": session_id,
    }


class MockAuditWriter:
    """In-memory audit writer for testing — records all writes."""

    def __init__(self, *, should_fail: bool = False):
        self.records: list[tuple[PolicyRequest, PolicyDecision]] = []
        self._should_fail = should_fail

    def write_policy_decision(
        self, request: PolicyRequest, decision: PolicyDecision
    ) -> None:
        if self._should_fail:
            raise AuditWriteError("Simulated audit write failure")
        self.records.append((request, decision))


class FailingPolicyEngine:
    """Policy engine that always raises errors — for fail-closed testing."""

    def __init__(self, error_type: str = "unavailable"):
        self._error_type = error_type

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        if self._error_type == "unavailable":
            raise PolicyEngineError("Cedar policy engine unavailable")
        raise RuntimeError("Unexpected internal error")


class TimingPolicyEngine:
    """Policy engine that tracks evaluation time — for P99 budget testing."""

    def __init__(self):
        self.evaluation_times: list[float] = []
        self._engine = LocalCedarEvaluator()

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        start = time.perf_counter()
        result = self._engine.evaluate(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        self.evaluation_times.append(elapsed_ms)
        return result


# ─── Fixture to reset evaluator singleton ─────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_evaluator():
    """Reset the module-level evaluator singleton after each test."""
    yield
    set_policy_evaluator(None)  # type: ignore


# ===========================================================================
# Section 1: Default-Deny (Req 5.1)
# ===========================================================================


class TestDefaultDeny:
    """Verify default-deny: no access without explicit Cedar permit."""

    def test_viewer_role_denied_no_matching_permit(self):
        """Viewer role has no permits — default-deny applies (Req 5.1)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )
        set_policy_evaluator(evaluator)

        state = _make_state(user_claims=_viewer_claims())
        result = tool_call(state)

        assert result["query_results"] is None
        assert "Authorization denied" in result["sql_error"]
        decision = result["policy_decision"]
        assert decision["decision"] == "DENY"
        assert decision["deny_reason"] == PolicyDenyReason.NO_MATCHING_PERMIT.value

    def test_unknown_action_denied(self):
        """An action not in the role's permit set is denied (Req 5.1)."""
        audit = MockAuditWriter()
        engine = LocalCedarEvaluator()
        evaluator = CedarPolicyEvaluator(
            policy_engine=engine,
            audit_writer=audit,
        )

        # Evaluate directly with an action that has no permit
        decision = evaluator.evaluate_tool_call(
            tool_name="delete_table",
            user_claims=_analyst_claims(),
            resource_database="analytics_db",
            resource_table="events",
            trace_id="trace-002",
        )

        assert decision.decision == PolicyDecisionType.DENY
        assert decision.deny_reason == PolicyDenyReason.NO_MATCHING_PERMIT

    def test_tool_call_returns_deny_without_executing_query(self):
        """When Cedar denies, no gateway call is made (Req 5.1, 6.3)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )
        set_policy_evaluator(evaluator)

        state = _make_state(user_claims=_viewer_claims())

        with patch("chatbot.agent.nodes.tool_call._invoke_gateway_tool") as mock_gw:
            result = tool_call(state)

        # Gateway should NOT be called
        mock_gw.assert_not_called()
        assert result["query_results"] is None
        assert "lake_formation_outcome" in result
        assert result["lake_formation_outcome"] is None  # LF not consulted


# ===========================================================================
# Section 2: Forbid-Wins (Req 5.2)
# ===========================================================================


class TestForbidWins:
    """Verify forbid-wins: forbid overrides any permit."""

    def test_pci_database_forbidden_even_for_analyst(self):
        """PCI databases forbidden regardless of role permits (Req 5.2)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )
        set_policy_evaluator(evaluator)

        claims = _analyst_claims()
        state = _make_state(
            sql="SELECT * FROM pci_cardholder.transactions LIMIT 10",
            user_claims=claims,
        )

        result = tool_call(state)

        assert result["query_results"] is None
        decision = result["policy_decision"]
        assert decision["decision"] == "DENY"
        assert decision["deny_reason"] == PolicyDenyReason.FORBID_OVERRIDE.value
        assert any("forbid-pci" in p for p in decision["determining_policies"])

    def test_tier_violation_forbidden(self):
        """Resource tier higher than principal tier is forbidden (Req 5.2)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )

        # Internal-tier user accessing restricted resource
        claims = {
            "sub": "user-001",
            "department": "analytics",
            "role": "analyst",
            "data_classification_tier": "internal",
            "groups": [],
        }

        decision = evaluator.evaluate_tool_call(
            tool_name="run_query",
            user_claims=claims,
            resource_database="analytics_db",
            resource_table="sensitive",
            resource_classification_tier="restricted",
            trace_id="trace-003",
        )

        assert decision.decision == PolicyDecisionType.DENY
        assert decision.deny_reason == PolicyDenyReason.FORBID_OVERRIDE
        assert "forbid-tier-violation" in decision.determining_policies


# ===========================================================================
# Section 3: Claims from JWT Only (Req 5.3)
# ===========================================================================


class TestClaimsFromJWTOnly:
    """Verify principal claims sourced exclusively from validated JWT."""

    def test_claims_mapped_from_jwt_fields(self):
        """PolicyRequest is built from JWT claim fields (Req 5.3)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )

        claims = {
            "sub": "user-jwt-sub-123",
            "department": "finance",
            "role": "manager",
            "data_classification_tier": "confidential",
            "groups": ["cross_department_access", "elevated_cost"],
        }

        evaluator.evaluate_tool_call(
            tool_name="run_query",
            user_claims=claims,
            resource_database="finance_db",
            resource_table="reports",
            trace_id="trace-jwt",
            session_id="session-jwt",
        )

        # Verify the audit record captured the correct principal
        assert len(audit.records) == 1
        request, _ = audit.records[0]
        assert request.principal_id == "user-jwt-sub-123"
        assert request.department == "finance"
        assert request.role == "manager"
        assert request.data_classification_tier == "confidential"
        assert set(request.groups) == {"cross_department_access", "elevated_cost"}

    def test_groups_as_string_handled(self):
        """If groups comes as a string (single group), it's converted to list."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )

        claims = {
            "sub": "user-001",
            "department": "hr",
            "role": "analyst",
            "data_classification_tier": "internal",
            "groups": "single-group",  # String instead of list
        }

        evaluator.evaluate_tool_call(
            tool_name="list_tables",
            user_claims=claims,
            resource_database="hr_db",
            resource_table="employees",
        )

        request, _ = audit.records[0]
        assert request.groups == ("single-group",)

    def test_missing_claims_result_in_empty_defaults(self):
        """Missing JWT claims result in empty strings, not errors."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )

        # Minimal claims (simulating partial JWT)
        claims = {"sub": "user-minimal"}

        decision = evaluator.evaluate_tool_call(
            tool_name="run_query",
            user_claims=claims,
            resource_database="some_db",
            resource_table="some_table",
        )

        # Should be denied (no matching role/permit) but not crash
        assert decision.decision == PolicyDecisionType.DENY
        request, _ = audit.records[0]
        assert request.department == ""
        assert request.role == ""
        assert request.groups == ()


# ===========================================================================
# Section 4: Log Decision Before Returning (Req 5.5)
# ===========================================================================


class TestAuditLogging:
    """Verify decision logged to audit store BEFORE returning."""

    def test_permit_decision_logged(self):
        """ALLOW decision is logged with policy ID and version (Req 5.5)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )

        claims = _analyst_claims()
        evaluator.evaluate_tool_call(
            tool_name="run_query",
            user_claims=claims,
            resource_database="analytics_db",
            resource_table="events",
            resource_classification_tier="internal",
            trace_id="trace-allow",
        )

        assert len(audit.records) == 1
        request, decision = audit.records[0]
        assert decision.decision == PolicyDecisionType.ALLOW
        assert decision.policy_version == "v1.0.0"
        assert len(decision.determining_policies) > 0

    def test_deny_decision_logged(self):
        """DENY decision is logged with deny reason (Req 5.5)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )

        decision = evaluator.evaluate_tool_call(
            tool_name="run_query",
            user_claims=_viewer_claims(),
            resource_database="analytics_db",
            resource_table="events",
            trace_id="trace-deny",
        )

        assert len(audit.records) == 1
        _, logged_decision = audit.records[0]
        assert logged_decision.decision == PolicyDecisionType.DENY
        assert logged_decision.deny_reason is not None

    def test_audit_contains_trace_and_session(self):
        """Audit records include trace_id and session_id for correlation."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )

        evaluator.evaluate_tool_call(
            tool_name="run_query",
            user_claims=_analyst_claims(),
            resource_database="analytics_db",
            resource_table="events",
            trace_id="trace-corr-123",
            session_id="session-corr-456",
        )

        request, _ = audit.records[0]
        assert request.trace_id == "trace-corr-123"
        assert request.session_id == "session-corr-456"

    def test_decision_to_audit_dict_format(self):
        """PolicyDecision.to_audit_dict() contains required fields."""
        decision = PolicyDecision(
            decision=PolicyDecisionType.ALLOW,
            determining_policies=("permit-analyst-run_query",),
            policy_version="v1.0.0",
            evaluation_time_ms=2.5,
            deny_reason=None,
        )

        audit_dict = decision.to_audit_dict()
        assert audit_dict["decision"] == "ALLOW"
        assert "permit-analyst-run_query" in audit_dict["determining_policies"]
        assert audit_dict["policy_version"] == "v1.0.0"
        assert audit_dict["evaluation_time_ms"] == 2.5
        assert audit_dict["deny_reason"] is None


# ===========================================================================
# Section 5: P99 Evaluation Within 30ms (Req 5.6)
# ===========================================================================


class TestEvaluationPerformance:
    """Verify evaluation completes within 30ms budget (Req 5.6)."""

    def test_evaluation_time_within_budget(self):
        """Single evaluation should complete well under 30ms."""
        timing_engine = TimingPolicyEngine()
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=timing_engine,
            audit_writer=audit,
        )

        for _ in range(100):
            evaluator.evaluate_tool_call(
                tool_name="run_query",
                user_claims=_analyst_claims(),
                resource_database="analytics_db",
                resource_table="events",
            )

        # P99 should be under 30ms (local evaluation is microsecond-level)
        sorted_times = sorted(timing_engine.evaluation_times)
        p99_index = int(len(sorted_times) * 0.99)
        p99 = sorted_times[p99_index]
        assert p99 < 30.0, f"P99 evaluation time {p99:.2f}ms exceeds 30ms budget"

    def test_evaluator_singleton_amortizes_init(self):
        """Singleton pattern avoids repeated initialization cost (Req 5.6)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )
        set_policy_evaluator(evaluator)

        eval1 = get_policy_evaluator()
        eval2 = get_policy_evaluator()
        assert eval1 is eval2  # Same instance reused


# ===========================================================================
# Section 6: Fail-Closed on Engine Error (Req 5.7)
# ===========================================================================


class TestFailClosedEngineError:
    """Verify fail-closed when policy engine is unavailable/errors."""

    def test_engine_unavailable_returns_deny(self):
        """PolicyEngineError → DENY with ENGINE_UNAVAILABLE reason (Req 5.7)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=FailingPolicyEngine("unavailable"),
            audit_writer=audit,
        )

        decision = evaluator.evaluate_tool_call(
            tool_name="run_query",
            user_claims=_analyst_claims(),
            resource_database="analytics_db",
            resource_table="events",
            trace_id="trace-fail-engine",
        )

        assert decision.decision == PolicyDecisionType.DENY
        assert decision.deny_reason == PolicyDenyReason.ENGINE_UNAVAILABLE
        assert "fail-closed-engine-error" in decision.determining_policies

    def test_unexpected_error_returns_deny(self):
        """Unexpected exception → DENY with EVALUATION_ERROR (Req 5.7)."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=FailingPolicyEngine("unexpected"),
            audit_writer=audit,
        )

        decision = evaluator.evaluate_tool_call(
            tool_name="run_query",
            user_claims=_analyst_claims(),
            resource_database="analytics_db",
            resource_table="events",
            trace_id="trace-fail-unexpected",
        )

        assert decision.decision == PolicyDecisionType.DENY
        assert decision.deny_reason == PolicyDenyReason.EVALUATION_ERROR

    def test_tool_call_node_denies_on_engine_failure(self):
        """tool_call node returns authorization error on engine failure."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=FailingPolicyEngine("unavailable"),
            audit_writer=audit,
        )
        set_policy_evaluator(evaluator)

        state = _make_state()
        result = tool_call(state)

        assert result["query_results"] is None
        assert "Authorization denied" in result["sql_error"]


# ===========================================================================
# Section 7: Fail-Closed on Audit Write Failure (Req 5.8)
# ===========================================================================


class TestFailClosedAuditFailure:
    """Verify fail-closed when audit write fails."""

    def test_audit_write_failure_returns_deny(self):
        """If audit write fails, decision is DENY regardless of policy (Req 5.8)."""
        failing_audit = MockAuditWriter(should_fail=True)
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=failing_audit,
        )

        # This request WOULD be permitted by policy, but audit fails
        decision = evaluator.evaluate_tool_call(
            tool_name="run_query",
            user_claims=_analyst_claims(),
            resource_database="analytics_db",
            resource_table="events",
            resource_classification_tier="internal",
            trace_id="trace-audit-fail",
        )

        assert decision.decision == PolicyDecisionType.DENY
        assert decision.deny_reason == PolicyDenyReason.AUDIT_WRITE_FAILED
        assert "fail-closed-audit-write-failed" in decision.determining_policies

    def test_tool_call_node_denies_on_audit_failure(self):
        """tool_call node returns deny when audit write fails (Req 5.8)."""
        failing_audit = MockAuditWriter(should_fail=True)
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=failing_audit,
        )
        set_policy_evaluator(evaluator)

        state = _make_state()
        result = tool_call(state)

        assert result["query_results"] is None
        assert "Authorization denied" in result["sql_error"]


# ===========================================================================
# Section 8: End-to-End Tool Call Flow
# ===========================================================================


class TestToolCallEndToEnd:
    """End-to-end tests for the tool_call node with Cedar evaluation."""

    def test_authorized_request_routes_through_gateway(self):
        """Permitted request reaches the Gateway for execution."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )
        set_policy_evaluator(evaluator)

        state = _make_state(
            sql="SELECT id, name FROM analytics_db.events LIMIT 10",
            user_claims=_analyst_claims(),
        )

        mock_result = {
            "columns": ["id", "name"],
            "rows": [{"id": 1, "name": "test"}],
            "row_count": 1,
            "bytes_scanned": 1024,
            "lake_formation_outcome": "allowed",
        }

        with patch(
            "chatbot.agent.nodes.tool_call._invoke_gateway_tool",
            return_value=mock_result,
        ) as mock_gw:
            result = tool_call(state)

        mock_gw.assert_called_once()
        assert result["query_results"] == mock_result
        assert result["sql_error"] is None
        assert result["policy_decision"]["decision"] == "ALLOW"

    def test_no_sql_returns_error_without_evaluation(self):
        """Missing SQL results in error without triggering policy evaluation."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )
        set_policy_evaluator(evaluator)

        state = {
            "generated_sql": None,
            "user_claims": _analyst_claims(),
            "sql_valid": True,
            "trace_id": "trace-no-sql",
            "session_id": "session-001",
        }

        result = tool_call(state)
        assert result["sql_error"] == "No validated SQL to execute"
        # No policy evaluation should have occurred
        assert len(audit.records) == 0

    def test_unvalidated_sql_returns_error(self):
        """SQL that hasn't been validated is rejected before policy eval."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )
        set_policy_evaluator(evaluator)

        state = _make_state(sql_valid=False)
        result = tool_call(state)

        assert result["sql_error"] == "SQL has not been validated"
        assert len(audit.records) == 0

    def test_gateway_failure_after_policy_allow(self):
        """If Gateway fails post-Cedar-allow, error is returned with decision."""
        audit = MockAuditWriter()
        evaluator = CedarPolicyEvaluator(
            policy_engine=LocalCedarEvaluator(),
            audit_writer=audit,
        )
        set_policy_evaluator(evaluator)

        state = _make_state(user_claims=_analyst_claims())

        with patch(
            "chatbot.agent.nodes.tool_call._invoke_gateway_tool",
            side_effect=RuntimeError("Gateway timeout"),
        ):
            result = tool_call(state)

        assert result["query_results"] is None
        assert "Gateway timeout" in result["sql_error"]
        # Policy decision should still be present (was ALLOW before gateway failed)
        assert result["policy_decision"]["decision"] == "ALLOW"


# ===========================================================================
# Section 9: SQL Resource Extraction
# ===========================================================================


class TestSqlResourceExtraction:
    """Test SQL parsing for resource identification in policy evaluation."""

    def test_simple_select_extracts_table(self):
        """Basic SELECT extracts database and table."""
        db, table = _extract_resource_from_sql("SELECT * FROM mydb.mytable")
        assert db == "mydb"
        assert table == "mytable"

    def test_select_without_database_prefix(self):
        """SELECT without db prefix returns empty database."""
        db, table = _extract_resource_from_sql("SELECT * FROM events")
        assert db == ""
        assert table == "events"

    def test_invalid_sql_returns_empty(self):
        """Unparseable SQL returns empty strings (policy will default-deny)."""
        db, table = _extract_resource_from_sql("THIS IS NOT SQL")
        assert db == ""
        assert table == ""

    def test_complex_sql_extracts_first_table(self):
        """JOIN query extracts the first table reference."""
        sql = "SELECT a.id FROM db1.table_a a JOIN db2.table_b b ON a.id = b.id"
        db, table = _extract_resource_from_sql(sql)
        assert db == "db1"
        assert table == "table_a"


# ===========================================================================
# Section 10: LocalCedarEvaluator Detailed Tests
# ===========================================================================


class TestLocalCedarEvaluator:
    """Detailed tests for the local Cedar policy evaluator logic."""

    def test_analyst_permitted_for_run_query(self):
        """Analyst role has permit for run_query action."""
        engine = LocalCedarEvaluator()
        request = PolicyRequest(
            principal_id="user-001",
            department="analytics",
            role="analyst",
            data_classification_tier="confidential",
            groups=("data-users",),
            action="run_query",
            resource_database="analytics_db",
            resource_table="events",
            resource_classification_tier="internal",
        )

        decision = engine.evaluate(request)
        assert decision.decision == PolicyDecisionType.ALLOW
        assert decision.policy_version == "v1.0.0"

    def test_unknown_role_default_deny(self):
        """Unknown role has no permits → default-deny."""
        engine = LocalCedarEvaluator()
        request = PolicyRequest(
            principal_id="user-001",
            department="analytics",
            role="intern",
            data_classification_tier="internal",
            groups=(),
            action="run_query",
            resource_database="analytics_db",
            resource_table="events",
            resource_classification_tier="internal",
        )

        decision = engine.evaluate(request)
        assert decision.decision == PolicyDecisionType.DENY
        assert decision.deny_reason == PolicyDenyReason.NO_MATCHING_PERMIT
        assert "default-deny" in decision.determining_policies

    def test_pci_database_always_forbidden(self):
        """PCI databases trigger forbid regardless of role."""
        engine = LocalCedarEvaluator()
        request = PolicyRequest(
            principal_id="user-admin",
            department="security",
            role="admin",
            data_classification_tier="restricted",
            groups=("admin-group",),
            action="run_query",
            resource_database="pci_cardholder",
            resource_table="cards",
            resource_classification_tier="restricted",
        )

        decision = engine.evaluate(request)
        assert decision.decision == PolicyDecisionType.DENY
        assert decision.deny_reason == PolicyDenyReason.FORBID_OVERRIDE

    def test_evaluation_includes_timing(self):
        """Evaluation result includes timing information."""
        engine = LocalCedarEvaluator()
        request = PolicyRequest(
            principal_id="user-001",
            department="analytics",
            role="analyst",
            data_classification_tier="internal",
            groups=(),
            action="run_query",
            resource_database="analytics_db",
            resource_table="events",
            resource_classification_tier="internal",
        )

        decision = engine.evaluate(request)
        assert decision.evaluation_time_ms >= 0
        assert decision.evaluation_time_ms < 30  # Well within budget
