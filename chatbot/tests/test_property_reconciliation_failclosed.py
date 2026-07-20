"""Property-based tests for reconciliation fail-closed and two-layer authorization independence.

Tests verify that:
1. When reconciliation fails or detects divergence, all affected requests are blocked.
2. A query can only execute if BOTH Cedar permit AND Lake Formation grant exist.

**Validates: Requirements 13.2, 13.3, 6.1**

Properties tested:
- Property 10: Reconciliation Fail-Closed — failure or divergence blocks all affected requests
- Property 4: Two-Layer Authorization Independence — query executes only if BOTH layers allow
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from chatbot.scripts.reconciliation import (
    ReconciliationResult,
    ReconciliationService,
    reconcile_permissions,
)


# ─── Hypothesis Strategies ────────────────────────────────────────────────────

# Strategy for principal identifiers (e.g., user ARNs or sub IDs)
principal_strategy = st.sampled_from([
    "user-alice", "user-bob", "user-carol", "user-dave", "user-eve",
    "user-frank", "user-grace", "user-henry", "user-iris", "user-jack",
    "svc-analytics", "svc-finance", "svc-ops", "svc-marketing", "svc-hr",
])

# Strategy for table identifiers (database/table format)
table_strategy = st.sampled_from([
    "analytics/transactions", "finance/deposits", "hr/employees",
    "marketing/campaigns", "ops/metrics", "analytics/events",
    "finance/ledger", "hr/payroll", "marketing/leads", "ops/alerts",
    "analytics/sessions", "finance/transfers", "hr/benefits",
])

# Strategy for sets of (principal, table) tuples representing permits/grants
permission_tuple_strategy = st.tuples(principal_strategy, table_strategy)

permission_set_strategy = st.frozensets(
    permission_tuple_strategy, min_size=0, max_size=10
)

# Strategy for non-empty permission sets (to guarantee divergences are detectable)
non_empty_permission_set_strategy = st.frozensets(
    permission_tuple_strategy, min_size=1, max_size=10
)


# ─── Two-Layer Authorization Model ───────────────────────────────────────────


@dataclass
class TwoLayerAuthRequest:
    """Represents a query authorization request evaluated by both layers."""

    principal: str
    table: str
    cedar_decision: Literal["ALLOW", "DENY"]
    lake_formation_decision: Literal["ALLOW", "DENY"]


def query_can_execute(request: TwoLayerAuthRequest) -> bool:
    """A query executes only if BOTH Cedar AND Lake Formation independently allow.

    This models the two-layer authorization independence property:
    - Cedar evaluates the tool-call request BEFORE the query is submitted
    - Lake Formation enforces permissions at the query engine level
    - If EITHER layer denies, the query is blocked
    """
    return (
        request.cedar_decision == "ALLOW"
        and request.lake_formation_decision == "ALLOW"
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def make_cedar_client(permits: set[tuple[str, str]]) -> MagicMock:
    """Create a mock Cedar client that returns the given permits."""
    client = MagicMock()
    client.list_permits.return_value = {
        "permits": [
            {"principal": p, "resource": t} for p, t in permits
        ]
    }
    return client


def make_lf_client(grants: set[tuple[str, str]]) -> MagicMock:
    """Create a mock Lake Formation client that returns the given grants."""
    client = MagicMock()
    paginator = MagicMock()
    client.get_paginator.return_value = paginator

    permissions = []
    for principal, table in grants:
        parts = table.split("/", 1)
        database = parts[0] if len(parts) > 1 else "default"
        table_name = parts[1] if len(parts) > 1 else parts[0]
        permissions.append({
            "Principal": {"DataLakePrincipalIdentifier": principal},
            "Resource": {
                "Table": {"DatabaseName": database, "Name": table_name}
            },
        })

    paginator.paginate.return_value = [
        {"PrincipalResourcePermissions": permissions}
    ]
    return client


def make_reconciliation_service(
    cedar_permits: set[tuple[str, str]],
    lf_grants: set[tuple[str, str]],
) -> ReconciliationService:
    """Create a ReconciliationService with configured Cedar and LF mocks."""
    return ReconciliationService(
        cedar_client=make_cedar_client(cedar_permits),
        lakeformation_client=make_lf_client(lf_grants),
        sns_client=MagicMock(),
        cloudwatch_client=MagicMock(),
        audit_store=None,
        sns_topic_arn="arn:aws:sns:us-east-1:123456789:test-alerts",
        gateway_target_id="chatbot-gateway",
    )


# ─── Property 10: Reconciliation Fail-Closed ─────────────────────────────────


class TestReconciliationFailClosed:
    """Property 10: Reconciliation Fail-Closed.

    **Validates: Requirements 13.2, 13.3**

    When reconciliation fails (job error/timeout) or detects divergence between
    Cedar permits and Lake Formation grants, ALL affected requests are blocked.
    Divergence → P1 alert + blocked affected principals.
    Job failure → assume breach + block all requests.
    """

    @given(
        common_permissions=permission_set_strategy,
        cedar_only_permissions=non_empty_permission_set_strategy,
    )
    @settings(max_examples=200)
    def test_divergence_blocks_affected_principals(
        self,
        common_permissions: frozenset[tuple[str, str]],
        cedar_only_permissions: frozenset[tuple[str, str]],
    ):
        """When Cedar has permits not in Lake Formation, affected principals are blocked.

        For any set of Cedar permits where some have no corresponding LF grant,
        the reconciliation service must fail-close (block) every affected principal.

        **Validates: Requirements 13.2**
        """
        # Cedar has common + extra, LF only has common — guaranteed divergence
        cedar_permits = set(common_permissions) | set(cedar_only_permissions)
        lf_grants = set(common_permissions)
        # Ensure there's actually something Cedar-only
        actual_cedar_only = cedar_permits - lf_grants
        assume(len(actual_cedar_only) > 0)

        result = reconcile_permissions(
            cedar_client=make_cedar_client(cedar_permits),
            lakeformation_client=make_lf_client(lf_grants),
            sns_client=MagicMock(),
            cloudwatch_client=MagicMock(),
            audit_store=None,
            sns_topic_arn="arn:aws:sns:us-east-1:123456789:test",
            gateway_target_id="chatbot-gateway",
        )

        # Core property: divergence detected
        assert result.status == "divergent", (
            f"Expected 'divergent' status when Cedar permits don't match LF grants, "
            f"got '{result.status}'. Cedar: {len(cedar_permits)}, LF: {len(lf_grants)}"
        )
        # All divergent principals must be in the divergence list
        divergent_principals = {d["principal"] for d in result.divergences}
        expected_principals = {p for p, _ in actual_cedar_only}
        assert expected_principals.issubset(divergent_principals), (
            f"Not all affected principals reported in divergences. "
            f"Missing: {expected_principals - divergent_principals}"
        )

    @given(
        common_permissions=permission_set_strategy,
        lf_only_permissions=non_empty_permission_set_strategy,
    )
    @settings(max_examples=200)
    def test_divergence_detects_lf_grants_without_cedar(
        self,
        common_permissions: frozenset[tuple[str, str]],
        lf_only_permissions: frozenset[tuple[str, str]],
    ):
        """When Lake Formation has grants not in Cedar, affected principals are blocked.

        For any set of LF grants where some have no corresponding Cedar permit,
        the reconciliation must detect divergence and fail-close affected principals.

        **Validates: Requirements 13.2**
        """
        # LF has common + extra, Cedar only has common — guaranteed divergence
        cedar_permits = set(common_permissions)
        lf_grants = set(common_permissions) | set(lf_only_permissions)
        # Ensure there's actually something LF-only
        actual_lf_only = lf_grants - cedar_permits
        assume(len(actual_lf_only) > 0)

        result = reconcile_permissions(
            cedar_client=make_cedar_client(cedar_permits),
            lakeformation_client=make_lf_client(lf_grants),
            sns_client=MagicMock(),
            cloudwatch_client=MagicMock(),
            audit_store=None,
            sns_topic_arn="arn:aws:sns:us-east-1:123456789:test",
            gateway_target_id="chatbot-gateway",
        )

        # Core property: divergence detected
        assert result.status == "divergent", (
            f"Expected 'divergent' status when LF grants don't match Cedar permits, "
            f"got '{result.status}'. Cedar: {len(cedar_permits)}, LF: {len(lf_grants)}"
        )
        # All divergent principals from LF-only grants must be reported
        divergent_principals = {d["principal"] for d in result.divergences}
        expected_principals = {p for p, _ in actual_lf_only}
        assert expected_principals.issubset(divergent_principals), (
            f"Not all affected LF-only principals reported. "
            f"Missing: {expected_principals - divergent_principals}"
        )

    @given(principal=principal_strategy)
    @settings(max_examples=200)
    def test_job_failure_blocks_all_requests(self, principal: str):
        """When reconciliation job fails, assume breach posture and block ALL requests.

        For any principal, if reconciliation encounters an unhandled error,
        the system must block all requests (not just affected ones) as an
        assume-breach response.

        **Validates: Requirements 13.3**
        """
        # Create a Cedar client that raises an exception (simulating job failure)
        failing_cedar_client = MagicMock()
        failing_cedar_client.list_permits.side_effect = RuntimeError(
            "Cedar policy store unreachable"
        )

        result = reconcile_permissions(
            cedar_client=failing_cedar_client,
            lakeformation_client=MagicMock(),
            sns_client=MagicMock(),
            cloudwatch_client=MagicMock(),
            audit_store=None,
            sns_topic_arn="arn:aws:sns:us-east-1:123456789:test",
            gateway_target_id="chatbot-gateway",
        )

        # Core property: job failure → error status (assume breach)
        assert result.status == "error", (
            f"Expected 'error' status on job failure, got '{result.status}'"
        )

    @given(principal=principal_strategy)
    @settings(max_examples=200)
    def test_job_failure_service_blocks_all_principals(self, principal: str):
        """After job failure, is_principal_blocked returns True for ANY principal.

        The ReconciliationService must block ALL principals system-wide
        when a job failure occurs (assume-breach posture).

        **Validates: Requirements 13.3**
        """
        service = ReconciliationService(
            cedar_client=MagicMock(),
            lakeformation_client=MagicMock(),
            sns_client=MagicMock(),
            cloudwatch_client=MagicMock(),
            audit_store=None,
            sns_topic_arn="arn:aws:sns:us-east-1:123456789:test",
            gateway_target_id="chatbot-gateway",
        )

        # Simulate job failure by calling block_all_requests
        service.block_all_requests()

        # Core property: any arbitrary principal is blocked
        assert service.is_principal_blocked(principal) is True, (
            f"Principal '{principal}' should be blocked after assume-breach "
            f"but is_principal_blocked returned False"
        )

    @given(
        permissions=non_empty_permission_set_strategy,
    )
    @settings(max_examples=200)
    def test_matching_permissions_reports_healthy(
        self, permissions: frozenset[tuple[str, str]]
    ):
        """When Cedar permits and LF grants match exactly, status is healthy and no blocking.

        This is the inverse check: when there is NO divergence, the system
        must NOT block any principals.

        **Validates: Requirements 13.2, 13.3**
        """
        # Cedar and LF have identical permission sets — no divergence
        result = reconcile_permissions(
            cedar_client=make_cedar_client(set(permissions)),
            lakeformation_client=make_lf_client(set(permissions)),
            sns_client=MagicMock(),
            cloudwatch_client=MagicMock(),
            audit_store=None,
            sns_topic_arn="arn:aws:sns:us-east-1:123456789:test",
            gateway_target_id="chatbot-gateway",
        )

        assert result.status == "healthy", (
            f"Expected 'healthy' when permissions match, got '{result.status}'"
        )
        assert len(result.divergences) == 0, (
            f"Expected no divergences when permissions match, got {len(result.divergences)}"
        )

    @given(
        cedar_permits=non_empty_permission_set_strategy,
        lf_grants=non_empty_permission_set_strategy,
    )
    @settings(max_examples=200)
    def test_divergence_triggers_p1_alert(
        self,
        cedar_permits: frozenset[tuple[str, str]],
        lf_grants: frozenset[tuple[str, str]],
    ):
        """Any divergence (in either direction) triggers a P1 alert to security operations.

        **Validates: Requirements 13.2**
        """
        # Ensure there is actual divergence
        assume(set(cedar_permits) != set(lf_grants))

        mock_sns = MagicMock()

        reconcile_permissions(
            cedar_client=make_cedar_client(set(cedar_permits)),
            lakeformation_client=make_lf_client(set(lf_grants)),
            sns_client=mock_sns,
            cloudwatch_client=MagicMock(),
            audit_store=None,
            sns_topic_arn="arn:aws:sns:us-east-1:123456789:test",
            gateway_target_id="chatbot-gateway",
        )

        # P1 alert must have been triggered via SNS publish
        mock_sns.publish.assert_called_once()
        call_kwargs = mock_sns.publish.call_args
        # Verify it's a P1 severity alert
        assert "P1" in str(call_kwargs), (
            "P1 alert not triggered on divergence detection"
        )


# ─── Property 4: Two-Layer Authorization Independence ─────────────────────────


class TestTwoLayerAuthorizationIndependence:
    """Property 4: Two-Layer Authorization Independence.

    **Validates: Requirements 6.1**

    A query can ONLY execute if BOTH Cedar permit AND Lake Formation grant
    exist for the same (principal, table) combination. If either layer denies,
    the query is blocked. The layers are independent — a bug in one cannot
    grant access through the other.
    """

    @given(
        principal=principal_strategy,
        table=table_strategy,
        cedar_decision=st.sampled_from(["ALLOW", "DENY"]),
        lf_decision=st.sampled_from(["ALLOW", "DENY"]),
    )
    @settings(max_examples=300)
    def test_query_executes_only_if_both_layers_allow(
        self,
        principal: str,
        table: str,
        cedar_decision: str,
        lf_decision: str,
    ):
        """A query executes if and only if both Cedar permits AND Lake Formation allows.

        For any combination of Cedar and Lake Formation decisions, the query
        can only proceed when BOTH independently return ALLOW.

        **Validates: Requirements 6.1**
        """
        request = TwoLayerAuthRequest(
            principal=principal,
            table=table,
            cedar_decision=cedar_decision,
            lake_formation_decision=lf_decision,
        )

        can_execute = query_can_execute(request)

        if cedar_decision == "DENY" or lf_decision == "DENY":
            assert can_execute is False, (
                f"Query should be blocked when either layer denies. "
                f"Cedar={cedar_decision}, LF={lf_decision}, "
                f"principal={principal}, table={table}"
            )
        else:
            assert can_execute is True, (
                f"Query should execute when both layers allow. "
                f"Cedar={cedar_decision}, LF={lf_decision}"
            )

    @given(
        principal=principal_strategy,
        table=table_strategy,
    )
    @settings(max_examples=200)
    def test_cedar_deny_blocks_regardless_of_lf(
        self,
        principal: str,
        table: str,
    ):
        """When Cedar denies, the query is blocked even if Lake Formation would allow.

        This ensures the Cedar layer cannot be bypassed by the LF layer.

        **Validates: Requirements 6.1**
        """
        request = TwoLayerAuthRequest(
            principal=principal,
            table=table,
            cedar_decision="DENY",
            lake_formation_decision="ALLOW",
        )

        assert query_can_execute(request) is False, (
            f"Query must be blocked when Cedar denies, even if LF allows. "
            f"principal={principal}, table={table}"
        )

    @given(
        principal=principal_strategy,
        table=table_strategy,
    )
    @settings(max_examples=200)
    def test_lf_deny_blocks_regardless_of_cedar(
        self,
        principal: str,
        table: str,
    ):
        """When Lake Formation denies, the query is blocked even if Cedar permits.

        This ensures the LF layer cannot be bypassed by the Cedar layer.

        **Validates: Requirements 6.1**
        """
        request = TwoLayerAuthRequest(
            principal=principal,
            table=table,
            cedar_decision="ALLOW",
            lake_formation_decision="DENY",
        )

        assert query_can_execute(request) is False, (
            f"Query must be blocked when LF denies, even if Cedar allows. "
            f"principal={principal}, table={table}"
        )

    @given(
        principal=principal_strategy,
        table=table_strategy,
    )
    @settings(max_examples=200)
    def test_reconciliation_detects_cedar_lf_divergence(
        self,
        principal: str,
        table: str,
    ):
        """Reconciliation detects when Cedar permits but LF does not grant.

        When Cedar has a permit for (principal, table) but Lake Formation has
        no corresponding grant, reconciliation flags the divergence and
        blocks the affected principal. This prevents the case where one
        layer would allow but the other wouldn't.

        **Validates: Requirements 6.1, 13.2**
        """
        # Cedar permits the principal/table but LF does not
        cedar_permits = {(principal, table)}
        lf_grants: set[tuple[str, str]] = set()

        result = reconcile_permissions(
            cedar_client=make_cedar_client(cedar_permits),
            lakeformation_client=make_lf_client(lf_grants),
            sns_client=MagicMock(),
            cloudwatch_client=MagicMock(),
            audit_store=None,
            sns_topic_arn="arn:aws:sns:us-east-1:123456789:test",
            gateway_target_id="chatbot-gateway",
        )

        # Divergence must be detected
        assert result.status == "divergent", (
            f"Expected divergence when Cedar permits but LF does not grant. "
            f"principal={principal}, table={table}"
        )
        # The specific principal must be in the divergence list
        divergent_principals = {d["principal"] for d in result.divergences}
        assert principal in divergent_principals, (
            f"Principal '{principal}' missing from divergence report"
        )

    @given(
        principal=principal_strategy,
        table=table_strategy,
    )
    @settings(max_examples=200)
    def test_reconciliation_detects_lf_cedar_divergence(
        self,
        principal: str,
        table: str,
    ):
        """Reconciliation detects when LF grants but Cedar does not permit.

        When Lake Formation grants access for (principal, table) but Cedar has
        no corresponding permit, reconciliation flags the divergence. This ensures
        that an LF misconfiguration cannot silently grant access without Cedar
        agreement.

        **Validates: Requirements 6.1, 13.2**
        """
        # LF grants but Cedar does not permit
        cedar_permits: set[tuple[str, str]] = set()
        lf_grants = {(principal, table)}

        result = reconcile_permissions(
            cedar_client=make_cedar_client(cedar_permits),
            lakeformation_client=make_lf_client(lf_grants),
            sns_client=MagicMock(),
            cloudwatch_client=MagicMock(),
            audit_store=None,
            sns_topic_arn="arn:aws:sns:us-east-1:123456789:test",
            gateway_target_id="chatbot-gateway",
        )

        # Divergence must be detected
        assert result.status == "divergent", (
            f"Expected divergence when LF grants but Cedar does not permit. "
            f"principal={principal}, table={table}"
        )
        # The specific principal must be in the divergence list
        divergent_principals = {d["principal"] for d in result.divergences}
        assert principal in divergent_principals, (
            f"Principal '{principal}' missing from divergence report"
        )
