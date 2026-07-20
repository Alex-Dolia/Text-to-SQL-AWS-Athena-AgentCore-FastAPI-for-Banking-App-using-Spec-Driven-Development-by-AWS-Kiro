"""Property-based tests for Cedar authorization model logic.

Tests verify the LOGIC of the authorization model (default-deny and forbid-wins
semantics) without requiring a Cedar runtime. The Cedar policy semantics are
modeled in Python based on the actual policies defined in chatbot/policies/.

**Validates: Requirements 5.1, 5.2**

Properties tested:
- Property 2: Default-Deny Authorization — no access without explicit Cedar permit
- Property 3: Forbid Always Wins — forbid overrides any permit regardless of how many permits match
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from hypothesis import given, assume, settings
from hypothesis import strategies as st

from chatbot.api.models import DataClassificationTier


# ─── Authorization Model (mirrors Cedar policy logic) ─────────────────────────

VALID_TIERS = ["public", "internal", "confidential", "restricted"]
TIER_LEVELS = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
VALID_ACTIONS = ["run_query", "list_tables", "get_schema", "estimate_cost"]
VALID_ROLES = ["analyst", "manager", "viewer", "admin", "security-operations"]
PCI_DATABASES = ["pci_cardholder", "pci_transactions"]


@dataclass
class CedarPrincipal:
    """Represents a user principal for Cedar policy evaluation."""

    entity_id: str
    role: str
    department: str
    data_classification_tier: str
    groups: list[str]
    department_databases: list[str]

    @property
    def tier_level(self) -> int:
        return TIER_LEVELS.get(self.data_classification_tier, -1)


@dataclass
class CedarResource:
    """Represents a table resource for Cedar policy evaluation."""

    entity_id: str
    database: str
    classification_tier: str

    @property
    def tier_level(self) -> int:
        return TIER_LEVELS.get(self.classification_tier, -1)


def forbid_matches(principal: CedarPrincipal, resource: CedarResource) -> bool:
    """Check if any forbid rule matches (from base.cedar).

    Forbid rules:
    1. Resource is in PCI databases (pci_cardholder, pci_transactions)
    2. Resource classification_tier > principal data_classification_tier
    """
    # PCI database forbid
    if resource.database in PCI_DATABASES:
        return True
    # Classification tier enforcement forbid
    if resource.tier_level > principal.tier_level:
        return True
    return False


def permit_matches(
    principal: CedarPrincipal, action: str, resource: CedarResource
) -> bool:
    """Check if any permit rule matches (from analysts.cedar and managers.cedar).

    Permit conditions:
    - Analyst: role=="analyst", resource.database in department_databases,
               resource.classification_tier <= principal.data_classification_tier
    - Manager: role=="manager", resource.database in department_databases,
               resource.classification_tier <= principal.data_classification_tier
    - Manager cross-department: role=="manager", "cross_department_access" in groups,
               resource.classification_tier <= principal.data_classification_tier
    """
    if action not in VALID_ACTIONS:
        return False

    tier_ok = resource.tier_level <= principal.tier_level

    if principal.role == "analyst":
        return (
            resource.database in principal.department_databases
            and tier_ok
        )

    if principal.role == "manager":
        # Department-scoped permit
        if resource.database in principal.department_databases and tier_ok:
            return True
        # Cross-department permit
        if "cross_department_access" in principal.groups and tier_ok:
            return True

    return False


def evaluate_authorization(
    principal: CedarPrincipal, action: str, resource: CedarResource
) -> Literal["ALLOW", "DENY"]:
    """Evaluate Cedar authorization decision.

    Implements Cedar semantics:
    1. If any forbid matches → DENY (forbid-wins, regardless of permits)
    2. If no permit matches → DENY (default-deny)
    3. If permit matches and no forbid matches → ALLOW
    """
    # Forbid-wins: check forbid rules first
    if forbid_matches(principal, resource):
        return "DENY"

    # Default-deny: must have explicit permit
    if not permit_matches(principal, action, resource):
        return "DENY"

    return "ALLOW"


# ─── Hypothesis Strategies ────────────────────────────────────────────────────

# Strategy for databases — mix of normal databases and PCI databases
database_names = st.sampled_from([
    "analytics_db", "finance_db", "hr_db", "marketing_db",
    "operations_db", "sales_db", "reporting_db",
    "pci_cardholder", "pci_transactions",
])

non_pci_databases = st.sampled_from([
    "analytics_db", "finance_db", "hr_db", "marketing_db",
    "operations_db", "sales_db", "reporting_db",
])

tier_strategy = st.sampled_from(VALID_TIERS)
action_strategy = st.sampled_from(VALID_ACTIONS)
role_strategy = st.sampled_from(VALID_ROLES)


@st.composite
def cedar_principal(draw) -> CedarPrincipal:
    """Generate a random Cedar principal."""
    role = draw(role_strategy)
    tier = draw(tier_strategy)
    dept_dbs = draw(st.lists(non_pci_databases, min_size=0, max_size=4, unique=True))
    groups = draw(
        st.lists(
            st.sampled_from([
                "cross_department_access", "elevated_cost",
                "pii_viewers", "data-users", "analytics-team",
            ]),
            min_size=0,
            max_size=3,
            unique=True,
        )
    )
    return CedarPrincipal(
        entity_id=draw(st.text(min_size=1, max_size=20, alphabet="abcdefghijklmnop0123456789")),
        role=role,
        department=draw(st.sampled_from(["analytics", "finance", "hr", "marketing", "operations"])),
        data_classification_tier=tier,
        groups=groups,
        department_databases=dept_dbs,
    )


@st.composite
def cedar_resource(draw) -> CedarResource:
    """Generate a random Cedar resource."""
    db = draw(database_names)
    tier = draw(tier_strategy)
    return CedarResource(
        entity_id=f"{db}/table_{draw(st.integers(min_value=1, max_value=100))}",
        database=db,
        classification_tier=tier,
    )


@st.composite
def principal_without_permit(draw) -> tuple[CedarPrincipal, str, CedarResource]:
    """Generate a principal/action/resource combination where NO permit can match.

    This is done by ensuring:
    - Role is not 'analyst' or 'manager' (no permits exist for other roles)
    OR
    - Database not in department_databases AND not cross-department manager
    """
    principal = draw(cedar_principal())
    action = draw(action_strategy)
    resource = draw(cedar_resource())

    # Ensure no permit condition is satisfied:
    # Option 1: Use a role that has no permits
    # Option 2: Use a database not in principal's department set and no cross-dept access
    # We force the role to be one without permits (viewer, admin, security-operations)
    assume(principal.role not in ("analyst", "manager"))

    return principal, action, resource


@st.composite
def principal_with_forbid(draw) -> tuple[CedarPrincipal, str, CedarResource]:
    """Generate a principal/action/resource where a forbid rule matches.

    Uses either:
    - PCI database (always forbidden)
    - Resource tier above principal tier (always forbidden)
    """
    principal = draw(cedar_principal())
    action = draw(action_strategy)
    resource = draw(cedar_resource())

    # Ensure at least one forbid condition matches
    use_pci = draw(st.booleans())
    if use_pci:
        # Force PCI database
        resource = CedarResource(
            entity_id=f"{draw(st.sampled_from(PCI_DATABASES))}/table_1",
            database=draw(st.sampled_from(PCI_DATABASES)),
            classification_tier=resource.classification_tier,
        )
    else:
        # Force resource tier > principal tier
        # Pick a resource tier strictly higher than principal's tier
        principal_level = TIER_LEVELS[principal.data_classification_tier]
        assume(principal_level < 3)  # Need room for a higher tier
        higher_tiers = [t for t, lvl in TIER_LEVELS.items() if lvl > principal_level]
        higher_tier = draw(st.sampled_from(higher_tiers))
        resource = CedarResource(
            entity_id=resource.entity_id,
            database=resource.database,
            classification_tier=higher_tier,
        )

    return principal, action, resource


@st.composite
def principal_with_permit_and_forbid(draw) -> tuple[CedarPrincipal, str, CedarResource]:
    """Generate a scenario where BOTH permit and forbid match.

    This is the critical forbid-wins test case:
    - An analyst/manager with PCI database in their department_databases
    - Resource is in PCI database (forbid) but also in department_databases (permit)
    """
    pci_db = draw(st.sampled_from(PCI_DATABASES))
    role = draw(st.sampled_from(["analyst", "manager"]))
    tier = draw(tier_strategy)
    action = draw(action_strategy)

    # Create principal whose department databases include the PCI database
    principal = CedarPrincipal(
        entity_id=draw(st.text(min_size=1, max_size=20, alphabet="abcdefghijklmnop0123456789")),
        role=role,
        department="finance",
        data_classification_tier=tier,
        groups=["cross_department_access"],  # Maximize permit chance
        department_databases=[pci_db, "finance_db"],
    )

    # Resource is in PCI database with tier at or below principal
    resource = CedarResource(
        entity_id=f"{pci_db}/sensitive_table",
        database=pci_db,
        classification_tier=tier,  # Same tier as principal, so tier forbid doesn't apply
    )

    return principal, action, resource


# ─── Property 2: Default-Deny Authorization ──────────────────────────────────


class TestDefaultDenyAuthorization:
    """Property 2: Default-Deny Authorization.

    **Validates: Requirements 5.1**

    For any randomly generated principal and resource, if no explicit permit
    condition is satisfied, access is denied. Cedar's default-deny means the
    absence of a matching permit results in DENY.
    """

    @given(data=principal_without_permit())
    @settings(max_examples=200)
    def test_no_permit_means_deny(
        self, data: tuple[CedarPrincipal, str, CedarResource]
    ):
        """If no permit policy matches the principal/action/resource, decision is DENY.

        **Validates: Requirements 5.1**
        """
        principal, action, resource = data

        decision = evaluate_authorization(principal, action, resource)

        assert decision == "DENY", (
            f"Expected DENY (default-deny) but got {decision} for "
            f"principal(role={principal.role}, tier={principal.data_classification_tier}) "
            f"action={action} "
            f"resource(db={resource.database}, tier={resource.classification_tier})"
        )

    @given(
        principal=cedar_principal(),
        resource=cedar_resource(),
    )
    @settings(max_examples=200)
    def test_invalid_action_always_denied(
        self, principal: CedarPrincipal, resource: CedarResource
    ):
        """Actions not in the defined set are always denied (default-deny).

        **Validates: Requirements 5.1**
        """
        invalid_action = "delete_table"  # Not in VALID_ACTIONS

        decision = evaluate_authorization(principal, invalid_action, resource)

        assert decision == "DENY", (
            f"Expected DENY for invalid action '{invalid_action}' but got {decision}"
        )

    @given(
        principal=cedar_principal(),
        action=action_strategy,
        resource=cedar_resource(),
    )
    @settings(max_examples=300)
    def test_default_deny_holds_universally(
        self, principal: CedarPrincipal, action: str, resource: CedarResource
    ):
        """For any principal/action/resource, ALLOW only occurs when permit matches
        AND no forbid matches. Otherwise, DENY.

        **Validates: Requirements 5.1**
        """
        decision = evaluate_authorization(principal, action, resource)

        has_permit = permit_matches(principal, action, resource)
        has_forbid = forbid_matches(principal, resource)

        if decision == "ALLOW":
            # ALLOW requires: permit matches AND no forbid
            assert has_permit, (
                f"Got ALLOW without a matching permit for "
                f"principal(role={principal.role}) action={action} "
                f"resource(db={resource.database})"
            )
            assert not has_forbid, (
                f"Got ALLOW despite a matching forbid for "
                f"resource(db={resource.database}, tier={resource.classification_tier})"
            )
        else:
            # DENY means: no permit OR forbid present
            assert not has_permit or has_forbid, (
                f"Got DENY but permit matched and no forbid matched for "
                f"principal(role={principal.role}) action={action} "
                f"resource(db={resource.database})"
            )


# ─── Property 3: Forbid Always Wins ──────────────────────────────────────────


class TestForbidAlwaysWins:
    """Property 3: Forbid Always Wins.

    **Validates: Requirements 5.2**

    For any randomly generated principal and resource, if a forbid condition
    matches (e.g., PCI database, tier violation), access is always denied
    regardless of how many permits match.
    """

    @given(data=principal_with_forbid())
    @settings(max_examples=200)
    def test_forbid_overrides_any_permit(
        self, data: tuple[CedarPrincipal, str, CedarResource]
    ):
        """When a forbid rule matches, decision is DENY regardless of permits.

        **Validates: Requirements 5.2**
        """
        principal, action, resource = data

        decision = evaluate_authorization(principal, action, resource)

        assert decision == "DENY", (
            f"Expected DENY (forbid-wins) but got {decision} for "
            f"principal(role={principal.role}, tier={principal.data_classification_tier}) "
            f"action={action} "
            f"resource(db={resource.database}, tier={resource.classification_tier})"
        )

    @given(data=principal_with_permit_and_forbid())
    @settings(max_examples=200)
    def test_forbid_wins_even_with_explicit_permit(
        self, data: tuple[CedarPrincipal, str, CedarResource]
    ):
        """Even when a permit explicitly matches, forbid overrides it.

        This is the critical case: a principal who WOULD be permitted (role matches,
        database in department_databases, tier OK) is still denied because a forbid
        rule matches (PCI database).

        **Validates: Requirements 5.2**
        """
        principal, action, resource = data

        # Verify the permit WOULD match (if not for forbid)
        has_permit = permit_matches(principal, action, resource)
        has_forbid = forbid_matches(principal, resource)

        # The forbid must match (PCI database)
        assert has_forbid, "Test setup error: forbid should match for PCI database"

        decision = evaluate_authorization(principal, action, resource)

        assert decision == "DENY", (
            f"Expected DENY (forbid-wins) but got {decision}. "
            f"permit_matches={has_permit}, forbid_matches={has_forbid} for "
            f"principal(role={principal.role}, dept_dbs={principal.department_databases}) "
            f"resource(db={resource.database})"
        )

    @given(
        principal=cedar_principal(),
        action=action_strategy,
        resource=cedar_resource(),
    )
    @settings(max_examples=300)
    def test_pci_database_always_denied(
        self, principal: CedarPrincipal, action: str, resource: CedarResource
    ):
        """PCI databases are ALWAYS denied regardless of principal attributes.

        **Validates: Requirements 5.2**
        """
        # Force resource to be a PCI database
        pci_resource = CedarResource(
            entity_id=f"pci_cardholder/transactions",
            database="pci_cardholder",
            classification_tier=resource.classification_tier,
        )

        decision = evaluate_authorization(principal, action, pci_resource)

        assert decision == "DENY", (
            f"PCI database access should always be DENY but got {decision} for "
            f"principal(role={principal.role}, tier={principal.data_classification_tier})"
        )

    @given(
        principal=cedar_principal(),
        action=action_strategy,
    )
    @settings(max_examples=200)
    def test_tier_violation_always_denied(
        self, principal: CedarPrincipal, action: str
    ):
        """Resource tier above principal tier is ALWAYS denied (forbid-wins).

        **Validates: Requirements 5.2**
        """
        principal_level = TIER_LEVELS[principal.data_classification_tier]
        assume(principal_level < 3)  # Need room for a higher tier

        # Pick a tier strictly higher than the principal's
        higher_tiers = [t for t, lvl in TIER_LEVELS.items() if lvl > principal_level]
        higher_tier = higher_tiers[0]  # Just use the first one that's higher

        resource = CedarResource(
            entity_id="some_db/some_table",
            database="analytics_db",
            classification_tier=higher_tier,
        )

        decision = evaluate_authorization(principal, action, resource)

        assert decision == "DENY", (
            f"Tier violation should always be DENY but got {decision}. "
            f"principal_tier={principal.data_classification_tier} "
            f"resource_tier={resource.classification_tier}"
        )
