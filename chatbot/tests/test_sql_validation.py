"""Unit tests for SQL validation edge cases.

Tests the validate_sql function against security-critical edge cases
including statement type rejection, partition filters, column selection,
cost thresholds, LIMIT injection, and unauthorized table references.

Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8
"""

import uuid

import pytest

from chatbot.api.models import UserClaims
from chatbot.mcp_server.validation import (
    ValidationResult,
    validate_sql,
)


# --- Fixtures ---


def make_user_claims(**overrides) -> UserClaims:
    """Create a valid UserClaims instance with optional overrides."""
    defaults = {
        "sub": "user-123",
        "department": "analytics",
        "role": "analyst",
        "data_classification_tier": "internal",
        "groups": ["data-users"],
        "session_id": str(uuid.uuid4()),
        "exp": 1700000000,
    }
    defaults.update(overrides)
    return UserClaims(**defaults)


@pytest.fixture
def user_claims() -> UserClaims:
    """Standard user without elevated_cost group."""
    return make_user_claims()


@pytest.fixture
def elevated_user_claims() -> UserClaims:
    """User with elevated_cost group membership."""
    return make_user_claims(groups=["data-users", "elevated_cost"])


@pytest.fixture
def authorized_tables() -> set[str]:
    """Standard set of authorized tables."""
    return {"analytics.sales", "analytics.users", "analytics.orders", "public.events"}


@pytest.fixture
def table_metadata() -> dict:
    """Standard table metadata with partition keys, column counts, and estimated sizes."""
    return {
        "analytics.sales": {
            "partition_keys": ["year", "month"],
            "column_count": 25,
            "estimated_size_bytes": 500_000_000_000,  # 500 GB
        },
        "analytics.users": {
            "partition_keys": [],
            "column_count": 10,
            "estimated_size_bytes": 1_000_000_000,  # 1 GB
        },
        "analytics.orders": {
            "partition_keys": ["order_date"],
            "column_count": 60,
            "estimated_size_bytes": 200_000_000_000,  # 200 GB
        },
        "public.events": {
            "partition_keys": ["event_date"],
            "column_count": 15,
            "estimated_size_bytes": 50_000_000_000,  # 50 GB
        },
    }


# --- Requirement 9.2: Non-SELECT statement rejection ---


class TestStatementTypeRejection:
    """INSERT/UPDATE/DELETE/DROP/ALTER/CREATE must all be rejected."""

    @pytest.mark.asyncio
    async def test_insert_rejected(self, user_claims, authorized_tables):
        result = await validate_sql(
            "INSERT INTO analytics.sales (id, amount) VALUES (1, 100)",
            user_claims,
            authorized_tables,
        )
        assert result.valid is False
        assert "SELECT" in result.rejection_reason
        assert "not allowed" in result.rejection_reason.lower() or "not permitted" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_update_rejected(self, user_claims, authorized_tables):
        result = await validate_sql(
            "UPDATE analytics.sales SET amount = 200 WHERE id = 1",
            user_claims,
            authorized_tables,
        )
        assert result.valid is False
        assert "SELECT" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_delete_rejected(self, user_claims, authorized_tables):
        result = await validate_sql(
            "DELETE FROM analytics.sales WHERE id = 1",
            user_claims,
            authorized_tables,
        )
        assert result.valid is False
        assert "SELECT" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_drop_table_rejected(self, user_claims, authorized_tables):
        result = await validate_sql(
            "DROP TABLE analytics.sales",
            user_claims,
            authorized_tables,
        )
        assert result.valid is False
        assert "SELECT" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_alter_table_rejected(self, user_claims, authorized_tables):
        result = await validate_sql(
            "ALTER TABLE analytics.sales ADD COLUMN new_col INT",
            user_claims,
            authorized_tables,
        )
        assert result.valid is False
        assert "SELECT" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_create_table_rejected(self, user_claims, authorized_tables):
        result = await validate_sql(
            "CREATE TABLE analytics.new_table (id INT, name STRING)",
            user_claims,
            authorized_tables,
        )
        assert result.valid is False
        assert "SELECT" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_multiple_statements_rejected(self, user_claims, authorized_tables):
        """Multiple statements (even if both SELECT) should be rejected."""
        result = await validate_sql(
            "SELECT 1; SELECT 2",
            user_claims,
            authorized_tables,
        )
        assert result.valid is False

    @pytest.mark.asyncio
    async def test_empty_sql_rejected(self, user_claims, authorized_tables):
        result = await validate_sql("", user_claims, authorized_tables)
        assert result.valid is False
        assert "empty" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_whitespace_only_rejected(self, user_claims, authorized_tables):
        result = await validate_sql("   \n\t  ", user_claims, authorized_tables)
        assert result.valid is False
        assert "empty" in result.rejection_reason.lower()


# --- Requirement 9.3: Partition filter enforcement ---


class TestPartitionFilterRejection:
    """Queries on partitioned tables without WHERE on partition key must be rejected."""

    @pytest.mark.asyncio
    async def test_partitioned_table_no_where_rejected(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Query on partitioned table with no WHERE clause at all."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is False
        assert "partition" in result.rejection_reason.lower()
        assert "sales" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_partitioned_table_where_without_partition_key_rejected(
        self, user_claims, authorized_tables, table_metadata
    ):
        """WHERE clause exists but doesn't reference any partition key."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE amount > 100",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is False
        assert "partition" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_partitioned_table_with_partition_key_filter_passes(
        self, user_claims, authorized_tables, table_metadata
    ):
        """WHERE clause references a partition key — should pass."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE year = 2024",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_partitioned_table_with_second_partition_key_passes(
        self, user_claims, authorized_tables, table_metadata
    ):
        """WHERE clause references second partition key — should pass."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE month = 12",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_non_partitioned_table_no_where_passes(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Non-partitioned table without WHERE should pass partition check."""
        result = await validate_sql(
            "SELECT id, name FROM analytics.users",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True


# --- Requirement 9.4: SELECT * on wide tables ---


class TestSelectStarWideTable:
    """SELECT * on tables with >50 columns must be rejected."""

    @pytest.mark.asyncio
    async def test_select_star_on_wide_table_rejected(
        self, user_claims, authorized_tables, table_metadata
    ):
        """SELECT * on analytics.orders (60 columns) should be rejected."""
        result = await validate_sql(
            "SELECT * FROM analytics.orders WHERE order_date = '2024-01-01'",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is False
        assert "SELECT *" in result.rejection_reason
        assert "50" in result.rejection_reason
        assert "orders" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_select_star_on_narrow_table_passes(
        self, user_claims, authorized_tables, table_metadata
    ):
        """SELECT * on analytics.users (10 columns) should pass."""
        result = await validate_sql(
            "SELECT * FROM analytics.users",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_explicit_columns_on_wide_table_passes(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Explicit columns on wide table should pass."""
        result = await validate_sql(
            "SELECT id, customer_name, total FROM analytics.orders WHERE order_date = '2024-01-01'",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True


# --- Requirement 9.5/9.7: Cost threshold and full-scan protection ---


class TestCostThreshold:
    """Cost threshold blocks without elevated_cost group (Requirement 9.5).

    Queries exceeding 10 GB estimated scan should be rejected for standard
    users but allowed for users with elevated_cost group membership.
    """

    @pytest.mark.asyncio
    async def test_exceeds_10gb_without_elevated_cost_rejected(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Query exceeding 10 GB without elevated_cost → rejected with suggestion."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE year = 2024",
            user_claims,
            authorized_tables,
            table_metadata,
            estimated_bytes_scanned=15_000_000_000,  # ~15 GB
        )
        assert result.valid is False
        assert "10 GB" in result.rejection_reason
        assert "filter" in result.rejection_reason.lower()
        assert result.estimated_bytes == 15_000_000_000

    @pytest.mark.asyncio
    async def test_exceeds_10gb_with_elevated_cost_passes(
        self, elevated_user_claims, authorized_tables, table_metadata
    ):
        """Query exceeding 10 GB WITH elevated_cost → passes."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE year = 2024",
            elevated_user_claims,
            authorized_tables,
            table_metadata,
            estimated_bytes_scanned=15_000_000_000,  # ~15 GB
        )
        assert result.valid is True
        assert result.estimated_bytes == 15_000_000_000

    @pytest.mark.asyncio
    async def test_under_10gb_passes_regardless_of_group(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Query under 10 GB → passes regardless of group membership."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE year = 2024",
            user_claims,
            authorized_tables,
            table_metadata,
            estimated_bytes_scanned=5_000_000_000,  # ~5 GB
        )
        assert result.valid is True
        assert result.estimated_bytes == 5_000_000_000

    @pytest.mark.asyncio
    async def test_no_estimated_bytes_passes(
        self, user_claims, authorized_tables, table_metadata
    ):
        """When estimated_bytes_scanned is None, cost check is skipped."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE year = 2024",
            user_claims,
            authorized_tables,
            table_metadata,
            estimated_bytes_scanned=None,
        )
        assert result.valid is True
        assert result.estimated_bytes is None

    @pytest.mark.asyncio
    async def test_exactly_10gb_passes(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Query at exactly 10 GB (not exceeding) should pass."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE year = 2024",
            user_claims,
            authorized_tables,
            table_metadata,
            estimated_bytes_scanned=10_737_418_240,  # exactly 10 GB
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_one_byte_over_10gb_rejected(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Query at 10 GB + 1 byte should be rejected."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE year = 2024",
            user_claims,
            authorized_tables,
            table_metadata,
            estimated_bytes_scanned=10_737_418_241,  # 10 GB + 1
        )
        assert result.valid is False
        assert "10 GB" in result.rejection_reason


class TestFullScanProtection:
    """Full table scan on >1 TB table without elevated_cost (Requirement 9.7).

    Tables exceeding 1 TB require partition filters or elevated_cost group.
    """

    @pytest.fixture
    def large_table_metadata(self) -> dict:
        """Table metadata with a table exceeding 1 TB."""
        return {
            "analytics.big_events": {
                "partition_keys": ["event_date"],
                "column_count": 30,
                "estimated_size_bytes": 2_000_000_000_000,  # 2 TB
            },
            "analytics.small_table": {
                "partition_keys": ["dt"],
                "column_count": 10,
                "estimated_size_bytes": 500_000_000_000,  # 500 GB
            },
            "analytics.huge_no_partitions": {
                "partition_keys": [],
                "column_count": 20,
                "estimated_size_bytes": 1_500_000_000_000,  # 1.5 TB
            },
        }

    @pytest.fixture
    def large_table_authorized(self) -> set[str]:
        """Authorized tables including the large ones."""
        return {"analytics.big_events", "analytics.small_table", "analytics.huge_no_partitions"}

    @pytest.mark.asyncio
    async def test_full_scan_over_1tb_without_partition_filter_rejected(
        self, user_claims, large_table_authorized, large_table_metadata
    ):
        """Full table scan on >1 TB without partition filter and without elevated_cost → rejected.

        Uses a table with no partition keys (analytics.huge_no_partitions) to test
        Step 6 specifically, since Step 4 would catch partitioned tables first.
        """
        result = await validate_sql(
            "SELECT id, data FROM analytics.huge_no_partitions WHERE status = 'active'",
            user_claims,
            large_table_authorized,
            large_table_metadata,
        )
        assert result.valid is False
        assert "full table scan" in result.rejection_reason.lower()
        assert "elevated_cost" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_full_scan_over_1tb_with_elevated_cost_passes(
        self, elevated_user_claims, large_table_authorized, large_table_metadata
    ):
        """Full table scan on >1 TB WITH elevated_cost → passes."""
        result = await validate_sql(
            "SELECT id, data FROM analytics.huge_no_partitions WHERE status = 'active'",
            elevated_user_claims,
            large_table_authorized,
            large_table_metadata,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_full_scan_over_1tb_with_partition_filter_passes(
        self, user_claims, large_table_authorized, large_table_metadata
    ):
        """Full scan on >1 TB table WITH partition filter → passes (not a full scan)."""
        result = await validate_sql(
            "SELECT id, data FROM analytics.big_events WHERE event_date = '2024-01-01'",
            user_claims,
            large_table_authorized,
            large_table_metadata,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_table_under_1tb_no_partition_filter_passes(
        self, user_claims, large_table_authorized, large_table_metadata
    ):
        """Table under 1 TB without partition filter passes full-scan check.

        Note: The partition filter check (Step 4) would catch this separately,
        but the full-scan protection (Step 6) doesn't apply.
        """
        # small_table has partition key 'dt' - add a filter to pass Step 4
        result = await validate_sql(
            "SELECT id FROM analytics.small_table WHERE dt = '2024-01-01'",
            user_claims,
            large_table_authorized,
            large_table_metadata,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_1tb_no_partitions_without_elevated_cost_rejected(
        self, user_claims, large_table_authorized, large_table_metadata
    ):
        """Table >1 TB with no partition keys defined and no elevated_cost → rejected."""
        result = await validate_sql(
            "SELECT id, data FROM analytics.huge_no_partitions",
            user_claims,
            large_table_authorized,
            large_table_metadata,
        )
        assert result.valid is False
        assert "full table scan" in result.rejection_reason.lower()
        assert "elevated_cost" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_full_scan_check_before_cost_threshold(
        self, user_claims, large_table_authorized, large_table_metadata
    ):
        """Full-scan check (9.7) runs before cost threshold (9.5).

        Even with a small estimated_bytes_scanned, full-scan protection
        can still reject the query.
        """
        result = await validate_sql(
            "SELECT id FROM analytics.huge_no_partitions WHERE status = 'active'",
            user_claims,
            large_table_authorized,
            large_table_metadata,
            estimated_bytes_scanned=1_000_000,  # 1 MB — under cost threshold
        )
        assert result.valid is False
        assert "full table scan" in result.rejection_reason.lower()


# --- Requirement 9.6: LIMIT injection ---


class TestLimitInjection:
    """LIMIT 10000 must be injected when no explicit LIMIT is present."""

    @pytest.mark.asyncio
    async def test_limit_injected_when_missing(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Query without LIMIT should have LIMIT 10000 injected."""
        result = await validate_sql(
            "SELECT id, name FROM analytics.users",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True
        assert result.modified_sql is not None
        assert "10000" in result.modified_sql

    @pytest.mark.asyncio
    async def test_existing_limit_preserved(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Query with explicit LIMIT should not have LIMIT modified."""
        result = await validate_sql(
            "SELECT id, name FROM analytics.users LIMIT 100",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True
        assert result.modified_sql is not None
        assert "100" in result.modified_sql
        # Should not inject default 10000
        assert "10000" not in result.modified_sql

    @pytest.mark.asyncio
    async def test_limit_injected_on_partitioned_table(
        self, user_claims, authorized_tables, table_metadata
    ):
        """LIMIT injection should work alongside partition filter requirement."""
        result = await validate_sql(
            "SELECT id, amount FROM analytics.sales WHERE year = 2024",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True
        assert result.modified_sql is not None
        assert "10000" in result.modified_sql

    @pytest.mark.asyncio
    async def test_small_explicit_limit_preserved(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Small LIMIT values should be preserved without modification."""
        result = await validate_sql(
            "SELECT id, name FROM analytics.users LIMIT 5",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True
        assert result.modified_sql is not None
        # The original limit should remain
        assert "5" in result.modified_sql


# --- Requirement 9.8: Unauthorized table references in subqueries/CTEs/JOINs ---


class TestUnauthorizedTableReferences:
    """Unauthorized tables in subqueries, CTEs, and JOINs must be rejected."""

    @pytest.mark.asyncio
    async def test_unauthorized_table_in_from_rejected(self, user_claims, table_metadata):
        """Direct reference to unauthorized table should be rejected."""
        authorized = {"analytics.users"}
        result = await validate_sql(
            "SELECT id FROM secret.financials",
            user_claims,
            authorized,
            table_metadata,
        )
        assert result.valid is False
        assert "not authorized" in result.rejection_reason.lower()
        assert "secret.financials" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_unauthorized_table_in_subquery_rejected(
        self, user_claims, table_metadata
    ):
        """Unauthorized table referenced in a subquery should be rejected."""
        authorized = {"analytics.users"}
        result = await validate_sql(
            "SELECT u.name FROM analytics.users u WHERE u.id IN (SELECT user_id FROM secret.transactions)",
            user_claims,
            authorized,
            table_metadata,
        )
        assert result.valid is False
        assert "not authorized" in result.rejection_reason.lower()
        assert "secret.transactions" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_unauthorized_table_in_join_rejected(
        self, user_claims, table_metadata
    ):
        """Unauthorized table referenced in a JOIN should be rejected."""
        authorized = {"analytics.users"}
        result = await validate_sql(
            "SELECT u.name, o.total FROM analytics.users u JOIN secret.orders o ON u.id = o.user_id",
            user_claims,
            authorized,
            table_metadata,
        )
        assert result.valid is False
        assert "not authorized" in result.rejection_reason.lower()
        assert "secret.orders" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_unauthorized_table_in_cte_rejected(
        self, user_claims, table_metadata
    ):
        """Unauthorized table referenced in a CTE should be rejected."""
        authorized = {"analytics.users"}
        result = await validate_sql(
            "WITH revenue AS (SELECT user_id, SUM(amount) as total FROM secret.payments GROUP BY user_id) SELECT u.name, r.total FROM analytics.users u JOIN revenue r ON u.id = r.user_id",
            user_claims,
            authorized,
            table_metadata,
        )
        assert result.valid is False
        assert "not authorized" in result.rejection_reason.lower()
        assert "secret.payments" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_all_tables_authorized_passes(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Query where all tables are authorized should pass."""
        result = await validate_sql(
            "SELECT s.id, u.name FROM analytics.sales s JOIN analytics.users u ON s.user_id = u.id WHERE s.year = 2024",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_cte_alias_not_treated_as_table(
        self, user_claims, authorized_tables, table_metadata
    ):
        """CTE aliases should not be treated as external table references."""
        result = await validate_sql(
            "WITH recent_sales AS (SELECT id, amount FROM analytics.sales WHERE year = 2024) SELECT id, amount FROM recent_sales",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_case_insensitive_authorization(
        self, user_claims, table_metadata
    ):
        """Table authorization should be case-insensitive."""
        authorized = {"Analytics.Sales", "analytics.users"}
        result = await validate_sql(
            "SELECT id FROM analytics.sales WHERE year = 2024",
            user_claims,
            authorized,
            table_metadata,
        )
        assert result.valid is True


# --- Requirement 9.1: Parse validity ---


class TestParseValidity:
    """Malformed SQL that cannot be parsed must be rejected."""

    @pytest.mark.asyncio
    async def test_malformed_sql_rejected(self, user_claims, authorized_tables):
        result = await validate_sql(
            "SELEKT * FRUM table",
            user_claims,
            authorized_tables,
        )
        # Depending on parser tolerance, this may or may not be parseable
        # But the result should either fail parse or fail statement type check
        assert result.valid is False

    @pytest.mark.asyncio
    async def test_valid_select_passes_parse(
        self, user_claims, authorized_tables, table_metadata
    ):
        """Valid SQL should pass the parse step."""
        result = await validate_sql(
            "SELECT id, name FROM analytics.users",
            user_claims,
            authorized_tables,
            table_metadata,
        )
        assert result.valid is True
