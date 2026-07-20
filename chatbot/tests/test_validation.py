"""Unit tests for SQL validation engine (chatbot/mcp_server/validation.py).

Tests cover task 4.1 implementation:
- Parse validity (Requirement 9.1)
- Statement type rejection (Requirement 9.2)
- Table authorization checking (Requirement 9.8)
- Ordered evaluation (Requirement 9.9)
- LIMIT injection (Requirement 9.6)
"""

import uuid

import pytest

from chatbot.api.models import UserClaims
from chatbot.mcp_server.validation import (
    COST_THRESHOLD_BYTES,
    DEFAULT_LIMIT,
    ELEVATED_COST_GROUP,
    FULL_SCAN_THRESHOLD_BYTES,
    TableMetadata,
    ValidationResult,
    _check_column_selection,
    _check_cost_threshold,
    _check_partition_filter,
    _check_table_authorization,
    _extract_table_references,
    _extract_where_columns,
    _has_select_star,
    _inject_limit,
    _is_select_statement,
    _parse_sql,
    validate_sql,
)


# --- Helpers ---


def make_user_claims(**overrides) -> UserClaims:
    """Create valid UserClaims for testing."""
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


# --- Parse Validity Tests (Requirement 9.1) ---


class TestParseValidity:
    def test_valid_select_parses(self):
        result = _parse_sql("SELECT id, name FROM users")
        assert result is not None

    def test_malformed_sql_returns_none(self):
        result = _parse_sql("SELEC id FROM")
        assert result is None

    def test_empty_string_returns_none(self):
        result = _parse_sql("")
        assert result is None

    def test_whitespace_only_returns_none(self):
        result = _parse_sql("   ")
        assert result is None

    def test_multiple_statements_returns_none(self):
        """Only single-statement SQL is allowed."""
        result = _parse_sql("SELECT 1; SELECT 2")
        assert result is None

    def test_complex_select_parses(self):
        sql = """
        WITH cte AS (
            SELECT id, name FROM db.users WHERE active = true
        )
        SELECT c.id, c.name, o.total
        FROM cte c
        JOIN db.orders o ON c.id = o.user_id
        WHERE o.total > 100
        ORDER BY o.total DESC
        """
        result = _parse_sql(sql)
        assert result is not None


# --- Statement Type Tests (Requirement 9.2) ---


class TestStatementType:
    def test_select_is_accepted(self):
        ast = _parse_sql("SELECT id FROM users")
        assert _is_select_statement(ast)

    def test_select_with_subquery_is_accepted(self):
        ast = _parse_sql("SELECT * FROM (SELECT id FROM users) sub")
        assert _is_select_statement(ast)

    def test_insert_is_rejected(self):
        ast = _parse_sql("INSERT INTO users (id) VALUES (1)")
        assert ast is not None
        assert not _is_select_statement(ast)

    def test_update_is_rejected(self):
        ast = _parse_sql("UPDATE users SET name = 'test' WHERE id = 1")
        assert ast is not None
        assert not _is_select_statement(ast)

    def test_delete_is_rejected(self):
        ast = _parse_sql("DELETE FROM users WHERE id = 1")
        assert ast is not None
        assert not _is_select_statement(ast)

    def test_drop_is_rejected(self):
        ast = _parse_sql("DROP TABLE users")
        assert ast is not None
        assert not _is_select_statement(ast)

    def test_alter_is_rejected(self):
        ast = _parse_sql("ALTER TABLE users ADD COLUMN email VARCHAR")
        assert ast is not None
        assert not _is_select_statement(ast)

    def test_create_is_rejected(self):
        ast = _parse_sql("CREATE TABLE users (id INT)")
        assert ast is not None
        assert not _is_select_statement(ast)


# --- Table Reference Extraction Tests (Requirement 9.8) ---


class TestTableExtraction:
    def test_single_table_from_clause(self):
        ast = _parse_sql("SELECT id FROM mydb.users")
        tables = _extract_table_references(ast)
        assert "mydb.users" in tables

    def test_unqualified_table(self):
        ast = _parse_sql("SELECT id FROM users")
        tables = _extract_table_references(ast)
        assert "users" in tables

    def test_join_tables(self):
        ast = _parse_sql(
            "SELECT u.id, o.total FROM db.users u JOIN db.orders o ON u.id = o.user_id"
        )
        tables = _extract_table_references(ast)
        assert "db.users" in tables
        assert "db.orders" in tables

    def test_subquery_tables(self):
        ast = _parse_sql(
            "SELECT * FROM (SELECT id FROM db.users) u "
            "WHERE u.id IN (SELECT user_id FROM db.orders)"
        )
        tables = _extract_table_references(ast)
        assert "db.users" in tables
        assert "db.orders" in tables

    def test_cte_references_excluded(self):
        """CTE aliases should not appear in the table set — only real tables."""
        ast = _parse_sql(
            "WITH active_users AS (SELECT id FROM db.users WHERE active = true) "
            "SELECT id FROM active_users"
        )
        tables = _extract_table_references(ast)
        assert "db.users" in tables
        assert "active_users" not in tables

    def test_multiple_ctes(self):
        ast = _parse_sql(
            "WITH cte1 AS (SELECT id FROM db.users), "
            "cte2 AS (SELECT user_id FROM db.orders) "
            "SELECT * FROM cte1 JOIN cte2 ON cte1.id = cte2.user_id"
        )
        tables = _extract_table_references(ast)
        assert "db.users" in tables
        assert "db.orders" in tables
        assert "cte1" not in tables
        assert "cte2" not in tables

    def test_left_right_join_tables(self):
        ast = _parse_sql(
            "SELECT * FROM db.users u "
            "LEFT JOIN db.orders o ON u.id = o.user_id "
            "RIGHT JOIN db.payments p ON o.id = p.order_id"
        )
        tables = _extract_table_references(ast)
        assert "db.users" in tables
        assert "db.orders" in tables
        assert "db.payments" in tables

    def test_case_insensitive_table_names(self):
        ast = _parse_sql("SELECT id FROM MyDB.Users")
        tables = _extract_table_references(ast)
        assert "mydb.users" in tables


# --- Table Authorization Tests (Requirement 9.8) ---


class TestTableAuthorization:
    def test_all_tables_authorized(self):
        tables = {"db.users", "db.orders"}
        authorized = {"db.users", "db.orders", "db.products"}
        result = _check_table_authorization(tables, authorized)
        assert result is None

    def test_unauthorized_table_rejected(self):
        tables = {"db.users", "db.secret_table"}
        authorized = {"db.users", "db.orders"}
        result = _check_table_authorization(tables, authorized)
        assert result is not None
        assert "db.secret_table" in result
        assert "not authorized" in result

    def test_empty_table_set_always_passes(self):
        tables: set[str] = set()
        authorized = {"db.users"}
        result = _check_table_authorization(tables, authorized)
        assert result is None

    def test_case_insensitive_authorization(self):
        tables = {"db.users"}
        authorized = {"DB.Users"}
        result = _check_table_authorization(tables, authorized)
        assert result is None

    def test_empty_authorized_set_rejects_all(self):
        tables = {"db.users"}
        authorized: set[str] = set()
        result = _check_table_authorization(tables, authorized)
        assert result is not None
        assert "db.users" in result


# --- LIMIT Injection Tests (Requirement 9.6) ---


class TestLimitInjection:
    def test_adds_limit_when_missing(self):
        ast = _parse_sql("SELECT id FROM users")
        modified = _inject_limit(ast)
        sql = modified.sql(dialect="trino")
        assert "LIMIT" in sql.upper()
        assert str(DEFAULT_LIMIT) in sql

    def test_preserves_existing_limit(self):
        ast = _parse_sql("SELECT id FROM users LIMIT 100")
        modified = _inject_limit(ast)
        sql = modified.sql(dialect="trino")
        assert "100" in sql
        # Should not inject 10000 when user already specified a limit
        assert str(DEFAULT_LIMIT) not in sql


# --- Full validate_sql() Integration Tests ---


class TestValidateSql:
    @pytest.mark.asyncio
    async def test_valid_select_passes(self):
        claims = make_user_claims()
        authorized = {"db.users"}
        result = await validate_sql(
            "SELECT id, name FROM db.users WHERE id = 1",
            claims,
            authorized_tables=authorized,
        )
        assert result.valid is True
        assert result.modified_sql is not None
        assert result.rejection_reason is None

    @pytest.mark.asyncio
    async def test_empty_sql_rejected(self):
        claims = make_user_claims()
        result = await validate_sql("", claims)
        assert result.valid is False
        assert "empty" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_whitespace_sql_rejected(self):
        claims = make_user_claims()
        result = await validate_sql("   \n  ", claims)
        assert result.valid is False
        assert "empty" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_malformed_sql_rejected(self):
        claims = make_user_claims()
        result = await validate_sql("SELEC id FORM users", claims)
        assert result.valid is False
        assert "malformed" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_insert_rejected(self):
        claims = make_user_claims()
        result = await validate_sql("INSERT INTO db.users (id) VALUES (1)", claims)
        assert result.valid is False
        assert "SELECT" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_update_rejected(self):
        claims = make_user_claims()
        result = await validate_sql(
            "UPDATE db.users SET name = 'x' WHERE id = 1", claims
        )
        assert result.valid is False
        assert "SELECT" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_delete_rejected(self):
        claims = make_user_claims()
        result = await validate_sql("DELETE FROM db.users WHERE id = 1", claims)
        assert result.valid is False
        assert "SELECT" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_drop_rejected(self):
        claims = make_user_claims()
        result = await validate_sql("DROP TABLE db.users", claims)
        assert result.valid is False
        assert "SELECT" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_unauthorized_table_rejected(self):
        claims = make_user_claims()
        authorized = {"db.users"}
        result = await validate_sql(
            "SELECT id FROM db.secret_data",
            claims,
            authorized_tables=authorized,
        )
        assert result.valid is False
        assert "not authorized" in result.rejection_reason.lower()
        assert "db.secret_data" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_unauthorized_table_in_join(self):
        claims = make_user_claims()
        authorized = {"db.users"}
        result = await validate_sql(
            "SELECT u.id FROM db.users u JOIN db.secret o ON u.id = o.uid",
            claims,
            authorized_tables=authorized,
        )
        assert result.valid is False
        assert "not authorized" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_unauthorized_table_in_subquery(self):
        claims = make_user_claims()
        authorized = {"db.users"}
        result = await validate_sql(
            "SELECT id FROM db.users WHERE id IN (SELECT uid FROM db.secret)",
            claims,
            authorized_tables=authorized,
        )
        assert result.valid is False
        assert "not authorized" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_unauthorized_table_in_cte(self):
        claims = make_user_claims()
        authorized = {"db.users"}
        result = await validate_sql(
            "WITH s AS (SELECT uid FROM db.secret) SELECT id FROM db.users",
            claims,
            authorized_tables=authorized,
        )
        assert result.valid is False
        assert "not authorized" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_limit_injected_on_valid_query(self):
        claims = make_user_claims()
        authorized = {"db.users"}
        result = await validate_sql(
            "SELECT id FROM db.users",
            claims,
            authorized_tables=authorized,
        )
        assert result.valid is True
        assert str(DEFAULT_LIMIT) in result.modified_sql

    @pytest.mark.asyncio
    async def test_existing_limit_preserved(self):
        claims = make_user_claims()
        authorized = {"db.users"}
        result = await validate_sql(
            "SELECT id FROM db.users LIMIT 500",
            claims,
            authorized_tables=authorized,
        )
        assert result.valid is True
        assert "500" in result.modified_sql
        assert str(DEFAULT_LIMIT) not in result.modified_sql

    @pytest.mark.asyncio
    async def test_authorization_skipped_when_none(self):
        """When authorized_tables is None, skip authorization check."""
        claims = make_user_claims()
        result = await validate_sql(
            "SELECT id FROM db.any_table",
            claims,
            authorized_tables=None,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_evaluation_order_parse_before_type(self):
        """Malformed SQL should fail at parse step, not statement type."""
        claims = make_user_claims()
        result = await validate_sql("DROPPPP TABLE users", claims)
        assert result.valid is False
        assert "malformed" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_evaluation_order_type_before_auth(self):
        """Non-SELECT should fail at type check, even if tables are unauthorized."""
        claims = make_user_claims()
        authorized = {"db.allowed"}
        result = await validate_sql(
            "INSERT INTO db.secret (id) VALUES (1)",
            claims,
            authorized_tables=authorized,
        )
        assert result.valid is False
        assert "SELECT" in result.rejection_reason
        # Should not mention table authorization
        assert "not authorized" not in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_multiple_statements_rejected_at_parse(self):
        claims = make_user_claims()
        result = await validate_sql(
            "SELECT 1; DROP TABLE users",
            claims,
        )
        assert result.valid is False
        assert "malformed" in result.rejection_reason.lower()


# --- Partition Filter Tests (Requirement 9.3) ---


class TestPartitionFilter:
    def test_partitioned_table_without_filter_rejected(self):
        """Query on partitioned table without WHERE on partition key is rejected."""
        ast = _parse_sql("SELECT id, name FROM db.events")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = _check_partition_filter(ast, tables, metadata)
        assert result is not None
        assert "partition key" in result.lower()
        assert "event_date" in result

    def test_partitioned_table_with_filter_passes(self):
        """Query on partitioned table with WHERE on partition key passes."""
        ast = _parse_sql(
            "SELECT id, name FROM db.events WHERE event_date = '2024-01-01'"
        )
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = _check_partition_filter(ast, tables, metadata)
        assert result is None

    def test_non_partitioned_table_without_where_passes(self):
        """Query on non-partitioned table without WHERE passes."""
        ast = _parse_sql("SELECT id FROM db.users")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.users": {"partition_keys": [], "column_count": 10}
        }
        result = _check_partition_filter(ast, tables, metadata)
        assert result is None

    def test_table_not_in_metadata_passes(self):
        """Table not in metadata is not checked for partition filter."""
        ast = _parse_sql("SELECT id FROM db.unknown")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {}
        result = _check_partition_filter(ast, tables, metadata)
        assert result is None

    def test_multiple_partition_keys_one_present(self):
        """If table has multiple partition keys, one in WHERE is sufficient."""
        ast = _parse_sql(
            "SELECT id FROM db.events WHERE region = 'us-east-1'"
        )
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date", "region"], "column_count": 10}
        }
        result = _check_partition_filter(ast, tables, metadata)
        assert result is None

    def test_partition_key_in_complex_where(self):
        """Partition key in a complex WHERE clause with AND is detected."""
        ast = _parse_sql(
            "SELECT id FROM db.events WHERE event_date > '2024-01-01' AND status = 'active'"
        )
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = _check_partition_filter(ast, tables, metadata)
        assert result is None

    def test_partition_key_case_insensitive(self):
        """Partition key matching is case-insensitive."""
        ast = _parse_sql(
            "SELECT id FROM db.events WHERE Event_Date = '2024-01-01'"
        )
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = _check_partition_filter(ast, tables, metadata)
        assert result is None


# --- Column Selection Tests (Requirement 9.4) ---


class TestColumnSelection:
    def test_select_star_on_wide_table_rejected(self):
        """SELECT * on table with >50 columns is rejected."""
        ast = _parse_sql("SELECT * FROM db.wide_table")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.wide_table": {"partition_keys": [], "column_count": 75}
        }
        result = _check_column_selection(ast, tables, metadata)
        assert result is not None
        assert "SELECT *" in result
        assert "75" in result
        assert "explicit column names" in result.lower()

    def test_select_star_on_narrow_table_passes(self):
        """SELECT * on table with ≤50 columns passes."""
        ast = _parse_sql("SELECT * FROM db.small_table")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.small_table": {"partition_keys": [], "column_count": 30}
        }
        result = _check_column_selection(ast, tables, metadata)
        assert result is None

    def test_explicit_columns_on_wide_table_passes(self):
        """Explicit column names on wide table passes."""
        ast = _parse_sql("SELECT id, name, email FROM db.wide_table")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.wide_table": {"partition_keys": [], "column_count": 75}
        }
        result = _check_column_selection(ast, tables, metadata)
        assert result is None

    def test_select_star_exactly_50_columns_passes(self):
        """SELECT * on table with exactly 50 columns passes (threshold is >50)."""
        ast = _parse_sql("SELECT * FROM db.border_table")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.border_table": {"partition_keys": [], "column_count": 50}
        }
        result = _check_column_selection(ast, tables, metadata)
        assert result is None

    def test_select_star_51_columns_rejected(self):
        """SELECT * on table with 51 columns is rejected."""
        ast = _parse_sql("SELECT * FROM db.border_table")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.border_table": {"partition_keys": [], "column_count": 51}
        }
        result = _check_column_selection(ast, tables, metadata)
        assert result is not None
        assert "SELECT *" in result

    def test_table_not_in_metadata_passes(self):
        """Table not in metadata is not checked for column count."""
        ast = _parse_sql("SELECT * FROM db.unknown")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {}
        result = _check_column_selection(ast, tables, metadata)
        assert result is None


# --- WHERE Column Extraction Tests ---


class TestWhereColumnExtraction:
    def test_simple_where(self):
        ast = _parse_sql("SELECT id FROM db.events WHERE event_date = '2024-01-01'")
        columns = _extract_where_columns(ast)
        assert "event_date" in columns

    def test_compound_where(self):
        ast = _parse_sql(
            "SELECT id FROM db.events WHERE event_date > '2024-01-01' AND region = 'us'"
        )
        columns = _extract_where_columns(ast)
        assert "event_date" in columns
        assert "region" in columns

    def test_no_where_returns_empty(self):
        ast = _parse_sql("SELECT id FROM db.events")
        columns = _extract_where_columns(ast)
        assert len(columns) == 0


# --- Full validate_sql() Integration Tests for Task 4.2 ---


class TestValidateSqlPartitionAndColumn:
    @pytest.mark.asyncio
    async def test_partitioned_table_without_filter_rejected(self):
        """Validation rejects query on partitioned table without partition filter."""
        claims = make_user_claims()
        authorized = {"db.events"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = await validate_sql(
            "SELECT id FROM db.events",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is False
        assert "partition key" in result.rejection_reason.lower()
        assert "event_date" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_partitioned_table_with_filter_passes(self):
        """Validation passes query on partitioned table with partition filter."""
        claims = make_user_claims()
        authorized = {"db.events"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = await validate_sql(
            "SELECT id FROM db.events WHERE event_date = '2024-01-01'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is True
        assert result.modified_sql is not None

    @pytest.mark.asyncio
    async def test_select_star_on_wide_table_rejected(self):
        """Validation rejects SELECT * on table with >50 columns."""
        claims = make_user_claims()
        authorized = {"db.wide_table"}
        metadata: dict[str, TableMetadata] = {
            "db.wide_table": {"partition_keys": [], "column_count": 75}
        }
        result = await validate_sql(
            "SELECT * FROM db.wide_table",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is False
        assert "SELECT *" in result.rejection_reason
        assert "explicit column names" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_explicit_columns_on_wide_table_passes(self):
        """Validation passes explicit columns on wide table."""
        claims = make_user_claims()
        authorized = {"db.wide_table"}
        metadata: dict[str, TableMetadata] = {
            "db.wide_table": {"partition_keys": [], "column_count": 75}
        }
        result = await validate_sql(
            "SELECT id, name FROM db.wide_table",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_evaluation_order_auth_before_partition(self):
        """Authorization failure should come before partition filter check."""
        claims = make_user_claims()
        authorized = {"db.other"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = await validate_sql(
            "SELECT id FROM db.events",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is False
        assert "not authorized" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_evaluation_order_partition_before_column(self):
        """Partition filter failure should come before column selection check."""
        claims = make_user_claims()
        authorized = {"db.events"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 75}
        }
        # SELECT * without partition filter — partition check should fail first
        result = await validate_sql(
            "SELECT * FROM db.events",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is False
        assert "partition key" in result.rejection_reason.lower()

    @pytest.mark.asyncio
    async def test_metadata_none_skips_partition_and_column_checks(self):
        """When table_metadata is None, partition and column checks are skipped."""
        claims = make_user_claims()
        authorized = {"db.events"}
        result = await validate_sql(
            "SELECT * FROM db.events",
            claims,
            authorized_tables=authorized,
            table_metadata=None,
        )
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_limit_still_injected_after_partition_and_column_pass(self):
        """LIMIT injection still works after partition and column checks pass."""
        claims = make_user_claims()
        authorized = {"db.events"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = await validate_sql(
            "SELECT id FROM db.events WHERE event_date = '2024-01-01'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is True
        assert str(DEFAULT_LIMIT) in result.modified_sql


# --- Cost Threshold Tests (Requirement 9.5) ---


class TestCostThreshold:
    def test_over_10gb_without_elevated_cost_rejected(self):
        """Query estimated >10 GB without elevated_cost group is rejected."""
        claims = make_user_claims(groups=["data-users"])
        ast = _parse_sql("SELECT id FROM db.events WHERE event_date = '2024-01-01'")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        estimated_bytes = COST_THRESHOLD_BYTES + 1  # Just over 10 GB
        result = _check_cost_threshold(ast, tables, metadata, claims, estimated_bytes)
        assert result is not None
        assert "10 GB" in result
        assert "elevated_cost" in result

    def test_over_10gb_with_elevated_cost_allowed(self):
        """Query estimated >10 GB WITH elevated_cost group is allowed."""
        claims = make_user_claims(groups=["data-users", ELEVATED_COST_GROUP])
        ast = _parse_sql("SELECT id FROM db.events WHERE event_date = '2024-01-01'")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        estimated_bytes = COST_THRESHOLD_BYTES + 1_000_000_000  # Well over 10 GB
        result = _check_cost_threshold(ast, tables, metadata, claims, estimated_bytes)
        assert result is None

    def test_under_10gb_without_elevated_cost_allowed(self):
        """Query estimated under 10 GB without elevated_cost is allowed."""
        claims = make_user_claims(groups=["data-users"])
        ast = _parse_sql("SELECT id FROM db.events WHERE event_date = '2024-01-01'")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        estimated_bytes = COST_THRESHOLD_BYTES - 1  # Just under 10 GB
        result = _check_cost_threshold(ast, tables, metadata, claims, estimated_bytes)
        assert result is None

    def test_exactly_10gb_without_elevated_cost_allowed(self):
        """Query estimated exactly 10 GB without elevated_cost is allowed (threshold is >10 GB)."""
        claims = make_user_claims(groups=["data-users"])
        ast = _parse_sql("SELECT id FROM db.events WHERE event_date = '2024-01-01'")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        estimated_bytes = COST_THRESHOLD_BYTES  # Exactly 10 GB
        result = _check_cost_threshold(ast, tables, metadata, claims, estimated_bytes)
        assert result is None

    def test_none_estimated_bytes_skips_cost_check(self):
        """When estimated_bytes_scanned is None, cost check is skipped."""
        claims = make_user_claims(groups=["data-users"])
        ast = _parse_sql("SELECT id FROM db.events WHERE event_date = '2024-01-01'")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = _check_cost_threshold(ast, tables, metadata, claims, None)
        assert result is None


# --- Full-Scan Protection Tests (Requirement 9.7) ---


class TestFullScanProtection:
    def test_full_scan_over_1tb_without_partition_filter_rejected(self):
        """Full table scan on table >1 TB without partition filter rejected without elevated_cost."""
        claims = make_user_claims(groups=["data-users"])
        ast = _parse_sql("SELECT id FROM db.big_table")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.big_table": {
                "partition_keys": ["event_date"],
                "column_count": 10,
                "estimated_size_bytes": FULL_SCAN_THRESHOLD_BYTES + 1,
            }
        }
        result = _check_cost_threshold(ast, tables, metadata, claims, None)
        assert result is not None
        assert "Full table scan" in result
        assert "elevated_cost" in result

    def test_full_scan_over_1tb_with_elevated_cost_allowed(self):
        """Full table scan on table >1 TB WITH elevated_cost group is allowed."""
        claims = make_user_claims(groups=["data-users", ELEVATED_COST_GROUP])
        ast = _parse_sql("SELECT id FROM db.big_table")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.big_table": {
                "partition_keys": ["event_date"],
                "column_count": 10,
                "estimated_size_bytes": FULL_SCAN_THRESHOLD_BYTES + 1,
            }
        }
        result = _check_cost_threshold(ast, tables, metadata, claims, None)
        assert result is None

    def test_full_scan_over_1tb_with_partition_filter_allowed(self):
        """Table >1 TB with partition filter is allowed (no elevated_cost needed)."""
        claims = make_user_claims(groups=["data-users"])
        ast = _parse_sql(
            "SELECT id FROM db.big_table WHERE event_date = '2024-01-01'"
        )
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.big_table": {
                "partition_keys": ["event_date"],
                "column_count": 10,
                "estimated_size_bytes": FULL_SCAN_THRESHOLD_BYTES + 1,
            }
        }
        result = _check_cost_threshold(ast, tables, metadata, claims, None)
        assert result is None

    def test_table_under_1tb_without_partition_filter_allowed(self):
        """Table ≤1 TB without partition filter is not subject to full-scan protection."""
        claims = make_user_claims(groups=["data-users"])
        ast = _parse_sql("SELECT id FROM db.medium_table")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.medium_table": {
                "partition_keys": ["event_date"],
                "column_count": 10,
                "estimated_size_bytes": FULL_SCAN_THRESHOLD_BYTES,  # Exactly 1 TB
            }
        }
        result = _check_cost_threshold(ast, tables, metadata, claims, None)
        assert result is None

    def test_table_over_1tb_no_partition_keys_defined_rejected(self):
        """Table >1 TB with no partition keys defined — full scan rejected."""
        claims = make_user_claims(groups=["data-users"])
        ast = _parse_sql("SELECT id FROM db.huge_unpartitioned")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {
            "db.huge_unpartitioned": {
                "partition_keys": [],
                "column_count": 10,
                "estimated_size_bytes": FULL_SCAN_THRESHOLD_BYTES + 1,
            }
        }
        result = _check_cost_threshold(ast, tables, metadata, claims, None)
        assert result is not None
        assert "Full table scan" in result

    def test_table_not_in_metadata_skips_full_scan_check(self):
        """Table not in metadata does not trigger full-scan protection."""
        claims = make_user_claims(groups=["data-users"])
        ast = _parse_sql("SELECT id FROM db.unknown_table")
        tables = _extract_table_references(ast)
        metadata: dict[str, TableMetadata] = {}
        result = _check_cost_threshold(ast, tables, metadata, claims, None)
        assert result is None


# --- validate_sql() Integration Tests for Cost Check (Task 4.3) ---


class TestValidateSqlCostCheck:
    @pytest.mark.asyncio
    async def test_cost_over_10gb_rejected_without_elevated_cost(self):
        """validate_sql rejects query with estimated >10 GB without elevated_cost."""
        claims = make_user_claims(groups=["data-users"])
        authorized = {"db.events"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        estimated_bytes = COST_THRESHOLD_BYTES + 1_000_000_000  # ~11 GB
        result = await validate_sql(
            "SELECT id FROM db.events WHERE event_date = '2024-01-01'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
            estimated_bytes_scanned=estimated_bytes,
        )
        assert result.valid is False
        assert "10 GB" in result.rejection_reason
        assert "elevated_cost" in result.rejection_reason
        assert result.estimated_bytes == estimated_bytes

    @pytest.mark.asyncio
    async def test_cost_over_10gb_allowed_with_elevated_cost(self):
        """validate_sql allows query with estimated >10 GB WITH elevated_cost."""
        claims = make_user_claims(groups=["data-users", ELEVATED_COST_GROUP])
        authorized = {"db.events"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        estimated_bytes = COST_THRESHOLD_BYTES + 1_000_000_000
        result = await validate_sql(
            "SELECT id FROM db.events WHERE event_date = '2024-01-01'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
            estimated_bytes_scanned=estimated_bytes,
        )
        assert result.valid is True
        assert result.modified_sql is not None
        assert result.estimated_bytes == estimated_bytes

    @pytest.mark.asyncio
    async def test_full_scan_over_1tb_rejected_without_elevated_cost(self):
        """validate_sql rejects full scan on >1 TB non-partitioned table without elevated_cost."""
        claims = make_user_claims(groups=["data-users"])
        authorized = {"db.big_table"}
        metadata: dict[str, TableMetadata] = {
            "db.big_table": {
                "partition_keys": [],
                "column_count": 10,
                "estimated_size_bytes": FULL_SCAN_THRESHOLD_BYTES + 1,
            }
        }
        result = await validate_sql(
            "SELECT id FROM db.big_table WHERE status = 'active'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is False
        assert "Full table scan" in result.rejection_reason
        assert "elevated_cost" in result.rejection_reason

    @pytest.mark.asyncio
    async def test_full_scan_over_1tb_allowed_with_elevated_cost(self):
        """validate_sql allows full scan on >1 TB non-partitioned table WITH elevated_cost."""
        claims = make_user_claims(groups=["data-users", ELEVATED_COST_GROUP])
        authorized = {"db.big_table"}
        metadata: dict[str, TableMetadata] = {
            "db.big_table": {
                "partition_keys": [],
                "column_count": 10,
                "estimated_size_bytes": FULL_SCAN_THRESHOLD_BYTES + 1,
            }
        }
        result = await validate_sql(
            "SELECT id FROM db.big_table WHERE status = 'active'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is True
        assert result.modified_sql is not None

    @pytest.mark.asyncio
    async def test_full_scan_over_1tb_with_partition_filter_allowed(self):
        """validate_sql allows >1 TB table with partition filter (no elevated_cost needed)."""
        claims = make_user_claims(groups=["data-users"])
        authorized = {"db.big_table"}
        metadata: dict[str, TableMetadata] = {
            "db.big_table": {
                "partition_keys": ["event_date"],
                "column_count": 10,
                "estimated_size_bytes": FULL_SCAN_THRESHOLD_BYTES + 1,
            }
        }
        result = await validate_sql(
            "SELECT id FROM db.big_table WHERE event_date = '2024-01-01'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is True
        assert result.modified_sql is not None

    @pytest.mark.asyncio
    async def test_validation_result_includes_estimated_bytes(self):
        """ValidationResult includes estimated_bytes when cost check is performed."""
        claims = make_user_claims(groups=["data-users", ELEVATED_COST_GROUP])
        authorized = {"db.events"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        estimated_bytes = 5_000_000_000  # 5 GB (under threshold)
        result = await validate_sql(
            "SELECT id FROM db.events WHERE event_date = '2024-01-01'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
            estimated_bytes_scanned=estimated_bytes,
        )
        assert result.valid is True
        assert result.estimated_bytes == estimated_bytes

    @pytest.mark.asyncio
    async def test_validation_result_estimated_bytes_none_when_not_provided(self):
        """ValidationResult has estimated_bytes=None when not provided."""
        claims = make_user_claims(groups=["data-users"])
        authorized = {"db.events"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        result = await validate_sql(
            "SELECT id FROM db.events WHERE event_date = '2024-01-01'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
        )
        assert result.valid is True
        assert result.estimated_bytes is None

    @pytest.mark.asyncio
    async def test_evaluation_order_column_check_before_cost_check(self):
        """Column selection failure (step 5) should come before cost check (step 6)."""
        claims = make_user_claims(groups=["data-users"])
        authorized = {"db.wide_table"}
        metadata: dict[str, TableMetadata] = {
            "db.wide_table": {
                "partition_keys": [],
                "column_count": 75,
                "estimated_size_bytes": FULL_SCAN_THRESHOLD_BYTES + 1,
            }
        }
        estimated_bytes = COST_THRESHOLD_BYTES + 1_000_000_000
        result = await validate_sql(
            "SELECT * FROM db.wide_table",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
            estimated_bytes_scanned=estimated_bytes,
        )
        assert result.valid is False
        # Should fail at column selection (step 5), not cost (step 6)
        assert "SELECT *" in result.rejection_reason
        assert "10 GB" not in result.rejection_reason

    @pytest.mark.asyncio
    async def test_limit_injected_after_cost_check_passes(self):
        """LIMIT is still injected when cost check passes."""
        claims = make_user_claims(groups=["data-users"])
        authorized = {"db.events"}
        metadata: dict[str, TableMetadata] = {
            "db.events": {"partition_keys": ["event_date"], "column_count": 10}
        }
        estimated_bytes = 5_000_000_000  # Under threshold
        result = await validate_sql(
            "SELECT id FROM db.events WHERE event_date = '2024-01-01'",
            claims,
            authorized_tables=authorized,
            table_metadata=metadata,
            estimated_bytes_scanned=estimated_bytes,
        )
        assert result.valid is True
        assert str(DEFAULT_LIMIT) in result.modified_sql
