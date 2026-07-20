"""Property-based tests for SQL Safety Invariant.

Tests verify that only validated SELECT statements with LIMIT and within cost
threshold ever pass validation. Non-SELECT statements are always rejected,
unparseable SQL is always rejected, and valid SELECT queries always have
LIMIT injected if not present.

**Validates: Requirements 9.1, 9.2, 9.6**

Properties tested:
- Property 11: SQL Safety Invariant — only validated SELECT with LIMIT and within
  cost threshold executes
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from hypothesis import given, assume, settings
from hypothesis import strategies as st

from chatbot.mcp_server.validation import (
    DEFAULT_LIMIT,
    ValidationResult,
    validate_sql,
)
from chatbot.api.models import UserClaims


# ─── Test infrastructure ──────────────────────────────────────────────────────


def _make_user_claims() -> UserClaims:
    """Create a valid UserClaims for testing SQL validation."""
    return UserClaims(
        sub="user-test-sql-safety",
        department="analytics",
        role="analyst",
        data_classification_tier="confidential",
        groups=["data-users", "analytics-team"],
        session_id=str(uuid.uuid4()),
        exp=9999999999,
    )


# A permissive authorized table set for tests that focus on SQL structure
AUTHORIZED_TABLES = {
    "analytics_db.transactions",
    "analytics_db.users",
    "analytics_db.orders",
    "analytics_db.events",
    "finance_db.ledger",
    "finance_db.accounts",
    "hr_db.employees",
    "reporting_db.summary",
    "transactions",
    "users",
    "orders",
    "events",
    "ledger",
    "accounts",
    "employees",
    "summary",
}


def _run_validate(sql: str, authorized_tables: set[str] | None = None) -> ValidationResult:
    """Run validate_sql synchronously for property tests."""
    claims = _make_user_claims()
    tables = authorized_tables if authorized_tables is not None else AUTHORIZED_TABLES
    return asyncio.get_event_loop().run_until_complete(
        validate_sql(sql, claims, authorized_tables=tables)
    )


# ─── Hypothesis Strategies ────────────────────────────────────────────────────

# Strategy for SQL statement keywords that are NOT SELECT (Requirement 9.2)
non_select_keywords = st.sampled_from([
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
    "TRUNCATE", "MERGE", "REPLACE", "GRANT", "REVOKE",
])

# Strategy for table names
table_names = st.sampled_from([
    "transactions", "users", "orders", "events",
    "ledger", "accounts", "employees", "summary",
])

# Strategy for column names
column_names = st.sampled_from([
    "id", "name", "amount", "date", "status", "category",
    "created_at", "updated_at", "user_id", "total",
])

# Strategy for WHERE conditions
where_conditions = st.sampled_from([
    "id > 0",
    "status = 'active'",
    "amount > 100",
    "date >= '2024-01-01'",
    "category = 'A'",
    "user_id = 123",
])

# Strategy for LIMIT values
limit_values = st.integers(min_value=1, max_value=100_000)


@st.composite
def non_select_sql(draw) -> str:
    """Generate non-SELECT SQL statements that should always be rejected.

    Generates INSERT, UPDATE, DELETE, DROP, ALTER, CREATE statements
    targeting valid tables.
    """
    keyword = draw(non_select_keywords)
    table = draw(table_names)

    if keyword == "INSERT":
        col = draw(column_names)
        return f"INSERT INTO {table} ({col}) VALUES ('test')"
    elif keyword == "UPDATE":
        col = draw(column_names)
        return f"UPDATE {table} SET {col} = 'modified' WHERE id = 1"
    elif keyword == "DELETE":
        return f"DELETE FROM {table} WHERE id = 1"
    elif keyword == "DROP":
        variant = draw(st.sampled_from(["TABLE", "VIEW", "INDEX"]))
        return f"DROP {variant} {table}"
    elif keyword == "ALTER":
        col = draw(column_names)
        return f"ALTER TABLE {table} ADD COLUMN {col} VARCHAR(255)"
    elif keyword == "CREATE":
        variant = draw(st.sampled_from(["TABLE", "VIEW"]))
        col = draw(column_names)
        return f"CREATE {variant} {table}_new AS SELECT {col} FROM {table}"
    elif keyword == "TRUNCATE":
        return f"TRUNCATE TABLE {table}"
    elif keyword == "MERGE":
        col = draw(column_names)
        return f"MERGE INTO {table} USING source ON {table}.id = source.id WHEN MATCHED THEN UPDATE SET {col} = source.{col}"
    elif keyword == "REPLACE":
        col = draw(column_names)
        return f"REPLACE INTO {table} ({col}) VALUES ('test')"
    elif keyword == "GRANT":
        return f"GRANT SELECT ON {table} TO user1"
    elif keyword == "REVOKE":
        return f"REVOKE SELECT ON {table} FROM user1"
    else:
        return f"{keyword} {table}"


@st.composite
def valid_select_without_limit(draw) -> str:
    """Generate valid SELECT statements WITHOUT an explicit LIMIT clause.

    These should pass validation and have LIMIT 10000 injected.
    """
    table = draw(table_names)
    cols = draw(st.lists(column_names, min_size=1, max_size=4, unique=True))
    col_list = ", ".join(cols)

    use_where = draw(st.booleans())
    where_clause = ""
    if use_where:
        condition = draw(where_conditions)
        where_clause = f" WHERE {condition}"

    return f"SELECT {col_list} FROM {table}{where_clause}"


@st.composite
def valid_select_with_limit(draw) -> str:
    """Generate valid SELECT statements WITH an explicit LIMIT clause.

    These should pass validation with their existing LIMIT preserved.
    """
    table = draw(table_names)
    cols = draw(st.lists(column_names, min_size=1, max_size=4, unique=True))
    col_list = ", ".join(cols)

    use_where = draw(st.booleans())
    where_clause = ""
    if use_where:
        condition = draw(where_conditions)
        where_clause = f" WHERE {condition}"

    limit = draw(limit_values)
    return f"SELECT {col_list} FROM {table}{where_clause} LIMIT {limit}"


@st.composite
def malformed_sql(draw) -> str:
    """Generate strings that are not valid SQL and cannot be parsed.

    These should always be rejected at the parse step (Requirement 9.1).
    Note: sqlglot is permissive — bare "SELECT" parses as valid. We focus
    on genuinely unparseable strings: gibberish, mismatched brackets,
    multiple statements (rejected by validation), and empty input.
    """
    strategy = draw(st.integers(min_value=0, max_value=4))

    if strategy == 0:
        # Random gibberish that doesn't start with SQL keywords
        return draw(st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "P")),
            min_size=5,
            max_size=50,
        ).filter(lambda s: not s.strip().upper().startswith(("SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER"))))
    elif strategy == 1:
        # Multiple statements (semicolons) — rejected as multi-statement
        table = draw(table_names)
        return f"SELECT id FROM {table}; SELECT name FROM {table}"
    elif strategy == 2:
        # Empty or whitespace
        return draw(st.sampled_from(["", "   ", "\n\t", "  \t  \n  "]))
    elif strategy == 3:
        # Truly broken syntax with unbalanced quotes/brackets
        table = draw(table_names)
        return draw(st.sampled_from([
            f"SELECT 'unclosed FROM {table}",
            f"SELECT id FROM {table} WHERE name = 'test",
            f"SELECT ((( FROM {table}",
            f"SELECT id FROM {table} GROUP BY HAVING",
        ]))
    else:
        # Non-SQL gibberish
        return draw(st.sampled_from([
            "SELCT id FROM table1",
            "!!!@@@###$$$",
            "not sql at all",
            "xyz 123 abc",
            "the quick brown fox",
        ]))


# ─── Property 11: SQL Safety Invariant ────────────────────────────────────────


class TestSQLSafetyInvariant:
    """Property 11: SQL Safety Invariant.

    **Validates: Requirements 9.1, 9.2, 9.6**

    Only validated SELECT statements with LIMIT and within cost threshold
    ever execute. Non-SELECT is always rejected. Unparseable SQL is always
    rejected. Valid SELECT always gets LIMIT injected if missing.
    """

    @given(sql=non_select_sql())
    @settings(max_examples=200)
    def test_non_select_statements_always_rejected(self, sql: str):
        """Non-SELECT SQL statements (INSERT, UPDATE, DELETE, DROP, ALTER, CREATE)
        are ALWAYS rejected by the validation engine.

        **Validates: Requirements 9.2**
        """
        result = _run_validate(sql)

        assert result.valid is False, (
            f"Non-SELECT statement should be rejected but was accepted: {sql!r}"
        )
        assert result.modified_sql is None, (
            f"Rejected SQL should have no modified_sql: {sql!r}"
        )
        assert result.rejection_reason is not None, (
            f"Rejected SQL should have a rejection_reason: {sql!r}"
        )

    @given(sql=malformed_sql())
    @settings(max_examples=200)
    def test_unparseable_sql_always_rejected(self, sql: str):
        """Malformed SQL that cannot be parsed into a valid AST is always rejected.

        **Validates: Requirements 9.1**
        """
        result = _run_validate(sql)

        assert result.valid is False, (
            f"Unparseable SQL should be rejected but was accepted: {sql!r}"
        )
        assert result.modified_sql is None, (
            f"Rejected SQL should have no modified_sql: {sql!r}"
        )
        assert result.rejection_reason is not None, (
            f"Rejected SQL should have a rejection_reason: {sql!r}"
        )

    @given(sql=valid_select_without_limit())
    @settings(max_examples=200)
    def test_valid_select_without_limit_gets_limit_injected(self, sql: str):
        """Valid SELECT statements without LIMIT always have LIMIT 10000 injected.

        When a validated SELECT does not include an explicit LIMIT, the system
        injects LIMIT 10000 before execution. The result is always valid with
        modified_sql containing the LIMIT clause.

        **Validates: Requirements 9.6**
        """
        result = _run_validate(sql)

        assert result.valid is True, (
            f"Valid SELECT should pass validation: {sql!r}\n"
            f"Rejection reason: {result.rejection_reason}"
        )
        assert result.modified_sql is not None, (
            f"Valid SQL should have modified_sql: {sql!r}"
        )
        # The modified SQL must contain LIMIT
        assert "LIMIT" in result.modified_sql.upper() or "limit" in result.modified_sql, (
            f"Modified SQL must contain LIMIT clause: {result.modified_sql!r}"
        )

    @given(sql=valid_select_with_limit())
    @settings(max_examples=200)
    def test_valid_select_with_limit_preserves_limit(self, sql: str):
        """Valid SELECT statements with explicit LIMIT pass and preserve the LIMIT.

        **Validates: Requirements 9.6**
        """
        result = _run_validate(sql)

        assert result.valid is True, (
            f"Valid SELECT with LIMIT should pass validation: {sql!r}\n"
            f"Rejection reason: {result.rejection_reason}"
        )
        assert result.modified_sql is not None, (
            f"Valid SQL should have modified_sql: {sql!r}"
        )
        # The modified SQL must still contain LIMIT
        assert "LIMIT" in result.modified_sql.upper() or "limit" in result.modified_sql, (
            f"Modified SQL must retain LIMIT clause: {result.modified_sql!r}"
        )

    @given(sql=valid_select_without_limit())
    @settings(max_examples=200)
    def test_validated_sql_is_always_select_with_limit(self, sql: str):
        """Core invariant: if validate_sql returns valid=True, the modified_sql
        is ALWAYS a SELECT statement with a LIMIT clause.

        This is the SQL Safety Invariant: no SQL passes through without being
        SELECT + LIMIT.

        **Validates: Requirements 9.1, 9.2, 9.6**
        """
        result = _run_validate(sql)

        if result.valid:
            # Invariant: modified_sql must exist
            assert result.modified_sql is not None

            # Invariant: must be parseable as SELECT
            modified_upper = result.modified_sql.upper().strip()
            assert modified_upper.startswith("SELECT"), (
                f"Valid result must be a SELECT statement: {result.modified_sql!r}"
            )

            # Invariant: must contain LIMIT
            assert "LIMIT" in modified_upper, (
                f"Valid result must contain LIMIT: {result.modified_sql!r}"
            )

    @given(
        sql=st.one_of(non_select_sql(), malformed_sql(), valid_select_without_limit(), valid_select_with_limit())
    )
    @settings(max_examples=300)
    def test_safety_invariant_universal(self, sql: str):
        """Universal safety property: for ANY input SQL, the output either:
        1. valid=False (rejected) — no SQL executes
        2. valid=True — modified_sql is a SELECT with LIMIT

        No other outcome is possible. This ensures the safety invariant holds
        regardless of what input the LLM produces.

        **Validates: Requirements 9.1, 9.2, 9.6**
        """
        result = _run_validate(sql)

        if result.valid:
            # If valid: must have modified_sql that is SELECT with LIMIT
            assert result.modified_sql is not None, (
                "Valid result must always have modified_sql"
            )
            modified_upper = result.modified_sql.upper().strip()
            assert modified_upper.startswith("SELECT"), (
                f"Valid result must be SELECT: {result.modified_sql!r}"
            )
            assert "LIMIT" in modified_upper, (
                f"Valid result must have LIMIT: {result.modified_sql!r}"
            )
            # rejection_reason should be None for valid results
            assert result.rejection_reason is None, (
                f"Valid result should not have rejection_reason: {result.rejection_reason}"
            )
        else:
            # If invalid: must have rejection_reason and no modified_sql
            assert result.rejection_reason is not None, (
                f"Invalid result must have rejection_reason for SQL: {sql!r}"
            )
            assert result.modified_sql is None, (
                f"Invalid result must not have modified_sql for SQL: {sql!r}"
            )
