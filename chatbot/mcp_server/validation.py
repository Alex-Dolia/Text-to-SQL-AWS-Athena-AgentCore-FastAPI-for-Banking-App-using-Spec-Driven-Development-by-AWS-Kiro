"""SQL validation engine for the chatbot security architecture.

Validates LLM-generated SQL before execution against Athena. Enforces
deterministic safety rules in a strict evaluation order (Requirement 9.9):

1. Parse validity — can it be parsed into an AST?
2. Statement type — is it SELECT?
3. Table authorization — are all referenced tables authorized for this user?
4. Partition filter — do partitioned tables have WHERE on partition key?
5. Column selection — no SELECT * on tables with >50 columns?
6. Scan size — within cost threshold?
7. LIMIT injection — add LIMIT 10000 if not present

Uses sqlglot for SQL parsing with Athena/Presto dialect support.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

import sqlglot
from sqlglot import exp as sqlglot_exp
from sqlglot.errors import ParseError, TokenError

from chatbot.api.models import UserClaims


@dataclass
class ValidationResult:
    """Result of SQL validation.

    Attributes:
        valid: Whether the SQL passed all validation checks.
        modified_sql: The SQL with LIMIT injected (if valid).
        rejection_reason: Human-readable reason for rejection (if invalid).
        estimated_bytes: Estimated bytes to be scanned (populated in cost check step).
    """

    valid: bool
    modified_sql: str | None = None
    rejection_reason: str | None = None
    estimated_bytes: int | None = None


class TableMetadata(TypedDict, total=False):
    """Metadata about a table used for partition and column validation.

    Attributes:
        partition_keys: List of partition key column names for the table.
        column_count: Total number of columns in the table.
        estimated_size_bytes: Estimated total size of the table in bytes.
    """

    partition_keys: list[str]
    column_count: int
    estimated_size_bytes: int


# Default row limit injected when no explicit LIMIT is present (Requirement 9.6)
DEFAULT_LIMIT = 10_000

# Cost threshold: 10 GB in bytes (Requirement 9.5)
COST_THRESHOLD_BYTES = 10_737_418_240

# Full-scan protection: 1 TB in bytes (Requirement 9.7)
FULL_SCAN_THRESHOLD_BYTES = 1_099_511_627_776

# Group name that allows elevated cost queries
ELEVATED_COST_GROUP = "elevated_cost"

# Athena/Presto dialect for sqlglot parsing
DIALECT = "trino"


def _parse_sql(sql: str) -> sqlglot_exp.Expression | None:
    """Parse SQL string into an AST using sqlglot.

    Returns the parsed expression or None if parsing fails.
    Uses Trino dialect since Athena is Presto/Trino-compatible.
    """
    try:
        statements = sqlglot.parse(sql, dialect=DIALECT)
        if not statements or statements[0] is None:
            return None
        # Only single-statement SQL is allowed
        if len(statements) > 1:
            return None
        return statements[0]
    except (ParseError, TokenError):
        return None


def _is_select_statement(expression: sqlglot_exp.Expression) -> bool:
    """Check if the parsed expression is a SELECT statement.

    Rejects INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, and any other
    non-SELECT statement type (Requirement 9.2).
    """
    return isinstance(expression, sqlglot_exp.Select)


def _extract_table_references(expression: sqlglot_exp.Expression) -> set[str]:
    """Extract all table references from the SQL AST.

    Finds tables in all locations (Requirement 9.8):
    - FROM clauses
    - JOIN clauses
    - Subqueries
    - Common Table Expressions (CTEs)

    Returns a set of fully-qualified table names in "database.table" format
    or just "table" if no database qualifier is present.
    """
    tables: set[str] = set()

    for table_node in expression.find_all(sqlglot_exp.Table):
        table_name = table_node.name
        if not table_name:
            continue

        # Build qualified name: database.table or just table
        db = table_node.db
        if db:
            qualified = f"{db}.{table_name}"
        else:
            qualified = table_name

        # Skip CTE references — they are not real table references
        # CTE names will be resolved separately
        tables.add(qualified.lower())

    # Remove CTE aliases from the table set — CTE names are defined in the
    # query itself, not external tables
    cte_names: set[str] = set()
    for cte in expression.find_all(sqlglot_exp.CTE):
        alias = cte.alias
        if alias:
            cte_names.add(alias.lower())

    tables -= cte_names

    return tables


def _check_table_authorization(
    tables: set[str], authorized_tables: set[str]
) -> str | None:
    """Check if all referenced tables are in the user's authorized set.

    Args:
        tables: Set of table references extracted from the SQL.
        authorized_tables: User's pre-computed authorized table set.

    Returns:
        None if all tables are authorized, or an error message naming
        the first unauthorized table found (Requirement 9.8).
    """
    # Normalize authorized tables to lowercase for case-insensitive comparison
    normalized_authorized = {t.lower() for t in authorized_tables}

    for table in sorted(tables):  # Sort for deterministic error messages
        if table not in normalized_authorized:
            return (
                f"Table '{table}' is not authorized for your account. "
                f"You can only query tables in your authorized set."
            )

    return None


def _extract_where_columns(expression: sqlglot_exp.Expression) -> set[str]:
    """Extract all column names referenced in WHERE clauses.

    Traverses all WHERE clauses in the query (including subqueries)
    and collects the column names used in conditions.

    Returns a set of lowercase column names found in WHERE clauses.
    """
    columns: set[str] = set()

    for where_node in expression.find_all(sqlglot_exp.Where):
        for col in where_node.find_all(sqlglot_exp.Column):
            col_name = col.name
            if col_name:
                columns.add(col_name.lower())

    return columns


def _check_partition_filter(
    expression: sqlglot_exp.Expression,
    tables: set[str],
    table_metadata: dict[str, TableMetadata],
) -> str | None:
    """Check that partitioned tables have WHERE on at least one partition key.

    For each referenced table that has partition_keys defined in its metadata,
    verifies the WHERE clause references at least one of those partition keys
    (Requirement 9.3).

    Args:
        expression: Parsed SQL AST.
        tables: Set of table references extracted from the SQL.
        table_metadata: Metadata dict keyed by table name (lowercase).

    Returns:
        None if all partitioned tables have appropriate filters,
        or an error message if a partitioned table is missing a partition filter.
    """
    where_columns = _extract_where_columns(expression)

    for table in sorted(tables):  # Sort for deterministic error messages
        metadata = table_metadata.get(table)
        if metadata is None:
            continue

        partition_keys = metadata.get("partition_keys", [])
        if not partition_keys:
            continue

        # Check if at least one partition key is referenced in WHERE
        partition_keys_lower = {pk.lower() for pk in partition_keys}
        if not where_columns & partition_keys_lower:
            partition_key_list = ", ".join(sorted(partition_keys))
            return (
                f"Query on partitioned table '{table}' must include a WHERE clause "
                f"filtering on at least one partition key: {partition_key_list}."
            )

    return None


def _has_select_star(expression: sqlglot_exp.Expression) -> bool:
    """Check if the outermost SELECT uses SELECT * (Star node).

    Returns True if the query uses SELECT * at any level that references
    actual tables (not subquery aliases).
    """
    # Check the top-level select expressions for Star nodes
    for select_expr in expression.find_all(sqlglot_exp.Star):
        return True
    return False


def _check_column_selection(
    expression: sqlglot_exp.Expression,
    tables: set[str],
    table_metadata: dict[str, TableMetadata],
) -> str | None:
    """Check that SELECT * is not used on tables with >50 columns.

    If the query uses SELECT * and any referenced table has more than 50
    columns, the query is rejected (Requirement 9.4).

    Args:
        expression: Parsed SQL AST.
        tables: Set of table references extracted from the SQL.
        table_metadata: Metadata dict keyed by table name (lowercase).

    Returns:
        None if column selection is valid, or an error message if SELECT *
        is used on a wide table.
    """
    if not _has_select_star(expression):
        return None

    # SELECT * is present — check if any referenced table has >50 columns
    for table in sorted(tables):  # Sort for deterministic error messages
        metadata = table_metadata.get(table)
        if metadata is None:
            continue

        column_count = metadata.get("column_count", 0)
        if column_count > 50:
            return (
                f"SELECT * is not permitted on table '{table}' which has "
                f"{column_count} columns (exceeds 50-column limit). "
                f"Please specify explicit column names."
            )

    return None


def _check_cost_threshold(
    expression: sqlglot_exp.Expression,
    tables: set[str],
    table_metadata: dict[str, TableMetadata],
    user_claims: UserClaims,
    estimated_bytes_scanned: int | None,
) -> str | None:
    """Check scan size constraints: full-scan protection and cost threshold.

    Implements two checks in order:
    1. Full-scan protection (Requirement 9.7): If any referenced table has
       estimated_size_bytes > 1 TB AND no WHERE clause filters on a partition
       key for that table, reject unless user has elevated_cost group.
    2. Cost threshold (Requirement 9.5): If estimated_bytes_scanned > 10 GB,
       reject unless user has elevated_cost group.

    Args:
        expression: Parsed SQL AST.
        tables: Set of table references extracted from the SQL.
        table_metadata: Metadata dict keyed by table name (lowercase).
        user_claims: Validated user claims from JWT.
        estimated_bytes_scanned: Simulated Athena dry-run result (bytes).

    Returns:
        None if checks pass, or rejection reason string.
    """
    has_elevated_cost = ELEVATED_COST_GROUP in user_claims.groups

    # Check 1: Full-scan protection (Requirement 9.7)
    if not has_elevated_cost:
        where_columns = _extract_where_columns(expression)

        for table in sorted(tables):
            metadata = table_metadata.get(table)
            if metadata is None:
                continue

            estimated_size = metadata.get("estimated_size_bytes", 0)
            if estimated_size <= FULL_SCAN_THRESHOLD_BYTES:
                continue

            # Table is > 1 TB — check if query has partition filter for it
            partition_keys = metadata.get("partition_keys", [])
            partition_keys_lower = {pk.lower() for pk in partition_keys}

            # If table has no partition keys defined, or WHERE doesn't filter
            # on any partition key, this is a full table scan
            if not partition_keys_lower or not (where_columns & partition_keys_lower):
                return (
                    f"Full table scan on '{table}' (>{estimated_size // (1024**4):.0f} TB) "
                    f"requires the elevated_cost entitlement. "
                    f"Add partition filters or request elevated_cost access."
                )

    # Check 2: Cost threshold (Requirement 9.5)
    if estimated_bytes_scanned is not None and not has_elevated_cost:
        if estimated_bytes_scanned > COST_THRESHOLD_BYTES:
            estimated_gb = estimated_bytes_scanned / (1024**3)
            return (
                f"Estimated scan size ({estimated_gb:.1f} GB) exceeds the 10 GB limit. "
                f"Please add date or partition filters to reduce scan size, "
                f"or request elevated_cost access."
            )

    return None


def _inject_limit(expression: sqlglot_exp.Expression) -> sqlglot_exp.Expression:
    """Inject LIMIT 10000 if no explicit LIMIT clause is present (Requirement 9.6).

    If a LIMIT is already present, the SQL is returned unchanged.
    """
    # Check if there's already a LIMIT clause on the outermost SELECT
    existing_limit = expression.find(sqlglot_exp.Limit)

    # Only inject if there's no LIMIT at the top level
    if existing_limit is None:
        expression = expression.limit(DEFAULT_LIMIT)

    return expression


async def validate_sql(
    sql: str,
    user_claims: UserClaims,
    authorized_tables: set[str] | None = None,
    table_metadata: dict[str, TableMetadata] | None = None,
    estimated_bytes_scanned: int | None = None,
) -> ValidationResult:
    """Validate and sanitize SQL before execution.

    Implements the full validation pipeline in strict evaluation order
    (Requirement 9.9):
    - Step 1: Parse validity
    - Step 2: Statement type check
    - Step 3: Table authorization
    - Step 4: Partition filter check
    - Step 5: Column selection check
    - Step 6: Scan size check (Requirements 9.5, 9.7)
    - Step 7: LIMIT injection

    Args:
        sql: Non-empty SQL string generated by the LLM.
        user_claims: Validated user claims from JWT.
        authorized_tables: User's pre-computed set of authorized tables.
            If None, authorization check is skipped (for testing).
        table_metadata: Dict of table metadata keyed by table name (lowercase).
            Contains partition_keys, column_count, and estimated_size_bytes.
            If None, partition, column, and cost checks are skipped (for testing).
        estimated_bytes_scanned: Simulated Athena dry-run estimate of bytes
            to be scanned. If None, cost threshold check is skipped.

    Returns:
        ValidationResult with valid=True and modified_sql (LIMIT injected)
        if all checks pass, or valid=False with rejection_reason if any
        check fails.
    """
    if not sql or not sql.strip():
        return ValidationResult(
            valid=False,
            rejection_reason="SQL statement is empty or contains only whitespace.",
        )

    # Step 1: Parse validity (Requirement 9.1)
    expression = _parse_sql(sql)
    if expression is None:
        return ValidationResult(
            valid=False,
            rejection_reason=(
                "SQL is malformed and cannot be parsed into a valid abstract syntax tree."
            ),
        )

    # Step 2: Statement type check (Requirement 9.2)
    if not _is_select_statement(expression):
        return ValidationResult(
            valid=False,
            rejection_reason=(
                "Only SELECT statements are permitted. "
                "INSERT, UPDATE, DELETE, DROP, ALTER, CREATE and other statements are not allowed."
            ),
        )

    # Step 3: Table authorization (Requirement 9.8)
    tables = _extract_table_references(expression)
    if authorized_tables is not None:
        auth_error = _check_table_authorization(tables, authorized_tables)
        if auth_error is not None:
            return ValidationResult(
                valid=False,
                rejection_reason=auth_error,
            )

    # Step 4: Partition filter check (Requirement 9.3)
    if table_metadata is not None:
        partition_error = _check_partition_filter(expression, tables, table_metadata)
        if partition_error is not None:
            return ValidationResult(
                valid=False,
                rejection_reason=partition_error,
            )

    # Step 5: Column selection check (Requirement 9.4)
    if table_metadata is not None:
        column_error = _check_column_selection(expression, tables, table_metadata)
        if column_error is not None:
            return ValidationResult(
                valid=False,
                rejection_reason=column_error,
            )

    # Step 6: Scan size check (Requirement 9.5, 9.7)
    if table_metadata is not None:
        cost_error = _check_cost_threshold(
            expression, tables, table_metadata, user_claims, estimated_bytes_scanned
        )
        if cost_error is not None:
            return ValidationResult(
                valid=False,
                rejection_reason=cost_error,
                estimated_bytes=estimated_bytes_scanned,
            )

    # Step 7: LIMIT injection (Requirement 9.6)
    modified_expression = _inject_limit(expression)
    modified_sql = modified_expression.sql(dialect=DIALECT)

    return ValidationResult(
        valid=True,
        modified_sql=modified_sql,
        estimated_bytes=estimated_bytes_scanned,
    )
