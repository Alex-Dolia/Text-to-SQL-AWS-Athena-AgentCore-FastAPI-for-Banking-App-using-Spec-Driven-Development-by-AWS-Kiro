"""SQL validation node — delegates to the validation engine.

Validates the generated SQL using the deterministic validation engine
in chatbot.mcp_server.validation. This provides a security boundary
ensuring only safe, bounded, authorized SELECT queries proceed to
execution (Requirements 9.1-9.9).

This node does NOT execute the SQL — it only validates the AST and
updates the state with the validation result.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from chatbot.api.models import UserClaims
from chatbot.mcp_server.validation import ValidationResult, validate_sql as _validate

logger = logging.getLogger(__name__)


def _build_user_claims(claims_dict: dict[str, Any]) -> UserClaims:
    """Build a UserClaims instance from the state dictionary.

    Args:
        claims_dict: Dictionary of user claims from the graph state.

    Returns:
        UserClaims Pydantic model instance.
    """
    return UserClaims(
        sub=claims_dict.get("sub", ""),
        department=claims_dict.get("department", ""),
        role=claims_dict.get("role", ""),
        data_classification_tier=claims_dict.get(
            "data_classification_tier", "public"
        ),
        groups=claims_dict.get("groups", []),
        session_id=claims_dict.get("session_id", "00000000-0000-4000-8000-000000000000"),
        exp=claims_dict.get("exp", 9999999999),
    )


def _get_authorized_tables(user_claims: dict[str, Any]) -> set[str] | None:
    """Retrieve the user's pre-computed authorized table set.

    In production, this is populated from Lake Formation grants at
    session start and cached in AgentCore Memory.

    Args:
        user_claims: User claims dictionary.

    Returns:
        Set of authorized table names or None if unavailable.
    """
    # Authorized tables are expected to be in the session state.
    # If not available, authorization check is skipped (handled by
    # Lake Formation at execution time as second layer).
    authorized = user_claims.get("authorized_tables")
    if authorized and isinstance(authorized, (list, set)):
        return set(authorized)
    return None


def _get_table_metadata(
    retrieved_schemas: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Build table metadata from retrieved schemas for validation checks.

    Extracts partition_keys and column_count from the retrieved schemas
    to support partition filter and column selection validation.

    Args:
        retrieved_schemas: List of schema dictionaries from RAG retrieval.

    Returns:
        Dictionary mapping table names to metadata, or None if unavailable.
    """
    if not retrieved_schemas:
        return None

    metadata: dict[str, Any] = {}
    for schema in retrieved_schemas:
        db = schema.get("database", "")
        table = schema.get("table_name", "")
        if not table:
            continue

        key = f"{db}.{table}".lower() if db else table.lower()
        columns = schema.get("columns", [])
        partition_keys = schema.get("partition_keys", [])

        metadata[key] = {
            "partition_keys": partition_keys,
            "column_count": len(columns),
        }

    return metadata if metadata else None


def validate_sql_node(state: dict[str, Any]) -> dict[str, Any]:
    """Validate generated SQL via the deterministic validation engine.

    Delegates to chatbot.mcp_server.validation.validate_sql() which
    enforces the full validation pipeline:
    1. Parse validity
    2. Statement type (SELECT only)
    3. Table authorization
    4. Partition filter
    5. Column selection
    6. Scan size check
    7. LIMIT injection

    Args:
        state: GraphState with generated_sql, user_claims, retrieved_schemas.

    Returns:
        Updated state with sql_valid, generated_sql (modified with LIMIT),
        or sql_error if validation failed.
    """
    generated_sql = state.get("generated_sql")
    user_claims = state.get("user_claims", {})
    retrieved_schemas = state.get("retrieved_schemas", [])

    if not generated_sql:
        return {
            **state,
            "sql_valid": False,
            "sql_error": "No SQL to validate",
        }

    # Build UserClaims for the validation engine
    try:
        claims = _build_user_claims(user_claims)
    except Exception as e:
        logger.error("Failed to build UserClaims for validation: %s", e)
        return {
            **state,
            "sql_valid": False,
            "sql_error": f"Invalid user claims: {e}",
        }

    # Get authorized tables and table metadata
    authorized_tables = _get_authorized_tables(user_claims)
    table_metadata = _get_table_metadata(retrieved_schemas)

    # Run the async validation engine
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in an async context, create a new task
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                result: ValidationResult = pool.submit(
                    asyncio.run,
                    _validate(generated_sql, claims, authorized_tables, table_metadata),
                ).result()
        else:
            result = asyncio.run(
                _validate(generated_sql, claims, authorized_tables, table_metadata)
            )
    except Exception as e:
        logger.error("SQL validation engine error: %s", e)
        return {
            **state,
            "sql_valid": False,
            "sql_error": f"Validation engine error: {e}",
        }

    if result.valid:
        logger.info("SQL validation passed. Modified SQL has LIMIT injected.")
        return {
            **state,
            "sql_valid": True,
            "generated_sql": result.modified_sql or generated_sql,
            "sql_error": None,
        }
    else:
        logger.info("SQL validation failed: %s", result.rejection_reason)
        return {
            **state,
            "sql_valid": False,
            "sql_error": result.rejection_reason,
        }
