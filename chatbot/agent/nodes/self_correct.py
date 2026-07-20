"""Self-correction node for SQL rewrite on error.

When a SQL query fails execution, this node attempts to rewrite the SQL
based on the error message. Bounded to a maximum of 2 retries via graph
edge conditions (Requirement 10.3).

Uses Claude Sonnet with temperature=0 for deterministic correction.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Claude Sonnet for SQL correction
SONNET_MODEL_ID = "anthropic.claude-sonnet-4-20250514"

# Maximum self-correction retries (structural bound, Requirement 10.3)
MAX_SELF_CORRECTION_RETRIES = 2

# Bedrock client configuration
_bedrock_config = Config(
    read_timeout=30,
    connect_timeout=5,
    retries={"max_attempts": 1},
)

CORRECTION_PROMPT = """You are a SQL expert for Amazon Athena (Presto/Trino dialect).
The following SQL query failed with an error. Please fix the SQL query.

Original user question: {user_message}

Failed SQL:
{failed_sql}

Error message:
{error_message}

Available table schemas:
{schemas_context}

RULES:
- Generate ONLY a corrected SELECT statement.
- Fix the specific error while preserving the query intent.
- Use proper Athena/Presto SQL syntax.
- Include appropriate partition filters if missing.
- Do NOT use SELECT * on tables with many columns.

Respond with ONLY the corrected SQL query. No explanation, no markdown."""


def self_correct(state: dict[str, Any]) -> dict[str, Any]:
    """Rewrite SQL after execution error (max 2 retries).

    Increments self_correction_attempts counter. The graph edge condition
    enforces the structural bound of 2 retries maximum (Requirement 10.3).

    If max retries are reached, the graph routes to format_respond with
    an error message suggesting the user rephrase (Requirement 17.4).

    Args:
        state: GraphState with generated_sql, sql_error, user_message,
               retrieved_schemas, and self_correction_attempts.

    Returns:
        Updated state with corrected generated_sql and incremented
        self_correction_attempts counter.
    """
    user_message = state.get("user_message", "")
    failed_sql = state.get("generated_sql", "")
    error_message = state.get("sql_error", "Unknown error")
    retrieved_schemas = state.get("retrieved_schemas", [])
    current_attempts = state.get("self_correction_attempts", 0)

    # Increment correction counter
    new_attempts = current_attempts + 1

    logger.info(
        "Self-correction attempt %d/%d for error: %s",
        new_attempts,
        MAX_SELF_CORRECTION_RETRIES,
        error_message[:100],
    )

    # If we've hit the maximum, don't attempt correction
    if new_attempts > MAX_SELF_CORRECTION_RETRIES:
        return {
            **state,
            "self_correction_attempts": new_attempts,
            "sql_valid": False,
            "error": (
                "SQL self-correction failed after maximum retries. "
                "Please rephrase your question or ask a simpler version."
            ),
        }

    # Build schemas context
    schemas_context = ""
    if retrieved_schemas:
        schema_parts = []
        for s in retrieved_schemas[:5]:
            db = s.get("database", "")
            table = s.get("table_name", "")
            cols = s.get("columns", [])
            col_names = []
            for c in cols[:20]:
                if isinstance(c, dict):
                    col_names.append(f"{c.get('name', '')} ({c.get('data_type', '')})")
                elif isinstance(c, str):
                    col_names.append(c)
            schema_parts.append(
                f"{db}.{table}: [{', '.join(col_names)}]"
            )
        schemas_context = "\n".join(schema_parts)
    else:
        schemas_context = "No schemas available."

    try:
        client = boto3.client("bedrock-runtime", config=_bedrock_config)

        prompt = CORRECTION_PROMPT.format(
            user_message=user_message,
            failed_sql=failed_sql,
            error_message=error_message,
            schemas_context=schemas_context,
        )

        response = client.invoke_model(
            modelId=SONNET_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 2000,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,  # Deterministic correction
                }
            ),
        )

        response_body = json.loads(response["body"].read())
        content = response_body.get("content", [{}])[0].get("text", "")

        # Clean up corrected SQL
        corrected_sql = content.strip()
        if corrected_sql.startswith("```"):
            lines = corrected_sql.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            corrected_sql = "\n".join(lines).strip()

        if not corrected_sql:
            return {
                **state,
                "self_correction_attempts": new_attempts,
                "sql_valid": False,
                "sql_error": "Self-correction returned empty SQL",
            }

        logger.info(
            "Self-correction produced new SQL (attempt %d): %.50s...",
            new_attempts,
            corrected_sql,
        )

        return {
            **state,
            "self_correction_attempts": new_attempts,
            "generated_sql": corrected_sql,
            "sql_valid": False,  # Must be re-validated
            "sql_error": None,
        }

    except (ClientError, Exception) as e:
        logger.error("Self-correction failed: %s", e)
        return {
            **state,
            "self_correction_attempts": new_attempts,
            "sql_valid": False,
            "sql_error": f"Self-correction error: {e}",
        }
