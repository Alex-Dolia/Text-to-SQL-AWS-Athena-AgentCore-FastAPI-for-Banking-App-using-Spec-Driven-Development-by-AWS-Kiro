"""SQL generation node using Claude Sonnet with temperature=0.

Generates SQL from the user's natural language query using Claude Sonnet
via Amazon Bedrock. Uses temperature=0 for deterministic, reproducible
SQL generation (Requirement 10.1).

The generated SQL is NOT executed here — it flows to the validate_sql node
for deterministic safety checks before execution.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Claude Sonnet model ID for high-quality SQL generation
SONNET_MODEL_ID = "anthropic.claude-sonnet-4-20250514"

# Bedrock client configuration
_bedrock_config = Config(
    read_timeout=30,
    connect_timeout=5,
    retries={"max_attempts": 1},
)

SQL_GENERATION_PROMPT = """You are a SQL expert for Amazon Athena (Presto/Trino dialect).
Generate a SQL SELECT query based on the user's natural language question.

RULES:
- Generate ONLY SELECT statements. Never INSERT, UPDATE, DELETE, DROP, ALTER, or CREATE.
- Use the table and column names from the provided schemas.
- Include appropriate WHERE clauses for partitioned tables (use partition keys).
- Do NOT use SELECT * on tables with many columns — be explicit about column names.
- Use proper Athena/Presto SQL syntax.
- Include appropriate date/time filters when the user mentions time periods.

User question: {user_message}

Resolved business terms: {resolved_terms}

Available table schemas:
{schemas_context}

Respond with ONLY the SQL query. No explanation, no markdown code blocks, just the SQL."""


def _build_schemas_context(schemas: list[dict[str, Any]]) -> str:
    """Build a context string from retrieved schemas for the SQL generation prompt."""
    if not schemas:
        return "No schemas available."

    context_parts = []
    for schema in schemas:
        db = schema.get("database", "")
        table = schema.get("table_name", "")
        description = schema.get("description", "")
        columns = schema.get("columns", [])
        partition_keys = schema.get("partition_keys", [])

        col_descriptions = []
        for col in columns[:30]:  # Limit to avoid token overflow
            if isinstance(col, dict):
                col_name = col.get("name", "")
                col_type = col.get("data_type", "")
                col_desc = col.get("description", "")
                col_descriptions.append(f"    - {col_name} ({col_type}): {col_desc}")
            elif isinstance(col, str):
                col_descriptions.append(f"    - {col}")

        part_str = f"  Partition keys: {', '.join(partition_keys)}" if partition_keys else ""
        cols_str = "\n".join(col_descriptions) if col_descriptions else "    (no column details)"

        context_parts.append(
            f"Table: {db}.{table}\n"
            f"  Description: {description}\n"
            f"{part_str}\n"
            f"  Columns:\n{cols_str}"
        )

    return "\n\n".join(context_parts)


def sql_generate(state: dict[str, Any]) -> dict[str, Any]:
    """Generate SQL using Claude Sonnet with temperature=0.

    Uses the retrieved schemas and resolved glossary terms to generate
    a SQL query from the user's natural language question. Temperature=0
    ensures deterministic output for reproducibility.

    Args:
        state: GraphState dictionary containing user_message, retrieved_schemas,
               resolved_terms, and user_claims.

    Returns:
        Updated state with 'generated_sql' containing the SQL query,
        or 'error' if generation failed.
    """
    user_message = state.get("user_message", "")
    retrieved_schemas = state.get("retrieved_schemas", [])
    resolved_terms = state.get("resolved_terms", {})

    if not user_message:
        return {
            **state,
            "generated_sql": None,
            "error": "Cannot generate SQL: no user message provided",
        }

    if not retrieved_schemas:
        return {
            **state,
            "generated_sql": None,
            "error": (
                "Cannot generate SQL: no table schemas available. "
                "No accessible tables match your question."
            ),
        }

    # Build prompt context
    schemas_context = _build_schemas_context(retrieved_schemas)
    terms_str = json.dumps(resolved_terms) if resolved_terms else "None"

    prompt = SQL_GENERATION_PROMPT.format(
        user_message=user_message,
        resolved_terms=terms_str,
        schemas_context=schemas_context,
    )

    try:
        client = boto3.client("bedrock-runtime", config=_bedrock_config)

        response = client.invoke_model(
            modelId=SONNET_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 2000,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,  # Deterministic SQL generation
                }
            ),
        )

        response_body = json.loads(response["body"].read())
        content = response_body.get("content", [{}])[0].get("text", "")

        # Clean up the generated SQL
        generated_sql = content.strip()

        # Remove markdown code blocks if model included them
        if generated_sql.startswith("```"):
            lines = generated_sql.split("\n")
            # Remove first and last lines (code block markers)
            lines = [l for l in lines if not l.strip().startswith("```")]
            generated_sql = "\n".join(lines).strip()

        if not generated_sql:
            return {
                **state,
                "generated_sql": None,
                "error": "SQL generation returned empty result",
            }

        logger.info(
            "Generated SQL (%.50s...): %d chars",
            generated_sql[:50],
            len(generated_sql),
        )

        return {
            **state,
            "generated_sql": generated_sql,
            "sql_valid": False,  # Not yet validated
            "sql_error": None,  # Clear previous errors
        }

    except ClientError as e:
        logger.error("Bedrock API error during SQL generation: %s", e)
        return {
            **state,
            "generated_sql": None,
            "error": f"SQL generation failed: {e}",
        }
    except Exception as e:
        logger.exception("Unexpected error during SQL generation")
        return {
            **state,
            "generated_sql": None,
            "error": f"SQL generation error: {e}",
        }
