"""Format response node with data freshness indicator.

Formats the final response to the user including:
- Query results in a readable format
- Data freshness information from Glue Catalog partition timestamps
- Any warnings (cost, partial results, etc.)
- Error messages with trace_id when applicable

This is the terminal node before END in the graph.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Maximum rows to include in response summary
MAX_DISPLAY_ROWS = 50


def _format_data_freshness(query_results: dict[str, Any]) -> str | None:
    """Extract and format data freshness from query results.

    Data freshness comes from Glue Catalog partition timestamps,
    indicating when the underlying data was last updated.

    Args:
        query_results: Query execution results with metadata.

    Returns:
        Formatted freshness string or None if unavailable.
    """
    freshness = query_results.get("data_freshness")
    if freshness:
        return f"Data current as of {freshness}"

    # Try to infer from partition metadata
    last_updated = query_results.get("last_updated")
    if last_updated:
        return f"Data current as of {last_updated}"

    return None


def _format_query_results(query_results: dict[str, Any]) -> str:
    """Format query results into a user-friendly response string.

    Args:
        query_results: Dictionary containing columns, rows, row_count, etc.

    Returns:
        Formatted response string with results summary.
    """
    rows = query_results.get("rows", [])
    columns = query_results.get("columns", [])
    row_count = query_results.get("row_count", len(rows))
    bytes_scanned = query_results.get("bytes_scanned", 0)

    if not rows:
        return "Your query returned no results."

    # Build response parts
    parts = []

    # Row count summary
    if row_count > MAX_DISPLAY_ROWS:
        parts.append(
            f"Your query returned {row_count:,} rows. "
            f"Showing the first {MAX_DISPLAY_ROWS}."
        )
        display_rows = rows[:MAX_DISPLAY_ROWS]
    else:
        parts.append(f"Your query returned {row_count:,} row{'s' if row_count != 1 else ''}.")
        display_rows = rows

    # Format as a simple table representation
    if columns and display_rows:
        # Header
        header = " | ".join(str(c) for c in columns)
        separator = "-" * len(header)
        parts.append(f"\n{header}")
        parts.append(separator)

        # Rows
        for row in display_rows[:MAX_DISPLAY_ROWS]:
            if isinstance(row, dict):
                row_values = [str(row.get(c, "")) for c in columns]
            elif isinstance(row, (list, tuple)):
                row_values = [str(v) for v in row]
            else:
                row_values = [str(row)]
            parts.append(" | ".join(row_values))

    # Bytes scanned info
    if bytes_scanned:
        gb_scanned = bytes_scanned / (1024**3)
        if gb_scanned >= 1:
            parts.append(f"\nData scanned: {gb_scanned:.2f} GB")
        else:
            mb_scanned = bytes_scanned / (1024**2)
            parts.append(f"\nData scanned: {mb_scanned:.1f} MB")

    return "\n".join(parts)


def _format_error_response(state: dict[str, Any]) -> str:
    """Format an error response with appropriate user guidance.

    Provides actionable messages without exposing security internals
    (Requirement 17.1-17.7).

    Args:
        state: GraphState with error information.

    Returns:
        User-friendly error message.
    """
    error = state.get("error", "")
    sql_error = state.get("sql_error", "")

    if "authorization" in error.lower() or "authorized" in error.lower():
        return (
            "Access to the requested data is not available. "
            "Please contact the Data Governance portal for access requests."
        )

    if "cost" in error.lower() or "threshold" in error.lower():
        return (
            "The estimated scan size exceeds your threshold. "
            "Please add date or partition filters to narrow the query scope."
        )

    if sql_error and "self-correction" in sql_error.lower():
        return (
            "I wasn't able to generate a working query for your request. "
            "Could you try rephrasing your question or asking a simpler version?"
        )

    if "guardrails" in error.lower() or "can't help" in error.lower():
        return (
            "I can't help with that request. "
            "Please rephrase your question about the data."
        )

    if "no accessible tables" in error.lower() or "no schemas" in error.lower():
        return (
            "No accessible tables match your question. "
            "Please verify you have access to the relevant data sources."
        )

    # Generic fallback (Requirement 17.6)
    if error:
        return error

    return "An unexpected error occurred. Please try again or contact support."


def format_respond(state: dict[str, Any]) -> dict[str, Any]:
    """Format the final response with data freshness indicator.

    Assembles the final user-facing response including:
    - Query results (formatted)
    - Data freshness information
    - Warnings and caveats
    - Error messages (if applicable)

    Args:
        state: GraphState with query_results, generated_sql, error, etc.

    Returns:
        Updated state with 'final_response' containing the formatted output.
    """
    error = state.get("error")
    sql_error = state.get("sql_error")
    query_results = state.get("query_results")
    generated_sql = state.get("generated_sql")

    # Handle error states
    if error or (sql_error and not query_results):
        response = _format_error_response(state)
        return {**state, "final_response": response}

    # Handle successful query results
    if query_results:
        parts = []

        # Format query results
        results_text = _format_query_results(query_results)
        parts.append(results_text)

        # Add data freshness indicator
        freshness = _format_data_freshness(query_results)
        if freshness:
            parts.append(f"\n📅 {freshness}")

        # Add warnings from guardrails
        findings = state.get("guardrails_findings", [])
        if findings:
            # Don't expose specific findings to user — just note redaction
            pii_findings = [f for f in findings if "PII" in f.upper()]
            if pii_findings:
                parts.append(
                    "\n⚠️ Some personal information has been redacted "
                    "for data protection."
                )

        response = "\n".join(parts)
        return {**state, "final_response": response}

    # Handle disambiguation response (already set by disambiguate node)
    if state.get("final_response"):
        return state

    # Fallback
    return {
        **state,
        "final_response": "I wasn't able to process your request. Please try again.",
    }
