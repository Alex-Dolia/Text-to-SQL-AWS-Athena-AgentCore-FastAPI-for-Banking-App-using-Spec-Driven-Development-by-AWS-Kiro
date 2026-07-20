"""Tool call node — routes through AgentCore Gateway with Cedar policy evaluation.

All tool calls are routed EXCLUSIVELY through the AgentCore Gateway
where Cedar policy evaluation occurs (Requirement 10.4). Direct tool
invocation outside the Gateway is rejected.

Cedar policy evaluation flow (Requirements 5.1–5.8):
1. Principal claims sourced exclusively from validated JWT (Req 5.3)
2. Cedar evaluates: default-deny (5.1), forbid-wins (5.2)
3. Decision logged to audit store BEFORE returning (Req 5.5)
4. Fail-closed on policy engine error (Req 5.7)
5. Fail-closed if audit write fails (Req 5.8)
6. Evaluation within 30ms at P99 (Req 5.6)

This node submits the validated SQL for execution via the run_query
MCP tool through the Gateway boundary.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from chatbot.policies.evaluator import (
    CedarPolicyEvaluator,
    PolicyDecisionType,
)

logger = logging.getLogger(__name__)

# AgentCore Gateway endpoint (VPC PrivateLink)
GATEWAY_ENDPOINT = "https://agentcore-gateway.vpc.internal"

# Gateway signature header (Requirement 10.4)
GATEWAY_SIGNATURE_HEADER = "X-AgentCore-Gateway-Signature"
GATEWAY_REQUEST_ID_HEADER = "X-AgentCore-Request-Id"
GATEWAY_ISSUER = "agentcore-gateway"

# Module-level evaluator instance (singleton for performance — Req 5.6)
_policy_evaluator: CedarPolicyEvaluator | None = None


def get_policy_evaluator() -> CedarPolicyEvaluator:
    """Get or create the Cedar policy evaluator singleton.

    Returns a shared instance to amortize initialization cost
    and meet the 30ms P99 evaluation budget (Req 5.6).
    """
    global _policy_evaluator
    if _policy_evaluator is None:
        _policy_evaluator = CedarPolicyEvaluator()
    return _policy_evaluator


def set_policy_evaluator(evaluator: CedarPolicyEvaluator | None) -> None:
    """Override the policy evaluator (for testing/dependency injection).

    Pass None to reset the singleton (useful in test teardown).
    """
    global _policy_evaluator
    _policy_evaluator = evaluator


def _extract_resource_from_sql(sql: str) -> tuple[str, str]:
    """Extract database and table from SQL for policy evaluation.

    Uses basic parsing to identify the target resource from the SQL.
    Falls back to empty strings if extraction fails (policy evaluation
    will default-deny without a matching resource).
    """
    try:
        import sqlglot

        parsed = sqlglot.parse_one(sql)
        tables = list(parsed.find_all(sqlglot.exp.Table))
        if tables:
            table = tables[0]
            db = table.db or ""
            table_name = table.name or ""
            return (db, table_name)
    except Exception:
        pass

    return ("", "")


def _invoke_gateway_tool(
    tool_name: str,
    arguments: dict[str, Any],
    user_claims: dict[str, Any],
) -> dict[str, Any]:
    """Invoke a tool via the AgentCore Gateway.

    Routes the tool call through the Gateway where Cedar policy
    evaluation occurs before the tool executes. This ensures
    authorization is enforced at the Gateway boundary.

    Args:
        tool_name: Name of the MCP tool to invoke.
        arguments: Tool-specific arguments.
        user_claims: Authenticated user claims from JWT.

    Returns:
        Tool execution result dictionary.

    Raises:
        RuntimeError: If the Gateway rejects the call or tool fails.
    """
    try:
        request_id = f"gw-{int(time.time() * 1000)}"

        response = httpx.post(
            f"{GATEWAY_ENDPOINT}/tools/{tool_name}",
            json={
                "arguments": arguments,
                "user_claims": user_claims,
            },
            headers={
                GATEWAY_SIGNATURE_HEADER: f"{GATEWAY_ISSUER}:{request_id}",
                GATEWAY_REQUEST_ID_HEADER: request_id,
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

        if response.status_code == 403:
            raise RuntimeError(
                "Authorization denied by Cedar policy at Gateway boundary"
            )
        elif response.status_code == 503:
            raise RuntimeError("AgentCore Gateway unavailable")
        elif response.status_code >= 400:
            error_body = response.json() if response.content else {}
            raise RuntimeError(
                f"Gateway tool call failed: {error_body.get('error', 'Unknown error')}"
            )

        return response.json()

    except httpx.TimeoutException:
        raise RuntimeError("Gateway tool call timed out")
    except httpx.ConnectError:
        raise RuntimeError("Cannot connect to AgentCore Gateway")
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        raise RuntimeError(f"Gateway tool call error: {e}")


def tool_call(state: dict[str, Any]) -> dict[str, Any]:
    """Execute tool call with Cedar policy evaluation and Gateway routing.

    Flow:
    1. Extract user_claims from state (sourced from validated JWT — Req 5.3)
    2. Evaluate Cedar policy BEFORE any tool execution (Req 5.1, 5.2)
    3. Log decision to audit store BEFORE returning (Req 5.5)
    4. If DENY: return immediately with authorization error
    5. If ALLOW: route tool call through AgentCore Gateway
    6. Fail-closed on any policy/audit error (Req 5.7, 5.8)

    Args:
        state: GraphState with generated_sql (validated), user_claims.

    Returns:
        Updated state with query_results or sql_error if execution failed.
    """
    generated_sql = state.get("generated_sql")
    user_claims = state.get("user_claims", {})
    trace_id = state.get("trace_id", "")
    session_id = state.get("session_id", "")

    if not generated_sql:
        return {
            **state,
            "query_results": None,
            "sql_error": "No validated SQL to execute",
        }

    if not state.get("sql_valid", False):
        return {
            **state,
            "query_results": None,
            "sql_error": "SQL has not been validated",
        }

    # ─── Step 1: Cedar Policy Evaluation (Req 5.1–5.8) ───────────────────
    # Principal claims sourced EXCLUSIVELY from validated JWT (Req 5.3).
    # user_claims is set by the auth layer from JWT validation — never from
    # user input or LLM content.
    resource_database, resource_table = _extract_resource_from_sql(generated_sql)

    evaluator = get_policy_evaluator()
    policy_decision = evaluator.evaluate_tool_call(
        tool_name="run_query",
        user_claims=user_claims,
        resource_database=resource_database,
        resource_table=resource_table,
        trace_id=trace_id,
        session_id=session_id,
    )

    # ─── Step 2: Enforce decision ────────────────────────────────────────
    if policy_decision.decision == PolicyDecisionType.DENY:
        # Cedar denied — do NOT route to Athena (Req 6.3)
        logger.warning(
            "Cedar policy DENIED tool call: action=run_query, principal=%s, "
            "resource=%s/%s, reason=%s, policies=%s",
            user_claims.get("sub", "unknown"),
            resource_database,
            resource_table,
            policy_decision.deny_reason,
            policy_decision.determining_policies,
        )
        return {
            **state,
            "query_results": None,
            "sql_error": "Authorization denied by Cedar policy at Gateway boundary",
            "policy_decision": policy_decision.to_audit_dict(),
            "lake_formation_outcome": None,  # LF not consulted on Cedar deny (Req 6.3)
        }

    # ─── Step 3: Route through Gateway (Cedar ALLOWED) ────────────────────
    try:
        result = _invoke_gateway_tool(
            tool_name="run_query",
            arguments={"sql": generated_sql},
            user_claims=user_claims,
        )

        logger.info(
            "Query executed successfully via Gateway. Rows: %s, Bytes: %s",
            result.get("row_count", "unknown"),
            result.get("bytes_scanned", "unknown"),
        )

        lake_formation_outcome = result.get("lake_formation_outcome", "allowed")

        return {
            **state,
            "query_results": result,
            "sql_error": None,
            "policy_decision": policy_decision.to_audit_dict(),
            "lake_formation_outcome": lake_formation_outcome,
        }

    except RuntimeError as e:
        error_msg = str(e)
        logger.error("Tool call failed via Gateway: %s", error_msg)

        # Determine Lake Formation outcome from error context
        lake_formation_outcome = None

        if "access denied" in error_msg.lower() or "lake formation" in error_msg.lower():
            # Cedar permitted but LF denied — divergence (Req 6.2)
            lake_formation_outcome = "denied"

        return {
            **state,
            "query_results": None,
            "sql_error": error_msg,
            "policy_decision": policy_decision.to_audit_dict(),
            "lake_formation_outcome": lake_formation_outcome,
        }
    except Exception as e:
        logger.exception("Unexpected error during tool call")
        return {
            **state,
            "query_results": None,
            "sql_error": f"Tool execution error: {e}",
            "policy_decision": policy_decision.to_audit_dict(),
            "lake_formation_outcome": None,
        }
