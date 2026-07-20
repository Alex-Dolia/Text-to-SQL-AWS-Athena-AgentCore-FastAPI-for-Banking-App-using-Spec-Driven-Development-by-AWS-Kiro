"""Agent graph definition with bounded loops.

Implements the LangGraph orchestration graph with structurally bounded
control flow. All nodes, edges, and paths are defined statically — no
dynamic creation at runtime (Requirement 10.1).

Bounded loops:
- Disambiguation: max 3 rounds (Requirement 10.2)
- Self-correction: max 2 retries (Requirement 10.3)

All tool calls route exclusively through AgentCore Gateway (Requirement 10.4).
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from chatbot.agent.nodes import (
    disambiguate as disambiguate_impl,
    format_respond as format_respond_impl,
    glossary_resolve as glossary_resolve_impl,
    intent_classify as intent_classify_impl,
    output_scan as output_scan_impl,
    schema_retrieve as schema_retrieve_impl,
    self_correct as self_correct_impl,
    sql_generate as sql_generate_impl,
    tool_call as tool_call_impl,
    validate_sql_node as validate_sql_impl,
)


class GraphState(TypedDict, total=False):
    """State schema for the agent graph.

    Uses TypedDict for LangGraph compatibility while mirroring
    the AgentState dataclass fields.
    """

    # Required fields — set at request start
    user_claims: dict[str, Any]
    user_message: str

    # Intent classification
    intent: str | None

    # Glossary resolution
    resolved_terms: dict[str, str] | None

    # Schema retrieval (filtered by user authorization)
    retrieved_schemas: list[dict[str, Any]] | None

    # Disambiguation loop — max 3 rounds (Requirement 10.2)
    disambiguation_rounds: int
    needs_disambiguation: bool

    # SQL generation and validation
    generated_sql: str | None
    sql_valid: bool

    # Self-correction loop — max 2 attempts (Requirement 10.3)
    self_correction_attempts: int
    sql_error: str | None

    # Query execution results
    query_results: dict[str, Any] | None

    # Policy evaluation results (Requirement 6.1 — Cedar before Athena)
    policy_decision: dict[str, Any] | None

    # Lake Formation outcome (Requirement 6.4 — enforced at query engine)
    lake_formation_outcome: str | None

    # Guardrails findings from input/output scanning
    guardrails_findings: list[str]

    # Final output
    final_response: str | None

    # Error state
    error: str | None


# ---------------------------------------------------------------------------
# Node functions — delegating to implementations in chatbot.agent.nodes
# ---------------------------------------------------------------------------


def intent_classify(state: GraphState) -> GraphState:
    """Classify user intent using Claude Haiku (2s budget).

    Determines if the query is actionable or needs disambiguation.
    """
    return intent_classify_impl(state)


def glossary_resolve(state: GraphState) -> GraphState:
    """Resolve business glossary terms to canonical names."""
    return glossary_resolve_impl(state)


def schema_retrieve(state: GraphState) -> GraphState:
    """Retrieve relevant schemas via RAG from OpenSearch.

    Results are filtered to only schemas matching the authenticated
    user's Lake Formation grants (Requirement 10.5).
    """
    return schema_retrieve_impl(state)


def disambiguate(state: GraphState) -> GraphState:
    """Generate a clarification question for the user.

    Increments disambiguation_rounds counter. The graph edge condition
    enforces the structural bound of 3 rounds maximum (Requirement 10.2).
    """
    return disambiguate_impl(state)


def sql_generate(state: GraphState) -> GraphState:
    """Generate SQL using Claude Sonnet (temperature=0)."""
    return sql_generate_impl(state)


def validate_sql(state: GraphState) -> GraphState:
    """Validate generated SQL via the SQL validation engine.

    Delegates to chatbot.mcp_server.validation for deterministic checks.
    """
    return validate_sql_impl(state)


def tool_call(state: GraphState) -> GraphState:
    """Execute tool call routed exclusively through AgentCore Gateway.

    All tool invocations MUST pass through the Gateway boundary where
    Cedar policy evaluation occurs (Requirement 10.4). Direct tool
    invocation outside the Gateway is rejected.
    """
    return tool_call_impl(state)


def self_correct(state: GraphState) -> GraphState:
    """Rewrite SQL after execution error.

    Increments self_correction_attempts counter. The graph edge condition
    enforces the structural bound of 2 retries maximum (Requirement 10.3).
    """
    return self_correct_impl(state)


def output_scan(state: GraphState) -> GraphState:
    """Scan output through Bedrock Guardrails for PII redaction and content safety."""
    return output_scan_impl(state)


def format_respond(state: GraphState) -> GraphState:
    """Format the final response with data freshness indicator."""
    return format_respond_impl(state)


# ---------------------------------------------------------------------------
# Conditional edge routing functions
# ---------------------------------------------------------------------------


def should_disambiguate(state: GraphState) -> Literal["disambiguate", "sql_generate"]:
    """Conditional edge: route to disambiguation if intent is unclear AND rounds < 3.

    Structural bound enforcement (Requirement 10.2):
    - If disambiguation_rounds >= 3, ALWAYS route to sql_generate
      (terminates the loop regardless of intent clarity)
    - If intent needs clarification AND rounds < 3, route to disambiguate
    - Otherwise, proceed to sql_generate
    """
    rounds = state.get("disambiguation_rounds", 0)
    needs_clarification = state.get("needs_disambiguation", False)

    if needs_clarification and rounds < AgentGraph.MAX_DISAMBIGUATION_ROUNDS:
        return "disambiguate"
    return "sql_generate"


def should_self_correct(state: GraphState) -> Literal["self_correct", "output_scan"]:
    """Conditional edge: retry SQL if error AND attempts < 2.

    Structural bound enforcement (Requirement 10.3):
    - If self_correction_attempts >= 2, ALWAYS route to output_scan
      (terminates the loop regardless of SQL validity)
    - If SQL execution failed AND attempts < 2, route to self_correct
    - Otherwise, proceed to output_scan
    """
    attempts = state.get("self_correction_attempts", 0)
    has_error = state.get("sql_error") is not None

    if has_error and attempts < AgentGraph.MAX_SELF_CORRECTION_RETRIES:
        return "self_correct"
    return "output_scan"


def after_disambiguate(state: GraphState) -> Literal["intent_classify", "format_respond"]:
    """Route after disambiguation: re-classify intent or give up.

    If max rounds reached after disambiguation, inform user and end.
    Otherwise loop back to intent classification.
    """
    rounds = state.get("disambiguation_rounds", 0)
    if rounds >= AgentGraph.MAX_DISAMBIGUATION_ROUNDS:
        return "format_respond"
    return "intent_classify"


def after_validate_sql(state: GraphState) -> Literal["tool_call", "self_correct", "format_respond"]:
    """Route after SQL validation.

    - If SQL is valid, proceed to tool_call (via Gateway)
    - If invalid and retries available, route to self_correct
    - If invalid and retries exhausted, format error response
    """
    sql_valid = state.get("sql_valid", False)
    attempts = state.get("self_correction_attempts", 0)

    if sql_valid:
        return "tool_call"
    if attempts < AgentGraph.MAX_SELF_CORRECTION_RETRIES:
        return "self_correct"
    return "format_respond"


# ---------------------------------------------------------------------------
# Agent Graph Builder
# ---------------------------------------------------------------------------


class AgentGraph:
    """LangGraph agent with explicit nodes and bounded conditional edges.

    All nodes and edges are defined statically in the graph definition.
    No nodes, edges, or paths are created dynamically at runtime
    (Requirement 10.1).

    Structural bounds enforce loop termination via graph edge conditions
    rather than runtime counters:
    - Disambiguation: max 3 rounds (Requirement 10.2)
    - Self-correction: max 2 retries (Requirement 10.3)

    All tool calls route exclusively through AgentCore Gateway
    (Requirement 10.4).
    """

    # Static node definitions — all paths visible to security review
    NODES: list[str] = [
        "intent_classify",
        "glossary_resolve",
        "schema_retrieve",
        "disambiguate",
        "sql_generate",
        "validate_sql",
        "tool_call",
        "self_correct",
        "output_scan",
        "format_respond",
    ]

    # Structural loop bounds — enforced by graph edge conditions
    MAX_DISAMBIGUATION_ROUNDS: int = 3
    MAX_SELF_CORRECTION_RETRIES: int = 2

    def build_graph(self) -> StateGraph:
        """Construct the agent graph with structurally bounded loops.

        Graph topology:
            START → intent_classify → glossary_resolve → schema_retrieve
                  → [conditional: should_disambiguate]
                      → disambiguate → [conditional: after_disambiguate]
                          → intent_classify (loop, max 3)
                          → format_respond → END (give up)
                      → sql_generate → validate_sql
                          → [conditional: after_validate_sql]
                              → tool_call → [conditional: should_self_correct]
                                  → self_correct → validate_sql (loop, max 2)
                                  → output_scan → format_respond → END
                              → self_correct → validate_sql (loop, max 2)
                              → format_respond → END (give up)

        Returns:
            StateGraph: Compiled LangGraph state graph with all nodes
                        and bounded conditional edges defined statically.
        """
        graph = StateGraph(GraphState)

        # --- Register all nodes statically (Requirement 10.1) ---
        graph.add_node("intent_classify", intent_classify)
        graph.add_node("glossary_resolve", glossary_resolve)
        graph.add_node("schema_retrieve", schema_retrieve)
        graph.add_node("disambiguate", disambiguate)
        graph.add_node("sql_generate", sql_generate)
        graph.add_node("validate_sql", validate_sql)
        graph.add_node("tool_call", tool_call)
        graph.add_node("self_correct", self_correct)
        graph.add_node("output_scan", output_scan)
        graph.add_node("format_respond", format_respond)

        # --- Define edges statically ---

        # Entry: START → intent_classify
        graph.add_edge(START, "intent_classify")

        # Linear flow: intent_classify → glossary_resolve → schema_retrieve
        graph.add_edge("intent_classify", "glossary_resolve")
        graph.add_edge("glossary_resolve", "schema_retrieve")

        # Conditional: after schema_retrieve, decide disambiguation vs sql_generate
        # Bounded loop: disambiguation ≤ 3 rounds (Requirement 10.2)
        graph.add_conditional_edges(
            "schema_retrieve",
            should_disambiguate,
            {
                "disambiguate": "disambiguate",
                "sql_generate": "sql_generate",
            },
        )

        # After disambiguation: loop back to intent_classify or give up
        graph.add_conditional_edges(
            "disambiguate",
            after_disambiguate,
            {
                "intent_classify": "intent_classify",
                "format_respond": "format_respond",
            },
        )

        # SQL generation → validation
        graph.add_edge("sql_generate", "validate_sql")

        # After validation: route to tool_call, self_correct, or give up
        # Bounded loop: self-correction ≤ 2 retries (Requirement 10.3)
        graph.add_conditional_edges(
            "validate_sql",
            after_validate_sql,
            {
                "tool_call": "tool_call",
                "self_correct": "self_correct",
                "format_respond": "format_respond",
            },
        )

        # After tool_call: check if self-correction needed
        graph.add_conditional_edges(
            "tool_call",
            should_self_correct,
            {
                "self_correct": "self_correct",
                "output_scan": "output_scan",
            },
        )

        # Self-correct loops back to validate_sql
        graph.add_edge("self_correct", "validate_sql")

        # Output scan → format response → END
        graph.add_edge("output_scan", "format_respond")
        graph.add_edge("format_respond", END)

        return graph
