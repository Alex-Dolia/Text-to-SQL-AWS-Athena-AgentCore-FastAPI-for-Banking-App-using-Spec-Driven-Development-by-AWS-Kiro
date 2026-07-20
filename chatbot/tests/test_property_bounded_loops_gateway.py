"""Property-based tests for bounded loops and gateway routing.

Tests verify that the agent graph's conditional edge functions enforce
structural bounds on loops (disambiguation ≤3, self-correction ≤2) across
ALL possible state combinations, and that all tool calls are routed
exclusively through the AgentCore Gateway.

**Validates: Requirements 10.2, 10.3, 10.4**

Properties tested:
- Property 6: Bounded Loops — disambiguation ≤3, self-correction ≤2
- Property 1: No Tool Call Bypasses Gateway — all tool calls route through Gateway
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch, MagicMock

from hypothesis import given, assume, settings
from hypothesis import strategies as st

from chatbot.agent.graph import (
    AgentGraph,
    GraphState,
    after_disambiguate,
    after_validate_sql,
    should_disambiguate,
    should_self_correct,
    tool_call,
)
from chatbot.agent.nodes.tool_call import (
    GATEWAY_ENDPOINT,
    GATEWAY_SIGNATURE_HEADER,
    GATEWAY_ISSUER,
    _invoke_gateway_tool,
)
from chatbot.policies.evaluator import PolicyDecisionType


# ─── Hypothesis Strategies ────────────────────────────────────────────────────

# Disambiguation rounds: test across a wide range including valid and overflow values
disambiguation_rounds_strategy = st.integers(min_value=0, max_value=100)

# Self-correction attempts: same approach
self_correction_attempts_strategy = st.integers(min_value=0, max_value=100)

# Whether disambiguation is needed
needs_disambiguation_strategy = st.booleans()

# SQL error messages (None means no error, non-None means an error occurred)
sql_error_strategy = st.one_of(
    st.none(),
    st.text(min_size=1, max_size=100, alphabet=st.characters(categories=("L", "N", "P", "Z"))),
)

# SQL validity flag
sql_valid_strategy = st.booleans()


@st.composite
def disambiguation_state(draw) -> GraphState:
    """Generate a random GraphState focused on disambiguation loop fields."""
    return {
        "needs_disambiguation": draw(needs_disambiguation_strategy),
        "disambiguation_rounds": draw(disambiguation_rounds_strategy),
        "user_message": "What is our revenue?",
        "user_claims": {"sub": "user-1", "role": "analyst"},
    }


@st.composite
def self_correction_state(draw) -> GraphState:
    """Generate a random GraphState focused on self-correction loop fields."""
    return {
        "sql_error": draw(sql_error_strategy),
        "self_correction_attempts": draw(self_correction_attempts_strategy),
        "generated_sql": "SELECT * FROM table",
        "user_claims": {"sub": "user-1", "role": "analyst"},
    }


@st.composite
def validate_sql_routing_state(draw) -> GraphState:
    """Generate a random GraphState for after_validate_sql routing."""
    return {
        "sql_valid": draw(sql_valid_strategy),
        "self_correction_attempts": draw(self_correction_attempts_strategy),
        "generated_sql": "SELECT id FROM table",
        "user_claims": {"sub": "user-1", "role": "analyst"},
    }


@st.composite
def tool_call_state(draw) -> GraphState:
    """Generate a random GraphState for tool_call node execution."""
    sql = draw(st.one_of(
        st.none(),
        st.text(min_size=1, max_size=200, alphabet=st.characters(categories=("L", "N", "P", "Z"))),
    ))
    sql_valid = draw(st.booleans())
    user_claims = {
        "sub": draw(st.text(min_size=1, max_size=30, alphabet="abcdefghijklmnop0123456789-")),
        "role": draw(st.sampled_from(["analyst", "manager", "viewer"])),
        "department": draw(st.sampled_from(["finance", "analytics", "hr"])),
    }
    return {
        "generated_sql": sql,
        "sql_valid": sql_valid,
        "user_claims": user_claims,
        "user_message": "Show me revenue data",
    }


# ─── Property 6: Bounded Loops ───────────────────────────────────────────────


class TestBoundedLoopsDisambiguation:
    """Property 6: Bounded Loops — Disambiguation ≤ 3.

    **Validates: Requirements 10.2**

    The disambiguation loop is structurally bounded to a maximum of 3 rounds.
    The should_disambiguate conditional edge function MUST route to sql_generate
    (terminating the loop) whenever disambiguation_rounds >= MAX_DISAMBIGUATION_ROUNDS,
    regardless of whether disambiguation is still needed.
    """

    @given(state=disambiguation_state())
    @settings(max_examples=500)
    def test_disambiguation_never_exceeds_bound(self, state: GraphState):
        """Disambiguation loop terminates at or before 3 rounds for any state.

        **Validates: Requirements 10.2**

        For ANY combination of needs_disambiguation and disambiguation_rounds,
        the edge function MUST route to sql_generate if rounds >= 3.
        """
        rounds = state.get("disambiguation_rounds", 0)
        result = should_disambiguate(state)

        if rounds >= AgentGraph.MAX_DISAMBIGUATION_ROUNDS:
            assert result == "sql_generate", (
                f"Expected 'sql_generate' (bound enforcement) when rounds={rounds} >= "
                f"MAX={AgentGraph.MAX_DISAMBIGUATION_ROUNDS}, but got '{result}'"
            )

    @given(
        rounds=st.integers(min_value=AgentGraph.MAX_DISAMBIGUATION_ROUNDS, max_value=1000),
        needs_disambiguation=st.booleans(),
    )
    @settings(max_examples=300)
    def test_at_or_above_max_always_terminates(
        self, rounds: int, needs_disambiguation: bool
    ):
        """At or above max rounds, the loop ALWAYS terminates regardless of need.

        **Validates: Requirements 10.2**

        Even if needs_disambiguation=True, once rounds >= 3, the edge function
        structurally prevents further disambiguation.
        """
        state: GraphState = {
            "disambiguation_rounds": rounds,
            "needs_disambiguation": needs_disambiguation,
        }
        result = should_disambiguate(state)

        assert result == "sql_generate", (
            f"Bound violated: got '{result}' at rounds={rounds} with "
            f"needs_disambiguation={needs_disambiguation}. "
            f"MAX_DISAMBIGUATION_ROUNDS={AgentGraph.MAX_DISAMBIGUATION_ROUNDS}"
        )

    @given(
        rounds=st.integers(min_value=0, max_value=AgentGraph.MAX_DISAMBIGUATION_ROUNDS - 1),
    )
    @settings(max_examples=100)
    def test_below_max_with_need_routes_to_disambiguate(self, rounds: int):
        """Below max rounds with disambiguation needed, routes to disambiguate.

        **Validates: Requirements 10.2**

        The loop only executes when BOTH conditions are met:
        rounds < MAX AND needs_disambiguation is True.
        """
        state: GraphState = {
            "disambiguation_rounds": rounds,
            "needs_disambiguation": True,
        }
        result = should_disambiguate(state)

        assert result == "disambiguate", (
            f"Expected 'disambiguate' when rounds={rounds} < MAX and "
            f"needs_disambiguation=True, but got '{result}'"
        )

    @given(rounds=disambiguation_rounds_strategy)
    @settings(max_examples=200)
    def test_no_need_never_disambiguates(self, rounds: int):
        """When disambiguation is not needed, never routes to disambiguate.

        **Validates: Requirements 10.2**

        The loop only fires when needs_disambiguation is True.
        """
        state: GraphState = {
            "disambiguation_rounds": rounds,
            "needs_disambiguation": False,
        }
        result = should_disambiguate(state)

        assert result == "sql_generate", (
            f"Expected 'sql_generate' when needs_disambiguation=False, "
            f"but got '{result}' at rounds={rounds}"
        )

    @given(rounds=disambiguation_rounds_strategy)
    @settings(max_examples=200)
    def test_after_disambiguate_terminates_at_max(self, rounds: int):
        """after_disambiguate routes to format_respond (terminates) at max rounds.

        **Validates: Requirements 10.2**

        Once the disambiguation count reaches MAX, the after_disambiguate
        function must exit the loop by routing to format_respond.
        """
        state: GraphState = {"disambiguation_rounds": rounds}
        result = after_disambiguate(state)

        if rounds >= AgentGraph.MAX_DISAMBIGUATION_ROUNDS:
            assert result == "format_respond", (
                f"Expected 'format_respond' at rounds={rounds} >= MAX, got '{result}'"
            )
        else:
            assert result == "intent_classify", (
                f"Expected 'intent_classify' at rounds={rounds} < MAX, got '{result}'"
            )


class TestBoundedLoopsSelfCorrection:
    """Property 6: Bounded Loops — Self-correction ≤ 2.

    **Validates: Requirements 10.3**

    The self-correction retry loop is structurally bounded to a maximum
    of 2 attempts. The should_self_correct conditional edge function MUST
    route to output_scan (terminating the loop) whenever
    self_correction_attempts >= MAX_SELF_CORRECTION_RETRIES, regardless
    of whether an SQL error exists.
    """

    @given(state=self_correction_state())
    @settings(max_examples=500)
    def test_self_correction_never_exceeds_bound(self, state: GraphState):
        """Self-correction loop terminates at or before 2 attempts for any state.

        **Validates: Requirements 10.3**

        For ANY combination of sql_error and self_correction_attempts,
        the edge function MUST route to output_scan if attempts >= 2.
        """
        attempts = state.get("self_correction_attempts", 0)
        result = should_self_correct(state)

        if attempts >= AgentGraph.MAX_SELF_CORRECTION_RETRIES:
            assert result == "output_scan", (
                f"Expected 'output_scan' (bound enforcement) when attempts={attempts} >= "
                f"MAX={AgentGraph.MAX_SELF_CORRECTION_RETRIES}, but got '{result}'"
            )

    @given(
        attempts=st.integers(min_value=AgentGraph.MAX_SELF_CORRECTION_RETRIES, max_value=1000),
        sql_error=sql_error_strategy,
    )
    @settings(max_examples=300)
    def test_at_or_above_max_always_terminates(
        self, attempts: int, sql_error: str | None
    ):
        """At or above max attempts, the loop ALWAYS terminates regardless of error state.

        **Validates: Requirements 10.3**

        Even if sql_error is not None (indicating a persistent error), once
        attempts >= 2, the edge function structurally prevents further retries.
        """
        state: GraphState = {
            "self_correction_attempts": attempts,
            "sql_error": sql_error,
        }
        result = should_self_correct(state)

        assert result == "output_scan", (
            f"Bound violated: got '{result}' at attempts={attempts} with "
            f"sql_error={sql_error!r}. "
            f"MAX_SELF_CORRECTION_RETRIES={AgentGraph.MAX_SELF_CORRECTION_RETRIES}"
        )

    @given(
        attempts=st.integers(min_value=0, max_value=AgentGraph.MAX_SELF_CORRECTION_RETRIES - 1),
        sql_error=st.text(min_size=1, max_size=50),
    )
    @settings(max_examples=100)
    def test_below_max_with_error_routes_to_self_correct(
        self, attempts: int, sql_error: str
    ):
        """Below max attempts with an error present, routes to self_correct.

        **Validates: Requirements 10.3**

        The retry loop only executes when BOTH conditions are met:
        attempts < MAX AND sql_error is not None.
        """
        state: GraphState = {
            "self_correction_attempts": attempts,
            "sql_error": sql_error,
        }
        result = should_self_correct(state)

        assert result == "self_correct", (
            f"Expected 'self_correct' when attempts={attempts} < MAX and "
            f"sql_error is present, but got '{result}'"
        )

    @given(attempts=self_correction_attempts_strategy)
    @settings(max_examples=200)
    def test_no_error_never_retries(self, attempts: int):
        """When no SQL error exists, never routes to self_correct.

        **Validates: Requirements 10.3**

        The retry loop only fires when sql_error is not None.
        """
        state: GraphState = {
            "self_correction_attempts": attempts,
            "sql_error": None,
        }
        result = should_self_correct(state)

        assert result == "output_scan", (
            f"Expected 'output_scan' when sql_error=None, "
            f"but got '{result}' at attempts={attempts}"
        )

    @given(
        sql_valid=sql_valid_strategy,
        attempts=self_correction_attempts_strategy,
    )
    @settings(max_examples=300)
    def test_after_validate_sql_respects_bound(
        self, sql_valid: bool, attempts: int
    ):
        """after_validate_sql never routes to self_correct when attempts >= max.

        **Validates: Requirements 10.3**

        The after_validate_sql routing also respects the self-correction bound.
        When retries are exhausted and SQL is invalid, it gives up (format_respond).
        """
        state: GraphState = {
            "sql_valid": sql_valid,
            "self_correction_attempts": attempts,
        }
        result = after_validate_sql(state)

        if sql_valid:
            assert result == "tool_call", (
                f"Expected 'tool_call' when sql_valid=True, got '{result}'"
            )
        elif attempts >= AgentGraph.MAX_SELF_CORRECTION_RETRIES:
            assert result == "format_respond", (
                f"Expected 'format_respond' (bound enforcement) when sql_valid=False "
                f"and attempts={attempts} >= MAX, got '{result}'"
            )
        else:
            assert result == "self_correct", (
                f"Expected 'self_correct' when sql_valid=False and "
                f"attempts={attempts} < MAX, got '{result}'"
            )


# ─── Property 1: No Tool Call Bypasses Gateway ────────────────────────────────


class TestNoToolCallBypassesGateway:
    """Property 1: No Tool Call Bypasses Gateway.

    **Validates: Requirements 10.4**

    All tool calls from the agent MUST route exclusively through the
    AgentCore Gateway. The tool_call node always invokes _invoke_gateway_tool
    which sends requests to the Gateway endpoint. No direct tool invocation
    is possible outside the Gateway boundary.
    """

    @given(state=tool_call_state())
    @settings(max_examples=200, deadline=None)
    def test_tool_call_always_routes_through_gateway(self, state: GraphState):
        """Every tool_call invocation uses the Gateway endpoint.

        **Validates: Requirements 10.4**

        For any generated state with valid SQL, the tool_call node must
        attempt to reach the AgentCore Gateway endpoint. We verify this
        by patching httpx.post and confirming the Gateway URL is used.

        The Cedar policy evaluator is mocked to return ALLOW so the test
        focuses on Gateway routing rather than audit store availability.
        """
        generated_sql = state.get("generated_sql")
        sql_valid = state.get("sql_valid", False)

        if not generated_sql or not sql_valid:
            # Without valid SQL, tool_call returns early with error
            result = tool_call(state)
            assert result.get("sql_error") is not None
            assert result.get("query_results") is None
            return

        # With valid SQL, it MUST attempt Gateway communication
        # Mock the Cedar policy evaluator to return ALLOW (bypasses audit store writes)
        mock_decision = MagicMock()
        mock_decision.decision = PolicyDecisionType.ALLOW
        mock_decision.to_audit_dict.return_value = {"decision": "ALLOW"}

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_tool_call.return_value = mock_decision

        with patch("chatbot.agent.nodes.tool_call.get_policy_evaluator", return_value=mock_evaluator):
            with patch("httpx.post") as mock_post:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "columns": ["id"],
                    "rows": [{"id": 1}],
                    "row_count": 1,
                    "bytes_scanned": 1024,
                    "execution_time_ms": 100,
                    "data_freshness": "2024-01-01T00:00:00Z",
                }
                mock_response.content = b'{"ok": true}'
                mock_post.return_value = mock_response

                result = tool_call(state)

                # Verify the Gateway was called
                mock_post.assert_called_once()
                call_args = mock_post.call_args

                # The URL must be the Gateway endpoint
                called_url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
                assert GATEWAY_ENDPOINT in called_url, (
                    f"Tool call did NOT route through Gateway. "
                    f"Called URL: {called_url}, Expected Gateway: {GATEWAY_ENDPOINT}"
                )

                # Gateway signature header must be present
                called_headers = call_args[1].get("headers", {})
                assert GATEWAY_SIGNATURE_HEADER in called_headers, (
                    f"Gateway signature header '{GATEWAY_SIGNATURE_HEADER}' missing. "
                    f"Headers sent: {list(called_headers.keys())}"
                )

                # Gateway signature must contain the issuer identifier
                sig_value = called_headers[GATEWAY_SIGNATURE_HEADER]
                assert GATEWAY_ISSUER in sig_value, (
                    f"Gateway signature does not contain issuer '{GATEWAY_ISSUER}'. "
                    f"Signature value: {sig_value}"
                )

    @given(state=tool_call_state())
    @settings(max_examples=200, deadline=None)
    def test_tool_call_never_invokes_mcp_directly(self, state: GraphState):
        """Tool calls never directly invoke MCP server tools.

        **Validates: Requirements 10.4**

        The tool_call node must not import or call MCP server functions
        directly. All tool invocation goes through the Gateway HTTP endpoint.
        """
        generated_sql = state.get("generated_sql")
        sql_valid = state.get("sql_valid", False)

        if not generated_sql or not sql_valid:
            return  # Skip states that don't trigger tool execution

        # Mock the Cedar policy evaluator to return ALLOW (bypasses audit store writes)
        mock_decision = MagicMock()
        mock_decision.decision = PolicyDecisionType.ALLOW
        mock_decision.to_audit_dict.return_value = {"decision": "ALLOW"}

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_tool_call.return_value = mock_decision

        # Patch httpx to catch any outbound call and verify it's Gateway-bound
        with patch("chatbot.agent.nodes.tool_call.get_policy_evaluator", return_value=mock_evaluator):
            with patch("httpx.post") as mock_post:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {"row_count": 0, "rows": []}
                mock_response.content = b'{"ok": true}'
                mock_post.return_value = mock_response

                tool_call(state)

                # All calls MUST be to the Gateway endpoint
                for call in mock_post.call_args_list:
                    url = call[0][0] if call[0] else call[1].get("url", "")
                    assert GATEWAY_ENDPOINT in url, (
                        f"Direct invocation detected outside Gateway! "
                        f"URL called: {url}"
                    )

    @given(
        tool_name=st.sampled_from(["run_query", "list_tables", "get_schema", "estimate_cost"]),
        sql=st.text(min_size=1, max_size=100, alphabet="abcdefghijklmnopqrstuvwxyz "),
        user_sub=st.text(min_size=1, max_size=20, alphabet="abcdefghijklmnop0123456789"),
    )
    @settings(max_examples=200)
    def test_gateway_tool_invocation_uses_correct_endpoint(
        self, tool_name: str, sql: str, user_sub: str
    ):
        """_invoke_gateway_tool always calls the Gateway endpoint with correct structure.

        **Validates: Requirements 10.4**

        The internal helper function constructs the correct Gateway URL
        and includes the necessary authentication headers for every tool call.
        """
        user_claims = {"sub": user_sub, "role": "analyst"}

        # httpx is imported locally inside _invoke_gateway_tool, so patch at module level
        with patch("httpx.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"result": "ok"}
            mock_response.content = b'{"result": "ok"}'
            mock_post.return_value = mock_response

            result = _invoke_gateway_tool(
                tool_name=tool_name,
                arguments={"sql": sql},
                user_claims=user_claims,
            )

            mock_post.assert_called_once()
            call_args = mock_post.call_args

            # Verify correct Gateway URL pattern: {GATEWAY_ENDPOINT}/tools/{tool_name}
            expected_url = f"{GATEWAY_ENDPOINT}/tools/{tool_name}"
            actual_url = call_args[0][0] if call_args[0] else ""
            assert actual_url == expected_url, (
                f"Expected URL: {expected_url}, Got: {actual_url}"
            )

            # Verify request body includes user_claims (for policy evaluation)
            request_json = call_args[1].get("json", {})
            assert "user_claims" in request_json, (
                "user_claims missing from Gateway request body — "
                "Cedar policy evaluation requires user identity"
            )
            assert request_json["user_claims"]["sub"] == user_sub

            # Verify arguments are passed through
            assert "arguments" in request_json
            assert request_json["arguments"]["sql"] == sql

    def test_graph_structure_tool_call_only_via_validated_path(self):
        """The graph structure ensures tool_call is only reachable after SQL validation.

        **Validates: Requirements 10.4**

        In the graph topology, tool_call can only be reached via:
        1. validate_sql → after_validate_sql → "tool_call" (requires sql_valid=True)

        There is no edge that bypasses validation to reach tool_call directly.
        This structural constraint ensures Gateway-routed execution only happens
        for validated SQL.
        """
        agent_graph = AgentGraph()
        graph = agent_graph.build_graph()

        # tool_call node exists
        assert "tool_call" in graph.nodes

        # The only direct incoming edges to tool_call come from conditional routing
        # after validate_sql. Verify there are no direct edges from other nodes
        # to tool_call (which would bypass validation).
        direct_edges_to_tool_call = [
            (src, dst) for src, dst in graph.edges if dst == "tool_call"
        ]

        # No static direct edge should exist to tool_call
        # (it's only reachable via conditional edges from validate_sql)
        assert len(direct_edges_to_tool_call) == 0, (
            f"Unexpected direct edges to tool_call: {direct_edges_to_tool_call}. "
            f"tool_call should only be reachable via conditional edge from validate_sql."
        )
