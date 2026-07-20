"""Unit tests for agent graph definition with bounded loops.

Validates:
- All 10 nodes are statically defined (Requirement 10.1)
- Conditional edges enforce disambiguation bound ≤3 (Requirement 10.2)
- Conditional edges enforce self-correction bound ≤2 (Requirement 10.3)
- Tool call routing through Gateway (Requirement 10.4)
"""

import pytest

from agent.graph import (
    AgentGraph,
    GraphState,
    after_disambiguate,
    after_validate_sql,
    should_disambiguate,
    should_self_correct,
)


class TestAgentGraphStructure:
    """Test that the graph is defined statically with all required nodes."""

    def setup_method(self) -> None:
        self.agent_graph = AgentGraph()
        self.graph = self.agent_graph.build_graph()

    def test_all_nodes_defined_statically(self) -> None:
        """Requirement 10.1: All nodes defined statically in graph definition."""
        expected_nodes = {
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
        }
        actual_nodes = set(self.graph.nodes.keys())
        assert expected_nodes == actual_nodes

    def test_node_count_matches_class_constant(self) -> None:
        """NODES class constant matches actual graph nodes."""
        assert len(AgentGraph.NODES) == 10
        assert set(AgentGraph.NODES) == set(self.graph.nodes.keys())

    def test_entry_point_is_intent_classify(self) -> None:
        """Graph starts at intent_classify node."""
        # START -> intent_classify edge should exist
        assert ("__start__", "intent_classify") in self.graph.edges

    def test_end_point_is_format_respond(self) -> None:
        """Graph ends at format_respond node."""
        assert ("format_respond", "__end__") in self.graph.edges

    def test_linear_edges_defined(self) -> None:
        """Linear edges are statically defined."""
        expected_linear_edges = [
            ("intent_classify", "glossary_resolve"),
            ("glossary_resolve", "schema_retrieve"),
            ("sql_generate", "validate_sql"),
            ("self_correct", "validate_sql"),
            ("output_scan", "format_respond"),
        ]
        for edge in expected_linear_edges:
            assert edge in self.graph.edges, f"Missing edge: {edge}"


class TestDisambiguationBound:
    """Test disambiguation loop is bounded to max 3 rounds (Requirement 10.2)."""

    def test_disambiguate_when_needed_and_under_limit(self) -> None:
        """Routes to disambiguate when clarification needed and rounds < 3."""
        state: GraphState = {
            "needs_disambiguation": True,
            "disambiguation_rounds": 0,
        }
        assert should_disambiguate(state) == "disambiguate"

    def test_disambiguate_at_round_2(self) -> None:
        """Routes to disambiguate at round 2 (still under max 3)."""
        state: GraphState = {
            "needs_disambiguation": True,
            "disambiguation_rounds": 2,
        }
        assert should_disambiguate(state) == "disambiguate"

    def test_no_disambiguate_at_max_rounds(self) -> None:
        """Structurally bounded: routes to sql_generate at round 3."""
        state: GraphState = {
            "needs_disambiguation": True,
            "disambiguation_rounds": 3,
        }
        assert should_disambiguate(state) == "sql_generate"

    def test_no_disambiguate_over_max_rounds(self) -> None:
        """Structurally bounded: never disambiguate beyond max."""
        state: GraphState = {
            "needs_disambiguation": True,
            "disambiguation_rounds": 5,
        }
        assert should_disambiguate(state) == "sql_generate"

    def test_no_disambiguate_when_not_needed(self) -> None:
        """Routes to sql_generate when no disambiguation needed."""
        state: GraphState = {
            "needs_disambiguation": False,
            "disambiguation_rounds": 0,
        }
        assert should_disambiguate(state) == "sql_generate"

    def test_after_disambiguate_loops_back(self) -> None:
        """After disambiguation, routes back to intent_classify if under max."""
        state: GraphState = {"disambiguation_rounds": 1}
        assert after_disambiguate(state) == "intent_classify"

    def test_after_disambiguate_gives_up_at_max(self) -> None:
        """After max disambiguation rounds, routes to format_respond (give up)."""
        state: GraphState = {"disambiguation_rounds": 3}
        assert after_disambiguate(state) == "format_respond"

    def test_max_disambiguation_constant(self) -> None:
        """MAX_DISAMBIGUATION_ROUNDS is 3."""
        assert AgentGraph.MAX_DISAMBIGUATION_ROUNDS == 3


class TestSelfCorrectionBound:
    """Test self-correction loop is bounded to max 2 retries (Requirement 10.3)."""

    def test_self_correct_when_error_and_under_limit(self) -> None:
        """Routes to self_correct when SQL error and attempts < 2."""
        state: GraphState = {
            "sql_error": "Table not found",
            "self_correction_attempts": 0,
        }
        assert should_self_correct(state) == "self_correct"

    def test_self_correct_at_attempt_1(self) -> None:
        """Routes to self_correct at attempt 1 (still under max 2)."""
        state: GraphState = {
            "sql_error": "Syntax error",
            "self_correction_attempts": 1,
        }
        assert should_self_correct(state) == "self_correct"

    def test_no_self_correct_at_max_attempts(self) -> None:
        """Structurally bounded: routes to output_scan at attempt 2."""
        state: GraphState = {
            "sql_error": "Still failing",
            "self_correction_attempts": 2,
        }
        assert should_self_correct(state) == "output_scan"

    def test_no_self_correct_over_max_attempts(self) -> None:
        """Structurally bounded: never self-correct beyond max."""
        state: GraphState = {
            "sql_error": "Persistent error",
            "self_correction_attempts": 5,
        }
        assert should_self_correct(state) == "output_scan"

    def test_no_self_correct_when_no_error(self) -> None:
        """Routes to output_scan when no SQL error."""
        state: GraphState = {
            "sql_error": None,
            "self_correction_attempts": 0,
        }
        assert should_self_correct(state) == "output_scan"

    def test_max_self_correction_constant(self) -> None:
        """MAX_SELF_CORRECTION_RETRIES is 2."""
        assert AgentGraph.MAX_SELF_CORRECTION_RETRIES == 2


class TestValidateSqlRouting:
    """Test after_validate_sql conditional edge."""

    def test_routes_to_tool_call_when_valid(self) -> None:
        """Routes to tool_call (Gateway) when SQL is valid."""
        state: GraphState = {
            "sql_valid": True,
            "self_correction_attempts": 0,
        }
        assert after_validate_sql(state) == "tool_call"

    def test_routes_to_self_correct_when_invalid_and_retries_available(self) -> None:
        """Routes to self_correct when SQL invalid and retries < max."""
        state: GraphState = {
            "sql_valid": False,
            "self_correction_attempts": 0,
        }
        assert after_validate_sql(state) == "self_correct"

    def test_routes_to_format_respond_when_invalid_and_retries_exhausted(self) -> None:
        """Routes to format_respond (give up) when retries exhausted."""
        state: GraphState = {
            "sql_valid": False,
            "self_correction_attempts": 2,
        }
        assert after_validate_sql(state) == "format_respond"


class TestGatewayRouting:
    """Test that tool calls route through AgentCore Gateway (Requirement 10.4)."""

    def test_tool_call_node_exists(self) -> None:
        """tool_call node is defined for Gateway routing."""
        graph = AgentGraph()
        g = graph.build_graph()
        assert "tool_call" in g.nodes

    def test_tool_call_only_reachable_after_validation(self) -> None:
        """tool_call is only reached after validate_sql passes.

        This ensures all tool calls go through the Gateway boundary
        where Cedar policy evaluation occurs.
        """
        # The only path to tool_call is via after_validate_sql returning "tool_call"
        # which requires sql_valid=True
        state: GraphState = {"sql_valid": False, "self_correction_attempts": 0}
        assert after_validate_sql(state) != "tool_call"

        state_valid: GraphState = {"sql_valid": True, "self_correction_attempts": 0}
        assert after_validate_sql(state_valid) == "tool_call"
