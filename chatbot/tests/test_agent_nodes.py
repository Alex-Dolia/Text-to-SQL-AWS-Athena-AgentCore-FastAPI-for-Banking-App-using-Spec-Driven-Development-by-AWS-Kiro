"""Unit tests for agent graph node functions.

Tests individual node functions from chatbot/agent/nodes/ with mocked
external dependencies (Bedrock, OpenSearch).

Validates:
- intent_classify: classification logic and error handling
- schema_retrieve: auth filtering by user authorization (Requirement 10.5)
- disambiguate: round tracking and max bound (Requirement 10.2)
- self_correct: attempt tracking and max bound (Requirement 10.3)
- validate_sql: delegation to validation engine

Requirements: 10.1, 10.2, 10.3, 10.5
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from typing import Any

import pytest

from chatbot.agent.nodes.intent_classify import (
    INTENT_ACTIONABLE,
    INTENT_AMBIGUOUS,
    INTENT_OUT_OF_SCOPE,
    intent_classify,
)
from chatbot.agent.nodes.disambiguate import (
    MAX_DISAMBIGUATION_ROUNDS,
    disambiguate,
)
from chatbot.agent.nodes.self_correct import (
    MAX_SELF_CORRECTION_RETRIES,
    self_correct,
)
from chatbot.agent.nodes.schema_retrieve import (
    _get_user_authorized_tags,
    schema_retrieve,
)
from chatbot.agent.nodes.validate_sql import validate_sql_node


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bedrock_response(intent: str, reason: str = "test") -> MagicMock:
    """Create a mock Bedrock invoke_model response."""
    body_content = json.dumps(
        {"content": [{"text": json.dumps({"intent": intent, "reason": reason})}]}
    )
    mock_body = MagicMock()
    mock_body.read.return_value = body_content.encode()
    return {"body": mock_body}


def _base_state(**overrides: Any) -> dict[str, Any]:
    """Create a base graph state dict for testing."""
    state: dict[str, Any] = {
        "user_message": "Show me total sales by region",
        "user_claims": {
            "sub": "user-123",
            "department": "analytics",
            "role": "analyst",
            "data_classification_tier": "internal",
            "groups": ["data-consumers"],
            "session_id": "00000000-0000-4000-8000-000000000001",
            "exp": 9999999999,
        },
        "intent": None,
        "resolved_terms": None,
        "retrieved_schemas": None,
        "disambiguation_rounds": 0,
        "needs_disambiguation": False,
        "generated_sql": None,
        "sql_valid": False,
        "self_correction_attempts": 0,
        "sql_error": None,
        "query_results": None,
        "guardrails_findings": [],
        "final_response": None,
        "error": None,
    }
    state.update(overrides)
    return state



# ===========================================================================
# Tests for intent_classify node
# ===========================================================================


class TestIntentClassify:
    """Test intent classification node (Requirement 10.1)."""

    @patch("chatbot.agent.nodes.intent_classify.CLASSIFICATION_PROMPT", "{user_message}")
    @patch("chatbot.agent.nodes.intent_classify._create_bedrock_client")
    def test_classifies_actionable_query(
        self, mock_client_factory: MagicMock
    ) -> None:
        """Actionable query is classified correctly."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response(INTENT_ACTIONABLE)
        mock_client_factory.return_value = mock_client

        state = _base_state(user_message="Show total sales by region last quarter")
        result = intent_classify(state)

        assert result["intent"] == INTENT_ACTIONABLE
        assert result["needs_disambiguation"] is False

    @patch("chatbot.agent.nodes.intent_classify.CLASSIFICATION_PROMPT", "{user_message}")
    @patch("chatbot.agent.nodes.intent_classify._create_bedrock_client")
    def test_classifies_ambiguous_query(
        self, mock_client_factory: MagicMock
    ) -> None:
        """Ambiguous query triggers disambiguation flag."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response(INTENT_AMBIGUOUS)
        mock_client_factory.return_value = mock_client

        state = _base_state(user_message="Show me the data")
        result = intent_classify(state)

        assert result["intent"] == INTENT_AMBIGUOUS
        assert result["needs_disambiguation"] is True

    @patch("chatbot.agent.nodes.intent_classify.CLASSIFICATION_PROMPT", "{user_message}")
    @patch("chatbot.agent.nodes.intent_classify._create_bedrock_client")
    def test_classifies_out_of_scope(
        self, mock_client_factory: MagicMock
    ) -> None:
        """Out-of-scope query is classified correctly."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response(INTENT_OUT_OF_SCOPE)
        mock_client_factory.return_value = mock_client

        state = _base_state(user_message="What's the weather today?")
        result = intent_classify(state)

        assert result["intent"] == INTENT_OUT_OF_SCOPE
        assert result["needs_disambiguation"] is False


    def test_empty_message_returns_out_of_scope(self) -> None:
        """Empty user message defaults to out_of_scope with error."""
        state = _base_state(user_message="")
        result = intent_classify(state)

        assert result["intent"] == INTENT_OUT_OF_SCOPE
        assert result["needs_disambiguation"] is False
        assert result.get("error") is not None

    @patch("chatbot.agent.nodes.intent_classify._create_bedrock_client")
    def test_invalid_json_response_defaults_to_ambiguous(
        self, mock_client_factory: MagicMock
    ) -> None:
        """Invalid JSON from model defaults to ambiguous (safe fallback)."""
        mock_client = MagicMock()
        body_content = json.dumps({"content": [{"text": "not valid json"}]})
        mock_body = MagicMock()
        mock_body.read.return_value = body_content.encode()
        mock_client.invoke_model.return_value = {"body": mock_body}
        mock_client_factory.return_value = mock_client

        state = _base_state()
        result = intent_classify(state)

        assert result["intent"] == INTENT_AMBIGUOUS

    @patch("chatbot.agent.nodes.intent_classify._create_bedrock_client")
    def test_unknown_intent_value_defaults_to_ambiguous(
        self, mock_client_factory: MagicMock
    ) -> None:
        """Unknown intent category from model defaults to ambiguous."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response("unknown_category")
        mock_client_factory.return_value = mock_client

        state = _base_state()
        result = intent_classify(state)

        assert result["intent"] == INTENT_AMBIGUOUS

    @patch("chatbot.agent.nodes.intent_classify._create_bedrock_client")
    def test_bedrock_client_error_defaults_to_ambiguous(
        self, mock_client_factory: MagicMock
    ) -> None:
        """Bedrock API error defaults to ambiguous (graceful degradation)."""
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "InvokeModel",
        )
        mock_client_factory.return_value = mock_client

        state = _base_state()
        result = intent_classify(state)

        assert result["intent"] == INTENT_AMBIGUOUS
        assert result["needs_disambiguation"] is True
        assert "error" in result



# ===========================================================================
# Tests for schema_retrieve node (Requirement 10.5)
# ===========================================================================


class TestSchemaRetrieveAuthFiltering:
    """Test schema retrieval filtering by user authorization (Requirement 10.5)."""

    def test_get_user_authorized_tags_analyst(self) -> None:
        """Analyst gets department + tier-appropriate tags."""
        claims = {
            "department": "analytics",
            "data_classification_tier": "internal",
            "groups": ["data-consumers"],
        }
        tags = _get_user_authorized_tags(claims)

        assert "analytics" in tags["department"]
        assert "shared" in tags["department"]
        # Internal tier can access public and internal
        assert tags["classification_tier"] == ["public", "internal"]
        assert tags["groups"] == ["data-consumers"]

    def test_get_user_authorized_tags_confidential_tier(self) -> None:
        """Confidential tier user can access public, internal, and confidential."""
        claims = {
            "department": "risk",
            "data_classification_tier": "confidential",
            "groups": ["risk-team", "elevated_cost"],
        }
        tags = _get_user_authorized_tags(claims)

        assert tags["classification_tier"] == ["public", "internal", "confidential"]

    def test_get_user_authorized_tags_public_tier(self) -> None:
        """Public tier user can only access public data."""
        claims = {
            "department": "support",
            "data_classification_tier": "public",
            "groups": [],
        }
        tags = _get_user_authorized_tags(claims)

        assert tags["classification_tier"] == ["public"]

    def test_get_user_authorized_tags_invalid_tier_defaults_to_public(self) -> None:
        """Invalid tier defaults to public-only access."""
        claims = {
            "department": "test",
            "data_classification_tier": "invalid_tier",
            "groups": [],
        }
        tags = _get_user_authorized_tags(claims)

        assert tags["classification_tier"] == ["public"]


    @patch("chatbot.agent.nodes.schema_retrieve._search_schemas")
    @patch("chatbot.agent.nodes.schema_retrieve._generate_embedding")
    def test_returns_only_authorized_schemas(
        self, mock_embed: MagicMock, mock_search: MagicMock
    ) -> None:
        """Only schemas matching user's LF grants are returned (Req 10.5)."""
        mock_embed.return_value = [0.1] * 1024  # Mock embedding vector
        mock_search.return_value = [
            {
                "database": "analytics_db",
                "table_name": "sales",
                "description": "Sales data",
                "columns": [{"name": "amount", "data_type": "double"}],
                "partition_keys": ["date"],
                "business_glossary_terms": [],
                "last_indexed": "2024-01-01",
            }
        ]

        state = _base_state()
        result = schema_retrieve(state)

        assert result["retrieved_schemas"] is not None
        assert len(result["retrieved_schemas"]) == 1
        assert result["retrieved_schemas"][0]["table_name"] == "sales"
        # Verify search was called with proper auth tags
        mock_search.assert_called_once()
        call_args = mock_search.call_args
        auth_tags = call_args[0][1]  # Second positional arg
        assert "department" in auth_tags
        assert "analytics" in auth_tags["department"]

    @patch("chatbot.agent.nodes.schema_retrieve._search_schemas")
    @patch("chatbot.agent.nodes.schema_retrieve._generate_embedding")
    def test_no_schemas_match_informs_user(
        self, mock_embed: MagicMock, mock_search: MagicMock
    ) -> None:
        """When no schemas match grants, user is informed (Req 10.5)."""
        mock_embed.return_value = [0.1] * 1024
        mock_search.return_value = []  # No authorized schemas match

        state = _base_state()
        result = schema_retrieve(state)

        assert result["retrieved_schemas"] == []
        assert "No accessible tables" in result.get("error", "")

    @patch("chatbot.agent.nodes.schema_retrieve._generate_embedding")
    def test_embedding_failure_returns_error(self, mock_embed: MagicMock) -> None:
        """Embedding generation failure is handled gracefully."""
        mock_embed.return_value = None  # Embedding failed

        state = _base_state()
        result = schema_retrieve(state)

        assert result["retrieved_schemas"] == []
        assert "embedding generation failed" in result.get("error", "")

    @patch("chatbot.agent.nodes.schema_retrieve._generate_embedding")
    def test_empty_claims_default_deny_no_schemas(self, mock_embed: MagicMock) -> None:
        """User with no identifiable claims gets no schemas (default-deny, Req 16.3)."""
        mock_embed.return_value = [0.1] * 1024

        state = _base_state()
        # Override user_claims with empty/missing authorization attributes
        state["user_claims"] = {
            "sub": "user-no-grants",
            "department": "",
            "data_classification_tier": "",
            "groups": [],
        }
        result = schema_retrieve(state)

        assert result["retrieved_schemas"] == []
        assert "No accessible tables" in result.get("error", "")

    def test_search_schemas_returns_empty_on_no_tags(self) -> None:
        """_search_schemas with empty authorized_tags returns empty (default-deny)."""
        from chatbot.agent.nodes.schema_retrieve import _search_schemas

        # Empty tags = no authorization → default-deny
        result = _search_schemas([0.1] * 1024, {})
        assert result == []

    def test_opensearch_collection_config_vpc_only(self) -> None:
        """OpenSearch collection config enforces VPC-only access (Req 16.5)."""
        from chatbot.agent.nodes.schema_retrieve import COLLECTION_CONFIG

        assert COLLECTION_CONFIG.collection_type == "VECTORSEARCH"
        assert COLLECTION_CONFIG.network_policy_type == "AllPrivate"

        policy = COLLECTION_CONFIG.get_network_policy()
        assert policy["AllowFromPublic"] is False



# ===========================================================================
# Tests for disambiguate node (Requirement 10.2)
# ===========================================================================


class TestDisambiguateNode:
    """Test disambiguation node with round tracking (Requirement 10.2)."""

    @patch("chatbot.agent.nodes.disambiguate.boto3.client")
    def test_increments_disambiguation_rounds(self, mock_boto: MagicMock) -> None:
        """Each call increments the round counter."""
        # Mock Bedrock response
        body_content = json.dumps(
            {"content": [{"text": json.dumps({"question": "Which table?", "options": ["A", "B"]})}]}
        )
        mock_body = MagicMock()
        mock_body.read.return_value = body_content.encode()
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = {"body": mock_body}
        mock_boto.return_value = mock_client

        state = _base_state(disambiguation_rounds=0, needs_disambiguation=True)
        result = disambiguate(state)

        assert result["disambiguation_rounds"] == 1

    @patch("chatbot.agent.nodes.disambiguate.boto3.client")
    def test_round_1_keeps_disambiguation_active(self, mock_boto: MagicMock) -> None:
        """At round 1, disambiguation remains active."""
        body_content = json.dumps(
            {"content": [{"text": json.dumps({"question": "What period?", "options": ["Q1", "Q2"]})}]}
        )
        mock_body = MagicMock()
        mock_body.read.return_value = body_content.encode()
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = {"body": mock_body}
        mock_boto.return_value = mock_client

        state = _base_state(disambiguation_rounds=0)
        result = disambiguate(state)

        assert result["disambiguation_rounds"] == 1
        assert result["needs_disambiguation"] is True
        assert result["final_response"] is not None

    def test_max_rounds_terminates_loop(self) -> None:
        """At max rounds (3), disambiguation terminates (Req 10.2)."""
        state = _base_state(disambiguation_rounds=2)
        result = disambiguate(state)

        # Round goes to 3 (max), terminates
        assert result["disambiguation_rounds"] == MAX_DISAMBIGUATION_ROUNDS
        assert result["needs_disambiguation"] is False
        assert "refine your question" in result["final_response"]

    def test_max_disambiguation_rounds_constant_is_3(self) -> None:
        """MAX_DISAMBIGUATION_ROUNDS is 3."""
        assert MAX_DISAMBIGUATION_ROUNDS == 3


    @patch("chatbot.agent.nodes.disambiguate.boto3.client")
    def test_bedrock_error_proceeds_without_disambiguation(
        self, mock_boto: MagicMock
    ) -> None:
        """Bedrock failure doesn't block; proceeds without disambiguation."""
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": "Unavailable"}},
            "InvokeModel",
        )
        mock_boto.return_value = mock_client

        state = _base_state(disambiguation_rounds=0)
        result = disambiguate(state)

        assert result["disambiguation_rounds"] == 1
        assert result["needs_disambiguation"] is False
        assert result["final_response"] is not None


# ===========================================================================
# Tests for self_correct node (Requirement 10.3)
# ===========================================================================


class TestSelfCorrectNode:
    """Test self-correction node with attempt tracking (Requirement 10.3)."""

    @patch("chatbot.agent.nodes.self_correct.boto3.client")
    def test_increments_correction_attempts(self, mock_boto: MagicMock) -> None:
        """Each call increments the attempt counter."""
        body_content = json.dumps(
            {"content": [{"text": "SELECT id, name FROM users LIMIT 100"}]}
        )
        mock_body = MagicMock()
        mock_body.read.return_value = body_content.encode()
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = {"body": mock_body}
        mock_boto.return_value = mock_client

        state = _base_state(
            self_correction_attempts=0,
            generated_sql="SELECT * FROM users",
            sql_error="SELECT * not allowed on wide table",
        )
        result = self_correct(state)

        assert result["self_correction_attempts"] == 1


    @patch("chatbot.agent.nodes.self_correct.boto3.client")
    def test_produces_corrected_sql(self, mock_boto: MagicMock) -> None:
        """Successful correction produces new SQL and resets sql_valid."""
        corrected = "SELECT id, name, email FROM users WHERE dept='analytics' LIMIT 100"
        body_content = json.dumps({"content": [{"text": corrected}]})
        mock_body = MagicMock()
        mock_body.read.return_value = body_content.encode()
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = {"body": mock_body}
        mock_boto.return_value = mock_client

        state = _base_state(
            self_correction_attempts=0,
            generated_sql="SELECT * FROM users",
            sql_error="SELECT * not allowed",
        )
        result = self_correct(state)

        assert result["generated_sql"] == corrected
        assert result["sql_valid"] is False  # Must be re-validated
        assert result["sql_error"] is None

    def test_exceeding_max_retries_stops_correction(self) -> None:
        """Beyond max retries (2), no correction is attempted (Req 10.3)."""
        state = _base_state(
            self_correction_attempts=2,
            generated_sql="SELECT bad_column FROM t",
            sql_error="Column not found",
        )
        result = self_correct(state)

        assert result["self_correction_attempts"] == 3
        assert result["sql_valid"] is False
        assert "maximum retries" in result.get("error", "")

    def test_max_self_correction_retries_constant_is_2(self) -> None:
        """MAX_SELF_CORRECTION_RETRIES is 2."""
        assert MAX_SELF_CORRECTION_RETRIES == 2

    @patch("chatbot.agent.nodes.self_correct.boto3.client")
    def test_bedrock_error_sets_sql_error(self, mock_boto: MagicMock) -> None:
        """Bedrock failure during correction sets sql_error."""
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "InvokeModel",
        )
        mock_boto.return_value = mock_client

        state = _base_state(
            self_correction_attempts=0,
            generated_sql="SELECT * FROM t",
            sql_error="Original error",
        )
        result = self_correct(state)

        assert result["self_correction_attempts"] == 1
        assert result["sql_valid"] is False
        assert result["sql_error"] is not None



# ===========================================================================
# Tests for validate_sql node
# ===========================================================================


class TestValidateSqlNode:
    """Test SQL validation node delegates to validation engine."""

    @patch("chatbot.agent.nodes.validate_sql.asyncio")
    @patch("chatbot.agent.nodes.validate_sql._validate")
    def test_valid_sql_passes(
        self, mock_validate: MagicMock, mock_asyncio: MagicMock
    ) -> None:
        """Valid SQL sets sql_valid=True and injects LIMIT."""
        from chatbot.mcp_server.validation import ValidationResult

        result_obj = ValidationResult(
            valid=True,
            modified_sql="SELECT id FROM sales LIMIT 10000",
        )
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = False
        mock_asyncio.get_event_loop.return_value = mock_loop
        mock_asyncio.run.return_value = result_obj

        state = _base_state(generated_sql="SELECT id FROM sales")
        result = validate_sql_node(state)

        assert result["sql_valid"] is True
        assert "LIMIT 10000" in result["generated_sql"]
        assert result["sql_error"] is None

    @patch("chatbot.agent.nodes.validate_sql.asyncio")
    @patch("chatbot.agent.nodes.validate_sql._validate")
    def test_invalid_sql_sets_error(
        self, mock_validate: MagicMock, mock_asyncio: MagicMock
    ) -> None:
        """Invalid SQL sets sql_valid=False with rejection reason."""
        from chatbot.mcp_server.validation import ValidationResult

        result_obj = ValidationResult(
            valid=False,
            rejection_reason="Only SELECT statements are permitted",
        )
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = False
        mock_asyncio.get_event_loop.return_value = mock_loop
        mock_asyncio.run.return_value = result_obj

        state = _base_state(generated_sql="DROP TABLE users")
        result = validate_sql_node(state)

        assert result["sql_valid"] is False
        assert "SELECT" in result["sql_error"]

    def test_no_sql_returns_error(self) -> None:
        """Missing generated_sql returns validation error."""
        state = _base_state(generated_sql=None)
        result = validate_sql_node(state)

        assert result["sql_valid"] is False
        assert "No SQL" in result["sql_error"]

    @patch("chatbot.agent.nodes.validate_sql.asyncio")
    @patch("chatbot.agent.nodes.validate_sql._validate")
    def test_unauthorized_table_rejected(
        self, mock_validate: MagicMock, mock_asyncio: MagicMock
    ) -> None:
        """SQL referencing unauthorized table is rejected."""
        from chatbot.mcp_server.validation import ValidationResult

        result_obj = ValidationResult(
            valid=False,
            rejection_reason="Unauthorized table reference: pci_cardholder.transactions",
        )
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = False
        mock_asyncio.get_event_loop.return_value = mock_loop
        mock_asyncio.run.return_value = result_obj

        state = _base_state(
            generated_sql="SELECT * FROM pci_cardholder.transactions",
            user_claims={
                "sub": "user-123",
                "department": "analytics",
                "role": "analyst",
                "data_classification_tier": "internal",
                "groups": [],
                "session_id": "00000000-0000-4000-8000-000000000001",
                "exp": 9999999999,
                "authorized_tables": ["analytics_db.sales", "analytics_db.users"],
            },
        )
        result = validate_sql_node(state)

        assert result["sql_valid"] is False
        assert "Unauthorized" in result["sql_error"]


    @patch("chatbot.agent.nodes.validate_sql.asyncio")
    @patch("chatbot.agent.nodes.validate_sql._validate")
    def test_validation_engine_exception_handled(
        self, mock_validate: MagicMock, mock_asyncio: MagicMock
    ) -> None:
        """Exception in validation engine is caught gracefully."""
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = False
        mock_asyncio.get_event_loop.return_value = mock_loop
        mock_asyncio.run.side_effect = RuntimeError("Engine crashed")

        state = _base_state(generated_sql="SELECT 1")
        result = validate_sql_node(state)

        assert result["sql_valid"] is False
        assert "error" in result["sql_error"].lower()


# ===========================================================================
# Tests for conditional edge logic (graph-level)
# ===========================================================================


class TestConditionalEdges:
    """Test conditional edge functions enforce loop bounds at graph level."""

    def test_should_disambiguate_routes_correctly_at_boundary(self) -> None:
        """Boundary test: round 2 → disambiguate, round 3 → sql_generate."""
        from chatbot.agent.graph import should_disambiguate

        # Round 2: still under limit
        state_under = {"needs_disambiguation": True, "disambiguation_rounds": 2}
        assert should_disambiguate(state_under) == "disambiguate"

        # Round 3: at limit, must route to sql_generate
        state_at = {"needs_disambiguation": True, "disambiguation_rounds": 3}
        assert should_disambiguate(state_at) == "sql_generate"

    def test_should_self_correct_routes_correctly_at_boundary(self) -> None:
        """Boundary test: attempt 1 → self_correct, attempt 2 → output_scan."""
        from chatbot.agent.graph import should_self_correct

        # Attempt 1: still under limit
        state_under = {"sql_error": "error", "self_correction_attempts": 1}
        assert should_self_correct(state_under) == "self_correct"

        # Attempt 2: at limit, must route to output_scan
        state_at = {"sql_error": "error", "self_correction_attempts": 2}
        assert should_self_correct(state_at) == "output_scan"

    def test_after_validate_sql_routes_to_gateway_when_valid(self) -> None:
        """Valid SQL routes to tool_call (through Gateway)."""
        from chatbot.agent.graph import after_validate_sql

        state = {"sql_valid": True, "self_correction_attempts": 0}
        assert after_validate_sql(state) == "tool_call"

    def test_after_validate_sql_exhausted_retries_gives_up(self) -> None:
        """Exhausted retries route to format_respond (give up)."""
        from chatbot.agent.graph import after_validate_sql

        state = {"sql_valid": False, "self_correction_attempts": 2}
        assert after_validate_sql(state) == "format_respond"

    def test_loop_bounds_enforced_structurally(self) -> None:
        """Both loop bounds are enforced by constants, not runtime logic."""
        from chatbot.agent.graph import AgentGraph

        assert AgentGraph.MAX_DISAMBIGUATION_ROUNDS == 3
        assert AgentGraph.MAX_SELF_CORRECTION_RETRIES == 2
