"""Unit tests for core Pydantic models and data classes.

Tests validation rules including UUID v4 session_id, tier hierarchy,
claim validation, and data model constraints.
"""

import uuid

import pytest
from pydantic import ValidationError

from chatbot.api.models import (
    ChatRequest,
    ChatResponse,
    DataClassificationTier,
    ErrorResponse,
    UserClaims,
)
from chatbot.agent.state import AgentState
from chatbot.mcp_server.tools.models import (
    ColumnInfo,
    CostEstimate,
    QueryResult,
    TableInfo,
)


# --- Helper fixtures ---


def make_valid_user_claims(**overrides) -> dict:
    """Create a valid UserClaims dict with optional overrides."""
    defaults = {
        "sub": "user-123-abc",
        "department": "analytics",
        "role": "analyst",
        "data_classification_tier": "internal",
        "groups": ["data-users", "analytics-team"],
        "session_id": str(uuid.uuid4()),
        "exp": 1700000000,
    }
    defaults.update(overrides)
    return defaults


# --- UserClaims Tests ---


class TestUserClaims:
    def test_valid_user_claims(self):
        claims = UserClaims(**make_valid_user_claims())
        assert claims.sub == "user-123-abc"
        assert claims.department == "analytics"
        assert claims.role == "analyst"
        assert claims.data_classification_tier == "internal"

    def test_session_id_must_be_uuid_v4(self):
        with pytest.raises(ValidationError, match="session_id must be a valid UUID v4"):
            UserClaims(**make_valid_user_claims(session_id="not-a-uuid"))

    def test_session_id_rejects_uuid_v1(self):
        uuid_v1 = str(uuid.uuid1())
        with pytest.raises(ValidationError, match="session_id must be a valid UUID v4"):
            UserClaims(**make_valid_user_claims(session_id=uuid_v1))

    def test_session_id_accepts_valid_uuid_v4(self):
        valid_uuid = str(uuid.uuid4())
        claims = UserClaims(**make_valid_user_claims(session_id=valid_uuid))
        assert claims.session_id == valid_uuid

    def test_tier_must_be_valid(self):
        with pytest.raises(ValidationError, match="data_classification_tier must be one of"):
            UserClaims(**make_valid_user_claims(data_classification_tier="top-secret"))

    def test_tier_normalized_to_lowercase(self):
        claims = UserClaims(**make_valid_user_claims(data_classification_tier="Confidential"))
        assert claims.data_classification_tier == "confidential"

    def test_sub_must_be_non_empty(self):
        with pytest.raises(ValidationError, match="non-empty"):
            UserClaims(**make_valid_user_claims(sub=""))

    def test_sub_must_not_be_whitespace_only(self):
        with pytest.raises(ValidationError, match="non-empty"):
            UserClaims(**make_valid_user_claims(sub="   "))

    def test_department_must_be_non_empty(self):
        with pytest.raises(ValidationError, match="non-empty"):
            UserClaims(**make_valid_user_claims(department=""))

    def test_role_must_be_non_empty(self):
        with pytest.raises(ValidationError, match="non-empty"):
            UserClaims(**make_valid_user_claims(role=""))

    def test_exp_must_be_positive(self):
        with pytest.raises(ValidationError, match="positive integer"):
            UserClaims(**make_valid_user_claims(exp=0))

    def test_exp_rejects_negative(self):
        with pytest.raises(ValidationError, match="positive integer"):
            UserClaims(**make_valid_user_claims(exp=-100))

    def test_groups_can_be_empty_list(self):
        claims = UserClaims(**make_valid_user_claims(groups=[]))
        assert claims.groups == []

    def test_all_valid_tiers(self):
        for tier in ["public", "internal", "confidential", "restricted"]:
            claims = UserClaims(**make_valid_user_claims(data_classification_tier=tier))
            assert claims.data_classification_tier == tier


# --- DataClassificationTier Tests ---


class TestDataClassificationTier:
    def test_hierarchy_levels(self):
        assert DataClassificationTier.hierarchy_level("public") == 0
        assert DataClassificationTier.hierarchy_level("internal") == 1
        assert DataClassificationTier.hierarchy_level("confidential") == 2
        assert DataClassificationTier.hierarchy_level("restricted") == 3

    def test_can_access_same_tier(self):
        assert DataClassificationTier.can_access("internal", "internal") is True

    def test_can_access_lower_tier(self):
        assert DataClassificationTier.can_access("confidential", "internal") is True
        assert DataClassificationTier.can_access("restricted", "public") is True

    def test_cannot_access_higher_tier(self):
        assert DataClassificationTier.can_access("public", "internal") is False
        assert DataClassificationTier.can_access("internal", "confidential") is False

    def test_restricted_can_access_all(self):
        for tier in ["public", "internal", "confidential", "restricted"]:
            assert DataClassificationTier.can_access("restricted", tier) is True

    def test_public_can_only_access_public(self):
        assert DataClassificationTier.can_access("public", "public") is True
        assert DataClassificationTier.can_access("public", "internal") is False
        assert DataClassificationTier.can_access("public", "confidential") is False
        assert DataClassificationTier.can_access("public", "restricted") is False


# --- ChatRequest Tests ---


class TestChatRequest:
    def test_valid_request(self):
        req = ChatRequest(
            message="Show me sales data",
            session_id=str(uuid.uuid4()),
        )
        assert req.message == "Show me sales data"
        assert req.conversation_id is None

    def test_session_id_must_be_uuid_v4(self):
        with pytest.raises(ValidationError, match="session_id must be a valid UUID v4"):
            ChatRequest(message="hello", session_id="invalid")

    def test_message_must_be_non_empty(self):
        with pytest.raises(ValidationError, match="non-empty"):
            ChatRequest(message="", session_id=str(uuid.uuid4()))

    def test_message_rejects_whitespace_only(self):
        with pytest.raises(ValidationError, match="non-empty"):
            ChatRequest(message="   ", session_id=str(uuid.uuid4()))

    def test_conversation_id_optional(self):
        req = ChatRequest(
            message="hello",
            session_id=str(uuid.uuid4()),
            conversation_id="conv-123",
        )
        assert req.conversation_id == "conv-123"


# --- ChatResponse Tests ---


class TestChatResponse:
    def test_minimal_response(self):
        resp = ChatResponse(answer="Here are your results")
        assert resp.answer == "Here are your results"
        assert resp.sql_generated is None
        assert resp.warnings == []

    def test_full_response(self):
        resp = ChatResponse(
            answer="Query complete",
            sql_generated="SELECT id FROM users",
            data_freshness="Data current as of 2024-01-15T10:00:00Z",
            row_count=42,
            cost_estimate_bytes=1_000_000,
            warnings=["Large result set"],
        )
        assert resp.row_count == 42
        assert len(resp.warnings) == 1


# --- ErrorResponse Tests ---


class TestErrorResponse:
    def test_valid_error_response(self):
        err = ErrorResponse(
            error_type="auth_denied",
            message="You do not have access to this table",
            trace_id=str(uuid.uuid4()),
        )
        assert err.error_type == "auth_denied"
        assert err.retry_after is None

    def test_trace_id_must_be_uuid_v4(self):
        with pytest.raises(ValidationError, match="trace_id must be a valid UUID v4"):
            ErrorResponse(
                error_type="sql_failed",
                message="Query failed",
                trace_id="not-a-uuid",
            )

    def test_rate_limited_with_retry_after(self):
        err = ErrorResponse(
            error_type="rate_limited",
            message="Rate limit exceeded",
            trace_id=str(uuid.uuid4()),
            retry_after=30,
        )
        assert err.retry_after == 30


# --- AgentState Tests ---


class TestAgentState:
    def _make_claims(self):
        return UserClaims(**make_valid_user_claims())

    def test_initial_state(self):
        state = AgentState(
            user_claims=self._make_claims(),
            user_message="Show me sales data",
        )
        assert state.intent is None
        assert state.disambiguation_rounds == 0
        assert state.self_correction_attempts == 0
        assert state.sql_valid is False
        assert state.error is None

    def test_can_disambiguate_under_limit(self):
        state = AgentState(
            user_claims=self._make_claims(),
            user_message="test",
        )
        assert state.can_disambiguate() is True
        state.increment_disambiguation()
        assert state.disambiguation_rounds == 1
        assert state.can_disambiguate() is True

    def test_cannot_disambiguate_at_limit(self):
        state = AgentState(
            user_claims=self._make_claims(),
            user_message="test",
            disambiguation_rounds=3,
        )
        assert state.can_disambiguate() is False

    def test_increment_disambiguation_raises_at_limit(self):
        state = AgentState(
            user_claims=self._make_claims(),
            user_message="test",
            disambiguation_rounds=3,
        )
        with pytest.raises(ValueError, match="exceeded maximum"):
            state.increment_disambiguation()

    def test_can_self_correct_under_limit(self):
        state = AgentState(
            user_claims=self._make_claims(),
            user_message="test",
        )
        assert state.can_self_correct() is True
        state.increment_self_correction()
        assert state.self_correction_attempts == 1
        assert state.can_self_correct() is True

    def test_cannot_self_correct_at_limit(self):
        state = AgentState(
            user_claims=self._make_claims(),
            user_message="test",
            self_correction_attempts=2,
        )
        assert state.can_self_correct() is False

    def test_increment_self_correction_raises_at_limit(self):
        state = AgentState(
            user_claims=self._make_claims(),
            user_message="test",
            self_correction_attempts=2,
        )
        with pytest.raises(ValueError, match="exceeded maximum"):
            state.increment_self_correction()

    def test_max_bounds_are_correct(self):
        state = AgentState(
            user_claims=self._make_claims(),
            user_message="test",
        )
        assert state.MAX_DISAMBIGUATION_ROUNDS == 3
        assert state.MAX_SELF_CORRECTION_ATTEMPTS == 2


# --- MCP Server Models Tests ---


class TestColumnInfo:
    def test_valid_column(self):
        col = ColumnInfo(
            name="user_id",
            data_type="string",
            description="Unique user identifier",
            is_pii=False,
            classification="internal",
        )
        assert col.name == "user_id"
        assert col.is_pii is False

    def test_classification_must_be_valid_tier(self):
        with pytest.raises(ValidationError, match="classification must be one of"):
            ColumnInfo(
                name="ssn",
                data_type="string",
                description="Social security number",
                is_pii=True,
                classification="top-secret",
            )

    def test_classification_normalized_to_lowercase(self):
        col = ColumnInfo(
            name="email",
            data_type="string",
            description="User email",
            is_pii=True,
            classification="Confidential",
        )
        assert col.classification == "confidential"

    def test_name_must_be_non_empty(self):
        with pytest.raises(ValidationError, match="non-empty"):
            ColumnInfo(
                name="",
                data_type="string",
                description="test",
                is_pii=False,
                classification="public",
            )


class TestTableInfo:
    def _make_column(self, **overrides) -> dict:
        defaults = {
            "name": "col1",
            "data_type": "string",
            "description": "Test column",
            "is_pii": False,
            "classification": "public",
        }
        defaults.update(overrides)
        return defaults

    def test_valid_table_info(self):
        table = TableInfo(
            database="analytics_db",
            table_name="sales",
            description="Sales transactions",
            columns=[self._make_column()],
            partition_keys=["year", "month"],
            last_updated="2024-01-15T10:00:00Z",
        )
        assert table.database == "analytics_db"
        assert len(table.partition_keys) == 2

    def test_database_must_be_non_empty(self):
        with pytest.raises(ValidationError, match="non-empty"):
            TableInfo(
                database="",
                table_name="sales",
                description="test",
                columns=[],
                partition_keys=[],
                last_updated="2024-01-15T10:00:00Z",
            )

    def test_table_name_must_be_non_empty(self):
        with pytest.raises(ValidationError, match="non-empty"):
            TableInfo(
                database="db",
                table_name="",
                description="test",
                columns=[],
                partition_keys=[],
                last_updated="2024-01-15T10:00:00Z",
            )


class TestCostEstimate:
    def test_valid_cost_estimate(self):
        est = CostEstimate(
            estimated_bytes_scanned=5_000_000_000,
            estimated_cost_usd=0.025,
            exceeds_threshold=False,
        )
        assert est.exceeds_threshold is False
        assert est.suggestion is None

    def test_exceeds_threshold_with_suggestion(self):
        est = CostEstimate(
            estimated_bytes_scanned=15_000_000_000,
            estimated_cost_usd=0.075,
            exceeds_threshold=True,
            suggestion="Add a date partition filter to reduce scan size",
        )
        assert est.exceeds_threshold is True
        assert est.suggestion is not None

    def test_bytes_scanned_must_be_non_negative(self):
        with pytest.raises(ValidationError, match="non-negative"):
            CostEstimate(
                estimated_bytes_scanned=-1,
                estimated_cost_usd=0.0,
                exceeds_threshold=False,
            )

    def test_cost_usd_must_be_non_negative(self):
        with pytest.raises(ValidationError, match="non-negative"):
            CostEstimate(
                estimated_bytes_scanned=100,
                estimated_cost_usd=-0.01,
                exceeds_threshold=False,
            )


class TestQueryResult:
    def test_valid_query_result(self):
        result = QueryResult(
            columns=["id", "name", "amount"],
            rows=[{"id": 1, "name": "Alice", "amount": 100}],
            row_count=1,
            bytes_scanned=500_000,
            execution_time_ms=1200,
            data_freshness="Data current as of 2024-01-15T08:00:00Z",
        )
        assert result.row_count == 1
        assert result.execution_time_ms == 1200

    def test_row_count_must_be_non_negative(self):
        with pytest.raises(ValidationError, match="non-negative"):
            QueryResult(
                columns=["id"],
                rows=[],
                row_count=-1,
                bytes_scanned=0,
                execution_time_ms=0,
                data_freshness="fresh",
            )

    def test_bytes_scanned_must_be_non_negative(self):
        with pytest.raises(ValidationError, match="non-negative"):
            QueryResult(
                columns=["id"],
                rows=[],
                row_count=0,
                bytes_scanned=-100,
                execution_time_ms=0,
                data_freshness="fresh",
            )

    def test_execution_time_must_be_non_negative(self):
        with pytest.raises(ValidationError, match="non-negative"):
            QueryResult(
                columns=["id"],
                rows=[],
                row_count=0,
                bytes_scanned=0,
                execution_time_ms=-1,
                data_freshness="fresh",
            )

    def test_data_freshness_must_be_non_empty(self):
        with pytest.raises(ValidationError, match="non-empty"):
            QueryResult(
                columns=["id"],
                rows=[],
                row_count=0,
                bytes_scanned=0,
                execution_time_ms=0,
                data_freshness="",
            )
