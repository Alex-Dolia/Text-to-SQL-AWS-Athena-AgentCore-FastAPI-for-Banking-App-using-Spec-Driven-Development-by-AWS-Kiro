"""Unit tests for MCP server tools: run_query OBO identity, workgroup enforcement, and estimate_cost thresholds.

Tests cover:
- run_query uses OBO token identity (not service role) (Requirement 7.1, 7.5)
- run_query always uses chatbot-readonly workgroup (Requirement 7.6)
- run_query fails closed when OBO token exchange fails (never falls back to service role)
- estimate_cost returns threshold warnings for queries exceeding 10 GB (Requirement 9.5)
- estimate_cost respects elevated_cost group membership (Requirement 16.3)

Uses unittest.mock to simulate AWS calls (STS, Athena, Glue).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatbot.api.models import UserClaims
from chatbot.mcp_server.tools.estimate_cost import (
    COST_THRESHOLD_BYTES,
    WORKGROUP as ESTIMATE_WORKGROUP,
    estimate_cost,
)
from chatbot.mcp_server.tools.run_query import (
    WORKGROUP as RUN_QUERY_WORKGROUP,
    run_query,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def analyst_user() -> UserClaims:
    """Analyst user without elevated_cost group."""
    return UserClaims(
        sub="user-analyst-001",
        department="analytics",
        role="analyst",
        data_classification_tier="internal",
        groups=["analysts", "data-team"],
        session_id="12345678-1234-4234-8234-123456789012",
        exp=9999999999,
    )


@pytest.fixture
def elevated_user() -> UserClaims:
    """Manager user with elevated_cost group."""
    return UserClaims(
        sub="user-manager-001",
        department="risk",
        role="manager",
        data_classification_tier="confidential",
        groups=["managers", "risk-team", "elevated_cost"],
        session_id="22345678-1234-4234-8234-123456789012",
        exp=9999999999,
    )


@pytest.fixture
def mock_athena_client() -> MagicMock:
    """Create a mock Athena client that simulates successful query execution."""
    client = MagicMock()

    # start_query_execution returns a query ID
    client.start_query_execution.return_value = {
        "QueryExecutionId": "query-exec-id-001"
    }

    # Waiter succeeds immediately
    waiter = MagicMock()
    waiter.wait.return_value = None
    client.get_waiter.return_value = waiter

    # get_query_execution returns statistics
    client.get_query_execution.return_value = {
        "QueryExecution": {
            "Statistics": {
                "DataScannedInBytes": 5_000_000,
                "EngineExecutionTimeInMillis": 1200,
            }
        }
    }

    # get_query_results returns sample data
    client.get_query_results.return_value = {
        "ResultSet": {
            "ResultSetMetadata": {
                "ColumnInfo": [
                    {"Name": "id"},
                    {"Name": "amount"},
                ]
            },
            "Rows": [
                {"Data": [{"VarCharValue": "id"}, {"VarCharValue": "amount"}]},
                {"Data": [{"VarCharValue": "1"}, {"VarCharValue": "100.50"}]},
                {"Data": [{"VarCharValue": "2"}, {"VarCharValue": "200.75"}]},
            ],
        }
    }

    return client


@pytest.fixture
def mock_glue_client() -> MagicMock:
    """Create a mock Glue client for data freshness."""
    client = MagicMock()
    client.get_partitions.return_value = {
        "Partitions": [
            {"LastAccessTime": "2024-01-15T10:30:00Z"}
        ]
    }
    return client


# ---------------------------------------------------------------------------
# run_query: OBO token identity enforcement (Requirement 7.1, 7.5)
# ---------------------------------------------------------------------------


class TestRunQueryOBOIdentity:
    """Tests for run_query OBO identity enforcement (Requirements 7.1, 7.5)."""

    async def test_requires_obo_token_or_athena_client(
        self, analyst_user: UserClaims
    ) -> None:
        """run_query raises ValueError when neither obo_token nor athena_client provided."""
        with pytest.raises(ValueError, match="obo_token.*athena_client"):
            await run_query(
                sql="SELECT * FROM analytics_db.transactions LIMIT 10",
                user_claims=analyst_user,
                obo_token=None,
                athena_client=None,
            )

    async def test_empty_sql_rejected(
        self, analyst_user: UserClaims, mock_athena_client: MagicMock
    ) -> None:
        """run_query raises ValueError for empty SQL."""
        with pytest.raises(ValueError, match="non-empty"):
            await run_query(
                sql="",
                user_claims=analyst_user,
                athena_client=mock_athena_client,
            )

    async def test_whitespace_only_sql_rejected(
        self, analyst_user: UserClaims, mock_athena_client: MagicMock
    ) -> None:
        """run_query raises ValueError for whitespace-only SQL."""
        with pytest.raises(ValueError, match="non-empty"):
            await run_query(
                sql="   \t\n  ",
                user_claims=analyst_user,
                athena_client=mock_athena_client,
            )

    @patch("chatbot.mcp_server.tools.run_query._create_athena_client_with_obo")
    async def test_obo_token_used_to_create_client(
        self,
        mock_create_client: MagicMock,
        analyst_user: UserClaims,
        mock_athena_client: MagicMock,
    ) -> None:
        """run_query uses OBO token to create Athena client (user identity, not service)."""
        mock_create_client.return_value = mock_athena_client

        await run_query(
            sql="SELECT id FROM analytics_db.transactions LIMIT 10",
            user_claims=analyst_user,
            obo_token="user-obo-token-xyz",
        )

        # Verify OBO token was used with user claims
        mock_create_client.assert_called_once_with(analyst_user, "user-obo-token-xyz")

    @patch("chatbot.mcp_server.tools.run_query._create_athena_client_with_obo")
    async def test_obo_exchange_failure_raises_runtime_error(
        self,
        mock_create_client: MagicMock,
        analyst_user: UserClaims,
    ) -> None:
        """run_query fails closed when OBO token exchange fails — never falls back to service role."""
        mock_create_client.side_effect = RuntimeError(
            "Identity delegation failed: unable to assume user federated identity."
        )

        with pytest.raises(RuntimeError, match="Identity delegation failed"):
            await run_query(
                sql="SELECT 1",
                user_claims=analyst_user,
                obo_token="invalid-obo-token",
            )

    @patch("chatbot.mcp_server.tools.run_query.boto3.client")
    def test_create_athena_client_uses_sts_assume_role_with_web_identity(
        self, mock_boto_client: MagicMock, analyst_user: UserClaims
    ) -> None:
        """The OBO client factory uses STS AssumeRoleWithWebIdentity (user identity, not service)."""
        from chatbot.mcp_server.tools.run_query import _create_athena_client_with_obo

        mock_sts = MagicMock()
        mock_sts.assume_role_with_web_identity.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIA_USER_CREDS",
                "SecretAccessKey": "secret_user_key",
                "SessionToken": "user_session_token",
            }
        }
        mock_boto_client.return_value = mock_sts

        # First call returns STS client, second returns Athena client
        mock_boto_client.side_effect = [mock_sts, MagicMock()]

        _create_athena_client_with_obo(analyst_user, "user-obo-token")

        # Verify STS was called with user's OBO token (not a shared credential)
        mock_sts.assume_role_with_web_identity.assert_called_once()
        call_kwargs = mock_sts.assume_role_with_web_identity.call_args[1]
        assert call_kwargs["WebIdentityToken"] == "user-obo-token"
        assert analyst_user.sub in call_kwargs["RoleSessionName"]

    async def test_query_executed_with_provided_athena_client(
        self,
        analyst_user: UserClaims,
        mock_athena_client: MagicMock,
        mock_glue_client: MagicMock,
    ) -> None:
        """run_query uses the provided Athena client (for testing) without OBO exchange."""
        result = await run_query(
            sql="SELECT id FROM analytics_db.transactions LIMIT 10",
            user_claims=analyst_user,
            athena_client=mock_athena_client,
            glue_client=mock_glue_client,
        )

        # Query was submitted
        mock_athena_client.start_query_execution.assert_called_once()
        assert result.row_count == 2
        assert result.columns == ["id", "amount"]


# ---------------------------------------------------------------------------
# run_query: Workgroup enforcement (Requirement 7.6)
# ---------------------------------------------------------------------------


class TestRunQueryWorkgroup:
    """Tests for run_query chatbot-readonly workgroup enforcement (Requirement 7.6)."""

    async def test_query_uses_chatbot_readonly_workgroup(
        self,
        analyst_user: UserClaims,
        mock_athena_client: MagicMock,
        mock_glue_client: MagicMock,
    ) -> None:
        """run_query always submits queries to the chatbot-readonly workgroup."""
        await run_query(
            sql="SELECT id FROM analytics_db.transactions LIMIT 10",
            user_claims=analyst_user,
            athena_client=mock_athena_client,
            glue_client=mock_glue_client,
        )

        call_kwargs = mock_athena_client.start_query_execution.call_args[1]
        assert call_kwargs["WorkGroup"] == "chatbot-readonly"

    async def test_workgroup_constant_is_chatbot_readonly(self) -> None:
        """The WORKGROUP constant in run_query module is 'chatbot-readonly'."""
        assert RUN_QUERY_WORKGROUP == "chatbot-readonly"

    async def test_workgroup_constant_matches_estimate_cost(self) -> None:
        """Both run_query and estimate_cost use the same chatbot-readonly workgroup."""
        assert RUN_QUERY_WORKGROUP == ESTIMATE_WORKGROUP == "chatbot-readonly"

    async def test_query_returns_result_with_execution_metadata(
        self,
        analyst_user: UserClaims,
        mock_athena_client: MagicMock,
        mock_glue_client: MagicMock,
    ) -> None:
        """run_query returns QueryResult with bytes_scanned and execution_time."""
        result = await run_query(
            sql="SELECT id FROM analytics_db.transactions LIMIT 10",
            user_claims=analyst_user,
            athena_client=mock_athena_client,
            glue_client=mock_glue_client,
        )

        assert result.bytes_scanned == 5_000_000
        assert result.execution_time_ms == 1200
        assert result.row_count == 2

    async def test_query_execution_failure_raises_runtime_error(
        self,
        analyst_user: UserClaims,
        mock_athena_client: MagicMock,
    ) -> None:
        """run_query raises RuntimeError when Athena execution fails."""
        waiter = MagicMock()
        waiter.wait.side_effect = Exception("Query timed out")
        mock_athena_client.get_waiter.return_value = waiter

        with pytest.raises(RuntimeError, match="Query execution failed"):
            await run_query(
                sql="SELECT * FROM analytics_db.big_table",
                user_claims=analyst_user,
                athena_client=mock_athena_client,
            )


# ---------------------------------------------------------------------------
# estimate_cost: Threshold warnings (Requirement 9.5)
# ---------------------------------------------------------------------------


class TestEstimateCostThresholds:
    """Tests for estimate_cost threshold warning behavior (Requirement 9.5)."""

    async def test_below_threshold_no_warning(
        self, analyst_user: UserClaims
    ) -> None:
        """Queries below 10 GB do not exceed threshold for normal users."""
        mock_client = MagicMock()
        mock_client.start_query_execution.return_value = {
            "QueryExecutionId": "explain-id-001"
        }
        waiter = MagicMock()
        waiter.wait.return_value = None
        mock_client.get_waiter.return_value = waiter

        # Under 10 GB (5 GB)
        mock_client.get_query_execution.return_value = {
            "QueryExecution": {
                "Statistics": {
                    "DataScannedInBytes": 5 * 1024 * 1024 * 1024,  # 5 GB
                }
            }
        }

        result = await estimate_cost(
            sql="SELECT id FROM analytics_db.transactions",
            user_claims=analyst_user,
            athena_client=mock_client,
        )

        assert result.exceeds_threshold is False
        assert result.suggestion is None
        assert result.estimated_bytes_scanned == 5 * 1024 * 1024 * 1024

    async def test_above_threshold_warning_for_normal_user(
        self, analyst_user: UserClaims
    ) -> None:
        """Queries exceeding 10 GB trigger threshold warning for users without elevated_cost."""
        mock_client = MagicMock()
        mock_client.start_query_execution.return_value = {
            "QueryExecutionId": "explain-id-002"
        }
        waiter = MagicMock()
        waiter.wait.return_value = None
        mock_client.get_waiter.return_value = waiter

        # 15 GB — above threshold
        estimated_bytes = 15 * 1024 * 1024 * 1024
        mock_client.get_query_execution.return_value = {
            "QueryExecution": {
                "Statistics": {
                    "DataScannedInBytes": estimated_bytes,
                }
            }
        }

        result = await estimate_cost(
            sql="SELECT * FROM analytics_db.large_table",
            user_claims=analyst_user,
            athena_client=mock_client,
        )

        assert result.exceeds_threshold is True
        assert result.suggestion is not None
        assert "10 GB" in result.suggestion
        assert "partition" in result.suggestion.lower() or "filter" in result.suggestion.lower()
        assert result.estimated_bytes_scanned == estimated_bytes

    async def test_above_threshold_no_warning_for_elevated_user(
        self, elevated_user: UserClaims
    ) -> None:
        """Users with elevated_cost group do NOT get threshold warning even above 10 GB."""
        mock_client = MagicMock()
        mock_client.start_query_execution.return_value = {
            "QueryExecutionId": "explain-id-003"
        }
        waiter = MagicMock()
        waiter.wait.return_value = None
        mock_client.get_waiter.return_value = waiter

        # 20 GB — above threshold but user has elevated_cost
        estimated_bytes = 20 * 1024 * 1024 * 1024
        mock_client.get_query_execution.return_value = {
            "QueryExecution": {
                "Statistics": {
                    "DataScannedInBytes": estimated_bytes,
                }
            }
        }

        result = await estimate_cost(
            sql="SELECT * FROM analytics_db.huge_table",
            user_claims=elevated_user,
            athena_client=mock_client,
        )

        assert result.exceeds_threshold is False
        assert result.suggestion is None

    async def test_exactly_at_threshold_no_warning(
        self, analyst_user: UserClaims
    ) -> None:
        """Queries at exactly 10 GB do NOT trigger the threshold (only > 10 GB triggers)."""
        mock_client = MagicMock()
        mock_client.start_query_execution.return_value = {
            "QueryExecutionId": "explain-id-004"
        }
        waiter = MagicMock()
        waiter.wait.return_value = None
        mock_client.get_waiter.return_value = waiter

        # Exactly 10 GB
        mock_client.get_query_execution.return_value = {
            "QueryExecution": {
                "Statistics": {
                    "DataScannedInBytes": COST_THRESHOLD_BYTES,
                }
            }
        }

        result = await estimate_cost(
            sql="SELECT * FROM analytics_db.medium_table",
            user_claims=analyst_user,
            athena_client=mock_client,
        )

        assert result.exceeds_threshold is False
        assert result.suggestion is None

    async def test_cost_estimation_uses_chatbot_readonly_workgroup(
        self, analyst_user: UserClaims
    ) -> None:
        """estimate_cost submits EXPLAIN query to chatbot-readonly workgroup."""
        mock_client = MagicMock()
        mock_client.start_query_execution.return_value = {
            "QueryExecutionId": "explain-id-005"
        }
        waiter = MagicMock()
        waiter.wait.return_value = None
        mock_client.get_waiter.return_value = waiter
        mock_client.get_query_execution.return_value = {
            "QueryExecution": {
                "Statistics": {"DataScannedInBytes": 1000}
            }
        }

        await estimate_cost(
            sql="SELECT id FROM analytics_db.transactions",
            user_claims=analyst_user,
            athena_client=mock_client,
        )

        call_kwargs = mock_client.start_query_execution.call_args[1]
        assert call_kwargs["WorkGroup"] == "chatbot-readonly"

    async def test_cost_estimation_requires_identity(
        self, analyst_user: UserClaims
    ) -> None:
        """estimate_cost raises ValueError when no identity credentials provided."""
        with pytest.raises(ValueError, match="obo_token.*athena_client"):
            await estimate_cost(
                sql="SELECT 1",
                user_claims=analyst_user,
                obo_token=None,
                athena_client=None,
            )

    async def test_empty_sql_rejected(
        self, analyst_user: UserClaims
    ) -> None:
        """estimate_cost raises ValueError for empty SQL."""
        with pytest.raises(ValueError, match="non-empty"):
            await estimate_cost(
                sql="",
                user_claims=analyst_user,
                athena_client=MagicMock(),
            )

    async def test_cost_usd_calculated_correctly(
        self, analyst_user: UserClaims
    ) -> None:
        """estimate_cost calculates USD cost at $5 per TB scanned."""
        mock_client = MagicMock()
        mock_client.start_query_execution.return_value = {
            "QueryExecutionId": "explain-id-006"
        }
        waiter = MagicMock()
        waiter.wait.return_value = None
        mock_client.get_waiter.return_value = waiter

        # 1 TB exactly
        one_tb = 1024**4
        mock_client.get_query_execution.return_value = {
            "QueryExecution": {
                "Statistics": {"DataScannedInBytes": one_tb}
            }
        }

        result = await estimate_cost(
            sql="SELECT * FROM analytics_db.huge",
            user_claims=analyst_user,
            athena_client=mock_client,
        )

        # $5 per TB scanned
        assert abs(result.estimated_cost_usd - 5.0) < 0.01

    async def test_dry_run_failure_raises_runtime_error(
        self, analyst_user: UserClaims
    ) -> None:
        """estimate_cost raises RuntimeError when Athena dry-run fails."""
        mock_client = MagicMock()
        mock_client.start_query_execution.side_effect = Exception("Athena unavailable")

        with pytest.raises(RuntimeError, match="Cost estimation failed"):
            await estimate_cost(
                sql="SELECT 1",
                user_claims=analyst_user,
                athena_client=mock_client,
            )

    @patch("chatbot.mcp_server.tools.estimate_cost._create_athena_client_with_obo")
    async def test_obo_token_used_for_client_creation(
        self,
        mock_create_client: MagicMock,
        analyst_user: UserClaims,
    ) -> None:
        """estimate_cost uses OBO token to create Athena client (user identity)."""
        mock_athena = MagicMock()
        mock_athena.start_query_execution.return_value = {
            "QueryExecutionId": "explain-id-007"
        }
        waiter = MagicMock()
        waiter.wait.return_value = None
        mock_athena.get_waiter.return_value = waiter
        mock_athena.get_query_execution.return_value = {
            "QueryExecution": {"Statistics": {"DataScannedInBytes": 100}}
        }
        mock_create_client.return_value = mock_athena

        await estimate_cost(
            sql="SELECT 1",
            user_claims=analyst_user,
            obo_token="user-obo-token-abc",
        )

        mock_create_client.assert_called_once_with(analyst_user, "user-obo-token-abc")


# ---------------------------------------------------------------------------
# run_query: Data freshness and result structure
# ---------------------------------------------------------------------------


class TestRunQueryResults:
    """Tests for run_query result structure and data freshness."""

    async def test_data_freshness_from_glue_partitions(
        self,
        analyst_user: UserClaims,
        mock_athena_client: MagicMock,
        mock_glue_client: MagicMock,
    ) -> None:
        """run_query includes data freshness from Glue partition timestamps."""
        result = await run_query(
            sql="SELECT id FROM analytics_db.transactions LIMIT 10",
            user_claims=analyst_user,
            athena_client=mock_athena_client,
            glue_client=mock_glue_client,
        )

        assert "2024-01-15" in result.data_freshness

    async def test_rows_parsed_correctly(
        self,
        analyst_user: UserClaims,
        mock_athena_client: MagicMock,
        mock_glue_client: MagicMock,
    ) -> None:
        """run_query parses Athena result rows into column-name keyed dicts."""
        result = await run_query(
            sql="SELECT id, amount FROM analytics_db.transactions LIMIT 10",
            user_claims=analyst_user,
            athena_client=mock_athena_client,
            glue_client=mock_glue_client,
        )

        assert result.row_count == 2
        assert result.rows[0] == {"id": "1", "amount": "100.50"}
        assert result.rows[1] == {"id": "2", "amount": "200.75"}
