"""Property-based tests for OBO Identity enforcement.

Tests verify that every Athena query execution requires the user's federated
identity via OBO token exchange — a shared service role is NEVER used.

**Validates: Requirements 7.1, 7.5**

Properties tested:
- Property 5: OBO Identity — Never Shared Role — every Athena query runs as
  user's federated identity. If neither an OBO token nor a pre-configured
  client is provided, a ValueError must be raised.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from chatbot.api.models import UserClaims


# ─── Hypothesis Strategies ────────────────────────────────────────────────────

VALID_TIERS = ["public", "internal", "confidential", "restricted"]
VALID_ROLES = ["analyst", "manager", "viewer", "admin"]
VALID_DEPARTMENTS = ["analytics", "finance", "hr", "marketing", "operations"]


@st.composite
def user_claims_strategy(draw) -> UserClaims:
    """Generate a random valid UserClaims instance."""
    session_id = str(uuid.uuid4())
    return UserClaims(
        sub=draw(st.text(min_size=3, max_size=30, alphabet="abcdefghijklmnop0123456789-_")),
        department=draw(st.sampled_from(VALID_DEPARTMENTS)),
        role=draw(st.sampled_from(VALID_ROLES)),
        data_classification_tier=draw(st.sampled_from(VALID_TIERS)),
        groups=draw(
            st.lists(
                st.sampled_from(["data-users", "elevated_cost", "pii_viewers", "analytics-team"]),
                min_size=0,
                max_size=3,
                unique=True,
            )
        ),
        session_id=session_id,
        exp=draw(st.integers(min_value=1_700_000_000, max_value=2_000_000_000)),
    )


@st.composite
def sql_query_strategy(draw) -> str:
    """Generate a random non-empty SQL SELECT query string."""
    table = draw(st.sampled_from([
        "analytics_db.user_activity",
        "finance_db.transactions",
        "hr_db.employees",
        "marketing_db.campaigns",
        "operations_db.metrics",
    ]))
    columns = draw(st.sampled_from([
        "id, name, created_at",
        "amount, currency, date",
        "COUNT(*)",
        "department, salary",
        "*",
    ]))
    limit = draw(st.integers(min_value=1, max_value=10000))
    return f"SELECT {columns} FROM {table} LIMIT {limit}"


# ─── Property 5: OBO Identity — Never Shared Role ────────────────────────────


class TestOBOIdentityEnforcement:
    """Property 5: OBO Identity — Never Shared Role.

    **Validates: Requirements 7.1, 7.5**

    For any user and any query, the tools MUST require an OBO token or
    pre-configured client (never a shared service role). If neither is
    provided, a ValueError must be raised.
    """

    @given(
        user_claims=user_claims_strategy(),
        sql=sql_query_strategy(),
    )
    @settings(max_examples=200)
    @pytest.mark.asyncio
    async def test_run_query_rejects_without_obo_token_or_client(
        self, user_claims: UserClaims, sql: str
    ):
        """run_query raises ValueError when neither obo_token nor athena_client provided.

        This enforces that queries CANNOT execute under a shared service role —
        the caller must explicitly provide either an OBO token (for federated
        identity exchange) or a pre-configured client (for testing).

        **Validates: Requirements 7.1, 7.5**
        """
        from chatbot.mcp_server.tools.run_query import run_query

        with pytest.raises(ValueError) as exc_info:
            await run_query(
                sql=sql,
                user_claims=user_claims,
                obo_token=None,
                athena_client=None,
            )

        # The error message should indicate that identity is required
        error_msg = str(exc_info.value).lower()
        assert "obo_token" in error_msg or "athena_client" in error_msg or "identity" in error_msg, (
            f"ValueError should mention identity requirement, got: {exc_info.value}"
        )

    @given(
        user_claims=user_claims_strategy(),
        sql=sql_query_strategy(),
    )
    @settings(max_examples=200)
    @pytest.mark.asyncio
    async def test_estimate_cost_rejects_without_obo_token_or_client(
        self, user_claims: UserClaims, sql: str
    ):
        """estimate_cost raises ValueError when neither obo_token nor athena_client provided.

        This enforces that cost estimations CANNOT run under a shared service role —
        even dry-run queries must use the user's federated identity.

        **Validates: Requirements 7.1, 7.5**
        """
        from chatbot.mcp_server.tools.estimate_cost import estimate_cost

        with pytest.raises(ValueError) as exc_info:
            await estimate_cost(
                sql=sql,
                user_claims=user_claims,
                obo_token=None,
                athena_client=None,
            )

        # The error message should indicate that identity is required
        error_msg = str(exc_info.value).lower()
        assert "obo_token" in error_msg or "athena_client" in error_msg or "identity" in error_msg, (
            f"ValueError should mention identity requirement, got: {exc_info.value}"
        )

    @given(
        user_claims=user_claims_strategy(),
        sql=sql_query_strategy(),
        obo_token=st.text(min_size=10, max_size=100, alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-_"),
    )
    @settings(max_examples=100, deadline=None)
    @pytest.mark.asyncio
    async def test_run_query_with_obo_token_calls_assume_role_with_web_identity(
        self, user_claims: UserClaims, sql: str, obo_token: str
    ):
        """When an OBO token is provided, run_query uses assume_role_with_web_identity.

        The athena_client MUST be created from the user's OBO token via STS
        assume_role_with_web_identity — this guarantees the query runs as
        the user's federated identity, not a shared service role.

        **Validates: Requirements 7.1, 7.5**
        """
        from chatbot.mcp_server.tools.run_query import run_query

        mock_sts = MagicMock()
        mock_sts.assume_role_with_web_identity.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA_FAKE_KEY",
                "SecretAccessKey": "fake_secret",
                "SessionToken": "fake_session_token",
            }
        }

        mock_athena = MagicMock()
        mock_athena.start_query_execution.return_value = {
            "QueryExecutionId": "test-query-id-123"
        }
        mock_athena.get_waiter.return_value.wait.return_value = None
        mock_athena.get_query_execution.return_value = {
            "QueryExecution": {
                "Statistics": {
                    "DataScannedInBytes": 1024,
                    "EngineExecutionTimeInMillis": 500,
                }
            }
        }
        mock_athena.get_query_results.return_value = {
            "ResultSet": {
                "Rows": [
                    {"Data": [{"VarCharValue": "col1"}]},
                    {"Data": [{"VarCharValue": "val1"}]},
                ],
                "ResultSetMetadata": {
                    "ColumnInfo": [{"Name": "col1"}]
                },
            }
        }

        with patch("chatbot.mcp_server.tools.run_query.boto3.client") as mock_boto_client:
            # First call creates STS client, second creates Athena client
            mock_boto_client.side_effect = [mock_sts, mock_athena]

            await run_query(
                sql=sql,
                user_claims=user_claims,
                obo_token=obo_token,
                athena_client=None,
            )

        # Verify assume_role_with_web_identity was called with the user's OBO token
        mock_sts.assume_role_with_web_identity.assert_called_once()
        call_kwargs = mock_sts.assume_role_with_web_identity.call_args[1]

        # The WebIdentityToken must be the user's OBO token
        assert call_kwargs["WebIdentityToken"] == obo_token, (
            f"Expected WebIdentityToken to be the user's OBO token, "
            f"but got: {call_kwargs['WebIdentityToken']}"
        )

        # The RoleSessionName must contain the user's sub (identity attribution)
        assert user_claims.sub in call_kwargs["RoleSessionName"], (
            f"RoleSessionName should contain user sub '{user_claims.sub}' "
            f"for identity attribution, got: {call_kwargs['RoleSessionName']}"
        )

    @given(
        user_claims=user_claims_strategy(),
        sql=sql_query_strategy(),
        obo_token=st.text(min_size=10, max_size=100, alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-_"),
    )
    @settings(max_examples=100, deadline=None)
    @pytest.mark.asyncio
    async def test_estimate_cost_with_obo_token_calls_assume_role_with_web_identity(
        self, user_claims: UserClaims, sql: str, obo_token: str
    ):
        """When an OBO token is provided, estimate_cost uses assume_role_with_web_identity.

        The athena_client MUST be created from the user's OBO token via STS
        assume_role_with_web_identity — this guarantees even cost estimations
        run as the user's federated identity.

        **Validates: Requirements 7.1, 7.5**
        """
        from chatbot.mcp_server.tools.estimate_cost import estimate_cost

        mock_sts = MagicMock()
        mock_sts.assume_role_with_web_identity.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA_FAKE_KEY",
                "SecretAccessKey": "fake_secret",
                "SessionToken": "fake_session_token",
            }
        }

        mock_athena = MagicMock()
        mock_athena.start_query_execution.return_value = {
            "QueryExecutionId": "test-query-id-456"
        }
        mock_athena.get_waiter.return_value.wait.return_value = None
        mock_athena.get_query_execution.return_value = {
            "QueryExecution": {
                "Statistics": {
                    "DataScannedInBytes": 2048,
                }
            }
        }

        with patch("chatbot.mcp_server.tools.estimate_cost.boto3.client") as mock_boto_client:
            mock_boto_client.side_effect = [mock_sts, mock_athena]

            await estimate_cost(
                sql=sql,
                user_claims=user_claims,
                obo_token=obo_token,
                athena_client=None,
            )

        # Verify assume_role_with_web_identity was called with the user's OBO token
        mock_sts.assume_role_with_web_identity.assert_called_once()
        call_kwargs = mock_sts.assume_role_with_web_identity.call_args[1]

        # The WebIdentityToken must be the user's OBO token
        assert call_kwargs["WebIdentityToken"] == obo_token, (
            f"Expected WebIdentityToken to be the user's OBO token, "
            f"but got: {call_kwargs['WebIdentityToken']}"
        )

        # The RoleSessionName must contain the user's sub (identity attribution)
        assert user_claims.sub in call_kwargs["RoleSessionName"], (
            f"RoleSessionName should contain user sub '{user_claims.sub}' "
            f"for identity attribution, got: {call_kwargs['RoleSessionName']}"
        )

    @given(
        user_claims=user_claims_strategy(),
        sql=sql_query_strategy(),
        obo_token=st.text(min_size=10, max_size=100, alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-_"),
    )
    @settings(max_examples=100, deadline=None)
    @pytest.mark.asyncio
    async def test_run_query_never_falls_back_on_obo_failure(
        self, user_claims: UserClaims, sql: str, obo_token: str
    ):
        """When OBO token exchange fails, run_query raises RuntimeError — never falls back.

        This is the fail-closed requirement: if the OBO exchange fails, the query
        MUST NOT execute under a shared service identity. The function must raise
        an error rather than proceeding.

        **Validates: Requirements 7.1, 7.5**
        """
        from chatbot.mcp_server.tools.run_query import run_query

        mock_sts = MagicMock()
        mock_sts.assume_role_with_web_identity.side_effect = Exception(
            "AccessDenied: OBO token expired or invalid"
        )

        with patch("chatbot.mcp_server.tools.run_query.boto3.client") as mock_boto_client:
            mock_boto_client.return_value = mock_sts

            with pytest.raises(RuntimeError) as exc_info:
                await run_query(
                    sql=sql,
                    user_claims=user_claims,
                    obo_token=obo_token,
                    athena_client=None,
                )

            # Error should indicate identity delegation failure, not a fallback
            error_msg = str(exc_info.value).lower()
            assert "identity" in error_msg or "federated" in error_msg or "service role" in error_msg, (
                f"RuntimeError should indicate identity delegation failure, got: {exc_info.value}"
            )
