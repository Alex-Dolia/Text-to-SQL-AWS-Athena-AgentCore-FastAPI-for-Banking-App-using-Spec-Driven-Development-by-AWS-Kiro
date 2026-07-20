"""Unit tests for list_tables and get_schema MCP tools.

Tests cover:
- list_tables returns only authorized tables for user (Requirement 16.3)
- get_schema rejects unauthorized table access (Requirement 6.4)
- Glue Catalog metadata is correctly mapped to TableInfo models
- Authorization filtering works with database wildcards
- Proper error handling on API failures

Uses unittest.mock to simulate AWS Glue and Lake Formation responses.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from chatbot.api.models import UserClaims
from chatbot.mcp_server.tools.get_schema import (
    GetSchemaError,
    TableNotAuthorizedError,
    TableNotFoundError,
    get_schema,
)
from chatbot.mcp_server.tools.list_tables import ListTablesError, list_tables


@pytest.fixture
def analyst_user() -> UserClaims:
    """Create an analyst user with internal data tier."""
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
def manager_user() -> UserClaims:
    """Create a manager user with confidential data tier."""
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
def mock_glue_client() -> MagicMock:
    """Create a mock Glue client."""
    return MagicMock()


@pytest.fixture
def mock_lf_client() -> MagicMock:
    """Create a mock Lake Formation client."""
    return MagicMock()


def _make_glue_table(
    name: str,
    database: str = "analytics_db",
    columns: list[dict] | None = None,
    partition_keys: list[dict] | None = None,
) -> dict:
    """Helper to create a Glue table metadata dict."""
    if columns is None:
        columns = [
            {"Name": "id", "Type": "int", "Comment": "Primary key", "Parameters": {}},
            {
                "Name": "amount",
                "Type": "double",
                "Comment": "Transaction amount",
                "Parameters": {"classification": "internal"},
            },
            {
                "Name": "customer_email",
                "Type": "string",
                "Comment": "Customer email",
                "Parameters": {"pii": "true", "classification": "confidential"},
            },
        ]
    if partition_keys is None:
        partition_keys = [
            {"Name": "dt", "Type": "string", "Comment": "Date partition", "Parameters": {}},
        ]

    return {
        "Name": name,
        "DatabaseName": database,
        "Description": f"Test table {name}",
        "StorageDescriptor": {
            "Columns": columns,
        },
        "PartitionKeys": partition_keys,
        "UpdateTime": "2024-01-15T10:30:00Z",
        "Parameters": {},
    }


def _make_lf_permission(database: str, table_name: str) -> dict:
    """Helper to create a Lake Formation permission entry."""
    return {
        "Principal": {"DataLakePrincipalIdentifier": "user-analyst-001"},
        "Resource": {
            "Table": {
                "DatabaseName": database,
                "Name": table_name,
            }
        },
        "Permissions": ["SELECT"],
    }


class TestListTables:
    """Tests for the list_tables tool."""

    async def test_returns_only_authorized_tables(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """list_tables returns only tables the user has Lake Formation grants for."""
        # Setup: user has grants for 2 of 3 tables
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [
                _make_lf_permission("analytics_db", "transactions"),
                _make_lf_permission("analytics_db", "customers"),
            ],
        }

        # Glue returns 3 tables (user only authorized for 2)
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "TableList": [
                    _make_glue_table("transactions"),
                    _make_glue_table("customers"),
                    _make_glue_table("internal_audit"),
                ]
            }
        ]
        mock_glue_client.get_paginator.return_value = paginator

        result = await list_tables(
            user_claims=analyst_user,
            glue_client=mock_glue_client,
            lf_client=mock_lf_client,
        )

        assert len(result) == 2
        table_names = {t.table_name for t in result}
        assert table_names == {"transactions", "customers"}
        assert "internal_audit" not in table_names

    async def test_returns_empty_when_no_grants(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """list_tables returns empty list when user has no Lake Formation grants."""
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [],
        }

        result = await list_tables(
            user_claims=analyst_user,
            glue_client=mock_glue_client,
            lf_client=mock_lf_client,
        )

        assert result == []
        # Glue should not be called when no grants exist
        mock_glue_client.get_paginator.assert_not_called()

    async def test_database_filter_restricts_results(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """list_tables respects database filter argument."""
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [
                _make_lf_permission("analytics_db", "transactions"),
                _make_lf_permission("risk_db", "risk_scores"),
            ],
        }

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"TableList": [_make_glue_table("transactions", database="analytics_db")]}
        ]
        mock_glue_client.get_paginator.return_value = paginator

        result = await list_tables(
            user_claims=analyst_user,
            database="analytics_db",
            glue_client=mock_glue_client,
            lf_client=mock_lf_client,
        )

        # Should only query analytics_db, not risk_db
        paginator.paginate.assert_called_once_with(DatabaseName="analytics_db")
        assert len(result) == 1
        assert result[0].database == "analytics_db"

    async def test_wildcard_grants_authorize_all_tables_in_db(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """Wildcard Lake Formation grants authorize all tables in a database."""
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [
                {
                    "Principal": {"DataLakePrincipalIdentifier": "user-analyst-001"},
                    "Resource": {
                        "Table": {
                            "DatabaseName": "analytics_db",
                            "Name": "ALL_TABLES",
                            "TableWildcard": {},
                        }
                    },
                    "Permissions": ["SELECT"],
                }
            ],
        }

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "TableList": [
                    _make_glue_table("transactions"),
                    _make_glue_table("customers"),
                    _make_glue_table("internal_audit"),
                ]
            }
        ]
        mock_glue_client.get_paginator.return_value = paginator

        result = await list_tables(
            user_claims=analyst_user,
            glue_client=mock_glue_client,
            lf_client=mock_lf_client,
        )

        # All tables in analytics_db should be authorized via wildcard
        assert len(result) == 3

    async def test_table_info_has_correct_structure(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """Returned TableInfo models have correct column info, partition keys, and freshness."""
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [
                _make_lf_permission("analytics_db", "transactions"),
            ],
        }

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"TableList": [_make_glue_table("transactions")]}
        ]
        mock_glue_client.get_paginator.return_value = paginator

        result = await list_tables(
            user_claims=analyst_user,
            glue_client=mock_glue_client,
            lf_client=mock_lf_client,
        )

        assert len(result) == 1
        table = result[0]
        assert table.database == "analytics_db"
        assert table.table_name == "transactions"
        assert table.description == "Test table transactions"
        assert len(table.columns) == 3
        assert table.partition_keys == ["dt"]
        assert table.last_updated == "2024-01-15T10:30:00Z"

        # Check column details
        id_col = next(c for c in table.columns if c.name == "id")
        assert id_col.data_type == "int"
        assert id_col.description == "Primary key"
        assert id_col.is_pii is False

        email_col = next(c for c in table.columns if c.name == "customer_email")
        assert email_col.is_pii is True
        assert email_col.classification == "confidential"

    async def test_lake_formation_api_failure_raises_error(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """ListTablesError raised when Lake Formation API fails."""
        mock_lf_client.list_permissions.side_effect = ClientError(
            error_response={"Error": {"Code": "InternalServiceException", "Message": "Service down"}},
            operation_name="ListPermissions",
        )

        with pytest.raises(ListTablesError, match="Failed to retrieve authorization grants"):
            await list_tables(
                user_claims=analyst_user,
                glue_client=mock_glue_client,
                lf_client=mock_lf_client,
            )

    async def test_pagination_with_next_token(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """list_tables handles paginated Lake Formation responses correctly."""
        # First call returns page 1 with NextToken
        mock_lf_client.list_permissions.side_effect = [
            {
                "PrincipalResourcePermissions": [
                    _make_lf_permission("analytics_db", "transactions"),
                ],
                "NextToken": "page2",
            },
            {
                "PrincipalResourcePermissions": [
                    _make_lf_permission("analytics_db", "customers"),
                ],
            },
        ]

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "TableList": [
                    _make_glue_table("transactions"),
                    _make_glue_table("customers"),
                ]
            }
        ]
        mock_glue_client.get_paginator.return_value = paginator

        result = await list_tables(
            user_claims=analyst_user,
            glue_client=mock_glue_client,
            lf_client=mock_lf_client,
        )

        assert len(result) == 2
        assert mock_lf_client.list_permissions.call_count == 2


class TestGetSchema:
    """Tests for the get_schema tool."""

    async def test_returns_schema_for_authorized_table(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """get_schema returns full schema when user is authorized."""
        # User has permission
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [
                _make_lf_permission("analytics_db", "transactions"),
            ],
        }

        mock_glue_client.get_table.return_value = {
            "Table": _make_glue_table("transactions", database="analytics_db")
        }

        result = await get_schema(
            user_claims=analyst_user,
            database="analytics_db",
            table="transactions",
            glue_client=mock_glue_client,
            lf_client=mock_lf_client,
        )

        assert result.database == "analytics_db"
        assert result.table_name == "transactions"
        assert len(result.columns) == 4  # 3 regular + 1 partition key column
        assert result.partition_keys == ["dt"]
        assert result.last_updated == "2024-01-15T10:30:00Z"

    async def test_rejects_unauthorized_table_access(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """get_schema raises TableNotAuthorizedError when user lacks grants."""
        # User has NO permission for this table
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [],
        }

        with pytest.raises(TableNotAuthorizedError) as exc_info:
            await get_schema(
                user_claims=analyst_user,
                database="restricted_db",
                table="pci_data",
                glue_client=mock_glue_client,
                lf_client=mock_lf_client,
            )

        assert exc_info.value.database == "restricted_db"
        assert exc_info.value.table == "pci_data"
        assert "not authorized" in exc_info.value.message

    async def test_raises_not_found_for_missing_table(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """get_schema raises TableNotFoundError when table doesn't exist."""
        # User is authorized
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [
                _make_lf_permission("analytics_db", "nonexistent"),
            ],
        }

        # But table doesn't exist in Glue
        mock_glue_client.get_table.side_effect = ClientError(
            error_response={
                "Error": {"Code": "EntityNotFoundException", "Message": "Table not found"}
            },
            operation_name="GetTable",
        )

        with pytest.raises(TableNotFoundError) as exc_info:
            await get_schema(
                user_claims=analyst_user,
                database="analytics_db",
                table="nonexistent",
                glue_client=mock_glue_client,
                lf_client=mock_lf_client,
            )

        assert exc_info.value.database == "analytics_db"
        assert exc_info.value.table == "nonexistent"

    async def test_includes_partition_keys_in_columns(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """get_schema includes partition key columns in the column list."""
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [
                _make_lf_permission("analytics_db", "transactions"),
            ],
        }

        table_data = _make_glue_table("transactions")
        mock_glue_client.get_table.return_value = {"Table": table_data}

        result = await get_schema(
            user_claims=analyst_user,
            database="analytics_db",
            table="transactions",
            glue_client=mock_glue_client,
            lf_client=mock_lf_client,
        )

        col_names = [c.name for c in result.columns]
        # Partition key 'dt' should be in columns list
        assert "dt" in col_names
        # And in partition_keys list
        assert "dt" in result.partition_keys

    async def test_authorization_check_before_catalog_query(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """Authorization is checked before querying Glue Catalog."""
        # User NOT authorized
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [],
        }

        with pytest.raises(TableNotAuthorizedError):
            await get_schema(
                user_claims=analyst_user,
                database="analytics_db",
                table="secret_table",
                glue_client=mock_glue_client,
                lf_client=mock_lf_client,
            )

        # Glue should NOT have been called (fail before catalog lookup)
        mock_glue_client.get_table.assert_not_called()

    async def test_fail_closed_on_lf_api_error(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """get_schema fails closed when Lake Formation API returns unexpected error."""
        mock_lf_client.list_permissions.side_effect = ClientError(
            error_response={
                "Error": {"Code": "InternalServiceException", "Message": "Service error"}
            },
            operation_name="ListPermissions",
        )

        # Should deny access (fail-closed) — raises TableNotAuthorizedError
        with pytest.raises(TableNotAuthorizedError):
            await get_schema(
                user_claims=analyst_user,
                database="analytics_db",
                table="transactions",
                glue_client=mock_glue_client,
                lf_client=mock_lf_client,
            )

    async def test_glue_api_failure_raises_error(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """GetSchemaError raised when Glue API returns unexpected error."""
        # User is authorized
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [
                _make_lf_permission("analytics_db", "transactions"),
            ],
        }

        # But Glue fails with a non-entity error
        mock_glue_client.get_table.side_effect = ClientError(
            error_response={
                "Error": {"Code": "InternalServiceException", "Message": "Glue down"}
            },
            operation_name="GetTable",
        )

        with pytest.raises(GetSchemaError, match="Failed to retrieve table schema"):
            await get_schema(
                user_claims=analyst_user,
                database="analytics_db",
                table="transactions",
                glue_client=mock_glue_client,
                lf_client=mock_lf_client,
            )

    async def test_pii_and_classification_correctly_mapped(
        self, analyst_user: UserClaims, mock_glue_client: MagicMock, mock_lf_client: MagicMock
    ) -> None:
        """Column PII flag and classification tier are correctly extracted."""
        mock_lf_client.list_permissions.return_value = {
            "PrincipalResourcePermissions": [
                _make_lf_permission("analytics_db", "users"),
            ],
        }

        table = {
            "Name": "users",
            "DatabaseName": "analytics_db",
            "Description": "User table",
            "StorageDescriptor": {
                "Columns": [
                    {
                        "Name": "user_id",
                        "Type": "bigint",
                        "Comment": "User ID",
                        "Parameters": {"classification": "public"},
                    },
                    {
                        "Name": "ssn",
                        "Type": "string",
                        "Comment": "Social Security Number",
                        "Parameters": {"pii": "true", "classification": "restricted"},
                    },
                ]
            },
            "PartitionKeys": [],
            "UpdateTime": "2024-02-01T08:00:00Z",
            "Parameters": {},
        }
        mock_glue_client.get_table.return_value = {"Table": table}

        result = await get_schema(
            user_claims=analyst_user,
            database="analytics_db",
            table="users",
            glue_client=mock_glue_client,
            lf_client=mock_lf_client,
        )

        user_id_col = next(c for c in result.columns if c.name == "user_id")
        assert user_id_col.is_pii is False
        assert user_id_col.classification == "public"

        ssn_col = next(c for c in result.columns if c.name == "ssn")
        assert ssn_col.is_pii is True
        assert ssn_col.classification == "restricted"
