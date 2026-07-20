"""List tables tool — returns tables filtered by user authorization.

Queries the AWS Glue Catalog for table metadata and filters results
based on the user's Lake Formation grants. Only tables the user is
authorized to access are returned.

Requirements: 16.3 (filter by Lake Formation grants), 6.4 (Lake Formation
column/row/cell permissions via OBO identity).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from chatbot.api.models import UserClaims
from chatbot.mcp_server.tools.models import ColumnInfo, TableInfo

logger = logging.getLogger(__name__)


class ListTablesError(Exception):
    """Raised when listing tables fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _create_glue_client(region_name: str = "us-east-1") -> "boto3.client":
    """Create a Glue client for catalog access."""
    return boto3.client("glue", region_name=region_name)


def _create_lakeformation_client(region_name: str = "us-east-1") -> "boto3.client":
    """Create a Lake Formation client for authorization checks."""
    return boto3.client("lakeformation", region_name=region_name)


def _get_user_authorized_tables(
    lf_client: "boto3.client",
    user_claims: UserClaims,
) -> set[tuple[str, str]]:
    """Retrieve the set of (database, table) tuples the user is authorized to access.

    Queries Lake Formation to get the list of tables the user has been
    granted access to via their federated identity.

    Args:
        lf_client: Lake Formation boto3 client.
        user_claims: Validated user claims from JWT.

    Returns:
        Set of (database_name, table_name) tuples the user can access.
    """
    authorized_tables: set[tuple[str, str]] = set()

    try:
        # Use ListPermissions to find tables granted to this user's principal
        # Lake Formation list_permissions does not support pagination via paginator,
        # so we use NextToken manually.
        next_token: str | None = None
        while True:
            kwargs: dict = {
                "Principal": {
                    "DataLakePrincipalIdentifier": user_claims.sub,
                },
                "ResourceType": "TABLE",
            }
            if next_token:
                kwargs["NextToken"] = next_token

            response = lf_client.list_permissions(**kwargs)

            for permission in response.get("PrincipalResourcePermissions", []):
                resource = permission.get("Resource", {})
                table_resource = resource.get("Table", {})
                if table_resource:
                    db_name = table_resource.get("DatabaseName", "")
                    table_name = table_resource.get("Name", "")
                    if db_name and table_name:
                        # TableWildcard means access to all tables in DB
                        if table_name == "ALL_TABLES" or "TableWildcard" in table_resource:
                            authorized_tables.add((db_name, "*"))
                        else:
                            authorized_tables.add((db_name, table_name))

            next_token = response.get("NextToken")
            if not next_token:
                break

    except ClientError as e:
        logger.error(
            "Failed to retrieve Lake Formation permissions for user %s: %s",
            user_claims.sub,
            str(e),
        )
        raise ListTablesError(
            f"Failed to retrieve authorization grants: {e.response['Error']['Message']}"
        ) from e

    return authorized_tables


def _is_table_authorized(
    database: str,
    table_name: str,
    authorized_tables: set[tuple[str, str]],
) -> bool:
    """Check if a specific table is in the user's authorized set.

    Args:
        database: The database name.
        table_name: The table name.
        authorized_tables: Set of authorized (database, table) tuples.

    Returns:
        True if the user is authorized to access this table.
    """
    # Direct match
    if (database, table_name) in authorized_tables:
        return True
    # Wildcard match (user has access to all tables in the database)
    if (database, "*") in authorized_tables:
        return True
    return False


def _get_table_freshness(table: dict) -> str:
    """Extract data freshness from Glue table metadata.

    Uses the table's UpdateTime or CreateTime from the Glue Catalog
    to determine when the data was last updated.

    Args:
        table: Glue table metadata dictionary.

    Returns:
        ISO 8601 timestamp string of last update.
    """
    update_time = table.get("UpdateTime")
    if update_time:
        if isinstance(update_time, datetime):
            return update_time.isoformat()
        return str(update_time)

    create_time = table.get("CreateTime")
    if create_time:
        if isinstance(create_time, datetime):
            return create_time.isoformat()
        return str(create_time)

    return datetime.now(timezone.utc).isoformat()


def _glue_table_to_table_info(table: dict, database: str) -> TableInfo:
    """Convert a Glue Catalog table dict to a TableInfo model.

    Args:
        table: Glue table metadata dictionary from GetTables/GetTable.
        database: The database name.

    Returns:
        TableInfo model with columns, partition keys, and freshness.
    """
    storage_descriptor = table.get("StorageDescriptor", {})
    glue_columns = storage_descriptor.get("Columns", [])
    partition_keys = table.get("PartitionKeys", [])

    columns: list[ColumnInfo] = []
    for col in glue_columns:
        parameters = col.get("Parameters", {})
        columns.append(
            ColumnInfo(
                name=col.get("Name", ""),
                data_type=col.get("Type", "string"),
                description=col.get("Comment", "") or parameters.get("comment", ""),
                is_pii=parameters.get("pii", "false").lower() == "true",
                classification=parameters.get("classification", "internal"),
            )
        )

    # Partition keys are also columns
    partition_key_names = [pk.get("Name", "") for pk in partition_keys]

    return TableInfo(
        database=database,
        table_name=table.get("Name", ""),
        description=table.get("Description", "") or table.get("Parameters", {}).get("comment", ""),
        columns=columns,
        partition_keys=partition_key_names,
        last_updated=_get_table_freshness(table),
    )


async def list_tables(
    user_claims: UserClaims,
    database: str | None = None,
    glue_client: "boto3.client | None" = None,
    lf_client: "boto3.client | None" = None,
) -> list[TableInfo]:
    """List tables filtered by user's Lake Formation authorization grants.

    Queries the Glue Catalog for all tables (optionally filtered by database)
    and returns only those the user is authorized to access based on their
    Lake Formation grants.

    Args:
        user_claims: Validated user claims from JWT.
        database: Optional database filter. If None, lists from all databases.
        glue_client: Optional Glue client (for testing/injection).
        lf_client: Optional Lake Formation client (for testing/injection).

    Returns:
        List of TableInfo models for authorized tables.

    Raises:
        ListTablesError: If Glue or Lake Formation API calls fail.

    Requirements:
        - 16.3: Filter by Lake Formation grants before returning results
        - 6.4: Use authenticated user's identity for permission checks
    """
    if glue_client is None:
        glue_client = _create_glue_client()
    if lf_client is None:
        lf_client = _create_lakeformation_client()

    # Step 1: Get user's authorized tables from Lake Formation
    authorized_tables = _get_user_authorized_tables(lf_client, user_claims)

    if not authorized_tables:
        logger.info(
            "User %s has no Lake Formation grants — returning empty table list",
            user_claims.sub,
        )
        return []

    # Step 2: Get tables from Glue Catalog
    result_tables: list[TableInfo] = []

    try:
        if database:
            # Query specific database
            result_tables = await _list_tables_in_database(
                glue_client, database, authorized_tables
            )
        else:
            # Query all databases the user has access to
            databases_to_query = {db for db, _ in authorized_tables}
            for db_name in sorted(databases_to_query):
                tables = await _list_tables_in_database(
                    glue_client, db_name, authorized_tables
                )
                result_tables.extend(tables)

    except ClientError as e:
        logger.error(
            "Failed to list tables from Glue Catalog for user %s: %s",
            user_claims.sub,
            str(e),
        )
        raise ListTablesError(
            f"Failed to retrieve table metadata: {e.response['Error']['Message']}"
        ) from e

    logger.info(
        "User %s authorized for %d tables (out of %d grants)",
        user_claims.sub,
        len(result_tables),
        len(authorized_tables),
    )

    return result_tables


async def _list_tables_in_database(
    glue_client: "boto3.client",
    database: str,
    authorized_tables: set[tuple[str, str]],
) -> list[TableInfo]:
    """List and filter tables in a specific database.

    Args:
        glue_client: Glue boto3 client.
        database: Database name to query.
        authorized_tables: Set of authorized (database, table) tuples.

    Returns:
        List of authorized TableInfo models from this database.
    """
    tables: list[TableInfo] = []

    try:
        paginator = glue_client.get_paginator("get_tables")
        page_iterator = paginator.paginate(DatabaseName=database)

        for page in page_iterator:
            for table in page.get("TableList", []):
                table_name = table.get("Name", "")
                if _is_table_authorized(database, table_name, authorized_tables):
                    tables.append(_glue_table_to_table_info(table, database))

    except ClientError as e:
        # If the database doesn't exist or we don't have access, skip it
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("EntityNotFoundException", "AccessDeniedException"):
            logger.warning(
                "Cannot access database '%s': %s",
                database,
                error_code,
            )
        else:
            raise

    return tables
