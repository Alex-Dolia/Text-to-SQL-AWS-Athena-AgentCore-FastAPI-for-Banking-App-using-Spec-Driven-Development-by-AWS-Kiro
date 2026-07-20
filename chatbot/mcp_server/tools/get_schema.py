"""Get schema tool — retrieve table schema with authorization check.

Queries the AWS Glue Catalog for detailed table schema metadata
after verifying the user is authorized to access the table via
Lake Formation grants.

Requirements: 16.3 (filter by Lake Formation grants), 6.4 (Lake Formation
column/row/cell permissions via OBO identity), 7.5 (user's federated identity).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from chatbot.api.models import UserClaims
from chatbot.mcp_server.tools.models import ColumnInfo, TableInfo

logger = logging.getLogger(__name__)


class GetSchemaError(Exception):
    """Raised when schema retrieval fails."""

    def __init__(self, message: str, error_code: str = "schema_error") -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class TableNotAuthorizedError(GetSchemaError):
    """Raised when the user is not authorized to access the requested table."""

    def __init__(self, database: str, table: str) -> None:
        super().__init__(
            message=f"Access denied: you are not authorized to access table '{database}.{table}'",
            error_code="authorization_denied",
        )
        self.database = database
        self.table = table


class TableNotFoundError(GetSchemaError):
    """Raised when the requested table does not exist in the Glue Catalog."""

    def __init__(self, database: str, table: str) -> None:
        super().__init__(
            message=f"Table '{database}.{table}' not found in the catalog",
            error_code="table_not_found",
        )
        self.database = database
        self.table = table


def _create_glue_client(region_name: str = "us-east-1") -> "boto3.client":
    """Create a Glue client for catalog access."""
    return boto3.client("glue", region_name=region_name)


def _create_lakeformation_client(region_name: str = "us-east-1") -> "boto3.client":
    """Create a Lake Formation client for authorization checks."""
    return boto3.client("lakeformation", region_name=region_name)


def _check_table_authorization(
    lf_client: "boto3.client",
    user_claims: UserClaims,
    database: str,
    table: str,
) -> bool:
    """Check if the user is authorized to access a specific table.

    Queries Lake Formation to verify the user has been granted access
    to the specified table.

    Args:
        lf_client: Lake Formation boto3 client.
        user_claims: Validated user claims from JWT.
        database: Database name.
        table: Table name.

    Returns:
        True if the user is authorized, False otherwise.
    """
    try:
        # Check if user has permissions on the specific table
        response = lf_client.list_permissions(
            Principal={
                "DataLakePrincipalIdentifier": user_claims.sub,
            },
            ResourceType="TABLE",
            Resource={
                "Table": {
                    "DatabaseName": database,
                    "Name": table,
                },
            },
        )

        permissions = response.get("PrincipalResourcePermissions", [])
        if permissions:
            return True

        # Also check for wildcard (all tables in database) grants
        wildcard_response = lf_client.list_permissions(
            Principal={
                "DataLakePrincipalIdentifier": user_claims.sub,
            },
            ResourceType="TABLE",
            Resource={
                "Table": {
                    "DatabaseName": database,
                    "TableWildcard": {},
                },
            },
        )

        wildcard_permissions = wildcard_response.get("PrincipalResourcePermissions", [])
        return len(wildcard_permissions) > 0

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "InvalidInputException":
            # Table or database doesn't exist in Lake Formation
            return False
        logger.error(
            "Failed to check Lake Formation authorization for %s.%s (user: %s): %s",
            database,
            table,
            user_claims.sub,
            str(e),
        )
        # Fail-closed: if we can't verify authorization, deny access
        return False


def _get_table_freshness(table: dict) -> str:
    """Extract data freshness from Glue table metadata.

    Uses UpdateTime or CreateTime, or partition-level timestamps
    to determine when data was last refreshed.

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


def _build_table_info(table: dict, database: str) -> TableInfo:
    """Build a TableInfo model from Glue Catalog table metadata.

    Extracts columns, partition keys, descriptions, PII classifications,
    and data freshness from the Glue table metadata.

    Args:
        table: Glue table metadata dictionary from GetTable.
        database: The database name.

    Returns:
        TableInfo model with full schema details.
    """
    storage_descriptor = table.get("StorageDescriptor", {})
    glue_columns = storage_descriptor.get("Columns", [])
    partition_keys = table.get("PartitionKeys", [])

    # Build column list from storage descriptor columns
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

    # Also include partition key columns in the column list
    for pk in partition_keys:
        pk_params = pk.get("Parameters", {})
        columns.append(
            ColumnInfo(
                name=pk.get("Name", ""),
                data_type=pk.get("Type", "string"),
                description=pk.get("Comment", "") or pk_params.get("comment", "Partition key"),
                is_pii=pk_params.get("pii", "false").lower() == "true",
                classification=pk_params.get("classification", "internal"),
            )
        )

    partition_key_names = [pk.get("Name", "") for pk in partition_keys]

    table_description = (
        table.get("Description", "")
        or table.get("Parameters", {}).get("comment", "")
        or f"Table {database}.{table.get('Name', '')}"
    )

    return TableInfo(
        database=database,
        table_name=table.get("Name", ""),
        description=table_description,
        columns=columns,
        partition_keys=partition_key_names,
        last_updated=_get_table_freshness(table),
    )


async def get_schema(
    user_claims: UserClaims,
    database: str,
    table: str,
    glue_client: "boto3.client | None" = None,
    lf_client: "boto3.client | None" = None,
) -> TableInfo:
    """Retrieve detailed schema for a table with authorization check.

    First verifies the user is authorized to access the table via Lake
    Formation grants, then retrieves full schema metadata from the Glue
    Catalog including columns, partition keys, and data freshness.

    Args:
        user_claims: Validated user claims from JWT.
        database: The database containing the table.
        table: The table name to retrieve schema for.
        glue_client: Optional Glue client (for testing/injection).
        lf_client: Optional Lake Formation client (for testing/injection).

    Returns:
        TableInfo model with full schema details.

    Raises:
        TableNotAuthorizedError: If user is not authorized to access the table.
        TableNotFoundError: If the table does not exist in the Glue Catalog.
        GetSchemaError: If Glue or Lake Formation API calls fail unexpectedly.

    Requirements:
        - 16.3: Filter by Lake Formation grants before returning schema
        - 6.4: Use authenticated user's identity for permission checks
        - 7.5: User's federated identity determines access
    """
    if glue_client is None:
        glue_client = _create_glue_client()
    if lf_client is None:
        lf_client = _create_lakeformation_client()

    # Step 1: Authorization check — verify user has Lake Formation grant
    is_authorized = _check_table_authorization(lf_client, user_claims, database, table)

    if not is_authorized:
        logger.warning(
            "AUTHORIZATION DENIED: User %s attempted to access schema for %s.%s "
            "without Lake Formation grant",
            user_claims.sub,
            database,
            table,
        )
        raise TableNotAuthorizedError(database=database, table=table)

    # Step 2: Retrieve table metadata from Glue Catalog
    try:
        response = glue_client.get_table(
            DatabaseName=database,
            Name=table,
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "EntityNotFoundException":
            raise TableNotFoundError(database=database, table=table) from e
        logger.error(
            "Failed to retrieve schema for %s.%s (user: %s): %s",
            database,
            table,
            user_claims.sub,
            str(e),
        )
        raise GetSchemaError(
            message=f"Failed to retrieve table schema: {e.response['Error']['Message']}"
        ) from e

    glue_table = response.get("Table", {})
    if not glue_table:
        raise TableNotFoundError(database=database, table=table)

    # Step 3: Build and return the TableInfo model
    table_info = _build_table_info(glue_table, database)

    logger.info(
        "Schema retrieved for %s.%s by user %s (%d columns, %d partition keys)",
        database,
        table,
        user_claims.sub,
        len(table_info.columns),
        len(table_info.partition_keys),
    )

    return table_info
