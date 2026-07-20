"""Execute validated SQL via Athena using the user's federated identity.

This tool runs a SQL query that has already passed the SQL validation engine
(validation.py). It uses the dedicated `chatbot-readonly` workgroup and
executes as the user's federated identity via OBO token exchange — NEVER
a shared service role.

Data freshness is sourced from Glue Catalog partition timestamps to provide
transparency about when the data was last updated.

Requirements: 7.1, 7.5, 7.6, 9.5

Key Security Properties:
- Property 5 (OBO Identity): Every query runs as the user's federated identity
- All queries use the chatbot-readonly workgroup (read-only, bytes-scanned limit)
- No fallback to service identity if OBO token fails (fail-closed)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.config import Config as BotoConfig

from chatbot.api.models import UserClaims
from chatbot.mcp_server.tools.models import QueryResult

logger = logging.getLogger(__name__)

# Athena workgroup dedicated to chatbot read-only queries
WORKGROUP = "chatbot-readonly"

# Maximum time to wait for query completion (seconds)
QUERY_TIMEOUT_SECONDS = 60

# Maximum poll attempts (1 second intervals)
MAX_POLL_ATTEMPTS = 60


def _create_athena_client_with_obo(user_claims: UserClaims, obo_token: str) -> Any:
    """Create a boto3 Athena client using the user's OBO token.

    Executes as the user's federated identity (Requirement 7.1, 7.5).
    NEVER uses a shared service role — every query is attributable to
    the authenticated end user.

    Args:
        user_claims: Validated claims from the user's JWT.
        obo_token: On-Behalf-Of token representing the user's federated identity.

    Returns:
        A boto3 Athena client configured with the user's credentials.

    Raises:
        RuntimeError: If the OBO token exchange fails.
    """
    try:
        sts_client = boto3.client("sts")

        # Assume role using the OBO token — produces credentials tied to
        # the user's federated identity, NOT the service role
        assumed_role = sts_client.assume_role_with_web_identity(
            RoleArn=f"arn:aws:iam::ACCOUNT_ID:role/chatbot-athena-federated",
            RoleSessionName=f"chatbot-{user_claims.sub}-{user_claims.session_id[:8]}",
            WebIdentityToken=obo_token,
            DurationSeconds=900,  # 15-minute session (least privilege)
        )

        credentials = assumed_role["Credentials"]

        athena_client = boto3.client(
            "athena",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            config=BotoConfig(
                retries={"max_attempts": 2, "mode": "standard"},
                connect_timeout=5,
                read_timeout=60,
            ),
        )

        return athena_client

    except Exception as e:
        # Fail-closed: NEVER fall back to a shared service identity (Requirement 7.6)
        logger.error(
            "OBO token exchange failed for user %s: %s. "
            "NOT falling back to shared service role.",
            user_claims.sub,
            str(e),
        )
        raise RuntimeError(
            f"Identity delegation failed: unable to assume user federated identity. "
            f"Query will NOT execute under a shared service role."
        ) from e


def _create_glue_client_with_obo(user_claims: UserClaims, obo_token: str) -> Any:
    """Create a boto3 Glue client using the user's OBO token.

    Used to retrieve partition timestamps for data freshness indicator.

    Args:
        user_claims: Validated claims from the user's JWT.
        obo_token: On-Behalf-Of token representing the user's federated identity.

    Returns:
        A boto3 Glue client configured with the user's credentials.
    """
    sts_client = boto3.client("sts")

    assumed_role = sts_client.assume_role_with_web_identity(
        RoleArn=f"arn:aws:iam::ACCOUNT_ID:role/chatbot-athena-federated",
        RoleSessionName=f"chatbot-glue-{user_claims.sub}-{user_claims.session_id[:8]}",
        WebIdentityToken=obo_token,
        DurationSeconds=900,
    )

    credentials = assumed_role["Credentials"]

    glue_client = boto3.client(
        "glue",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        config=BotoConfig(
            retries={"max_attempts": 2, "mode": "standard"},
            connect_timeout=5,
            read_timeout=10,
        ),
    )

    return glue_client


def _get_data_freshness(
    glue_client: Any,
    database: str,
    table: str,
) -> str:
    """Get data freshness from Glue Catalog partition timestamps.

    Queries the most recent partition to determine when the data was
    last updated, providing transparency to users.

    Args:
        glue_client: Configured Glue client (user identity).
        database: Database name.
        table: Table name.

    Returns:
        Human-readable data freshness string (ISO 8601 timestamp).
    """
    try:
        # Get the most recent partitions to determine data freshness
        response = glue_client.get_partitions(
            DatabaseName=database,
            TableName=table,
            MaxResults=1,
            Segment={"SegmentNumber": 0, "TotalSegments": 1},
        )

        partitions = response.get("Partitions", [])
        if partitions:
            # Use the most recent partition's creation time
            last_partition = partitions[0]
            last_access_time = last_partition.get(
                "LastAccessTime", last_partition.get("CreationTime")
            )
            if last_access_time:
                if isinstance(last_access_time, datetime):
                    return f"Data current as of {last_access_time.isoformat()}"
                return f"Data current as of {last_access_time}"

        # Fallback: get table metadata for last updated time
        table_response = glue_client.get_table(
            DatabaseName=database,
            Name=table,
        )
        table_meta = table_response.get("Table", {})
        update_time = table_meta.get("UpdateTime", table_meta.get("CreateTime"))
        if update_time:
            if isinstance(update_time, datetime):
                return f"Data current as of {update_time.isoformat()}"
            return f"Data current as of {update_time}"

        return "Data freshness unknown — no partition or table timestamp available"

    except Exception as e:
        logger.warning(
            "Failed to determine data freshness for %s.%s: %s",
            database,
            table,
            str(e),
        )
        return "Data freshness unavailable"


def _extract_tables_from_sql(sql: str) -> list[tuple[str, str]]:
    """Extract (database, table) pairs from SQL for data freshness lookup.

    Uses sqlglot to parse the SQL and extract table references.

    Returns:
        List of (database, table_name) tuples.
    """
    try:
        import sqlglot
        from sqlglot import exp as sqlglot_exp

        statements = sqlglot.parse(sql, dialect="trino")
        if not statements or statements[0] is None:
            return []

        expression = statements[0]
        tables: list[tuple[str, str]] = []

        for table_node in expression.find_all(sqlglot_exp.Table):
            table_name = table_node.name
            db = table_node.db
            if table_name and db:
                tables.append((db, table_name))
            elif table_name:
                tables.append(("default", table_name))

        return tables

    except Exception:
        return []


async def run_query(
    sql: str,
    user_claims: UserClaims,
    obo_token: str | None = None,
    athena_client: Any | None = None,
    glue_client: Any | None = None,
) -> QueryResult:
    """Execute validated SQL via Athena as the authenticated user.

    This function MUST only be called with SQL that has already passed
    the validation engine (validate_sql). It executes the query using
    the dedicated chatbot-readonly workgroup under the user's federated
    identity via OBO token exchange.

    SECURITY INVARIANT (Property 5 - OBO Identity):
    Every Athena query runs as the user's federated identity. If OBO
    token exchange fails, the query is rejected — NEVER falls back to
    a shared service role.

    Args:
        sql: Validated SQL query to execute (must have passed validate_sql).
        user_claims: Validated claims from the authenticated user's JWT.
        obo_token: On-Behalf-Of token for the user's federated identity.
            Required if athena_client is not provided.
        athena_client: Optional pre-configured Athena client (for testing).
        glue_client: Optional pre-configured Glue client (for testing).

    Returns:
        QueryResult with columns, rows, execution metadata, and data freshness.

    Raises:
        ValueError: If SQL is empty or no identity credentials provided.
        RuntimeError: If OBO exchange fails or query execution fails.
    """
    if not sql or not sql.strip():
        raise ValueError("SQL statement must be non-empty")

    # Enforce OBO identity requirement (Requirement 7.1, 7.5)
    if athena_client is None:
        if obo_token is None:
            raise ValueError(
                "Either obo_token or athena_client must be provided. "
                "Queries MUST execute as user's federated identity (Requirement 7.1). "
                "Shared service role execution is NEVER permitted."
            )
        athena_client = _create_athena_client_with_obo(user_claims, obo_token)

    # Execute the query in the chatbot-readonly workgroup
    try:
        start_response = athena_client.start_query_execution(
            QueryString=sql,
            WorkGroup=WORKGROUP,
            ResultReuseConfiguration={
                "ResultReuseByAgeConfiguration": {"Enabled": True, "MaxAgeInMinutes": 5}
            },
        )

        query_execution_id = start_response["QueryExecutionId"]

        logger.info(
            "Query started for user %s: execution_id=%s, workgroup=%s",
            user_claims.sub,
            query_execution_id,
            WORKGROUP,
        )

        # Wait for query completion
        waiter = athena_client.get_waiter("query_succeeded")
        waiter.wait(
            QueryExecutionId=query_execution_id,
            WaiterConfig={"Delay": 1, "MaxAttempts": MAX_POLL_ATTEMPTS},
        )

    except Exception as e:
        logger.error(
            "Query execution failed for user %s: %s",
            user_claims.sub,
            str(e),
        )
        raise RuntimeError(f"Query execution failed: {str(e)}") from e

    # Get execution metadata (bytes scanned, execution time)
    try:
        execution_response = athena_client.get_query_execution(
            QueryExecutionId=query_execution_id
        )
        execution = execution_response["QueryExecution"]
        statistics = execution.get("Statistics", {})
        bytes_scanned = statistics.get("DataScannedInBytes", 0)
        execution_time_ms = statistics.get("EngineExecutionTimeInMillis", 0)

    except Exception as e:
        logger.warning(
            "Failed to get execution statistics: %s",
            str(e),
        )
        bytes_scanned = 0
        execution_time_ms = 0

    # Get query results
    try:
        results_response = athena_client.get_query_results(
            QueryExecutionId=query_execution_id
        )

        result_set = results_response.get("ResultSet", {})
        result_rows = result_set.get("Rows", [])
        column_info = result_set.get("ResultSetMetadata", {}).get("ColumnInfo", [])

        # Extract column names from metadata
        columns = [col.get("Name", f"col_{i}") for i, col in enumerate(column_info)]

        # Parse rows (first row is header in Athena results)
        rows: list[dict[str, Any]] = []
        data_rows = result_rows[1:] if len(result_rows) > 1 else []

        for row in data_rows:
            row_data = row.get("Data", [])
            row_dict: dict[str, Any] = {}
            for i, cell in enumerate(row_data):
                col_name = columns[i] if i < len(columns) else f"col_{i}"
                row_dict[col_name] = cell.get("VarCharValue")
            rows.append(row_dict)

    except Exception as e:
        logger.error(
            "Failed to retrieve query results for user %s: %s",
            user_claims.sub,
            str(e),
        )
        raise RuntimeError(f"Failed to retrieve query results: {str(e)}") from e

    # Get data freshness from Glue Catalog partition timestamps
    data_freshness = "Data freshness unavailable"
    tables = _extract_tables_from_sql(sql)

    if tables:
        database, table = tables[0]  # Use primary table for freshness
        try:
            if glue_client is None:
                if obo_token is not None:
                    glue_client = _create_glue_client_with_obo(user_claims, obo_token)

            if glue_client is not None:
                data_freshness = _get_data_freshness(glue_client, database, table)
        except Exception as e:
            logger.warning(
                "Data freshness lookup failed: %s",
                str(e),
            )
            data_freshness = "Data freshness unavailable"

    row_count = len(rows)

    logger.info(
        "Query completed for user %s: %d rows, %d bytes scanned, %dms",
        user_claims.sub,
        row_count,
        bytes_scanned,
        execution_time_ms,
    )

    return QueryResult(
        columns=columns,
        rows=rows,
        row_count=row_count,
        bytes_scanned=bytes_scanned,
        execution_time_ms=execution_time_ms,
        data_freshness=data_freshness,
    )
