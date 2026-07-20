"""Dry-run cost estimation tool for Athena queries.

Performs an Athena StartQueryExecution with ResultReuseConfiguration to
estimate bytes scanned without actually executing the query. Uses the
dedicated `chatbot-readonly` workgroup and executes as the user's
federated identity via OBO token (never a shared service role).

Requirements: 7.1, 7.5, 7.6, 9.5
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.config import Config as BotoConfig

from chatbot.api.models import UserClaims
from chatbot.mcp_server.tools.models import CostEstimate

logger = logging.getLogger(__name__)

# Athena workgroup dedicated to chatbot read-only queries
WORKGROUP = "chatbot-readonly"

# Cost threshold: 10 GB in bytes (Requirement 9.5)
COST_THRESHOLD_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB

# Athena pricing: $5 per TB scanned
ATHENA_COST_PER_BYTE = 5.0 / (1024**4)


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
    """
    # Create STS client to assume role with the OBO token
    # The OBO token is exchanged for temporary credentials scoped to the user
    sts_client = boto3.client("sts")

    # Assume role using the OBO token — this produces credentials tied to
    # the user's federated identity, NOT the service role
    assumed_role = sts_client.assume_role_with_web_identity(
        RoleArn=f"arn:aws:iam::ACCOUNT_ID:role/chatbot-athena-federated",
        RoleSessionName=f"chatbot-{user_claims.sub}-{user_claims.session_id[:8]}",
        WebIdentityToken=obo_token,
        DurationSeconds=900,  # 15-minute session (least privilege)
    )

    credentials = assumed_role["Credentials"]

    # Create Athena client with user-scoped credentials
    athena_client = boto3.client(
        "athena",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        config=BotoConfig(
            retries={"max_attempts": 2, "mode": "standard"},
            connect_timeout=5,
            read_timeout=30,
        ),
    )

    return athena_client


async def estimate_cost(
    sql: str,
    user_claims: UserClaims,
    obo_token: str | None = None,
    athena_client: Any | None = None,
) -> CostEstimate:
    """Estimate the cost of a SQL query via Athena dry-run.

    Performs a StartQueryExecution with EXPLAIN to get the estimated bytes
    scanned without executing the query. Compares against the 10 GB threshold
    (Requirement 9.5) and flags queries that exceed it for users without
    the elevated_cost group.

    All operations execute as the user's federated identity via OBO token
    (Requirements 7.1, 7.5). NEVER uses a shared service role.

    Args:
        sql: The SQL query to estimate cost for (must be valid SELECT).
        user_claims: Validated claims from the authenticated user's JWT.
        obo_token: On-Behalf-Of token for the user's federated identity.
            If None and no athena_client provided, raises ValueError.
        athena_client: Optional pre-configured Athena client (for testing).
            If provided, obo_token is not used.

    Returns:
        CostEstimate with estimated bytes, cost, and threshold status.

    Raises:
        ValueError: If SQL is empty or no identity credentials provided.
        RuntimeError: If the dry-run estimation fails.
    """
    if not sql or not sql.strip():
        raise ValueError("SQL statement must be non-empty for cost estimation")

    # Create Athena client with user identity (OBO token)
    if athena_client is None:
        if obo_token is None:
            raise ValueError(
                "Either obo_token or athena_client must be provided. "
                "Queries cannot execute without user federated identity (Requirement 7.1)."
            )
        athena_client = _create_athena_client_with_obo(user_claims, obo_token)

    # Use EXPLAIN to estimate bytes scanned without executing the query
    explain_sql = f"EXPLAIN (TYPE DISTRIBUTED) {sql}"

    try:
        # Start the EXPLAIN query in the chatbot-readonly workgroup
        response = athena_client.start_query_execution(
            QueryString=explain_sql,
            WorkGroup=WORKGROUP,
            ResultReuseConfiguration={
                "ResultReuseByAgeConfiguration": {"Enabled": True, "MaxAgeInMinutes": 5}
            },
        )

        query_execution_id = response["QueryExecutionId"]

        # Wait for the EXPLAIN query to complete
        waiter = athena_client.get_waiter("query_succeeded")
        waiter.wait(
            QueryExecutionId=query_execution_id,
            WaiterConfig={"Delay": 1, "MaxAttempts": 30},
        )

        # Get execution statistics for the bytes scanned estimate
        execution_response = athena_client.get_query_execution(
            QueryExecutionId=query_execution_id
        )

        statistics = execution_response["QueryExecution"].get("Statistics", {})
        estimated_bytes = statistics.get("DataScannedInBytes", 0)

    except Exception as e:
        logger.error(
            "Cost estimation failed for user %s: %s",
            user_claims.sub,
            str(e),
        )
        raise RuntimeError(f"Cost estimation failed: {str(e)}") from e

    # Calculate estimated cost (Athena: $5 per TB)
    estimated_cost_usd = estimated_bytes * ATHENA_COST_PER_BYTE

    # Check if exceeds threshold (Requirement 9.5)
    has_elevated_cost = "elevated_cost" in user_claims.groups
    exceeds_threshold = estimated_bytes > COST_THRESHOLD_BYTES and not has_elevated_cost

    # Build suggestion if threshold exceeded
    suggestion: str | None = None
    if exceeds_threshold:
        suggestion = (
            "Query exceeds 10 GB scan threshold. Consider adding date or partition "
            "filters to reduce the scan size, or request elevated_cost group membership."
        )

    logger.info(
        "Cost estimate for user %s: %d bytes (%.4f USD), exceeds_threshold=%s",
        user_claims.sub,
        estimated_bytes,
        estimated_cost_usd,
        exceeds_threshold,
    )

    return CostEstimate(
        estimated_bytes_scanned=estimated_bytes,
        estimated_cost_usd=round(estimated_cost_usd, 6),
        exceeds_threshold=exceeds_threshold,
        suggestion=suggestion,
    )
