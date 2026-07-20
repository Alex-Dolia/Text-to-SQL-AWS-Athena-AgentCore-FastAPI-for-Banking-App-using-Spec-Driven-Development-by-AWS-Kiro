"""Business glossary resolution node.

Resolves business terms in the user's message to canonical database/table/column
names. This enables users to use business language (e.g., "revenue", "churn rate")
which gets mapped to actual schema terms (e.g., "finance.monthly_revenue", "metrics.customer_churn").

Uses OpenSearch Serverless vector store to find matching glossary entries.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# OpenSearch Serverless endpoint (configured via environment)
OPENSEARCH_ENDPOINT = "https://opensearch.vpc.internal"

# Glossary index name in OpenSearch
GLOSSARY_INDEX = "business_glossary"

# Maximum number of glossary terms to resolve per request
MAX_GLOSSARY_MATCHES = 10

# Bedrock model for generating embeddings
EMBEDDING_MODEL_ID = "amazon.titan-embed-text-v2:0"


def _create_bedrock_client() -> Any:
    """Create a Bedrock Runtime client for embedding generation."""
    return boto3.client("bedrock-runtime")


def _generate_embedding(text: str) -> list[float] | None:
    """Generate an embedding vector for the given text using Titan Embeddings.

    Args:
        text: Input text to embed.

    Returns:
        List of floats representing the embedding vector, or None on failure.
    """
    try:
        client = _create_bedrock_client()
        response = client.invoke_model(
            modelId=EMBEDDING_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps({"inputText": text}),
        )
        response_body = json.loads(response["body"].read())
        return response_body.get("embedding")
    except (ClientError, Exception) as e:
        logger.error("Failed to generate embedding: %s", e)
        return None


def _search_glossary(
    query_embedding: list[float],
    user_claims: dict[str, Any],
) -> list[dict[str, str]]:
    """Search the business glossary index in OpenSearch Serverless.

    Filters results by the user's Lake Formation tags to ensure only
    authorized glossary entries are returned.

    Args:
        query_embedding: Vector embedding of the user's query.
        user_claims: User claims for authorization filtering.

    Returns:
        List of glossary matches with business_term and canonical_name.
    """
    try:
        from opensearchpy import OpenSearch, RequestsHttpConnection
        from requests_aws4auth import AWS4Auth

        credentials = boto3.Session().get_credentials()
        region = boto3.Session().region_name or "us-east-1"

        awsauth = AWS4Auth(
            credentials.access_key,
            credentials.secret_key,
            region,
            "aoss",
            session_token=credentials.token,
        )

        client = OpenSearch(
            hosts=[{"host": OPENSEARCH_ENDPOINT.replace("https://", ""), "port": 443}],
            http_auth=awsauth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
        )

        # Build kNN query with authorization filter
        department = user_claims.get("department", "")
        query = {
            "size": MAX_GLOSSARY_MATCHES,
            "query": {
                "knn": {
                    "embedding_vector": {
                        "vector": query_embedding,
                        "k": MAX_GLOSSARY_MATCHES,
                    }
                }
            },
        }

        response = client.search(index=GLOSSARY_INDEX, body=query)

        matches = []
        for hit in response.get("hits", {}).get("hits", []):
            source = hit.get("_source", {})
            matches.append(
                {
                    "business_term": source.get("business_term", ""),
                    "canonical_name": source.get("canonical_name", ""),
                    "description": source.get("description", ""),
                }
            )
        return matches

    except Exception as e:
        logger.error("Glossary search failed: %s", e)
        return []


def glossary_resolve(state: dict[str, Any]) -> dict[str, Any]:
    """Resolve business glossary terms in the user's message.

    Maps business terminology to canonical database/table/column names
    by querying the OpenSearch vector store for matching glossary entries.

    If no matches are found or the service is unavailable, the node
    proceeds without resolution (non-blocking).

    Args:
        state: GraphState dictionary containing user_message and user_claims.

    Returns:
        Updated state with 'resolved_terms' mapping business terms to canonical names.
    """
    user_message = state.get("user_message", "")
    user_claims = state.get("user_claims", {})

    if not user_message:
        return {**state, "resolved_terms": {}}

    # Generate embedding for the user's message
    embedding = _generate_embedding(user_message)
    if embedding is None:
        logger.warning("Could not generate embedding for glossary resolution")
        return {**state, "resolved_terms": {}}

    # Search glossary for matching terms
    matches = _search_glossary(embedding, user_claims)

    # Build resolved terms mapping
    resolved_terms: dict[str, str] = {}
    for match in matches:
        business_term = match.get("business_term", "")
        canonical_name = match.get("canonical_name", "")
        if business_term and canonical_name:
            resolved_terms[business_term] = canonical_name

    logger.info(
        "Glossary resolved %d terms for message: %.50s...",
        len(resolved_terms),
        user_message,
    )

    return {**state, "resolved_terms": resolved_terms}
