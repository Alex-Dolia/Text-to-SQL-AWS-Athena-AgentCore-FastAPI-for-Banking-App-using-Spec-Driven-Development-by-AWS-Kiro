"""Schema retrieval node via RAG from OpenSearch Serverless.

Retrieves relevant table schemas via vector similarity search (RAG),
filtered by the authenticated user's Lake Formation grants. Only schemas
matching the user's authorization are included in LLM context
(Requirement 10.5).

If no schemas match the user's grants, the user is informed that no
accessible tables match their question — unfiltered schema context is
NEVER passed to the LLM.

OpenSearch Serverless Configuration (Requirement 16.5):
- Collection type: VECTORSEARCH (vector type)
- Network access: VPC-only (no public endpoint)
- Authentication: IAM via SigV4 with 'aoss' service
- Encryption: AWS-owned key (or customer CMK via KMS)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# OpenSearch Serverless endpoint (VPC-only, Requirement 16.5)
# Configured for VPC endpoint access only — no public endpoint exists.
OPENSEARCH_ENDPOINT = "https://opensearch.vpc.internal"

# Schema embeddings index
SCHEMA_INDEX = "schema_embeddings"

# Top-k results for RAG retrieval
TOP_K_RESULTS = 5

# Bedrock model for generating embeddings
EMBEDDING_MODEL_ID = "amazon.titan-embed-text-v2:0"


@dataclass
class OpenSearchCollectionConfig:
    """OpenSearch Serverless collection configuration for schema embeddings.

    Enforces vector type with VPC-only access per Requirement 16.5.
    No public endpoint SHALL exist for the collection.
    """

    collection_name: str = "chatbot-schema-embeddings"
    collection_type: str = "VECTORSEARCH"
    description: str = "Schema embeddings for authorization-filtered RAG retrieval"

    # Network policy: VPC-only access (no public endpoint)
    network_policy_type: str = "AllPrivate"
    vpc_endpoint_ids: list[str] | None = None

    # Encryption: AWS-owned key or customer CMK
    encryption_policy_type: str = "AWSOwnedKey"

    def get_network_policy(self) -> dict[str, Any]:
        """Generate the network access policy for VPC-only access.

        Returns a policy that restricts all access to VPC endpoints only.
        No public network access is permitted (Requirement 16.5).
        """
        rules = [
            {
                "ResourceType": "collection",
                "Resource": [f"collection/{self.collection_name}"],
            },
            {
                "ResourceType": "dashboard",
                "Resource": [f"collection/{self.collection_name}"],
            },
        ]

        # VPC-only: all access through VPC endpoint
        policy = {
            "Rules": rules,
            "AllowFromPublic": False,
        }
        if self.vpc_endpoint_ids:
            policy["SourceVPCEs"] = self.vpc_endpoint_ids

        return policy

    def get_encryption_policy(self) -> dict[str, Any]:
        """Generate the encryption policy for the collection."""
        return {
            "Rules": [
                {
                    "ResourceType": "collection",
                    "Resource": [f"collection/{self.collection_name}"],
                }
            ],
            "AWSOwnedKey": self.encryption_policy_type == "AWSOwnedKey",
        }


# Default collection configuration (VPC-only, vector type)
COLLECTION_CONFIG = OpenSearchCollectionConfig()


def _generate_embedding(text: str) -> list[float] | None:
    """Generate an embedding vector using Titan Embeddings.

    Args:
        text: Input text to embed.

    Returns:
        Embedding vector or None on failure.
    """
    try:
        client = boto3.client("bedrock-runtime")
        response = client.invoke_model(
            modelId=EMBEDDING_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps({"inputText": text}),
        )
        response_body = json.loads(response["body"].read())
        return response_body.get("embedding")
    except (ClientError, Exception) as e:
        logger.error("Failed to generate embedding for schema retrieval: %s", e)
        return None


def _get_user_authorized_tags(user_claims: dict[str, Any]) -> dict[str, list[str]]:
    """Extract Lake Formation authorization tags from user claims.

    These tags are used to filter OpenSearch results to only schemas
    the user is authorized to access (Requirement 16.3).

    Default-deny: if no authorization tags can be derived from user claims,
    returns an empty dict which signals that NO schemas should be returned
    (the caller must treat empty tags as "no access").

    Args:
        user_claims: User claims from validated JWT.

    Returns:
        Dictionary of tag keys to allowed tag values for filtering.
        Empty dict means no authorization could be derived (default-deny).
    """
    department = user_claims.get("department", "")
    tier = user_claims.get("data_classification_tier", "public")
    groups = user_claims.get("groups", [])

    # Build filter tags based on user's authorization attributes
    tags: dict[str, list[str]] = {}
    if department:
        tags["department"] = [department, "shared"]
    if tier:
        # User can access their tier and below
        tier_hierarchy = ["public", "internal", "confidential", "restricted"]
        try:
            tier_index = tier_hierarchy.index(tier)
            tags["classification_tier"] = tier_hierarchy[: tier_index + 1]
        except ValueError:
            tags["classification_tier"] = ["public"]
    if groups:
        tags["groups"] = groups

    return tags


def _search_schemas(
    query_embedding: list[float],
    authorized_tags: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Search schema embeddings filtered by user authorization tags.

    Filters by lake_formation_tags before selecting top-k results
    (Requirement 16.3). Only schemas matching the user's grants are returned.

    SECURITY: If authorized_tags is empty (no identifiable grants), returns
    an empty list. This enforces default-deny — unfiltered results are NEVER
    returned to the LLM context.

    Args:
        query_embedding: Vector embedding of the user's query.
        authorized_tags: Lake Formation tags the user is authorized for.
                         Empty dict = no access (default-deny).

    Returns:
        List of schema documents matching the query and authorization.
    """
    # Default-deny: if no authorization tags, return nothing.
    # This prevents unfiltered schema context from reaching the LLM.
    if not authorized_tags:
        logger.warning(
            "No authorization tags derived for user — default-deny applied, "
            "returning zero schemas (Requirement 16.3)"
        )
        return []

    try:
        from opensearchpy import OpenSearch, RequestsHttpConnection
        from requests_aws4auth import AWS4Auth

        credentials = boto3.Session().get_credentials()
        region = boto3.Session().region_name or "us-east-1"

        awsauth = AWS4Auth(
            credentials.access_key,
            credentials.secret_key,
            region,
            "aoss",  # OpenSearch Serverless service
            session_token=credentials.token,
        )

        client = OpenSearch(
            hosts=[{"host": OPENSEARCH_ENDPOINT.replace("https://", ""), "port": 443}],
            http_auth=awsauth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
        )

        # Build authorization filter from Lake Formation tags (Requirement 16.3)
        # All filter clauses are applied BEFORE top-k selection,
        # ensuring only authorized schemas are candidates for retrieval.
        filter_clauses = []
        for tag_key, tag_values in authorized_tags.items():
            filter_clauses.append(
                {"terms": {f"lake_formation_tags.{tag_key}": tag_values}}
            )

        # kNN query with pre-filter: authorization filter applied before
        # vector similarity ranking selects top-k results.
        query = {
            "size": TOP_K_RESULTS,
            "query": {
                "bool": {
                    "must": [
                        {
                            "knn": {
                                "embedding_vector": {
                                    "vector": query_embedding,
                                    "k": TOP_K_RESULTS,
                                }
                            }
                        }
                    ],
                    "filter": filter_clauses,
                }
            },
        }

        response = client.search(index=SCHEMA_INDEX, body=query)

        schemas = []
        for hit in response.get("hits", {}).get("hits", []):
            source = hit.get("_source", {})
            schemas.append(
                {
                    "database": source.get("database", ""),
                    "table_name": source.get("table_name", ""),
                    "description": source.get("description", ""),
                    "columns": source.get("columns", []),
                    "partition_keys": source.get("partition_keys", []),
                    "business_glossary_terms": source.get("business_glossary_terms", []),
                    "last_indexed": source.get("last_indexed", ""),
                    "data_freshness": source.get("data_freshness", ""),
                }
            )

        return schemas

    except Exception as e:
        logger.error("Schema search failed: %s", e)
        return []


def schema_retrieve(state: dict[str, Any]) -> dict[str, Any]:
    """Retrieve relevant schemas via RAG filtered by user authorization.

    Queries OpenSearch Serverless for schema embeddings matching the user's
    query, filtered to only schemas the user is authorized to access via
    Lake Formation grants (Requirement 10.5, 16.3).

    Authorization filter is applied BEFORE top-k selection, ensuring
    no unfiltered schema context ever reaches the LLM.

    If no schemas match the user's grants, the state is updated to inform
    the user — unfiltered schema context is NEVER passed to the LLM.

    Args:
        state: GraphState dictionary containing user_message, user_claims,
               and resolved_terms.

    Returns:
        Updated state with 'retrieved_schemas' containing authorized schema results.
    """
    user_message = state.get("user_message", "")
    user_claims = state.get("user_claims", {})
    resolved_terms = state.get("resolved_terms", {})

    # Enrich query with resolved glossary terms
    query_text = user_message
    if resolved_terms:
        term_context = " ".join(resolved_terms.values())
        query_text = f"{user_message} {term_context}"

    # Generate embedding for the enriched query
    embedding = _generate_embedding(query_text)
    if embedding is None:
        logger.warning("Could not generate embedding for schema retrieval")
        return {
            **state,
            "retrieved_schemas": [],
            "error": "Schema retrieval unavailable: embedding generation failed",
        }

    # Get user's authorized Lake Formation tags
    authorized_tags = _get_user_authorized_tags(user_claims)

    # Default-deny: if no authorization tags could be derived, block retrieval
    if not authorized_tags:
        logger.warning(
            "No authorization tags for user %s — denying schema retrieval (default-deny)",
            user_claims.get("sub", "unknown"),
        )
        return {
            **state,
            "retrieved_schemas": [],
            "needs_disambiguation": False,
            "error": (
                "No accessible tables match your question. "
                "Please verify you have access to the relevant data sources."
            ),
        }

    # Search schemas with authorization filtering (filter applied before top-k)
    schemas = _search_schemas(embedding, authorized_tags)

    if not schemas:
        # No schemas match user's grants — inform user (Requirement 10.5)
        logger.info(
            "No authorized schemas found for user %s query: %.50s...",
            user_claims.get("sub", "unknown"),
            user_message,
        )
        return {
            **state,
            "retrieved_schemas": [],
            "needs_disambiguation": False,
            "error": (
                "No accessible tables match your question. "
                "Please verify you have access to the relevant data sources."
            ),
        }

    logger.info(
        "Retrieved %d authorized schemas for user %s",
        len(schemas),
        user_claims.get("sub", "unknown"),
    )

    return {**state, "retrieved_schemas": schemas}
