"""Schema re-indexing pipeline for EventBridge-triggered synchronization.

Keeps OpenSearch Serverless vector store in sync with the AWS Glue Catalog.
Triggered by EventBridge rules on Glue Catalog changes (table create/modify/delete).

Re-indexes schema embeddings within 60 minutes of table creation/modification events.
Removes embeddings on table deletion within 60 minutes.

Includes business glossary terms, synonyms, and Lake Formation tags in embeddings.
Implements retry logic: 3 attempts with exponential backoff, alert on failure.

Requirements: 16.1, 16.2, 16.4
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Constants
MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 2.0
REINDEX_SLA_MINUTES = 60
OPENSEARCH_ENDPOINT = "https://opensearch.vpc.internal"
SCHEMA_INDEX = "schema_embeddings"
EMBEDDING_MODEL_ID = "amazon.titan-embed-text-v2:0"
ALERT_NAMESPACE = "Chatbot/SchemaSync"
ALERT_METRIC_NAME = "ReindexFailure"


class EventType(Enum):
    """Glue Catalog event types from EventBridge."""

    CREATE_TABLE = "CreateTable"
    UPDATE_TABLE = "UpdateTable"
    DELETE_TABLE = "DeleteTable"
    BATCH_CREATE_PARTITION = "BatchCreatePartition"
    UPDATE_PARTITION = "UpdatePartition"


class ReindexError(Exception):
    """Raised when schema re-indexing fails after all retry attempts."""

    def __init__(self, database: str, table: str, message: str = "Re-index failed after all retries"):
        self.database = database
        self.table = table
        super().__init__(f"{message} [{database}.{table}]")


@dataclass
class SchemaEmbedding:
    """Schema embedding document for OpenSearch Serverless.

    Matches the vector store schema defined in the design document.
    Includes business glossary terms, synonyms, and Lake Formation tags
    for authorization-filtered RAG retrieval.
    """

    embedding_id: str
    database: str
    table_name: str
    column_name: str | None = None
    description: str = ""
    business_glossary_terms: list[str] = field(default_factory=list)
    synonyms: list[str] = field(default_factory=list)
    data_type: str | None = None
    embedding_vector: list[float] = field(default_factory=list)
    last_indexed: str = ""
    lake_formation_tags: dict[str, Any] = field(default_factory=dict)
    columns: list[dict[str, Any]] = field(default_factory=list)
    partition_keys: list[str] = field(default_factory=list)

    def to_document(self) -> dict[str, Any]:
        """Convert to OpenSearch document format."""
        doc: dict[str, Any] = {
            "embedding_id": self.embedding_id,
            "database": self.database,
            "table_name": self.table_name,
            "description": self.description,
            "business_glossary_terms": self.business_glossary_terms,
            "synonyms": self.synonyms,
            "embedding_vector": self.embedding_vector,
            "last_indexed": self.last_indexed,
            "lake_formation_tags": self.lake_formation_tags,
            "columns": self.columns,
            "partition_keys": self.partition_keys,
        }
        if self.column_name:
            doc["column_name"] = self.column_name
        if self.data_type:
            doc["data_type"] = self.data_type
        return doc


@dataclass
class GlueTableMetadata:
    """Metadata extracted from Glue Catalog for a table."""

    database: str
    table_name: str
    description: str
    columns: list[dict[str, str]]
    partition_keys: list[str]
    parameters: dict[str, str] = field(default_factory=dict)
    last_updated: str = ""


@dataclass
class ReindexResult:
    """Result of a re-indexing operation."""

    success: bool
    database: str
    table_name: str
    event_type: str
    embeddings_indexed: int = 0
    embeddings_removed: int = 0
    duration_seconds: float = 0.0
    error: str | None = None


class SchemaReindexPipeline:
    """EventBridge-triggered schema re-indexing pipeline.

    Handles Glue Catalog change events to keep OpenSearch Serverless
    vector store synchronized. Implements retry with exponential backoff
    and alerts on failure.

    Requirements: 16.1, 16.2, 16.4
    """

    def __init__(
        self,
        *,
        glue_client: Any | None = None,
        bedrock_client: Any | None = None,
        opensearch_client: Any | None = None,
        cloudwatch_client: Any | None = None,
        lakeformation_client: Any | None = None,
        opensearch_endpoint: str = OPENSEARCH_ENDPOINT,
        schema_index: str = SCHEMA_INDEX,
    ):
        """Initialize the re-indexing pipeline.

        Args:
            glue_client: Optional boto3 Glue client (for testing/injection).
            bedrock_client: Optional boto3 Bedrock Runtime client.
            opensearch_client: Optional OpenSearch client instance.
            cloudwatch_client: Optional boto3 CloudWatch client.
            lakeformation_client: Optional boto3 Lake Formation client.
            opensearch_endpoint: OpenSearch Serverless endpoint URL.
            schema_index: Name of the schema embeddings index.
        """
        self._glue = glue_client or boto3.client("glue")
        self._bedrock = bedrock_client or boto3.client("bedrock-runtime")
        self._cloudwatch = cloudwatch_client or boto3.client("cloudwatch")
        self._lakeformation = lakeformation_client or boto3.client("lakeformation")
        self._opensearch_endpoint = opensearch_endpoint
        self._schema_index = schema_index
        self._opensearch = opensearch_client or self._create_opensearch_client()

    def _create_opensearch_client(self) -> Any:
        """Create an authenticated OpenSearch Serverless client.

        Uses IAM authentication via SigV4 for VPC-only access.
        """
        try:
            from opensearchpy import OpenSearch, RequestsHttpConnection
            from requests_aws4auth import AWS4Auth

            session = boto3.Session()
            credentials = session.get_credentials()
            region = session.region_name or "us-east-1"

            awsauth = AWS4Auth(
                credentials.access_key,
                credentials.secret_key,
                region,
                "aoss",
                session_token=credentials.token,
            )

            host = self._opensearch_endpoint.replace("https://", "").replace("http://", "")
            return OpenSearch(
                hosts=[{"host": host, "port": 443}],
                http_auth=awsauth,
                use_ssl=True,
                verify_certs=True,
                connection_class=RequestsHttpConnection,
            )
        except ImportError:
            logger.warning("opensearch-py not available; using mock client")
            return None

    def handle_event(self, event: dict[str, Any]) -> ReindexResult:
        """Handle an EventBridge event for Glue Catalog changes.

        This is the main entry point triggered by EventBridge rules.
        Dispatches to create/update or delete handlers based on event type.

        Args:
            event: EventBridge event payload containing Glue Catalog change details.

        Returns:
            ReindexResult with outcome of the re-indexing operation.
        """
        start_time = time.monotonic()

        # Parse the EventBridge event
        try:
            event_type, database, table_name = self._parse_event(event)
        except ValueError as e:
            duration = time.monotonic() - start_time
            logger.error("Failed to parse EventBridge event: %s", str(e))
            return ReindexResult(
                success=False,
                database="",
                table_name="",
                event_type="unknown",
                duration_seconds=duration,
                error=str(e),
            )

        logger.info(
            "Processing Glue Catalog event: %s for %s.%s",
            event_type,
            database,
            table_name,
        )

        try:
            if event_type == EventType.DELETE_TABLE:
                result = self._handle_delete(database, table_name)
            else:
                result = self._handle_create_or_update(database, table_name, event_type)

            result.duration_seconds = time.monotonic() - start_time
            logger.info(
                "Re-indexing completed: %s.%s (%s) in %.1fs",
                database,
                table_name,
                event_type.value,
                result.duration_seconds,
            )
            return result

        except ReindexError as e:
            duration = time.monotonic() - start_time
            logger.error(
                "Re-indexing FAILED for %s.%s after all retries: %s",
                database,
                table_name,
                str(e),
            )
            return ReindexResult(
                success=False,
                database=database,
                table_name=table_name,
                event_type=event_type.value,
                duration_seconds=duration,
                error=str(e),
            )

    def _parse_event(self, event: dict[str, Any]) -> tuple[EventType, str, str]:
        """Parse an EventBridge event to extract event type, database, and table.

        Supports Glue API call events via CloudTrail integration.

        Args:
            event: Raw EventBridge event payload.

        Returns:
            Tuple of (EventType, database_name, table_name).

        Raises:
            ValueError: If the event cannot be parsed.
        """
        detail = event.get("detail", {})

        # Handle Glue API call events (via CloudTrail)
        event_name = detail.get("eventName", "")
        request_params = detail.get("requestParameters", {})

        # Map API call names to EventType
        event_type_map = {
            "CreateTable": EventType.CREATE_TABLE,
            "UpdateTable": EventType.UPDATE_TABLE,
            "DeleteTable": EventType.DELETE_TABLE,
            "BatchCreatePartition": EventType.BATCH_CREATE_PARTITION,
            "UpdatePartition": EventType.UPDATE_PARTITION,
        }

        event_type = event_type_map.get(event_name)
        if event_type is None:
            raise ValueError(f"Unsupported Glue event type: {event_name}")

        # Extract database and table from request parameters
        database = request_params.get("databaseName", "")
        table_name = request_params.get("tableName", "")

        # For table input nested structures
        if not table_name:
            table_input = request_params.get("tableInput", {})
            table_name = table_input.get("name", "")

        if not database or not table_name:
            raise ValueError(
                f"Could not extract database/table from event: {event_name}"
            )

        return event_type, database, table_name

    def _handle_create_or_update(
        self, database: str, table_name: str, event_type: EventType
    ) -> ReindexResult:
        """Handle table creation or modification by re-indexing embeddings.

        Fetches table metadata from Glue Catalog, generates embeddings using
        Bedrock Titan, and indexes them to OpenSearch Serverless.

        Implements retry: 3 attempts with exponential backoff (Requirement 16.4).

        Args:
            database: Glue database name.
            table_name: Glue table name.
            event_type: The type of change event.

        Returns:
            ReindexResult indicating success/failure.

        Raises:
            ReindexError: If all retry attempts fail.
        """
        last_error: Exception | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                # Step 1: Fetch table metadata from Glue Catalog
                metadata = self._fetch_table_metadata(database, table_name)

                # Step 2: Fetch Lake Formation tags for authorization filtering
                lf_tags = self._fetch_lake_formation_tags(database, table_name)

                # Step 3: Fetch business glossary terms and synonyms
                glossary_terms, synonyms = self._fetch_glossary_data(database, table_name)

                # Step 4: Generate schema embeddings
                embeddings = self._generate_schema_embeddings(
                    metadata=metadata,
                    lake_formation_tags=lf_tags,
                    glossary_terms=glossary_terms,
                    synonyms=synonyms,
                )

                # Step 5: Remove old embeddings for this table
                self._remove_table_embeddings(database, table_name)

                # Step 6: Index new embeddings to OpenSearch
                indexed_count = self._index_embeddings(embeddings)

                return ReindexResult(
                    success=True,
                    database=database,
                    table_name=table_name,
                    event_type=event_type.value,
                    embeddings_indexed=indexed_count,
                )

            except (ClientError, OSError, Exception) as exc:
                last_error = exc
                logger.warning(
                    "Re-index attempt %d/%d failed for %s.%s: %s",
                    attempt,
                    MAX_RETRIES,
                    database,
                    table_name,
                    str(exc),
                )
                if attempt < MAX_RETRIES:
                    backoff = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
                    time.sleep(backoff)

        # All retries exhausted — emit alert
        self._emit_failure_alert(database, table_name, str(last_error))
        raise ReindexError(database, table_name)

    def _handle_delete(self, database: str, table_name: str) -> ReindexResult:
        """Handle table deletion by removing embeddings from OpenSearch.

        Removes all embeddings for the specified table within 60 minutes
        of the deletion event (Requirement 16.2).

        Implements retry: 3 attempts with exponential backoff (Requirement 16.4).

        Args:
            database: Glue database name.
            table_name: Glue table name.

        Returns:
            ReindexResult indicating success/failure.

        Raises:
            ReindexError: If all retry attempts fail.
        """
        last_error: Exception | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                removed_count = self._remove_table_embeddings(database, table_name)

                return ReindexResult(
                    success=True,
                    database=database,
                    table_name=table_name,
                    event_type=EventType.DELETE_TABLE.value,
                    embeddings_removed=removed_count,
                )

            except (ClientError, OSError, Exception) as exc:
                last_error = exc
                logger.warning(
                    "Delete attempt %d/%d failed for %s.%s: %s",
                    attempt,
                    MAX_RETRIES,
                    database,
                    table_name,
                    str(exc),
                )
                if attempt < MAX_RETRIES:
                    backoff = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
                    time.sleep(backoff)

        # All retries exhausted — emit alert
        self._emit_failure_alert(database, table_name, str(last_error))
        raise ReindexError(database, table_name)

    def _fetch_table_metadata(self, database: str, table_name: str) -> GlueTableMetadata:
        """Fetch table metadata from the Glue Catalog.

        Args:
            database: Glue database name.
            table_name: Glue table name.

        Returns:
            GlueTableMetadata with table details.

        Raises:
            ClientError: If the Glue API call fails.
        """
        response = self._glue.get_table(DatabaseName=database, Name=table_name)
        table = response["Table"]

        columns = []
        for col in table.get("StorageDescriptor", {}).get("Columns", []):
            columns.append({
                "name": col.get("Name", ""),
                "data_type": col.get("Type", ""),
                "description": col.get("Comment", ""),
            })

        partition_keys = [
            pk.get("Name", "") for pk in table.get("PartitionKeys", [])
        ]

        return GlueTableMetadata(
            database=database,
            table_name=table_name,
            description=table.get("Description", "") or table.get("Parameters", {}).get("comment", ""),
            columns=columns,
            partition_keys=partition_keys,
            parameters=table.get("Parameters", {}),
            last_updated=table.get("UpdateTime", datetime.now(timezone.utc)).isoformat()
            if isinstance(table.get("UpdateTime"), datetime)
            else str(table.get("UpdateTime", datetime.now(timezone.utc).isoformat())),
        )

    def _fetch_lake_formation_tags(
        self, database: str, table_name: str
    ) -> dict[str, Any]:
        """Fetch Lake Formation tags for a table.

        Tags are stored in embeddings for authorization-filtered retrieval.
        Users can only retrieve schemas matching their Lake Formation grants.

        Args:
            database: Glue database name.
            table_name: Glue table name.

        Returns:
            Dictionary of Lake Formation tag keys to values.
        """
        try:
            response = self._lakeformation.get_resource_lf_tags(
                Resource={
                    "Table": {
                        "DatabaseName": database,
                        "Name": table_name,
                    }
                }
            )

            tags: dict[str, Any] = {}
            for tag_detail in response.get("LFTagOnDatabase", []):
                tags[tag_detail["TagKey"]] = tag_detail["TagValues"]
            for tag_detail in response.get("LFTagsOnTable", []):
                tags[tag_detail["TagKey"]] = tag_detail["TagValues"]
            for col_tags in response.get("LFTagsOnColumns", []):
                # Include column-level tags at the table level for filtering
                for tag_detail in col_tags.get("LFTags", []):
                    key = tag_detail["TagKey"]
                    values = tag_detail["TagValues"]
                    if key in tags:
                        # Merge values for existing keys
                        existing = tags[key] if isinstance(tags[key], list) else [tags[key]]
                        tags[key] = list(set(existing + values))
                    else:
                        tags[key] = values

            return tags

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("EntityNotFoundException", "AccessDeniedException"):
                logger.warning(
                    "Could not fetch LF tags for %s.%s: %s",
                    database,
                    table_name,
                    error_code,
                )
                return {}
            raise

    def _fetch_glossary_data(
        self, database: str, table_name: str
    ) -> tuple[list[str], list[str]]:
        """Fetch business glossary terms and synonyms for a table.

        Retrieves glossary metadata from Glue Catalog table parameters.
        Business terms and synonyms are stored as comma-separated values
        in table parameters (custom metadata).

        Args:
            database: Glue database name.
            table_name: Glue table name.

        Returns:
            Tuple of (glossary_terms, synonyms).
        """
        try:
            response = self._glue.get_table(DatabaseName=database, Name=table_name)
            parameters = response["Table"].get("Parameters", {})

            # Extract business glossary terms from table parameters
            glossary_raw = parameters.get("business_glossary_terms", "")
            glossary_terms = [
                term.strip() for term in glossary_raw.split(",") if term.strip()
            ]

            # Extract synonyms from table parameters
            synonyms_raw = parameters.get("synonyms", "")
            synonyms = [s.strip() for s in synonyms_raw.split(",") if s.strip()]

            return glossary_terms, synonyms

        except ClientError as e:
            logger.warning(
                "Could not fetch glossary data for %s.%s: %s",
                database,
                table_name,
                str(e),
            )
            return [], []

    def _generate_schema_embeddings(
        self,
        metadata: GlueTableMetadata,
        lake_formation_tags: dict[str, Any],
        glossary_terms: list[str],
        synonyms: list[str],
    ) -> list[SchemaEmbedding]:
        """Generate schema embeddings using Bedrock Titan Embeddings.

        Creates a table-level embedding that combines the table description,
        column information, business glossary terms, and synonyms into a
        rich text representation for vector similarity search.

        Args:
            metadata: Table metadata from Glue Catalog.
            lake_formation_tags: Lake Formation tags for authorization filtering.
            glossary_terms: Business glossary terms associated with the table.
            synonyms: Synonym terms for the table.

        Returns:
            List of SchemaEmbedding objects ready for indexing.
        """
        embeddings: list[SchemaEmbedding] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Build rich text representation for the table-level embedding
        text_parts = [
            f"Table: {metadata.database}.{metadata.table_name}",
            f"Description: {metadata.description}" if metadata.description else "",
        ]

        # Include column information
        if metadata.columns:
            col_descriptions = []
            for col in metadata.columns:
                col_desc = f"{col['name']} ({col['data_type']})"
                if col.get("description"):
                    col_desc += f": {col['description']}"
                col_descriptions.append(col_desc)
            text_parts.append(f"Columns: {', '.join(col_descriptions)}")

        # Include partition keys
        if metadata.partition_keys:
            text_parts.append(f"Partition keys: {', '.join(metadata.partition_keys)}")

        # Include business glossary terms
        if glossary_terms:
            text_parts.append(f"Business terms: {', '.join(glossary_terms)}")

        # Include synonyms
        if synonyms:
            text_parts.append(f"Also known as: {', '.join(synonyms)}")

        embedding_text = "\n".join(part for part in text_parts if part)

        # Generate embedding vector using Bedrock Titan
        embedding_vector = self._generate_embedding(embedding_text)

        if embedding_vector:
            table_embedding = SchemaEmbedding(
                embedding_id=f"{metadata.database}/{metadata.table_name}/{uuid.uuid4().hex[:8]}",
                database=metadata.database,
                table_name=metadata.table_name,
                description=metadata.description,
                business_glossary_terms=glossary_terms,
                synonyms=synonyms,
                embedding_vector=embedding_vector,
                last_indexed=now_iso,
                lake_formation_tags=lake_formation_tags,
                columns=[
                    {
                        "name": col["name"],
                        "data_type": col["data_type"],
                        "description": col.get("description", ""),
                    }
                    for col in metadata.columns
                ],
                partition_keys=metadata.partition_keys,
            )
            embeddings.append(table_embedding)

        return embeddings

    def _generate_embedding(self, text: str) -> list[float] | None:
        """Generate an embedding vector using Bedrock Titan Embeddings.

        Args:
            text: Input text to embed.

        Returns:
            Embedding vector (list of floats) or None on failure.
        """
        try:
            response = self._bedrock.invoke_model(
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

    def _remove_table_embeddings(self, database: str, table_name: str) -> int:
        """Remove all embeddings for a specific table from OpenSearch.

        Uses a delete-by-query to remove all documents matching
        the database and table_name combination.

        Args:
            database: Glue database name.
            table_name: Glue table name.

        Returns:
            Number of embeddings removed.
        """
        if self._opensearch is None:
            logger.warning("OpenSearch client not available; skipping deletion")
            return 0

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"database": database}},
                        {"term": {"table_name": table_name}},
                    ]
                }
            }
        }

        response = self._opensearch.delete_by_query(
            index=self._schema_index, body=query
        )

        deleted = response.get("deleted", 0)
        logger.info(
            "Removed %d embeddings for %s.%s",
            deleted,
            database,
            table_name,
        )
        return deleted

    def _index_embeddings(self, embeddings: list[SchemaEmbedding]) -> int:
        """Index schema embeddings to OpenSearch Serverless.

        Uses bulk indexing for efficiency when multiple embeddings
        need to be indexed for a single table.

        Args:
            embeddings: List of SchemaEmbedding objects to index.

        Returns:
            Number of embeddings successfully indexed.
        """
        if self._opensearch is None:
            logger.warning("OpenSearch client not available; skipping indexing")
            return 0

        if not embeddings:
            return 0

        indexed_count = 0
        for embedding in embeddings:
            doc = embedding.to_document()
            try:
                self._opensearch.index(
                    index=self._schema_index,
                    id=embedding.embedding_id,
                    body=doc,
                )
                indexed_count += 1
            except Exception as e:
                logger.error(
                    "Failed to index embedding %s: %s",
                    embedding.embedding_id,
                    str(e),
                )
                raise

        logger.info(
            "Indexed %d embeddings for %s.%s",
            indexed_count,
            embeddings[0].database if embeddings else "unknown",
            embeddings[0].table_name if embeddings else "unknown",
        )
        return indexed_count

    def _emit_failure_alert(
        self, database: str, table_name: str, error_message: str
    ) -> None:
        """Emit CloudWatch alert on re-indexing failure.

        Triggered after all retry attempts are exhausted (Requirement 16.4).

        Args:
            database: Glue database name.
            table_name: Glue table name.
            error_message: Description of the failure.
        """
        try:
            self._cloudwatch.put_metric_data(
                Namespace=ALERT_NAMESPACE,
                MetricData=[
                    {
                        "MetricName": ALERT_METRIC_NAME,
                        "Value": 1.0,
                        "Unit": "Count",
                        "Dimensions": [
                            {"Name": "Database", "Value": database},
                            {"Name": "Table", "Value": table_name},
                        ],
                    }
                ],
            )
            logger.info(
                "Failure alert emitted for %s.%s: %s",
                database,
                table_name,
                error_message,
            )
        except (ClientError, OSError) as exc:
            logger.error(
                "Failed to emit CloudWatch alert for %s.%s: %s",
                database,
                table_name,
                str(exc),
            )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda handler for EventBridge-triggered schema re-indexing.

    Entry point when deployed as a Lambda function triggered by EventBridge
    rules on Glue Catalog changes.

    Args:
        event: EventBridge event payload.
        context: Lambda context object.

    Returns:
        Dictionary with statusCode and result details.
    """
    logger.info("Schema re-index Lambda triggered: %s", json.dumps(event, default=str))

    pipeline = SchemaReindexPipeline()
    result = pipeline.handle_event(event)

    response = {
        "statusCode": 200 if result.success else 500,
        "body": {
            "success": result.success,
            "database": result.database,
            "table_name": result.table_name,
            "event_type": result.event_type,
            "embeddings_indexed": result.embeddings_indexed,
            "embeddings_removed": result.embeddings_removed,
            "duration_seconds": round(result.duration_seconds, 2),
        },
    }

    if result.error:
        response["body"]["error"] = result.error

    logger.info("Schema re-index result: %s", json.dumps(response, default=str))
    return response
