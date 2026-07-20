"""Unit tests for the schema re-indexing pipeline.

Tests re-indexing on create/modify/delete events, retry logic,
alert emission on failure, and correct embedding generation.

Requirements: 16.1, 16.2, 16.4
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from scripts.reindex_vectors import (
    EventType,
    GlueTableMetadata,
    ReindexError,
    ReindexResult,
    SchemaEmbedding,
    SchemaReindexPipeline,
    lambda_handler,
)


@pytest.fixture
def mock_glue_client():
    """Create a mock Glue client with a default table response."""
    client = MagicMock()
    client.get_table.return_value = {
        "Table": {
            "Name": "transactions",
            "DatabaseName": "finance_db",
            "Description": "Customer transaction records",
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "bigint", "Comment": "Transaction ID"},
                    {"Name": "amount", "Type": "decimal(10,2)", "Comment": "Transaction amount"},
                    {"Name": "customer_id", "Type": "string", "Comment": "Customer identifier"},
                ]
            },
            "PartitionKeys": [{"Name": "partition_date", "Type": "string"}],
            "Parameters": {
                "business_glossary_terms": "transaction,payment,settlement",
                "synonyms": "txn,trade,deal",
                "comment": "Customer transaction records",
            },
            "UpdateTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        }
    }
    return client


@pytest.fixture
def mock_bedrock_client():
    """Create a mock Bedrock Runtime client for embedding generation."""
    client = MagicMock()
    # Return a mock embedding vector
    mock_body = MagicMock()
    mock_body.read.return_value = json.dumps(
        {"embedding": [0.1, 0.2, 0.3, 0.4, 0.5] * 64}
    ).encode()
    client.invoke_model.return_value = {"body": mock_body}
    return client


@pytest.fixture
def mock_opensearch_client():
    """Create a mock OpenSearch client."""
    client = MagicMock()
    client.index.return_value = {"result": "created"}
    client.delete_by_query.return_value = {"deleted": 2}
    return client


@pytest.fixture
def mock_cloudwatch_client():
    """Create a mock CloudWatch client."""
    client = MagicMock()
    client.put_metric_data.return_value = {}
    return client


@pytest.fixture
def mock_lakeformation_client():
    """Create a mock Lake Formation client."""
    client = MagicMock()
    client.get_resource_lf_tags.return_value = {
        "LFTagOnDatabase": [],
        "LFTagsOnTable": [
            {"TagKey": "department", "TagValues": ["finance"]},
            {"TagKey": "classification_tier", "TagValues": ["confidential"]},
        ],
        "LFTagsOnColumns": [],
    }
    return client


@pytest.fixture
def pipeline(
    mock_glue_client,
    mock_bedrock_client,
    mock_opensearch_client,
    mock_cloudwatch_client,
    mock_lakeformation_client,
):
    """Create a SchemaReindexPipeline with all mocked clients."""
    return SchemaReindexPipeline(
        glue_client=mock_glue_client,
        bedrock_client=mock_bedrock_client,
        opensearch_client=mock_opensearch_client,
        cloudwatch_client=mock_cloudwatch_client,
        lakeformation_client=mock_lakeformation_client,
    )


def _make_create_event(database: str = "finance_db", table_name: str = "transactions"):
    """Create a sample EventBridge CreateTable event."""
    return {
        "source": "aws.glue",
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventName": "CreateTable",
            "requestParameters": {
                "databaseName": database,
                "tableInput": {"name": table_name},
            },
        },
    }


def _make_update_event(database: str = "finance_db", table_name: str = "transactions"):
    """Create a sample EventBridge UpdateTable event."""
    return {
        "source": "aws.glue",
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventName": "UpdateTable",
            "requestParameters": {
                "databaseName": database,
                "tableName": table_name,
            },
        },
    }


def _make_delete_event(database: str = "finance_db", table_name: str = "transactions"):
    """Create a sample EventBridge DeleteTable event."""
    return {
        "source": "aws.glue",
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventName": "DeleteTable",
            "requestParameters": {
                "databaseName": database,
                "tableName": table_name,
            },
        },
    }


class TestSchemaReindexPipelineCreateUpdate:
    """Tests for table creation and modification re-indexing."""

    def test_create_table_indexes_embeddings(self, pipeline, mock_opensearch_client):
        """Re-indexing on table creation indexes embeddings to OpenSearch."""
        event = _make_create_event()
        result = pipeline.handle_event(event)

        assert result.success is True
        assert result.database == "finance_db"
        assert result.table_name == "transactions"
        assert result.event_type == "CreateTable"
        assert result.embeddings_indexed > 0
        mock_opensearch_client.index.assert_called()

    def test_update_table_reindexes_embeddings(self, pipeline, mock_opensearch_client):
        """Re-indexing on table update removes old and indexes new embeddings."""
        event = _make_update_event()
        result = pipeline.handle_event(event)

        assert result.success is True
        assert result.event_type == "UpdateTable"
        assert result.embeddings_indexed > 0
        # Old embeddings should be removed first
        mock_opensearch_client.delete_by_query.assert_called()
        mock_opensearch_client.index.assert_called()

    def test_embeddings_include_glossary_terms(self, pipeline, mock_opensearch_client):
        """Indexed embeddings include business glossary terms."""
        event = _make_create_event()
        pipeline.handle_event(event)

        # Check the indexed document includes glossary terms
        call_args = mock_opensearch_client.index.call_args
        doc = call_args.kwargs.get("body") or call_args[1].get("body")
        assert "transaction" in doc["business_glossary_terms"]
        assert "payment" in doc["business_glossary_terms"]
        assert "settlement" in doc["business_glossary_terms"]

    def test_embeddings_include_synonyms(self, pipeline, mock_opensearch_client):
        """Indexed embeddings include synonyms."""
        event = _make_create_event()
        pipeline.handle_event(event)

        call_args = mock_opensearch_client.index.call_args
        doc = call_args.kwargs.get("body") or call_args[1].get("body")
        assert "txn" in doc["synonyms"]
        assert "trade" in doc["synonyms"]

    def test_embeddings_include_lake_formation_tags(self, pipeline, mock_opensearch_client):
        """Indexed embeddings include Lake Formation tags for authorization filtering."""
        event = _make_create_event()
        pipeline.handle_event(event)

        call_args = mock_opensearch_client.index.call_args
        doc = call_args.kwargs.get("body") or call_args[1].get("body")
        assert doc["lake_formation_tags"]["department"] == ["finance"]
        assert doc["lake_formation_tags"]["classification_tier"] == ["confidential"]


class TestSchemaReindexPipelineDelete:
    """Tests for table deletion embedding removal."""

    def test_delete_table_removes_embeddings(self, pipeline, mock_opensearch_client):
        """Re-indexing on table deletion removes embeddings from OpenSearch."""
        event = _make_delete_event()
        result = pipeline.handle_event(event)

        assert result.success is True
        assert result.event_type == "DeleteTable"
        assert result.embeddings_removed == 2
        mock_opensearch_client.delete_by_query.assert_called_once()

    def test_delete_uses_correct_query(self, pipeline, mock_opensearch_client):
        """Deletion query targets the correct database and table."""
        event = _make_delete_event(database="hr_db", table_name="employees")
        pipeline.handle_event(event)

        call_args = mock_opensearch_client.delete_by_query.call_args
        body = call_args.kwargs.get("body") or call_args[1].get("body")
        must_clauses = body["query"]["bool"]["must"]
        assert {"term": {"database": "hr_db"}} in must_clauses
        assert {"term": {"table_name": "employees"}} in must_clauses


class TestRetryLogic:
    """Tests for retry with exponential backoff and alert on failure."""

    @patch("scripts.reindex_vectors.time.sleep")
    def test_retries_on_failure_up_to_3_attempts(
        self, mock_sleep, pipeline, mock_glue_client, mock_opensearch_client
    ):
        """Pipeline retries up to 3 times with exponential backoff on failure."""
        # Make opensearch indexing fail
        mock_opensearch_client.index.side_effect = Exception("Connection timeout")

        event = _make_create_event()
        result = pipeline.handle_event(event)

        assert result.success is False
        assert result.error is not None
        # Should have slept twice (between attempt 1-2 and 2-3)
        assert mock_sleep.call_count == 2
        # Exponential backoff: 2s, 4s
        mock_sleep.assert_any_call(2.0)
        mock_sleep.assert_any_call(4.0)

    @patch("scripts.reindex_vectors.time.sleep")
    def test_emits_alert_after_all_retries_exhausted(
        self, mock_sleep, pipeline, mock_opensearch_client, mock_cloudwatch_client
    ):
        """CloudWatch alert is emitted when all retries are exhausted."""
        mock_opensearch_client.index.side_effect = Exception("Service unavailable")

        event = _make_create_event()
        pipeline.handle_event(event)

        mock_cloudwatch_client.put_metric_data.assert_called_once()
        call_args = mock_cloudwatch_client.put_metric_data.call_args
        kwargs = call_args.kwargs if call_args.kwargs else call_args[1]
        assert kwargs["Namespace"] == "Chatbot/SchemaSync"
        metric_data = kwargs["MetricData"][0]
        assert metric_data["MetricName"] == "ReindexFailure"
        assert metric_data["Value"] == 1.0

    @patch("scripts.reindex_vectors.time.sleep")
    def test_succeeds_on_retry(
        self, mock_sleep, pipeline, mock_opensearch_client
    ):
        """Pipeline succeeds if a retry attempt succeeds."""
        # Fail first, succeed second
        mock_opensearch_client.index.side_effect = [
            Exception("Temporary error"),
            {"result": "created"},
        ]
        # delete_by_query also needs to succeed twice (once per attempt)
        mock_opensearch_client.delete_by_query.return_value = {"deleted": 0}

        event = _make_create_event()
        result = pipeline.handle_event(event)

        assert result.success is True
        assert result.embeddings_indexed == 1

    @patch("scripts.reindex_vectors.time.sleep")
    def test_delete_retries_on_failure(
        self, mock_sleep, pipeline, mock_opensearch_client, mock_cloudwatch_client
    ):
        """Delete operation also retries with exponential backoff."""
        mock_opensearch_client.delete_by_query.side_effect = Exception("Timeout")

        event = _make_delete_event()
        result = pipeline.handle_event(event)

        assert result.success is False
        assert mock_sleep.call_count == 2
        mock_cloudwatch_client.put_metric_data.assert_called_once()


class TestEventParsing:
    """Tests for EventBridge event parsing."""

    def test_parse_create_table_event(self, pipeline):
        """Correctly parses a CreateTable EventBridge event."""
        event = _make_create_event("my_db", "my_table")
        result = pipeline.handle_event(event)
        assert result.database == "my_db"
        assert result.table_name == "my_table"

    def test_parse_update_table_event(self, pipeline):
        """Correctly parses an UpdateTable EventBridge event."""
        event = _make_update_event("analytics", "page_views")
        result = pipeline.handle_event(event)
        assert result.database == "analytics"
        assert result.table_name == "page_views"

    def test_parse_delete_table_event(self, pipeline):
        """Correctly parses a DeleteTable EventBridge event."""
        event = _make_delete_event("staging", "temp_data")
        result = pipeline.handle_event(event)
        assert result.database == "staging"
        assert result.table_name == "temp_data"

    def test_unsupported_event_type_returns_error(self, pipeline):
        """Unsupported event types result in a failed result."""
        event = {
            "detail": {
                "eventName": "UnsupportedAction",
                "requestParameters": {
                    "databaseName": "db",
                    "tableName": "tbl",
                },
            }
        }
        result = pipeline.handle_event(event)
        assert result.success is False
        assert result.error is not None

    def test_missing_database_returns_error(self, pipeline):
        """Events missing database name result in a failed result."""
        event = {
            "detail": {
                "eventName": "CreateTable",
                "requestParameters": {
                    "tableInput": {"name": "orphan_table"},
                },
            }
        }
        result = pipeline.handle_event(event)
        assert result.success is False


class TestEmbeddingGeneration:
    """Tests for embedding vector generation."""

    def test_generates_embedding_with_titan(self, pipeline, mock_bedrock_client):
        """Embedding generation calls Bedrock Titan model."""
        event = _make_create_event()
        pipeline.handle_event(event)

        mock_bedrock_client.invoke_model.assert_called()
        call_args = mock_bedrock_client.invoke_model.call_args
        kwargs = call_args.kwargs if call_args.kwargs else call_args[1]
        assert kwargs["modelId"] == "amazon.titan-embed-text-v2:0"

    def test_embedding_text_includes_table_info(self, pipeline, mock_bedrock_client):
        """Embedding text includes table name, description, and columns."""
        event = _make_create_event()
        pipeline.handle_event(event)

        call_args = mock_bedrock_client.invoke_model.call_args
        kwargs = call_args.kwargs if call_args.kwargs else call_args[1]
        body = json.loads(kwargs["body"])
        input_text = body["inputText"]

        assert "finance_db.transactions" in input_text
        assert "amount" in input_text
        assert "partition_date" in input_text

    def test_embedding_failure_results_in_no_indexing(
        self, pipeline, mock_bedrock_client, mock_opensearch_client
    ):
        """If embedding generation fails, no documents are indexed."""
        mock_body = MagicMock()
        mock_body.read.return_value = json.dumps({"embedding": None}).encode()
        mock_bedrock_client.invoke_model.return_value = {"body": mock_body}

        event = _make_create_event()
        result = pipeline.handle_event(event)

        # Should succeed (no error) but with 0 embeddings indexed
        assert result.success is True
        assert result.embeddings_indexed == 0
        mock_opensearch_client.index.assert_not_called()


class TestLambdaHandler:
    """Tests for the Lambda handler entry point."""

    @patch("scripts.reindex_vectors.SchemaReindexPipeline")
    def test_lambda_handler_returns_200_on_success(self, mock_pipeline_cls):
        """Lambda handler returns 200 on successful re-indexing."""
        mock_instance = MagicMock()
        mock_instance.handle_event.return_value = ReindexResult(
            success=True,
            database="db",
            table_name="tbl",
            event_type="CreateTable",
            embeddings_indexed=1,
        )
        mock_pipeline_cls.return_value = mock_instance

        event = _make_create_event()
        response = lambda_handler(event, None)

        assert response["statusCode"] == 200
        assert response["body"]["success"] is True

    @patch("scripts.reindex_vectors.SchemaReindexPipeline")
    def test_lambda_handler_returns_500_on_failure(self, mock_pipeline_cls):
        """Lambda handler returns 500 on failed re-indexing."""
        mock_instance = MagicMock()
        mock_instance.handle_event.return_value = ReindexResult(
            success=False,
            database="db",
            table_name="tbl",
            event_type="CreateTable",
            error="Connection timeout",
        )
        mock_pipeline_cls.return_value = mock_instance

        event = _make_create_event()
        response = lambda_handler(event, None)

        assert response["statusCode"] == 500
        assert response["body"]["error"] == "Connection timeout"


class TestSchemaEmbeddingModel:
    """Tests for the SchemaEmbedding data model."""

    def test_to_document_includes_all_fields(self):
        """SchemaEmbedding.to_document() includes all required fields."""
        embedding = SchemaEmbedding(
            embedding_id="db/table/abc123",
            database="finance_db",
            table_name="transactions",
            description="Transaction records",
            business_glossary_terms=["payment", "settlement"],
            synonyms=["txn"],
            embedding_vector=[0.1, 0.2, 0.3],
            last_indexed="2024-01-15T10:30:00+00:00",
            lake_formation_tags={"department": ["finance"]},
            columns=[{"name": "id", "data_type": "bigint", "description": "ID"}],
            partition_keys=["partition_date"],
        )

        doc = embedding.to_document()

        assert doc["embedding_id"] == "db/table/abc123"
        assert doc["database"] == "finance_db"
        assert doc["table_name"] == "transactions"
        assert doc["description"] == "Transaction records"
        assert doc["business_glossary_terms"] == ["payment", "settlement"]
        assert doc["synonyms"] == ["txn"]
        assert doc["embedding_vector"] == [0.1, 0.2, 0.3]
        assert doc["lake_formation_tags"] == {"department": ["finance"]}
        assert doc["columns"] == [{"name": "id", "data_type": "bigint", "description": "ID"}]
        assert doc["partition_keys"] == ["partition_date"]

    def test_to_document_includes_column_name_when_set(self):
        """Column-level embeddings include column_name in document."""
        embedding = SchemaEmbedding(
            embedding_id="db/table/col/abc",
            database="db",
            table_name="tbl",
            column_name="amount",
            data_type="decimal(10,2)",
        )

        doc = embedding.to_document()
        assert doc["column_name"] == "amount"
        assert doc["data_type"] == "decimal(10,2)"
