"""Pydantic models for MCP Server tool inputs and outputs.

Defines schema, cost estimation, and query result models used by
the MCP Server tools (list_tables, get_schema, estimate_cost, run_query).
"""

from __future__ import annotations

from pydantic import BaseModel, field_validator


class ColumnInfo(BaseModel):
    """Column metadata from the Glue Catalog.

    Includes PII classification and data classification tier
    for authorization-filtered schema retrieval.
    """

    name: str
    data_type: str
    description: str
    is_pii: bool
    classification: str  # public, internal, confidential, restricted

    @field_validator("classification")
    @classmethod
    def validate_classification(cls, v: str) -> str:
        """Validate that classification is a valid tier value."""
        valid_tiers = {"public", "internal", "confidential", "restricted"}
        if v.lower() not in valid_tiers:
            raise ValueError(
                f"classification must be one of: {', '.join(sorted(valid_tiers))}"
            )
        return v.lower()

    @field_validator("name")
    @classmethod
    def validate_name_non_empty(cls, v: str) -> str:
        """Validate that column name is non-empty."""
        if not v or not v.strip():
            raise ValueError("Column name must be a non-empty string")
        return v


class TableInfo(BaseModel):
    """Table metadata from the Glue Catalog.

    Used by list_tables and get_schema tools to provide
    schema information filtered by user authorization.
    """

    database: str
    table_name: str
    description: str
    columns: list[ColumnInfo]
    partition_keys: list[str]
    last_updated: str  # ISO 8601

    @field_validator("database", "table_name")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        """Validate that database and table_name are non-empty."""
        if not v or not v.strip():
            raise ValueError("Field must be a non-empty string")
        return v

    @field_validator("last_updated")
    @classmethod
    def validate_last_updated_format(cls, v: str) -> str:
        """Validate that last_updated is a non-empty ISO 8601 string."""
        if not v or not v.strip():
            raise ValueError("last_updated must be a non-empty ISO 8601 timestamp")
        return v


class CostEstimate(BaseModel):
    """Cost estimation result from Athena dry-run.

    Used to enforce the 10 GB scan threshold (Requirement 9.5)
    and provide cost guidance to users.
    """

    estimated_bytes_scanned: int
    estimated_cost_usd: float
    exceeds_threshold: bool  # True if > 10 GB without elevated_cost group
    suggestion: str | None = None  # Partition filter / column reduction suggestion

    @field_validator("estimated_bytes_scanned")
    @classmethod
    def validate_bytes_non_negative(cls, v: int) -> int:
        """Validate that estimated bytes scanned is non-negative."""
        if v < 0:
            raise ValueError("estimated_bytes_scanned must be non-negative")
        return v

    @field_validator("estimated_cost_usd")
    @classmethod
    def validate_cost_non_negative(cls, v: float) -> float:
        """Validate that estimated cost is non-negative."""
        if v < 0:
            raise ValueError("estimated_cost_usd must be non-negative")
        return v


class QueryResult(BaseModel):
    """Result from executing a validated SQL query via Athena.

    Includes execution metadata for audit trail and data freshness
    indicator for user-facing responses.
    """

    columns: list[str]
    rows: list[dict]
    row_count: int
    bytes_scanned: int
    execution_time_ms: int
    data_freshness: str  # From Glue Catalog partition timestamps

    @field_validator("row_count")
    @classmethod
    def validate_row_count_non_negative(cls, v: int) -> int:
        """Validate that row count is non-negative."""
        if v < 0:
            raise ValueError("row_count must be non-negative")
        return v

    @field_validator("bytes_scanned")
    @classmethod
    def validate_bytes_scanned_non_negative(cls, v: int) -> int:
        """Validate that bytes scanned is non-negative."""
        if v < 0:
            raise ValueError("bytes_scanned must be non-negative")
        return v

    @field_validator("execution_time_ms")
    @classmethod
    def validate_execution_time_non_negative(cls, v: int) -> int:
        """Validate that execution time is non-negative."""
        if v < 0:
            raise ValueError("execution_time_ms must be non-negative")
        return v

    @field_validator("data_freshness")
    @classmethod
    def validate_data_freshness_non_empty(cls, v: str) -> str:
        """Validate that data freshness is a non-empty string."""
        if not v or not v.strip():
            raise ValueError("data_freshness must be a non-empty string")
        return v
