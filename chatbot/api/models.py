"""Core Pydantic models for the FastAPI session/auth layer.

Defines request/response schemas and user claims with validation rules
for the chatbot security architecture.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Literal

from pydantic import BaseModel, field_validator


class DataClassificationTier(str, Enum):
    """Data classification tier hierarchy: public < internal < confidential < restricted."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @classmethod
    def hierarchy_level(cls, tier: str) -> int:
        """Return numeric level for tier comparison. Higher = more privileged."""
        levels = {
            cls.PUBLIC: 0,
            cls.INTERNAL: 1,
            cls.CONFIDENTIAL: 2,
            cls.RESTRICTED: 3,
        }
        return levels[cls(tier)]

    @classmethod
    def can_access(cls, user_tier: str, resource_tier: str) -> bool:
        """Check if a user tier can access a resource tier (user >= resource)."""
        return cls.hierarchy_level(user_tier) >= cls.hierarchy_level(resource_tier)


class UserClaims(BaseModel):
    """Claims extracted from a validated JWT token.

    All fields are required — authentication is denied if any claim is missing
    from the IdP assertion (Requirement 1.4, 1.5).
    """

    sub: str  # Cognito user ID
    department: str  # Mapped from SAML assertion
    role: str  # e.g., "analyst", "manager"
    data_classification_tier: str  # e.g., "confidential", "internal"
    groups: list[str]  # IdP group memberships
    session_id: str  # Unique session identifier (UUID v4)
    exp: int  # Token expiry (15-min max)

    @field_validator("session_id")
    @classmethod
    def validate_session_id_uuid_v4(cls, v: str) -> str:
        """Validate that session_id is a valid UUID v4."""
        try:
            parsed = uuid.UUID(v, version=4)
        except (ValueError, AttributeError):
            raise ValueError("session_id must be a valid UUID v4")
        # Ensure the string representation matches UUID v4 format
        if str(parsed) != v.lower():
            raise ValueError("session_id must be a valid UUID v4")
        return v

    @field_validator("data_classification_tier")
    @classmethod
    def validate_tier(cls, v: str) -> str:
        """Validate that data_classification_tier is a valid tier value."""
        valid_tiers = {"public", "internal", "confidential", "restricted"}
        if v.lower() not in valid_tiers:
            raise ValueError(
                f"data_classification_tier must be one of: {', '.join(sorted(valid_tiers))}"
            )
        return v.lower()

    @field_validator("sub", "department", "role")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        """Validate that required string claims are non-empty."""
        if not v or not v.strip():
            raise ValueError("Claim must be a non-empty string")
        return v

    @field_validator("groups")
    @classmethod
    def validate_groups_not_empty(cls, v: list[str]) -> list[str]:
        """Validate that groups list is provided (can be empty list but must exist)."""
        if v is None:
            raise ValueError("groups must be provided")
        return v

    @field_validator("exp")
    @classmethod
    def validate_exp_positive(cls, v: int) -> int:
        """Validate that exp is a positive integer timestamp."""
        if v <= 0:
            raise ValueError("exp must be a positive integer (Unix timestamp)")
        return v


class ChatRequest(BaseModel):
    """Incoming chat request from the user."""

    message: str
    session_id: str
    conversation_id: str | None = None

    @field_validator("session_id")
    @classmethod
    def validate_session_id_uuid_v4(cls, v: str) -> str:
        """Validate that session_id is a valid UUID v4."""
        try:
            parsed = uuid.UUID(v, version=4)
        except (ValueError, AttributeError):
            raise ValueError("session_id must be a valid UUID v4")
        if str(parsed) != v.lower():
            raise ValueError("session_id must be a valid UUID v4")
        return v

    @field_validator("message")
    @classmethod
    def validate_message_non_empty(cls, v: str) -> str:
        """Validate that message is non-empty."""
        if not v or not v.strip():
            raise ValueError("message must be a non-empty string")
        return v


class ChatResponse(BaseModel):
    """Response returned to the user after processing a chat request."""

    answer: str
    sql_generated: str | None = None
    data_freshness: str | None = None
    row_count: int | None = None
    cost_estimate_bytes: int | None = None
    warnings: list[str] = []


ErrorType = Literal[
    "auth_denied",
    "cost_exceeded",
    "sql_failed",
    "rate_limited",
    "out_of_scope",
    "service_unavailable",
    "internal_error",
]


class ErrorResponse(BaseModel):
    """Structured error response with trace_id for correlation (Requirement 17.5).

    error_type classifies the error for programmatic handling.
    message provides user-facing actionable guidance without exposing internal details.
    """

    error_type: str  # auth_denied, cost_exceeded, sql_failed, rate_limited, out_of_scope
    message: str  # User-facing actionable guidance
    trace_id: str  # UUID v4 for end-to-end request correlation
    retry_after: int | None = None  # For rate limiting (seconds until reset)

    @field_validator("trace_id")
    @classmethod
    def validate_trace_id_uuid_v4(cls, v: str) -> str:
        """Validate that trace_id is a valid UUID v4."""
        try:
            parsed = uuid.UUID(v, version=4)
        except (ValueError, AttributeError):
            raise ValueError("trace_id must be a valid UUID v4")
        if str(parsed) != v.lower():
            raise ValueError("trace_id must be a valid UUID v4")
        return v
