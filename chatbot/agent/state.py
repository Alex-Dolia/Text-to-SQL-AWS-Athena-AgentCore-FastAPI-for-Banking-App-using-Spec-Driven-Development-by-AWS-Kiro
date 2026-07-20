"""Agent state dataclass for LangGraph orchestration.

Defines the state that flows through the agent graph nodes,
including structural bounds for disambiguation and self-correction loops.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from chatbot.api.models import UserClaims


@dataclass
class AgentState:
    """State object passed through the LangGraph agent graph.

    Structural bounds:
    - disambiguation_rounds: max 3 (enforced by graph edge conditions)
    - self_correction_attempts: max 2 (enforced by graph edge conditions)

    These bounds prevent runaway loops and ensure all execution paths
    are visible to security review (Requirement 10.2, 10.3).
    """

    # Required fields — set at request start
    user_claims: UserClaims
    user_message: str

    # Intent classification
    intent: str | None = None

    # Glossary resolution
    resolved_terms: dict[str, str] | None = None

    # Schema retrieval (filtered by user authorization)
    retrieved_schemas: list[dict] | None = None

    # Disambiguation loop — max 3 rounds (Requirement 10.2)
    disambiguation_rounds: int = 0

    # SQL generation and validation
    generated_sql: str | None = None
    sql_valid: bool = False

    # Self-correction loop — max 2 attempts (Requirement 10.3)
    self_correction_attempts: int = 0

    # Query execution results
    query_results: dict | None = None

    # Guardrails findings from input/output scanning
    guardrails_findings: list[str] = field(default_factory=list)

    # Final output
    final_response: str | None = None

    # Error state
    error: str | None = None

    # --- Structural bound constants ---
    MAX_DISAMBIGUATION_ROUNDS: int = field(default=3, init=False, repr=False)
    MAX_SELF_CORRECTION_ATTEMPTS: int = field(default=2, init=False, repr=False)

    def can_disambiguate(self) -> bool:
        """Check if another disambiguation round is allowed."""
        return self.disambiguation_rounds < self.MAX_DISAMBIGUATION_ROUNDS

    def can_self_correct(self) -> bool:
        """Check if another self-correction attempt is allowed."""
        return self.self_correction_attempts < self.MAX_SELF_CORRECTION_ATTEMPTS

    def increment_disambiguation(self) -> None:
        """Record a disambiguation round. Raises if bounds exceeded."""
        if not self.can_disambiguate():
            raise ValueError(
                f"Disambiguation rounds exceeded maximum of {self.MAX_DISAMBIGUATION_ROUNDS}"
            )
        self.disambiguation_rounds += 1

    def increment_self_correction(self) -> None:
        """Record a self-correction attempt. Raises if bounds exceeded."""
        if not self.can_self_correct():
            raise ValueError(
                f"Self-correction attempts exceeded maximum of {self.MAX_SELF_CORRECTION_ATTEMPTS}"
            )
        self.self_correction_attempts += 1
