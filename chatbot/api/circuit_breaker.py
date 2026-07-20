"""Circuit breaker for AgentCore Runtime availability.

Protects the API from cascading failures when the AgentCore Runtime is
unavailable. Opens after >50% failures in a 30-second window (min 5 requests),
returns HTTP 503 within 200ms when open, transitions to half-open after 60s,
and closes on successful probe or re-opens on failed probe.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("chatbot.security")


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


class CircuitBreakerOpenError(Exception):
    """Raised when the circuit breaker is open and requests are rejected.

    Attributes:
        retry_after: Seconds until the circuit breaker transitions to half-open.
        message: User-facing message indicating service unavailability.
    """

    def __init__(self, retry_after: int, message: str) -> None:
        self.retry_after = retry_after
        self.message = message
        super().__init__(message)


@dataclass
class _RequestRecord:
    """Record of a request outcome within the rolling window."""

    timestamp: float
    success: bool


@dataclass
class CircuitBreakerConfig:
    """Configuration for the circuit breaker.

    Attributes:
        failure_threshold_pct: Percentage of failures to trigger open (default 50).
        window_seconds: Rolling window for failure calculation (default 30).
        min_requests: Minimum requests in window before evaluating (default 5).
        recovery_timeout_seconds: Time in open state before half-open (default 60).
        alert_callback: Optional async callable on closed→open transition.
    """

    failure_threshold_pct: float = 50.0
    window_seconds: float = 30.0
    min_requests: int = 5
    recovery_timeout_seconds: float = 60.0
    alert_callback: Any = None


class CircuitBreaker:
    """Circuit breaker protecting AgentCore Runtime calls.

    States:
    - CLOSED: Normal operation, requests pass through.
    - OPEN: Requests fail immediately with 503 (within 200ms).
    - HALF_OPEN: One probe request allowed; success closes, failure re-opens.

    Transition rules:
    - CLOSED → OPEN: >50% failures in 30s window with min 5 requests.
    - OPEN → HALF_OPEN: After 60s recovery timeout.
    - HALF_OPEN → CLOSED: Probe request succeeds.
    - HALF_OPEN → OPEN: Probe request fails.
    """

    def __init__(self, config: CircuitBreakerConfig | None = None) -> None:
        self._config = config or CircuitBreakerConfig()
        self._state: CircuitState = CircuitState.CLOSED
        self._records: list[_RequestRecord] = []
        self._opened_at: float = 0.0
        self._half_open_probe_in_flight: bool = False

    @property
    def state(self) -> CircuitState:
        """Current circuit breaker state."""
        # Check if we should transition from OPEN to HALF_OPEN
        if self._state == CircuitState.OPEN:
            elapsed = time.time() - self._opened_at
            if elapsed >= self._config.recovery_timeout_seconds:
                self._state = CircuitState.HALF_OPEN
                self._half_open_probe_in_flight = False
        return self._state

    @property
    def failure_rate(self) -> float:
        """Current failure rate percentage within the rolling window."""
        records = self._get_window_records()
        if not records:
            return 0.0
        failures = sum(1 for r in records if not r.success)
        return (failures / len(records)) * 100.0

    def _get_window_records(self, now: float | None = None) -> list[_RequestRecord]:
        """Get records within the rolling window."""
        current = now or time.time()
        window_start = current - self._config.window_seconds
        return [r for r in self._records if r.timestamp >= window_start]

    def _prune_old_records(self, now: float | None = None) -> None:
        """Remove records outside the rolling window."""
        current = now or time.time()
        window_start = current - self._config.window_seconds
        self._records = [r for r in self._records if r.timestamp >= window_start]

    async def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute a function through the circuit breaker.

        If the circuit is OPEN, raises CircuitBreakerOpenError immediately.
        If HALF_OPEN, allows exactly one probe request.
        If CLOSED, executes normally and records the outcome.

        Args:
            func: Async callable to execute.
            *args: Positional arguments for func.
            **kwargs: Keyword arguments for func.

        Returns:
            The result of func(*args, **kwargs).

        Raises:
            CircuitBreakerOpenError: When circuit is OPEN.
        """
        current_state = self.state  # This may transition OPEN → HALF_OPEN

        if current_state == CircuitState.OPEN:
            retry_after = self._calculate_retry_after()
            raise CircuitBreakerOpenError(
                retry_after=retry_after,
                message="Service temporarily unavailable. The AgentCore Runtime is not responding. Please try again later.",
            )

        if current_state == CircuitState.HALF_OPEN:
            if self._half_open_probe_in_flight:
                # Only one probe allowed in half-open
                raise CircuitBreakerOpenError(
                    retry_after=1,
                    message="Service temporarily unavailable. A recovery probe is in progress.",
                )
            self._half_open_probe_in_flight = True

        # Execute the function
        try:
            result = await func(*args, **kwargs)
            await self._record_success()
            return result
        except Exception as e:
            await self._record_failure()
            raise

    async def _record_success(self) -> None:
        """Record a successful request and potentially close the circuit."""
        now = time.time()
        self._records.append(_RequestRecord(timestamp=now, success=True))
        self._prune_old_records(now)

        if self._state == CircuitState.HALF_OPEN:
            # Probe succeeded — close the circuit
            self._state = CircuitState.CLOSED
            self._half_open_probe_in_flight = False
            self._records.clear()
            logger.info("Circuit breaker HALF_OPEN → CLOSED: probe succeeded")

    async def _record_failure(self) -> None:
        """Record a failed request and potentially open the circuit."""
        now = time.time()
        self._records.append(_RequestRecord(timestamp=now, success=False))
        self._prune_old_records(now)

        if self._state == CircuitState.HALF_OPEN:
            # Probe failed — re-open the circuit
            self._transition_to_open(now)
            self._half_open_probe_in_flight = False
            logger.info("Circuit breaker HALF_OPEN → OPEN: probe failed")
            return

        if self._state == CircuitState.CLOSED:
            # Check if we should open
            window_records = self._get_window_records(now)
            if len(window_records) >= self._config.min_requests:
                failures = sum(1 for r in window_records if not r.success)
                failure_rate = (failures / len(window_records)) * 100.0
                if failure_rate > self._config.failure_threshold_pct:
                    await self._transition_to_open_with_alert(now, failure_rate)

    def _transition_to_open(self, now: float) -> None:
        """Transition circuit to OPEN state."""
        self._state = CircuitState.OPEN
        self._opened_at = now

    async def _transition_to_open_with_alert(self, now: float, failure_rate: float) -> None:
        """Transition circuit to OPEN with P2 alert (Requirement 4.5)."""
        self._state = CircuitState.OPEN
        self._opened_at = now

        logger.warning(
            "Circuit breaker CLOSED → OPEN: failure_rate=%.1f%%, timestamp=%s",
            failure_rate,
            now,
        )

        # Emit P2 alert
        security_logger.warning(
            "CIRCUIT_BREAKER_OPEN",
            extra={
                "event_type": "operational_alert",
                "severity": "P2",
                "alert_type": "circuit_breaker_state_change",
                "transition": "closed_to_open",
                "failure_rate_pct": failure_rate,
                "timestamp": now,
            },
        )

        # Call alert callback if configured
        if self._config.alert_callback:
            try:
                await self._config.alert_callback(failure_rate, now)
            except Exception:
                logger.exception("Failed to execute circuit breaker alert callback")

    def _calculate_retry_after(self) -> int:
        """Calculate seconds until half-open transition."""
        elapsed = time.time() - self._opened_at
        remaining = self._config.recovery_timeout_seconds - elapsed
        return max(1, int(remaining) + 1)

    def reset(self) -> None:
        """Reset the circuit breaker to initial state (for testing)."""
        self._state = CircuitState.CLOSED
        self._records.clear()
        self._opened_at = 0.0
        self._half_open_probe_in_flight = False


# Module-level singleton
_circuit_breaker: CircuitBreaker | None = None


def get_circuit_breaker(config: CircuitBreakerConfig | None = None) -> CircuitBreaker:
    """Get or create the module-level CircuitBreaker singleton."""
    global _circuit_breaker
    if _circuit_breaker is None:
        _circuit_breaker = CircuitBreaker(config)
    return _circuit_breaker


def reset_circuit_breaker() -> None:
    """Reset the module-level singleton (for testing)."""
    global _circuit_breaker
    _circuit_breaker = None
