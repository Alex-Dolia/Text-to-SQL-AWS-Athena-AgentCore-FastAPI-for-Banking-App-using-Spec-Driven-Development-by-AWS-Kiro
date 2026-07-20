"""Session management, trace ID generation, auth failure tracking, and circuit breaker middleware.

Implements:
- 45-minute idle session timeout with server-side last-activity tracking
- UUID v4 trace_id in X-Trace-Id response header for every request
- Per-IP auth failure tracking with security alert on >5 failures/60s
- HTTP 401 on expired session directing user to re-authenticate
- Circuit breaker for AgentCore Runtime availability (503 on open)
- Session termination enforcement: blocks requests from terminated sessions (Req 8.5)

Requirements: 2.2, 2.3, 2.4, 2.5, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 8.5
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Structured security logger for SIEM-bound alerts
security_logger = logging.getLogger("chatbot.security")


# ---------------------------------------------------------------------------
# Session Store
# ---------------------------------------------------------------------------

SESSION_IDLE_TIMEOUT_SECONDS: int = 45 * 60  # 45 minutes


@dataclass
class SessionEntry:
    """Server-side session state for idle timeout enforcement."""

    user_id: str
    last_activity: float  # Unix timestamp of last authenticated request
    created_at: float  # Unix timestamp of session creation

    def is_expired(self, now: float | None = None) -> bool:
        """Check if session has exceeded the 45-minute idle timeout."""
        current = now if now is not None else time.time()
        return (current - self.last_activity) > SESSION_IDLE_TIMEOUT_SECONDS

    def touch(self, now: float | None = None) -> None:
        """Update last_activity to current time."""
        self.last_activity = now if now is not None else time.time()


class SessionStore:
    """In-memory session store keyed by session_id.

    Tracks last activity timestamp for idle timeout enforcement.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionEntry] = {}

    def get(self, session_id: str) -> SessionEntry | None:
        """Retrieve a session entry by session_id."""
        return self._sessions.get(session_id)

    def create(self, session_id: str, user_id: str, now: float | None = None) -> SessionEntry:
        """Create a new session entry."""
        current = now if now is not None else time.time()
        entry = SessionEntry(user_id=user_id, last_activity=current, created_at=current)
        self._sessions[session_id] = entry
        return entry

    def invalidate(self, session_id: str) -> None:
        """Remove a session from the store (invalidation)."""
        self._sessions.pop(session_id, None)

    def touch(self, session_id: str, now: float | None = None) -> None:
        """Update last_activity for an existing session."""
        entry = self._sessions.get(session_id)
        if entry:
            entry.touch(now)

    def cleanup_expired(self, now: float | None = None) -> int:
        """Remove all expired sessions. Returns count of removed sessions."""
        current = now if now is not None else time.time()
        expired_ids = [
            sid for sid, entry in self._sessions.items() if entry.is_expired(current)
        ]
        for sid in expired_ids:
            del self._sessions[sid]
        return len(expired_ids)

    @property
    def active_count(self) -> int:
        """Number of sessions currently in the store."""
        return len(self._sessions)


# Module-level session store singleton
_session_store: SessionStore | None = None


def get_session_store() -> SessionStore:
    """Get or create the module-level SessionStore singleton."""
    global _session_store
    if _session_store is None:
        _session_store = SessionStore()
    return _session_store


def reset_session_store() -> None:
    """Reset the session store singleton (for testing)."""
    global _session_store
    _session_store = None


# ---------------------------------------------------------------------------
# Auth Failure Tracker
# ---------------------------------------------------------------------------

AUTH_FAILURE_THRESHOLD: int = 5
AUTH_FAILURE_WINDOW_SECONDS: int = 60


@dataclass
class AuthFailureTracker:
    """Tracks authentication failures per IP with a sliding 60-second window.

    Logs a security alert when failures from a single IP exceed 5 within
    60 seconds (Requirement 2.5).
    """

    _failures: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    def record_failure(self, ip_address: str, now: float | None = None) -> bool:
        """Record an auth failure for the given IP.

        Returns True if the threshold was exceeded (alert should fire).
        """
        current = now if now is not None else time.time()
        window_start = current - AUTH_FAILURE_WINDOW_SECONDS

        # Prune old entries outside the sliding window
        self._failures[ip_address] = [
            ts for ts in self._failures[ip_address] if ts > window_start
        ]

        # Record new failure
        self._failures[ip_address].append(current)

        # Check threshold
        failure_count = len(self._failures[ip_address])
        if failure_count > AUTH_FAILURE_THRESHOLD:
            self._emit_security_alert(ip_address, failure_count, current)
            return True
        return False

    def get_failure_count(self, ip_address: str, now: float | None = None) -> int:
        """Get current failure count for an IP within the sliding window."""
        current = now if now is not None else time.time()
        window_start = current - AUTH_FAILURE_WINDOW_SECONDS
        return len([ts for ts in self._failures.get(ip_address, []) if ts > window_start])

    def _emit_security_alert(self, ip_address: str, count: int, timestamp: float) -> None:
        """Emit a structured security alert for SIEM ingestion."""
        security_logger.warning(
            "AUTH_FAILURE_THRESHOLD_EXCEEDED",
            extra={
                "event_type": "security_alert",
                "alert_type": "auth_failure_spike",
                "ip_address": ip_address,
                "failure_count": count,
                "window_seconds": AUTH_FAILURE_WINDOW_SECONDS,
                "threshold": AUTH_FAILURE_THRESHOLD,
                "timestamp": timestamp,
            },
        )

    def cleanup(self, now: float | None = None) -> None:
        """Remove stale entries older than the sliding window."""
        current = now if now is not None else time.time()
        window_start = current - AUTH_FAILURE_WINDOW_SECONDS
        empty_ips = []
        for ip, timestamps in self._failures.items():
            self._failures[ip] = [ts for ts in timestamps if ts > window_start]
            if not self._failures[ip]:
                empty_ips.append(ip)
        for ip in empty_ips:
            del self._failures[ip]


# Module-level auth failure tracker singleton
_auth_failure_tracker: AuthFailureTracker | None = None


def get_auth_failure_tracker() -> AuthFailureTracker:
    """Get or create the module-level AuthFailureTracker singleton."""
    global _auth_failure_tracker
    if _auth_failure_tracker is None:
        _auth_failure_tracker = AuthFailureTracker()
    return _auth_failure_tracker


def reset_auth_failure_tracker() -> None:
    """Reset the auth failure tracker singleton (for testing)."""
    global _auth_failure_tracker
    _auth_failure_tracker = None


# ---------------------------------------------------------------------------
# Trace ID Generation
# ---------------------------------------------------------------------------


def generate_trace_id() -> str:
    """Generate a UUID v4 trace_id for request correlation (Requirement 2.3)."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Middleware Classes
# ---------------------------------------------------------------------------


class TraceIdMiddleware(BaseHTTPMiddleware):
    """Adds a unique X-Trace-Id (UUID v4) header to every response.

    Requirement 2.3: Include unique trace_id in response header for every request.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        trace_id = generate_trace_id()
        # Store trace_id in request state for downstream use
        request.state.trace_id = trace_id

        response = await call_next(request)
        response.headers["X-Trace-Id"] = trace_id
        return response


class SessionTimeoutMiddleware(BaseHTTPMiddleware):
    """Enforces 45-minute idle session timeout.

    Requirement 2.2: Invalidate session after 45 minutes of inactivity.
    Requirement 2.4: Return HTTP 401 on auth failure with re-authentication message.
    Requirement 2.5: Log security alert when auth failures exceed 5/min from same IP.
    """

    def __init__(self, app: Any, session_store: SessionStore | None = None) -> None:
        super().__init__(app)
        self._session_store = session_store or get_session_store()
        self._auth_failure_tracker = get_auth_failure_tracker()

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip session checks for health/non-authenticated endpoints
        if self._is_exempt_path(request.url.path):
            return await call_next(request)

        # Extract session_id from request (header or validated JWT claims)
        session_id = self._extract_session_id(request)

        if session_id:
            # Check if session was terminated due to excessive BLOCK actions (Req 8.5)
            if self._is_session_terminated(session_id):
                self._record_auth_failure(request)
                return self._terminated_session_response(request)

            session = self._session_store.get(session_id)

            if session is not None:
                # Check if session has exceeded idle timeout
                if session.is_expired():
                    self._session_store.invalidate(session_id)
                    self._record_auth_failure(request)
                    return self._expired_session_response(request)

                # Session is active — update last_activity
                session.touch()
            # If no session found in store, it may be a new session;
            # let the auth layer handle creation after JWT validation

        response = await call_next(request)
        return response

    def _is_exempt_path(self, path: str) -> bool:
        """Paths exempt from session timeout checks."""
        exempt_paths = {"/health", "/healthz", "/ready", "/docs", "/openapi.json"}
        return path in exempt_paths

    def _extract_session_id(self, request: Request) -> str | None:
        """Extract session_id from request headers or state.

        Looks for X-Session-Id header or session_id set by auth layer.
        """
        # Check if auth layer has already set session_id in state
        if hasattr(request.state, "session_id"):
            return request.state.session_id

        # Fall back to header
        return request.headers.get("X-Session-Id")

    def _record_auth_failure(self, request: Request) -> None:
        """Record auth failure for the request's source IP."""
        client_ip = self._get_client_ip(request)
        self._auth_failure_tracker.record_failure(client_ip)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, considering X-Forwarded-For."""
        # Check X-Forwarded-For for requests behind ALB
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # First IP in the chain is the original client
            return forwarded_for.split(",")[0].strip()
        # Fall back to direct client
        if request.client:
            return request.client.host
        return "unknown"

    def _expired_session_response(self, request: Request) -> JSONResponse:
        """Return HTTP 401 response for expired sessions."""
        trace_id = getattr(request.state, "trace_id", generate_trace_id())
        return JSONResponse(
            status_code=401,
            content={
                "error_type": "auth_denied",
                "message": (
                    "Your session has expired due to inactivity. "
                    "Please re-authenticate to continue."
                ),
                "trace_id": trace_id,
            },
            headers={"X-Trace-Id": trace_id},
        )

    def _is_session_terminated(self, session_id: str) -> bool:
        """Check if session was terminated due to excessive guardrails BLOCK actions.

        Integrates with the content safety SessionBlockTracker to enforce
        re-authentication after session termination (Requirement 8.5).
        """
        try:
            from chatbot.agent.nodes.content_safety import get_block_tracker
            tracker = get_block_tracker()
            return tracker.is_terminated(session_id)
        except ImportError:
            # If content_safety module is not available, allow request
            return False

    def _terminated_session_response(self, request: Request) -> JSONResponse:
        """Return HTTP 401 response for terminated sessions requiring re-auth.

        Requirement 8.5: Require re-authentication after terminated session.
        """
        trace_id = getattr(request.state, "trace_id", generate_trace_id())
        return JSONResponse(
            status_code=401,
            content={
                "error_type": "auth_denied",
                "message": (
                    "Your session has been terminated due to repeated policy violations. "
                    "Please re-authenticate to continue."
                ),
                "trace_id": trace_id,
            },
            headers={"X-Trace-Id": trace_id},
        )


def record_auth_failure_for_ip(request: Request) -> bool:
    """Public helper to record an auth failure for the requesting IP.

    Called by auth layer when JWT validation fails (Requirement 2.5).
    Returns True if threshold was exceeded (alert fired).
    """
    tracker = get_auth_failure_tracker()
    # Extract client IP
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    elif request.client:
        client_ip = request.client.host
    else:
        client_ip = "unknown"

    return tracker.record_failure(client_ip)


# ---------------------------------------------------------------------------
# Circuit Breaker for AgentCore Runtime
# ---------------------------------------------------------------------------

# Circuit breaker configuration constants
CIRCUIT_BREAKER_WINDOW_SECONDS: int = 30  # Rolling window for failure rate
CIRCUIT_BREAKER_FAILURE_THRESHOLD: float = 0.50  # 50% failure rate
CIRCUIT_BREAKER_MIN_REQUESTS: int = 5  # Minimum requests before opening
CIRCUIT_BREAKER_RECOVERY_TIMEOUT: float = 60.0  # Seconds before half-open
CIRCUIT_BREAKER_REQUEST_TIMEOUT: float = 5.0  # Max seconds for runtime call


class CircuitState(Enum):
    """States for the circuit breaker state machine."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class RequestOutcome:
    """Records a single request outcome within the rolling window."""

    timestamp: float
    success: bool


class CircuitBreaker:
    """Circuit breaker for AgentCore Runtime availability.

    Implements a three-state circuit breaker (closed, open, half-open) with:
    - Rolling 30-second window for failure rate calculation
    - 50% failure threshold with minimum 5 requests before opening
    - 60-second recovery timeout before transitioning to half-open
    - Exactly 1 probe request in half-open state
    - P2 operational alert on closed→open transition

    Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
    """

    def __init__(self, now: float | None = None) -> None:
        self._state: CircuitState = CircuitState.CLOSED
        self._outcomes: list[RequestOutcome] = []
        self._opened_at: float = 0.0  # Timestamp when circuit opened
        self._half_open_probe_in_flight: bool = False
        self._now_override: float | None = now  # For testing

    @property
    def state(self) -> CircuitState:
        """Current circuit breaker state, accounting for recovery timeout."""
        if self._state == CircuitState.OPEN:
            now = self._current_time()
            elapsed = now - self._opened_at
            if elapsed >= CIRCUIT_BREAKER_RECOVERY_TIMEOUT:
                return CircuitState.HALF_OPEN
        return self._state

    @property
    def raw_state(self) -> CircuitState:
        """Internal state without time-based transitions (for testing)."""
        return self._state

    def _current_time(self) -> float:
        """Get current time, using override if set (for testing)."""
        if self._now_override is not None:
            return self._now_override
        return time.time()

    def set_time(self, now: float) -> None:
        """Override the current time (for testing)."""
        self._now_override = now

    def clear_time_override(self) -> None:
        """Clear time override (for testing)."""
        self._now_override = None

    def should_allow_request(self) -> bool:
        """Determine if a request should be allowed through the circuit breaker.

        Returns True if the request should proceed, False if it should be
        rejected with HTTP 503.

        Requirement 4.6: When open, return 503 without forwarding.
        Requirement 4.2: After 60s in open, allow exactly 1 probe.
        """
        current_state = self.state  # This accounts for recovery timeout

        if current_state == CircuitState.CLOSED:
            return True

        if current_state == CircuitState.HALF_OPEN:
            # Allow exactly 1 probe request (Requirement 4.2)
            if not self._half_open_probe_in_flight:
                self._half_open_probe_in_flight = True
                return True
            # Additional requests while probe is in flight are rejected
            return False

        # OPEN state — reject immediately (Requirement 4.6)
        return False

    def record_success(self, now: float | None = None) -> None:
        """Record a successful request to the AgentCore Runtime.

        If in half-open state, transitions to closed (Requirement 4.3).
        """
        current = now if now is not None else self._current_time()
        self._outcomes.append(RequestOutcome(timestamp=current, success=True))
        self._prune_window(current)

        if self.state == CircuitState.HALF_OPEN:
            # Probe succeeded → close circuit (Requirement 4.3)
            self._state = CircuitState.CLOSED
            self._half_open_probe_in_flight = False
            logger.info("Circuit breaker closed: probe request succeeded")

    def record_failure(self, now: float | None = None) -> None:
        """Record a failed request to the AgentCore Runtime.

        Failures include: connection refused, timeout >5s, HTTP 5xx.
        If in half-open state, transitions back to open (Requirement 4.4).
        If in closed state, may transition to open based on failure rate (Requirement 4.1).
        """
        current = now if now is not None else self._current_time()
        self._outcomes.append(RequestOutcome(timestamp=current, success=False))
        self._prune_window(current)

        current_state = self.state

        if current_state == CircuitState.HALF_OPEN:
            # Probe failed → re-open circuit (Requirement 4.4)
            self._transition_to_open(current)
            self._half_open_probe_in_flight = False
            logger.info("Circuit breaker re-opened: probe request failed")
            return

        if current_state == CircuitState.CLOSED:
            self._check_threshold(current)

    def _check_threshold(self, now: float) -> None:
        """Check if failure rate exceeds threshold and open circuit if needed.

        Requirement 4.1: Open if >50% failures in 30s window with min 5 requests.
        """
        window_start = now - CIRCUIT_BREAKER_WINDOW_SECONDS
        recent = [o for o in self._outcomes if o.timestamp > window_start]

        total = len(recent)
        if total < CIRCUIT_BREAKER_MIN_REQUESTS:
            return  # Not enough data to evaluate

        failures = sum(1 for o in recent if not o.success)
        failure_rate = failures / total

        if failure_rate > CIRCUIT_BREAKER_FAILURE_THRESHOLD:
            self._transition_to_open(now)
            self._emit_p2_alert(failure_rate, now)

    def _transition_to_open(self, now: float) -> None:
        """Transition circuit breaker to open state."""
        self._state = CircuitState.OPEN
        self._opened_at = now
        self._half_open_probe_in_flight = False

    def _emit_p2_alert(self, failure_rate: float, timestamp: float) -> None:
        """Emit a P2 operational alert on closed→open transition.

        Requirement 4.5: Alert contains failure rate percentage and timestamp.
        """
        security_logger.warning(
            "CIRCUIT_BREAKER_OPENED",
            extra={
                "event_type": "operational_alert",
                "alert_priority": "P2",
                "alert_type": "circuit_breaker_state_change",
                "transition": "closed_to_open",
                "failure_rate_percent": round(failure_rate * 100, 1),
                "timestamp": timestamp,
                "recovery_timeout_seconds": CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
            },
        )

    def _prune_window(self, now: float) -> None:
        """Remove outcomes older than the rolling window."""
        window_start = now - CIRCUIT_BREAKER_WINDOW_SECONDS
        self._outcomes = [o for o in self._outcomes if o.timestamp > window_start]

    def get_failure_rate(self, now: float | None = None) -> float:
        """Get current failure rate within the rolling window (for monitoring)."""
        current = now if now is not None else self._current_time()
        window_start = current - CIRCUIT_BREAKER_WINDOW_SECONDS
        recent = [o for o in self._outcomes if o.timestamp > window_start]
        if not recent:
            return 0.0
        failures = sum(1 for o in recent if not o.success)
        return failures / len(recent)

    def get_request_count(self, now: float | None = None) -> int:
        """Get total request count within the rolling window (for monitoring)."""
        current = now if now is not None else self._current_time()
        window_start = current - CIRCUIT_BREAKER_WINDOW_SECONDS
        return len([o for o in self._outcomes if o.timestamp > window_start])

    def reset(self) -> None:
        """Reset circuit breaker to initial closed state (for testing)."""
        self._state = CircuitState.CLOSED
        self._outcomes = []
        self._opened_at = 0.0
        self._half_open_probe_in_flight = False


# Module-level circuit breaker singleton
_circuit_breaker: CircuitBreaker | None = None


def get_circuit_breaker() -> CircuitBreaker:
    """Get or create the module-level CircuitBreaker singleton."""
    global _circuit_breaker
    if _circuit_breaker is None:
        _circuit_breaker = CircuitBreaker()
    return _circuit_breaker


def reset_circuit_breaker() -> None:
    """Reset the circuit breaker singleton (for testing)."""
    global _circuit_breaker
    _circuit_breaker = None


# ---------------------------------------------------------------------------
# Circuit Breaker Middleware
# ---------------------------------------------------------------------------


class CircuitBreakerMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that applies circuit breaker protection for AgentCore Runtime.

    Intercepts requests to protected endpoints and:
    - Returns HTTP 503 immediately if circuit is open (Requirement 4.6)
    - Allows probe request in half-open state (Requirement 4.2)
    - Tracks success/failure for closed state evaluation (Requirement 4.1)

    Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
    """

    # Paths that route to the AgentCore Runtime (protected by circuit breaker)
    PROTECTED_PATHS: set[str] = {"/chat", "/agent", "/query"}

    def __init__(
        self,
        app: Any,
        circuit_breaker: CircuitBreaker | None = None,
        protected_paths: set[str] | None = None,
    ) -> None:
        super().__init__(app)
        self._circuit_breaker = circuit_breaker or get_circuit_breaker()
        if protected_paths is not None:
            self.PROTECTED_PATHS = protected_paths

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Only apply circuit breaker to paths that hit AgentCore Runtime
        if not self._is_protected_path(request.url.path):
            return await call_next(request)

        # Check if circuit breaker allows the request
        if not self._circuit_breaker.should_allow_request():
            return self._service_unavailable_response(request)

        # Forward request to AgentCore Runtime
        try:
            response = await call_next(request)

            # Record outcome based on response status
            if response.status_code >= 500:
                self._circuit_breaker.record_failure()
            else:
                self._circuit_breaker.record_success()

            return response

        except Exception:
            # Connection refused, timeout, or other transport errors
            self._circuit_breaker.record_failure()
            return self._service_unavailable_response(request)

    def _is_protected_path(self, path: str) -> bool:
        """Check if the request path is protected by the circuit breaker."""
        return path in self.PROTECTED_PATHS

    def _service_unavailable_response(self, request: Request) -> JSONResponse:
        """Return HTTP 503 response indicating Runtime unavailability.

        Requirement 4.1, 4.6: Return within 200ms without forwarding.
        """
        trace_id = getattr(request.state, "trace_id", generate_trace_id())
        return JSONResponse(
            status_code=503,
            content={
                "error_type": "service_unavailable",
                "message": (
                    "The service is temporarily unavailable. "
                    "Please try again shortly."
                ),
                "trace_id": trace_id,
            },
            headers={"X-Trace-Id": trace_id},
        )
