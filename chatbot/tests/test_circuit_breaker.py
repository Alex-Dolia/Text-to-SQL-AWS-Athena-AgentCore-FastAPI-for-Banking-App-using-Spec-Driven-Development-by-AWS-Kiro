"""Unit tests for circuit breaker middleware (chatbot/api/middleware.py).

Tests circuit breaker state transitions, failure rate tracking, and HTTP 503 responses.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
"""

from __future__ import annotations

import logging
import time

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from chatbot.api.middleware import (
    CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    CIRCUIT_BREAKER_MIN_REQUESTS,
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
    CIRCUIT_BREAKER_WINDOW_SECONDS,
    CircuitBreaker,
    CircuitBreakerMiddleware,
    CircuitState,
    TraceIdMiddleware,
    get_circuit_breaker,
    reset_circuit_breaker,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_cb_singleton():
    """Reset circuit breaker singleton between tests."""
    reset_circuit_breaker()
    yield
    reset_circuit_breaker()


@pytest.fixture
def cb() -> CircuitBreaker:
    """Create a fresh circuit breaker with controllable time."""
    breaker = CircuitBreaker(now=1000.0)
    return breaker


@pytest.fixture
def test_app_with_cb() -> tuple[FastAPI, CircuitBreaker]:
    """Create a test FastAPI app with circuit breaker middleware."""
    breaker = CircuitBreaker()

    app = FastAPI()

    # Simulated AgentCore Runtime endpoint
    @app.get("/chat")
    async def chat(request: Request):
        return JSONResponse(content={"answer": "hello"}, status_code=200)

    @app.get("/chat-error")
    async def chat_error(request: Request):
        return JSONResponse(content={"error": "runtime error"}, status_code=500)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    # Add middleware (circuit breaker protects /chat and /chat-error)
    app.add_middleware(
        CircuitBreakerMiddleware,
        circuit_breaker=breaker,
        protected_paths={"/chat", "/chat-error"},
    )
    app.add_middleware(TraceIdMiddleware)

    return app, breaker


# ---------------------------------------------------------------------------
# Tests: CircuitBreaker State Machine
# ---------------------------------------------------------------------------


class TestCircuitBreakerState:
    """Tests for circuit breaker state transitions."""

    def test_initial_state_is_closed(self, cb: CircuitBreaker):
        """Circuit breaker starts in closed state."""
        assert cb.state == CircuitState.CLOSED

    def test_stays_closed_with_all_successes(self, cb: CircuitBreaker):
        """Circuit remains closed when all requests succeed."""
        now = 1000.0
        for i in range(10):
            cb.record_success(now=now + i)
        cb.set_time(now + 10)
        assert cb.state == CircuitState.CLOSED

    def test_stays_closed_below_min_requests(self, cb: CircuitBreaker):
        """Circuit stays closed even with 100% failures if below min request threshold."""
        now = 1000.0
        # Record only 4 failures (below CIRCUIT_BREAKER_MIN_REQUESTS=5)
        for i in range(4):
            cb.record_failure(now=now + i)
        cb.set_time(now + 4)
        assert cb.state == CircuitState.CLOSED

    def test_opens_on_50_percent_failures_with_min_requests(self, cb: CircuitBreaker):
        """Circuit opens when >50% failures in 30s window with ≥5 requests.

        Requirement 4.1: Open on >50% failures in 30s window (min 5 requests).
        """
        now = 1000.0
        # 2 successes, 4 failures = 66% failure rate, 6 total requests
        cb.record_success(now=now)
        cb.record_success(now=now + 1)
        cb.record_failure(now=now + 2)
        cb.record_failure(now=now + 3)
        cb.record_failure(now=now + 4)
        # After this failure, we have 4/6 = 66% > 50%, total 6 >= 5
        cb.record_failure(now=now + 5)
        cb.set_time(now + 5)
        assert cb.state == CircuitState.OPEN

    def test_stays_closed_at_exactly_50_percent(self, cb: CircuitBreaker):
        """Circuit stays closed at exactly 50% failure rate (threshold is >50%)."""
        now = 1000.0
        # 3 successes, 3 failures = exactly 50%
        cb.record_success(now=now)
        cb.record_success(now=now + 1)
        cb.record_success(now=now + 2)
        cb.record_failure(now=now + 3)
        cb.record_failure(now=now + 4)
        cb.record_failure(now=now + 5)
        cb.set_time(now + 5)
        assert cb.state == CircuitState.CLOSED

    def test_transitions_to_half_open_after_recovery_timeout(self, cb: CircuitBreaker):
        """Open circuit transitions to half-open after 60 seconds.

        Requirement 4.2: After 60s in open state, transition to half-open.
        """
        now = 1000.0
        # Force open
        for i in range(5):
            cb.record_failure(now=now + i)
        cb.set_time(now + 5)
        assert cb.state == CircuitState.OPEN

        # Advance time by 60 seconds
        cb.set_time(now + 5 + CIRCUIT_BREAKER_RECOVERY_TIMEOUT)
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_closes_on_successful_probe(self, cb: CircuitBreaker):
        """Half-open circuit closes when probe request succeeds.

        Requirement 4.3: Probe success → closed state.
        """
        now = 1000.0
        # Force open
        for i in range(5):
            cb.record_failure(now=now + i)

        # Advance to half-open
        half_open_time = now + 5 + CIRCUIT_BREAKER_RECOVERY_TIMEOUT
        cb.set_time(half_open_time)
        assert cb.state == CircuitState.HALF_OPEN

        # Allow probe
        assert cb.should_allow_request() is True

        # Probe succeeds
        cb.record_success(now=half_open_time + 1)
        cb.set_time(half_open_time + 1)
        assert cb.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failed_probe(self, cb: CircuitBreaker):
        """Half-open circuit re-opens when probe request fails.

        Requirement 4.4: Probe failure → open state, restart 60s wait.
        """
        now = 1000.0
        # Force open
        for i in range(5):
            cb.record_failure(now=now + i)

        # Advance to half-open
        half_open_time = now + 5 + CIRCUIT_BREAKER_RECOVERY_TIMEOUT
        cb.set_time(half_open_time)
        assert cb.state == CircuitState.HALF_OPEN

        # Allow probe
        assert cb.should_allow_request() is True

        # Probe fails
        cb.record_failure(now=half_open_time + 1)
        cb.set_time(half_open_time + 1)
        assert cb.raw_state == CircuitState.OPEN

        # Must wait another 60s before half-open again
        cb.set_time(half_open_time + 1 + CIRCUIT_BREAKER_RECOVERY_TIMEOUT - 1)
        assert cb.state == CircuitState.OPEN  # Not yet

        cb.set_time(half_open_time + 1 + CIRCUIT_BREAKER_RECOVERY_TIMEOUT)
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_allows_only_one_probe(self, cb: CircuitBreaker):
        """Half-open state permits exactly 1 probe request.

        Requirement 4.2: Permit exactly 1 probe request.
        """
        now = 1000.0
        # Force open
        for i in range(5):
            cb.record_failure(now=now + i)

        # Advance to half-open
        half_open_time = now + 5 + CIRCUIT_BREAKER_RECOVERY_TIMEOUT
        cb.set_time(half_open_time)

        # First request allowed (probe)
        assert cb.should_allow_request() is True
        # Second request rejected while probe is in-flight
        assert cb.should_allow_request() is False
        # Third also rejected
        assert cb.should_allow_request() is False


# ---------------------------------------------------------------------------
# Tests: CircuitBreaker Request Routing
# ---------------------------------------------------------------------------


class TestCircuitBreakerRequestRouting:
    """Tests for should_allow_request() behavior."""

    def test_closed_allows_all_requests(self, cb: CircuitBreaker):
        """Closed circuit allows all requests."""
        for _ in range(20):
            assert cb.should_allow_request() is True

    def test_open_rejects_all_requests(self, cb: CircuitBreaker):
        """Open circuit rejects all requests.

        Requirement 4.6: Return 503 without forwarding when open.
        """
        now = 1000.0
        # Force open
        for i in range(5):
            cb.record_failure(now=now + i)
        cb.set_time(now + 5)
        assert cb.state == CircuitState.OPEN

        # All requests rejected
        for _ in range(10):
            assert cb.should_allow_request() is False


# ---------------------------------------------------------------------------
# Tests: Rolling Window
# ---------------------------------------------------------------------------


class TestCircuitBreakerRollingWindow:
    """Tests for the rolling 30-second failure window."""

    def test_old_failures_do_not_count(self, cb: CircuitBreaker):
        """Failures older than 30 seconds are pruned from the window."""
        now = 1000.0
        # Record 5 failures at now
        for i in range(5):
            cb.record_failure(now=now + i)

        # At this point circuit should be open
        cb.set_time(now + 5)
        assert cb.state == CircuitState.OPEN

        # Advance past recovery timeout
        recovered_time = now + 5 + CIRCUIT_BREAKER_RECOVERY_TIMEOUT
        cb.set_time(recovered_time)
        assert cb.state == CircuitState.HALF_OPEN

        # Probe succeeds → closes
        assert cb.should_allow_request() is True
        cb.record_success(now=recovered_time + 1)
        cb.set_time(recovered_time + 1)
        assert cb.state == CircuitState.CLOSED

        # Now record new successes — old failures are outside window
        for i in range(5):
            cb.record_success(now=recovered_time + 2 + i)
        cb.set_time(recovered_time + 7)
        assert cb.state == CircuitState.CLOSED
        assert cb.get_failure_rate(now=recovered_time + 7) == 0.0

    def test_failure_rate_calculation(self, cb: CircuitBreaker):
        """Failure rate is correctly calculated within the window."""
        now = 1000.0
        # 3 successes + 2 failures = 2/5 = 40%
        cb.record_success(now=now)
        cb.record_success(now=now + 1)
        cb.record_success(now=now + 2)
        cb.record_failure(now=now + 3)
        cb.record_failure(now=now + 4)
        assert cb.get_failure_rate(now=now + 4) == pytest.approx(0.4)

    def test_request_count_tracks_window(self, cb: CircuitBreaker):
        """Request count reflects only entries within the rolling window."""
        now = 1000.0
        cb.record_success(now=now)
        cb.record_failure(now=now + 1)
        assert cb.get_request_count(now=now + 1) == 2

        # After window expires, count should be 0
        assert cb.get_request_count(now=now + CIRCUIT_BREAKER_WINDOW_SECONDS + 2) == 0


# ---------------------------------------------------------------------------
# Tests: P2 Alert on closed→open Transition
# ---------------------------------------------------------------------------


class TestCircuitBreakerAlerts:
    """Tests for P2 operational alert on state transitions."""

    def test_p2_alert_emitted_on_closed_to_open(self, cb: CircuitBreaker, caplog):
        """P2 alert is triggered when circuit transitions from closed to open.

        Requirement 4.5: Trigger P2 alert with failure rate and timestamp.
        """
        now = 1000.0
        with caplog.at_level(logging.WARNING, logger="chatbot.security"):
            # Force open: 5 failures out of 5 = 100%
            for i in range(5):
                cb.record_failure(now=now + i)

        # Check alert was emitted
        assert len(caplog.records) >= 1
        alert_record = caplog.records[-1]
        assert alert_record.message == "CIRCUIT_BREAKER_OPENED"
        assert alert_record.alert_priority == "P2"
        assert alert_record.alert_type == "circuit_breaker_state_change"
        assert alert_record.transition == "closed_to_open"
        assert alert_record.failure_rate_percent == 100.0

    def test_no_alert_when_below_threshold(self, cb: CircuitBreaker, caplog):
        """No alert when failure rate doesn't exceed threshold."""
        now = 1000.0
        with caplog.at_level(logging.WARNING, logger="chatbot.security"):
            # 3 successes, 2 failures = 40% < 50%
            cb.record_success(now=now)
            cb.record_success(now=now + 1)
            cb.record_success(now=now + 2)
            cb.record_failure(now=now + 3)
            cb.record_failure(now=now + 4)

        # No alert should be emitted
        security_alerts = [
            r for r in caplog.records if r.message == "CIRCUIT_BREAKER_OPENED"
        ]
        assert len(security_alerts) == 0


# ---------------------------------------------------------------------------
# Tests: CircuitBreakerMiddleware Integration (via HTTPX)
# ---------------------------------------------------------------------------


class TestCircuitBreakerMiddleware:
    """Integration tests for CircuitBreakerMiddleware with FastAPI."""

    @pytest.mark.asyncio
    async def test_health_endpoint_not_protected(self, test_app_with_cb):
        """Health endpoint is not protected by circuit breaker."""
        app, breaker = test_app_with_cb

        # Force circuit open
        now = time.time()
        for i in range(5):
            breaker.record_failure(now=now + i)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/health")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_closed_circuit_passes_requests(self, test_app_with_cb):
        """Closed circuit allows requests through to the backend."""
        app, breaker = test_app_with_cb

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/chat")
            assert response.status_code == 200
            assert response.json() == {"answer": "hello"}

    @pytest.mark.asyncio
    async def test_open_circuit_returns_503(self, test_app_with_cb):
        """Open circuit returns HTTP 503 without forwarding request.

        Requirement 4.1, 4.6: Return 503 when circuit is open.
        """
        app, breaker = test_app_with_cb

        # Force open
        now = time.time()
        for i in range(5):
            breaker.record_failure(now=now + i)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/chat")
            assert response.status_code == 503
            body = response.json()
            assert body["error_type"] == "service_unavailable"
            assert "trace_id" in body
            assert "X-Trace-Id" in response.headers

    @pytest.mark.asyncio
    async def test_503_response_includes_trace_id(self, test_app_with_cb):
        """503 response includes X-Trace-Id header for correlation."""
        app, breaker = test_app_with_cb

        # Force open
        now = time.time()
        for i in range(5):
            breaker.record_failure(now=now + i)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/chat")
            assert response.status_code == 503
            trace_id = response.headers.get("X-Trace-Id")
            assert trace_id is not None
            # Should also be in body
            assert response.json()["trace_id"] == trace_id

    @pytest.mark.asyncio
    async def test_backend_5xx_recorded_as_failure(self, test_app_with_cb):
        """HTTP 5xx from backend is recorded as a failure."""
        app, breaker = test_app_with_cb

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Hit the error endpoint multiple times
            for _ in range(5):
                await client.get("/chat-error")

        # After 5 failures (100%), circuit should be open
        assert breaker.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_backend_2xx_recorded_as_success(self, test_app_with_cb):
        """HTTP 2xx from backend is recorded as a success."""
        app, breaker = test_app_with_cb

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            for _ in range(5):
                response = await client.get("/chat")
                assert response.status_code == 200

        # Circuit stays closed
        assert breaker.state == CircuitState.CLOSED
        assert breaker.get_request_count() == 5


# ---------------------------------------------------------------------------
# Tests: Singleton Management
# ---------------------------------------------------------------------------


class TestCircuitBreakerSingleton:
    """Tests for circuit breaker singleton access."""

    def test_get_circuit_breaker_returns_same_instance(self):
        """get_circuit_breaker should return the same instance."""
        cb1 = get_circuit_breaker()
        cb2 = get_circuit_breaker()
        assert cb1 is cb2

    def test_reset_creates_new_instance(self):
        """reset_circuit_breaker should clear the singleton."""
        cb1 = get_circuit_breaker()
        reset_circuit_breaker()
        cb2 = get_circuit_breaker()
        assert cb1 is not cb2

    def test_reset_clears_state(self):
        """New instance after reset starts in closed state."""
        cb = get_circuit_breaker()
        now = time.time()
        for i in range(5):
            cb.record_failure(now=now + i)
        assert cb.state == CircuitState.OPEN

        reset_circuit_breaker()
        cb_new = get_circuit_breaker()
        assert cb_new.state == CircuitState.CLOSED
