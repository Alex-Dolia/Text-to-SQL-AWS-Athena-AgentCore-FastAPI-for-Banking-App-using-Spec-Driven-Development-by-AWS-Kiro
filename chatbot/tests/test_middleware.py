"""Unit tests for session management and middleware (chatbot/api/middleware.py).

Tests session timeout enforcement, trace_id generation, and auth failure tracking.

Requirements: 2.2, 2.3, 2.4, 2.5
"""

from __future__ import annotations

import time
import uuid

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from chatbot.api.middleware import (
    AUTH_FAILURE_THRESHOLD,
    AUTH_FAILURE_WINDOW_SECONDS,
    SESSION_IDLE_TIMEOUT_SECONDS,
    AuthFailureTracker,
    SessionEntry,
    SessionStore,
    SessionTimeoutMiddleware,
    TraceIdMiddleware,
    generate_trace_id,
    get_auth_failure_tracker,
    get_session_store,
    record_auth_failure_for_ip,
    reset_auth_failure_tracker,
    reset_session_store,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset module-level singletons between tests."""
    reset_session_store()
    reset_auth_failure_tracker()
    yield
    reset_session_store()
    reset_auth_failure_tracker()


@pytest.fixture
def session_store() -> SessionStore:
    return SessionStore()


@pytest.fixture
def auth_failure_tracker() -> AuthFailureTracker:
    return AuthFailureTracker()


@pytest.fixture
def test_app() -> FastAPI:
    """Create a test FastAPI app with middleware registered."""
    app = FastAPI()

    # Add middleware (order matters: TraceId first, then Session)
    app.add_middleware(SessionTimeoutMiddleware)
    app.add_middleware(TraceIdMiddleware)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/chat")
    async def chat(request: Request):
        return JSONResponse(
            content={"answer": "test response"},
            status_code=200,
        )

    return app


@pytest.fixture
def test_app_with_session() -> FastAPI:
    """Create a test app with an active session pre-configured."""
    store = SessionStore()
    store.create("test-session-id", "user-123")

    app = FastAPI()
    app.add_middleware(SessionTimeoutMiddleware, session_store=store)
    app.add_middleware(TraceIdMiddleware)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/chat")
    async def chat(request: Request):
        return JSONResponse(content={"answer": "test"}, status_code=200)

    return app


# ---------------------------------------------------------------------------
# Tests: SessionEntry
# ---------------------------------------------------------------------------


class TestSessionEntry:
    """Tests for SessionEntry data class."""

    def test_new_session_not_expired(self):
        """A freshly created session should not be expired."""
        now = time.time()
        entry = SessionEntry(user_id="user-1", last_activity=now, created_at=now)
        assert not entry.is_expired(now)

    def test_session_expired_after_45_min(self):
        """Session should be expired after 45 minutes of inactivity."""
        now = time.time()
        entry = SessionEntry(
            user_id="user-1",
            last_activity=now - SESSION_IDLE_TIMEOUT_SECONDS - 1,
            created_at=now - 3600,
        )
        assert entry.is_expired(now)

    def test_session_not_expired_at_44_min(self):
        """Session should NOT be expired at 44 minutes of inactivity."""
        now = time.time()
        entry = SessionEntry(
            user_id="user-1",
            last_activity=now - (44 * 60),
            created_at=now - 3600,
        )
        assert not entry.is_expired(now)

    def test_session_expired_exactly_at_45_min(self):
        """Session at exactly 45 minutes (boundary) should NOT be expired (>45, not >=)."""
        now = time.time()
        entry = SessionEntry(
            user_id="user-1",
            last_activity=now - SESSION_IDLE_TIMEOUT_SECONDS,
            created_at=now - 3600,
        )
        assert not entry.is_expired(now)

    def test_touch_updates_last_activity(self):
        """Touching a session should update last_activity."""
        now = time.time()
        entry = SessionEntry(user_id="user-1", last_activity=now - 1000, created_at=now - 2000)
        entry.touch(now)
        assert entry.last_activity == now
        assert not entry.is_expired(now)


# ---------------------------------------------------------------------------
# Tests: SessionStore
# ---------------------------------------------------------------------------


class TestSessionStore:
    """Tests for SessionStore in-memory store."""

    def test_create_and_get_session(self, session_store: SessionStore):
        """Creating a session should allow retrieval by ID."""
        session_store.create("session-1", "user-1")
        entry = session_store.get("session-1")
        assert entry is not None
        assert entry.user_id == "user-1"

    def test_get_nonexistent_session_returns_none(self, session_store: SessionStore):
        """Getting a nonexistent session returns None."""
        assert session_store.get("nonexistent") is None

    def test_invalidate_removes_session(self, session_store: SessionStore):
        """Invalidating a session removes it from the store."""
        session_store.create("session-1", "user-1")
        session_store.invalidate("session-1")
        assert session_store.get("session-1") is None

    def test_invalidate_nonexistent_is_noop(self, session_store: SessionStore):
        """Invalidating a nonexistent session does not raise."""
        session_store.invalidate("nonexistent")  # Should not raise

    def test_touch_updates_activity(self, session_store: SessionStore):
        """Touching a session updates last_activity."""
        now = time.time()
        session_store.create("session-1", "user-1", now=now - 1000)
        session_store.touch("session-1", now=now)
        entry = session_store.get("session-1")
        assert entry is not None
        assert entry.last_activity == now

    def test_cleanup_removes_expired_sessions(self, session_store: SessionStore):
        """Cleanup removes sessions past idle timeout."""
        now = time.time()
        session_store.create("active", "user-1", now=now)
        session_store.create("expired", "user-2", now=now - SESSION_IDLE_TIMEOUT_SECONDS - 60)
        removed = session_store.cleanup_expired(now=now)
        assert removed == 1
        assert session_store.get("active") is not None
        assert session_store.get("expired") is None

    def test_active_count(self, session_store: SessionStore):
        """Active count reflects current number of sessions."""
        assert session_store.active_count == 0
        session_store.create("s1", "u1")
        session_store.create("s2", "u2")
        assert session_store.active_count == 2
        session_store.invalidate("s1")
        assert session_store.active_count == 1


# ---------------------------------------------------------------------------
# Tests: AuthFailureTracker
# ---------------------------------------------------------------------------


class TestAuthFailureTracker:
    """Tests for per-IP auth failure tracking and alerting."""

    def test_single_failure_does_not_alert(self, auth_failure_tracker: AuthFailureTracker):
        """A single failure should not trigger an alert."""
        exceeded = auth_failure_tracker.record_failure("192.168.1.1")
        assert not exceeded

    def test_five_failures_does_not_alert(self, auth_failure_tracker: AuthFailureTracker):
        """Exactly 5 failures should not trigger an alert (threshold is >5)."""
        now = time.time()
        for i in range(5):
            exceeded = auth_failure_tracker.record_failure("192.168.1.1", now=now + i)
        assert not exceeded

    def test_six_failures_triggers_alert(self, auth_failure_tracker: AuthFailureTracker):
        """6 failures within 60s should trigger a security alert."""
        now = time.time()
        for i in range(5):
            auth_failure_tracker.record_failure("192.168.1.1", now=now + i)
        exceeded = auth_failure_tracker.record_failure("192.168.1.1", now=now + 5)
        assert exceeded

    def test_failures_outside_window_do_not_count(self, auth_failure_tracker: AuthFailureTracker):
        """Failures older than 60 seconds are pruned and don't count."""
        now = time.time()
        # Record 5 failures all outside the window (61-65 seconds ago)
        for i in range(5):
            auth_failure_tracker.record_failure(
                "192.168.1.1", now=now - AUTH_FAILURE_WINDOW_SECONDS - 1 - i
            )
        # Record 1 new failure — should only see 1 in the window
        exceeded = auth_failure_tracker.record_failure("192.168.1.1", now=now)
        assert not exceeded
        assert auth_failure_tracker.get_failure_count("192.168.1.1", now=now) == 1

    def test_different_ips_tracked_independently(self, auth_failure_tracker: AuthFailureTracker):
        """Failures from different IPs should be tracked independently."""
        now = time.time()
        for i in range(5):
            auth_failure_tracker.record_failure("192.168.1.1", now=now + i)
        # IP 2 has only 1 failure
        exceeded = auth_failure_tracker.record_failure("192.168.1.2", now=now)
        assert not exceeded
        assert auth_failure_tracker.get_failure_count("192.168.1.2", now=now) == 1

    def test_get_failure_count_within_window(self, auth_failure_tracker: AuthFailureTracker):
        """get_failure_count returns count within the sliding window."""
        now = time.time()
        auth_failure_tracker.record_failure("10.0.0.1", now=now - 30)
        auth_failure_tracker.record_failure("10.0.0.1", now=now - 10)
        auth_failure_tracker.record_failure("10.0.0.1", now=now)
        assert auth_failure_tracker.get_failure_count("10.0.0.1", now=now) == 3

    def test_cleanup_removes_stale_entries(self, auth_failure_tracker: AuthFailureTracker):
        """Cleanup should remove entries older than the sliding window."""
        now = time.time()
        auth_failure_tracker.record_failure("10.0.0.1", now=now - 120)
        auth_failure_tracker.cleanup(now=now)
        assert auth_failure_tracker.get_failure_count("10.0.0.1", now=now) == 0


# ---------------------------------------------------------------------------
# Tests: generate_trace_id
# ---------------------------------------------------------------------------


class TestTraceIdGeneration:
    """Tests for UUID v4 trace_id generation."""

    def test_trace_id_is_valid_uuid4(self):
        """Generated trace_id should be a valid UUID v4."""
        trace_id = generate_trace_id()
        parsed = uuid.UUID(trace_id, version=4)
        assert str(parsed) == trace_id

    def test_trace_ids_are_unique(self):
        """Each generated trace_id should be unique."""
        ids = {generate_trace_id() for _ in range(100)}
        assert len(ids) == 100


# ---------------------------------------------------------------------------
# Tests: TraceIdMiddleware (integration via HTTPX)
# ---------------------------------------------------------------------------


class TestTraceIdMiddleware:
    """Tests for TraceIdMiddleware adding X-Trace-Id to responses."""

    @pytest.mark.asyncio
    async def test_trace_id_header_present_on_every_response(self, test_app: FastAPI):
        """Every response should include X-Trace-Id header."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/health")
            assert "X-Trace-Id" in response.headers
            # Validate it's a proper UUID v4
            trace_id = response.headers["X-Trace-Id"]
            parsed = uuid.UUID(trace_id, version=4)
            assert str(parsed) == trace_id

    @pytest.mark.asyncio
    async def test_each_request_gets_unique_trace_id(self, test_app: FastAPI):
        """Each request should get a different trace_id."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            r1 = await client.get("/health")
            r2 = await client.get("/health")
            assert r1.headers["X-Trace-Id"] != r2.headers["X-Trace-Id"]


# ---------------------------------------------------------------------------
# Tests: SessionTimeoutMiddleware (integration via HTTPX)
# ---------------------------------------------------------------------------


class TestSessionTimeoutMiddleware:
    """Tests for session timeout enforcement middleware."""

    @pytest.mark.asyncio
    async def test_health_endpoint_exempt_from_session_check(self, test_app: FastAPI):
        """Health endpoint should bypass session timeout checks."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/health")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_expired_session_returns_401(self, test_app_with_session: FastAPI):
        """An expired session should return HTTP 401 with re-auth message."""
        # Manually expire the session
        store = get_session_store()
        # Override the store used by the middleware — we use the fixture's store
        # The fixture pre-creates the session, so we need to expire it
        app = test_app_with_session
        # Access the middleware's session store and expire the session
        for middleware in app.user_middleware:
            if middleware.cls == SessionTimeoutMiddleware:
                mw_store = middleware.kwargs.get("session_store")
                if mw_store:
                    entry = mw_store.get("test-session-id")
                    if entry:
                        entry.last_activity = (
                            time.time() - SESSION_IDLE_TIMEOUT_SECONDS - 60
                        )

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/chat", headers={"X-Session-Id": "test-session-id"}
            )
            assert response.status_code == 401
            body = response.json()
            assert body["error_type"] == "auth_denied"
            assert "re-authenticate" in body["message"].lower()
            assert "trace_id" in body
            # Validate trace_id is UUID v4
            uuid.UUID(body["trace_id"], version=4)

    @pytest.mark.asyncio
    async def test_active_session_passes_through(self, test_app_with_session: FastAPI):
        """An active (non-expired) session should allow the request."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app_with_session), base_url="http://test"
        ) as client:
            response = await client.get(
                "/chat", headers={"X-Session-Id": "test-session-id"}
            )
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_expired_session_response_includes_trace_id_header(
        self, test_app_with_session: FastAPI
    ):
        """Expired session 401 response should include X-Trace-Id header."""
        app = test_app_with_session
        for middleware in app.user_middleware:
            if middleware.cls == SessionTimeoutMiddleware:
                mw_store = middleware.kwargs.get("session_store")
                if mw_store:
                    entry = mw_store.get("test-session-id")
                    if entry:
                        entry.last_activity = (
                            time.time() - SESSION_IDLE_TIMEOUT_SECONDS - 60
                        )

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/chat", headers={"X-Session-Id": "test-session-id"}
            )
            assert response.status_code == 401
            assert "X-Trace-Id" in response.headers


# ---------------------------------------------------------------------------
# Tests: Singleton management
# ---------------------------------------------------------------------------


class TestSingletons:
    """Tests for module-level singleton access."""

    def test_get_session_store_returns_same_instance(self):
        """get_session_store should return the same instance."""
        store1 = get_session_store()
        store2 = get_session_store()
        assert store1 is store2

    def test_reset_session_store_creates_new_instance(self):
        """reset_session_store should clear the singleton."""
        store1 = get_session_store()
        reset_session_store()
        store2 = get_session_store()
        assert store1 is not store2

    def test_get_auth_failure_tracker_returns_same_instance(self):
        """get_auth_failure_tracker should return the same instance."""
        tracker1 = get_auth_failure_tracker()
        tracker2 = get_auth_failure_tracker()
        assert tracker1 is tracker2

    def test_reset_auth_failure_tracker_creates_new_instance(self):
        """reset_auth_failure_tracker should clear the singleton."""
        tracker1 = get_auth_failure_tracker()
        reset_auth_failure_tracker()
        tracker2 = get_auth_failure_tracker()
        assert tracker1 is not tracker2
