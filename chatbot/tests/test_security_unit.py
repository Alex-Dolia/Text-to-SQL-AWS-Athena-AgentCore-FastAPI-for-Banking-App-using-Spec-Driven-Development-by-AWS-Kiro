"""Comprehensive unit tests for auth, rate limiting, circuit breaker, and session timeout.

Task 2.7: Write unit tests for auth, rate limiting, circuit breaker.
- JWT validation: valid token, expired, wrong audience, wrong issuer, invalid signature, missing claims
- Rate limiter: under limit, at limit, over limit, bucket refill, concurrent requests
- Circuit breaker: closed→open, open→half-open, half-open→closed, half-open→open
- Session timeout: active session, idle expiry, re-authentication flow

Requirements: 2.1, 2.2, 3.1, 4.1
"""

from __future__ import annotations

import asyncio
import base64
import time
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from chatbot.api.auth import (
    AuthConfig,
    AuthenticationError,
    JWKSCache,
    _CachedJWKS,
    validate_jwt,
)
from chatbot.api.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
    get_circuit_breaker,
    reset_circuit_breaker,
)
from chatbot.api.middleware import (
    SESSION_IDLE_TIMEOUT_SECONDS,
    SessionEntry,
    SessionStore,
)
from chatbot.api.models import UserClaims
from chatbot.api.rate_limiter import RateLimiter, RateLimitExceeded


# ---------------------------------------------------------------------------
# Test Helpers - RSA Key Pair for JWT Tests
# ---------------------------------------------------------------------------

_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_rsa_public_key = _rsa_private_key.public_key()

TEST_RSA_PRIVATE_PEM = _rsa_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

_pub_numbers = _rsa_public_key.public_numbers()


def _int_to_base64url(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    n_bytes = n.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")


TEST_RSA_PUBLIC_KEY_JWK = {
    "kty": "RSA",
    "kid": "test-key-1",
    "use": "sig",
    "alg": "RS256",
    "n": _int_to_base64url(_pub_numbers.n),
    "e": _int_to_base64url(_pub_numbers.e),
}

TEST_AUTH_CONFIG = AuthConfig(
    cognito_user_pool_id="us-east-1_TestPool",
    cognito_region="us-east-1",
    cognito_app_client_id="test-client-id-123",
)


def _make_token(claims: dict | None = None, headers: dict | None = None) -> str:
    """Create a signed JWT token for testing."""
    now = int(time.time())
    default_claims = {
        "sub": "user-test-001",
        "aud": TEST_AUTH_CONFIG.audience,
        "iss": TEST_AUTH_CONFIG.issuer,
        "exp": now + 900,
        "iat": now,
        "custom:department": "analytics",
        "custom:role": "analyst",
        "custom:data-classification-tier": "internal",
        "cognito:groups": ["data-users"],
        "event_id": str(uuid.uuid4()),
    }
    if claims:
        default_claims.update(claims)
    token_headers = headers or {"kid": "test-key-1"}
    return jwt.encode(default_claims, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers=token_headers)


def _make_jwks_cache() -> JWKSCache:
    """Create a JWKSCache with pre-loaded keys."""
    cache = JWKSCache(TEST_AUTH_CONFIG)
    cache._cache = _CachedJWKS(
        keys={"test-key-1": TEST_RSA_PUBLIC_KEY_JWK},
        fetched_at=time.time(),
        ttl_seconds=300.0,
    )
    return cache


# ===========================================================================
# Section 1: JWT Validation Tests (Requirement 2.1)
# ===========================================================================


class TestJWTValidation:
    """JWT validation: valid token, expired, wrong audience, wrong issuer,
    invalid signature, missing claims."""

    @pytest.mark.asyncio
    async def test_valid_token_returns_user_claims(self):
        """A properly signed token with all claims returns UserClaims."""
        token = _make_token()
        cache = _make_jwks_cache()
        result = await validate_jwt(token, config=TEST_AUTH_CONFIG, jwks_cache=cache)
        assert isinstance(result, UserClaims)
        assert result.sub == "user-test-001"
        assert result.department == "analytics"
        assert result.role == "analyst"

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self):
        """Token with exp in the past raises AuthenticationError."""
        token = _make_token(claims={"exp": int(time.time()) - 3600})
        cache = _make_jwks_cache()
        with pytest.raises(AuthenticationError, match="Token has expired"):
            await validate_jwt(token, config=TEST_AUTH_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_wrong_audience_rejected(self):
        """Token with mismatched audience raises AuthenticationError."""
        token = _make_token(claims={"aud": "wrong-client-id"})
        cache = _make_jwks_cache()
        with pytest.raises(AuthenticationError, match="Invalid token audience"):
            await validate_jwt(token, config=TEST_AUTH_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_wrong_issuer_rejected(self):
        """Token with mismatched issuer raises AuthenticationError."""
        token = _make_token(claims={"iss": "https://evil.example.com"})
        cache = _make_jwks_cache()
        with pytest.raises(AuthenticationError, match="Invalid token issuer"):
            await validate_jwt(token, config=TEST_AUTH_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(self):
        """Token with corrupted signature raises AuthenticationError."""
        token = _make_token()
        parts = token.split(".")
        corrupted = parts[2][:-4] + "ZZZZ"
        tampered = f"{parts[0]}.{parts[1]}.{corrupted}"
        cache = _make_jwks_cache()
        with pytest.raises(AuthenticationError, match="Invalid token signature"):
            await validate_jwt(tampered, config=TEST_AUTH_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_missing_department_claim_rejected(self):
        """Token without custom:department raises specific error."""
        now = int(time.time())
        raw = {
            "sub": "user-1",
            "aud": TEST_AUTH_CONFIG.audience,
            "iss": TEST_AUTH_CONFIG.issuer,
            "exp": now + 900,
            "iat": now,
            "custom:role": "analyst",
            "custom:data-classification-tier": "internal",
            "cognito:groups": ["team"],
            "event_id": str(uuid.uuid4()),
        }
        token = jwt.encode(raw, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key-1"})
        cache = _make_jwks_cache()
        with pytest.raises(AuthenticationError, match="Missing required claim: department"):
            await validate_jwt(token, config=TEST_AUTH_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_missing_role_claim_rejected(self):
        """Token without custom:role raises specific error."""
        now = int(time.time())
        raw = {
            "sub": "user-1",
            "aud": TEST_AUTH_CONFIG.audience,
            "iss": TEST_AUTH_CONFIG.issuer,
            "exp": now + 900,
            "iat": now,
            "custom:department": "analytics",
            "custom:data-classification-tier": "internal",
            "cognito:groups": ["team"],
            "event_id": str(uuid.uuid4()),
        }
        token = jwt.encode(raw, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key-1"})
        cache = _make_jwks_cache()
        with pytest.raises(AuthenticationError, match="Missing required claim: role"):
            await validate_jwt(token, config=TEST_AUTH_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_missing_groups_claim_rejected(self):
        """Token without groups claim raises specific error."""
        now = int(time.time())
        raw = {
            "sub": "user-1",
            "aud": TEST_AUTH_CONFIG.audience,
            "iss": TEST_AUTH_CONFIG.issuer,
            "exp": now + 900,
            "iat": now,
            "custom:department": "analytics",
            "custom:role": "analyst",
            "custom:data-classification-tier": "internal",
            "event_id": str(uuid.uuid4()),
        }
        token = jwt.encode(raw, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key-1"})
        cache = _make_jwks_cache()
        with pytest.raises(AuthenticationError, match="Missing required claim: groups"):
            await validate_jwt(token, config=TEST_AUTH_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_token_lifetime_exceeding_15min_rejected(self):
        """Token with lifetime > 900s is rejected (Req 1.3)."""
        now = int(time.time())
        token = _make_token(claims={"iat": now, "exp": now + 1800})  # 30 min
        cache = _make_jwks_cache()
        with pytest.raises(AuthenticationError, match="Token lifetime exceeds maximum"):
            await validate_jwt(token, config=TEST_AUTH_CONFIG, jwks_cache=cache)


# ===========================================================================
# Section 2: Rate Limiter Tests (Requirement 3.1)
# ===========================================================================


class TestRateLimiter:
    """Rate limiter: under limit, at limit, over limit, bucket refill,
    concurrent requests."""

    @pytest.fixture
    def limiter(self) -> RateLimiter:
        return RateLimiter()

    @pytest.mark.asyncio
    async def test_under_limit_requests_succeed(self, limiter: RateLimiter):
        """Requests below 30/min threshold succeed without error."""
        for _ in range(10):
            await limiter.check_rate_limit("user-1")
        state = limiter.get_bucket_state("user-1")
        assert state["tokens"] == 20

    @pytest.mark.asyncio
    async def test_at_limit_all_30_succeed(self, limiter: RateLimiter):
        """Exactly 30 requests in one window all succeed."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")
        state = limiter.get_bucket_state("user-1")
        assert state["tokens"] == 0

    @pytest.mark.asyncio
    async def test_over_limit_raises_rate_limit_exceeded(self, limiter: RateLimiter):
        """Request #31 raises RateLimitExceeded with retry_after."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")
        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter.check_rate_limit("user-1")
        assert 1 <= exc_info.value.retry_after <= 60
        assert "Rate limit exceeded" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_bucket_refills_after_window_expires(self, limiter: RateLimiter):
        """After 60s window reset, user gets full 30 tokens back."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")
        # Simulate window expiry
        bucket = limiter._buckets["user-1"]
        bucket.window_start = time.time() - 61
        await limiter.check_rate_limit("user-1")
        state = limiter.get_bucket_state("user-1")
        assert state["tokens"] == 29

    @pytest.mark.asyncio
    async def test_concurrent_requests_respect_limit(self):
        """50 concurrent requests from same user: only 30 succeed."""
        limiter = RateLimiter()

        async def attempt() -> bool:
            try:
                await limiter.check_rate_limit("user-concurrent")
                return True
            except RateLimitExceeded:
                return False

        results = await asyncio.gather(*[attempt() for _ in range(50)])
        successes = sum(1 for r in results if r)
        assert successes == 30

    @pytest.mark.asyncio
    async def test_different_users_independent(self, limiter: RateLimiter):
        """Rate limit buckets are independent per user."""
        for _ in range(30):
            await limiter.check_rate_limit("user-a")
        # user-b should still be fine
        await limiter.check_rate_limit("user-b")
        state = limiter.get_bucket_state("user-b")
        assert state["tokens"] == 29


# ===========================================================================
# Section 3: Circuit Breaker Tests (Requirement 4.1)
# ===========================================================================


class TestCircuitBreakerClosedToOpen:
    """Circuit breaker: closed→open transition."""

    @pytest.fixture
    def cb(self) -> CircuitBreaker:
        return CircuitBreaker(CircuitBreakerConfig(
            failure_threshold_pct=50.0,
            window_seconds=30.0,
            min_requests=5,
            recovery_timeout_seconds=60.0,
        ))

    @pytest.mark.asyncio
    async def test_closed_state_passes_requests(self, cb: CircuitBreaker):
        """In CLOSED state, requests pass through normally."""
        async def success_fn():
            return "ok"

        result = await cb.call(success_fn)
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_opens_after_50pct_failures_with_min_5_requests(self, cb: CircuitBreaker):
        """Circuit opens when >50% of requests fail (min 5 in window)."""
        async def success_fn():
            return "ok"

        async def failure_fn():
            raise RuntimeError("connection refused")

        # 2 successes + 3 failures = 60% failure rate, 5 total requests
        await cb.call(success_fn)
        await cb.call(success_fn)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)

        # Now circuit should be OPEN
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_does_not_open_below_min_requests(self, cb: CircuitBreaker):
        """Circuit stays closed if fewer than 5 requests in window."""
        async def failure_fn():
            raise RuntimeError("fail")

        # Only 4 failures (below min_requests=5)
        for _ in range(4):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)

        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_open_circuit_rejects_with_503_error(self, cb: CircuitBreaker):
        """Open circuit raises CircuitBreakerOpenError immediately."""
        async def failure_fn():
            raise RuntimeError("fail")

        # Force open: 5 failures
        for _ in range(5):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)

        assert cb.state == CircuitState.OPEN

        # Next request should be rejected immediately
        async def any_fn():
            return "should not run"

        with pytest.raises(CircuitBreakerOpenError) as exc_info:
            await cb.call(any_fn)
        assert "unavailable" in exc_info.value.message.lower()
        assert exc_info.value.retry_after >= 1

    @pytest.mark.asyncio
    async def test_p2_alert_on_closed_to_open(self):
        """P2 alert fires when circuit transitions closed→open (Req 4.5)."""
        alert_mock = AsyncMock()
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold_pct=50.0,
            window_seconds=30.0,
            min_requests=5,
            recovery_timeout_seconds=60.0,
            alert_callback=alert_mock,
        ))

        async def failure_fn():
            raise RuntimeError("fail")

        for _ in range(5):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)

        assert cb.state == CircuitState.OPEN
        alert_mock.assert_called_once()
        # Alert receives failure_rate and timestamp
        args = alert_mock.call_args[0]
        assert args[0] == 100.0  # 100% failure rate


class TestCircuitBreakerOpenToHalfOpen:
    """Circuit breaker: open→half-open transition."""

    @pytest.mark.asyncio
    async def test_transitions_to_half_open_after_recovery_timeout(self):
        """After 60s in OPEN state, circuit transitions to HALF_OPEN."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold_pct=50.0,
            window_seconds=30.0,
            min_requests=5,
            recovery_timeout_seconds=60.0,
        ))

        async def failure_fn():
            raise RuntimeError("fail")

        # Force open
        for _ in range(5):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)

        assert cb.state == CircuitState.OPEN

        # Simulate 60s elapsed
        cb._opened_at = time.time() - 61.0

        # State property should now report HALF_OPEN
        assert cb.state == CircuitState.HALF_OPEN


class TestCircuitBreakerHalfOpenToClosed:
    """Circuit breaker: half-open→closed transition."""

    @pytest.mark.asyncio
    async def test_closes_on_successful_probe(self):
        """Successful probe in HALF_OPEN closes the circuit (Req 4.3)."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold_pct=50.0,
            window_seconds=30.0,
            min_requests=5,
            recovery_timeout_seconds=60.0,
        ))

        async def failure_fn():
            raise RuntimeError("fail")

        async def success_fn():
            return "recovered"

        # Force open then half-open
        for _ in range(5):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)
        cb._opened_at = time.time() - 61.0
        assert cb.state == CircuitState.HALF_OPEN

        # Successful probe should close the circuit
        result = await cb.call(success_fn)
        assert result == "recovered"
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_closed_circuit_passes_all_requests(self):
        """After closing, all requests pass through normally again."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold_pct=50.0,
            window_seconds=30.0,
            min_requests=5,
            recovery_timeout_seconds=60.0,
        ))

        async def failure_fn():
            raise RuntimeError("fail")

        async def success_fn():
            return "ok"

        # Open → half-open → close
        for _ in range(5):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)
        cb._opened_at = time.time() - 61.0
        await cb.call(success_fn)
        assert cb.state == CircuitState.CLOSED

        # Multiple requests should all pass now
        for _ in range(10):
            result = await cb.call(success_fn)
            assert result == "ok"


class TestCircuitBreakerHalfOpenToOpen:
    """Circuit breaker: half-open→open transition."""

    @pytest.mark.asyncio
    async def test_reopens_on_failed_probe(self):
        """Failed probe in HALF_OPEN re-opens the circuit (Req 4.4)."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold_pct=50.0,
            window_seconds=30.0,
            min_requests=5,
            recovery_timeout_seconds=60.0,
        ))

        async def failure_fn():
            raise RuntimeError("fail")

        # Force open then half-open
        for _ in range(5):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)
        cb._opened_at = time.time() - 61.0
        assert cb.state == CircuitState.HALF_OPEN

        # Failed probe should re-open
        with pytest.raises(RuntimeError):
            await cb.call(failure_fn)

        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_reopened_circuit_rejects_immediately(self):
        """After re-opening from half-open, requests are rejected."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold_pct=50.0,
            window_seconds=30.0,
            min_requests=5,
            recovery_timeout_seconds=60.0,
        ))

        async def failure_fn():
            raise RuntimeError("fail")

        async def success_fn():
            return "ok"

        # Open → half-open → re-open
        for _ in range(5):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)
        cb._opened_at = time.time() - 61.0
        with pytest.raises(RuntimeError):
            await cb.call(failure_fn)

        assert cb.state == CircuitState.OPEN

        # Should reject immediately
        with pytest.raises(CircuitBreakerOpenError):
            await cb.call(success_fn)

    @pytest.mark.asyncio
    async def test_only_one_probe_allowed_in_half_open(self):
        """In HALF_OPEN, only one probe passes; others are rejected."""
        cb = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold_pct=50.0,
            window_seconds=30.0,
            min_requests=5,
            recovery_timeout_seconds=60.0,
        ))

        async def failure_fn():
            raise RuntimeError("fail")

        # Force open then half-open
        for _ in range(5):
            with pytest.raises(RuntimeError):
                await cb.call(failure_fn)
        cb._opened_at = time.time() - 61.0
        assert cb.state == CircuitState.HALF_OPEN

        # Manually set probe in-flight to simulate concurrent request
        cb._half_open_probe_in_flight = True

        async def success_fn():
            return "ok"

        # Second request should be rejected while probe is in-flight
        with pytest.raises(CircuitBreakerOpenError):
            await cb.call(success_fn)


# ===========================================================================
# Section 4: Session Timeout Tests (Requirement 2.2)
# ===========================================================================


class TestSessionTimeout:
    """Session timeout: active session, idle expiry, re-authentication flow."""

    def test_active_session_not_expired(self):
        """Session with recent activity is not expired."""
        now = time.time()
        entry = SessionEntry(user_id="user-1", last_activity=now, created_at=now)
        assert not entry.is_expired(now)

    def test_session_expires_after_45min_idle(self):
        """Session becomes expired after 45 minutes of no activity."""
        now = time.time()
        entry = SessionEntry(
            user_id="user-1",
            last_activity=now - SESSION_IDLE_TIMEOUT_SECONDS - 1,
            created_at=now - 7200,
        )
        assert entry.is_expired(now)

    def test_session_not_expired_at_boundary(self):
        """Session at exactly 45min boundary is NOT expired (> not >=)."""
        now = time.time()
        entry = SessionEntry(
            user_id="user-1",
            last_activity=now - SESSION_IDLE_TIMEOUT_SECONDS,
            created_at=now - 7200,
        )
        assert not entry.is_expired(now)

    def test_touch_resets_idle_timer(self):
        """Touching a session resets the idle countdown."""
        now = time.time()
        entry = SessionEntry(
            user_id="user-1",
            last_activity=now - SESSION_IDLE_TIMEOUT_SECONDS - 60,
            created_at=now - 7200,
        )
        assert entry.is_expired(now)
        entry.touch(now)
        assert not entry.is_expired(now)

    def test_session_store_invalidation(self):
        """Invalidated session is removed and cannot be retrieved."""
        store = SessionStore()
        store.create("session-abc", "user-1")
        assert store.get("session-abc") is not None
        store.invalidate("session-abc")
        assert store.get("session-abc") is None

    def test_expired_session_triggers_reauth(self):
        """Expired session from store is cleaned up correctly."""
        store = SessionStore()
        now = time.time()
        store.create("session-old", "user-1", now=now - SESSION_IDLE_TIMEOUT_SECONDS - 60)
        store.create("session-new", "user-2", now=now)

        removed = store.cleanup_expired(now=now)
        assert removed == 1
        assert store.get("session-old") is None
        assert store.get("session-new") is not None

    def test_session_store_touch_updates_activity(self):
        """Touching via store updates the session's last_activity."""
        store = SessionStore()
        now = time.time()
        store.create("s1", "user-1", now=now - 1000)
        store.touch("s1", now=now)
        entry = store.get("s1")
        assert entry is not None
        assert entry.last_activity == now
        assert not entry.is_expired(now)


# ===========================================================================
# Section 5: Circuit Breaker Singleton Tests
# ===========================================================================


class TestCircuitBreakerSingleton:
    """Tests for module-level circuit breaker singleton management."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuit_breaker()
        yield
        reset_circuit_breaker()

    def test_singleton_returns_same_instance(self):
        cb1 = get_circuit_breaker()
        cb2 = get_circuit_breaker()
        assert cb1 is cb2

    def test_reset_creates_new_instance(self):
        cb1 = get_circuit_breaker()
        reset_circuit_breaker()
        cb2 = get_circuit_breaker()
        assert cb1 is not cb2
