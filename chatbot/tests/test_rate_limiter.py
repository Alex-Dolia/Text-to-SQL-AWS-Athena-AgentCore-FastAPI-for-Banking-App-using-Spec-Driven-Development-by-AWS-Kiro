"""Unit tests for the rate limiting middleware (chatbot/api/rate_limiter.py).

Tests cover: under limit, at limit, over limit, bucket refill, concurrent
requests, Retry-After header values, consecutive rate-limiting alerts, and
multiple users.

Requirements: 3.1, 3.2, 3.3, 3.4
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest

from chatbot.api.rate_limiter import (
    RateLimiter,
    RateLimitExceeded,
    get_rate_limiter,
    reset_rate_limiter,
)


@pytest.fixture
def limiter() -> RateLimiter:
    """Create a fresh RateLimiter for each test."""
    return RateLimiter()


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset the module-level singleton between tests."""
    reset_rate_limiter()
    yield
    reset_rate_limiter()


class TestUnderLimit:
    """Tests that requests under the rate limit succeed."""

    @pytest.mark.asyncio
    async def test_first_request_succeeds(self, limiter: RateLimiter):
        """First request from a user always succeeds."""
        await limiter.check_rate_limit("user-1")
        state = limiter.get_bucket_state("user-1")
        assert state is not None
        assert state["tokens"] == 29

    @pytest.mark.asyncio
    async def test_requests_up_to_limit_succeed(self, limiter: RateLimiter):
        """Exactly 30 requests within a window all succeed."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")

        state = limiter.get_bucket_state("user-1")
        assert state["tokens"] == 0

    @pytest.mark.asyncio
    async def test_different_users_have_independent_buckets(self, limiter: RateLimiter):
        """Each user has their own independent rate limit bucket."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")

        # user-2 should still be able to make requests
        await limiter.check_rate_limit("user-2")
        state = limiter.get_bucket_state("user-2")
        assert state["tokens"] == 29


class TestOverLimit:
    """Tests that requests over the rate limit are rejected."""

    @pytest.mark.asyncio
    async def test_31st_request_raises_rate_limit_exceeded(self, limiter: RateLimiter):
        """Request #31 within a window raises RateLimitExceeded."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")

        with pytest.raises(RateLimitExceeded):
            await limiter.check_rate_limit("user-1")

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded_has_retry_after(self, limiter: RateLimiter):
        """RateLimitExceeded contains a valid retry_after value (1-60)."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")

        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter.check_rate_limit("user-1")

        assert 1 <= exc_info.value.retry_after <= 60

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded_has_error_message(self, limiter: RateLimiter):
        """RateLimitExceeded contains a user-facing error message (Req 3.4)."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")

        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter.check_rate_limit("user-1")

        assert "Rate limit exceeded" in exc_info.value.message
        assert "retry after" in exc_info.value.message.lower()

    @pytest.mark.asyncio
    async def test_multiple_rejected_requests_still_rejected(self, limiter: RateLimiter):
        """Multiple requests after exhaustion are all rejected."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")

        for _ in range(5):
            with pytest.raises(RateLimitExceeded):
                await limiter.check_rate_limit("user-1")


class TestBucketRefill:
    """Tests for the 60-second window reset and token refill (Req 3.2)."""

    @pytest.mark.asyncio
    async def test_bucket_refills_after_window_expires(self, limiter: RateLimiter):
        """Tokens are fully restored after the 60-second window elapses."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")

        # Simulate window reset by advancing the window start time
        bucket = limiter._buckets["user-1"]
        bucket.window_start = time.time() - 61  # Window expired

        # Should succeed again
        await limiter.check_rate_limit("user-1")
        state = limiter.get_bucket_state("user-1")
        assert state["tokens"] == 29  # 30 - 1 = 29

    @pytest.mark.asyncio
    async def test_partial_consumption_resets_on_window_expiry(self, limiter: RateLimiter):
        """Even partially consumed tokens refill to full 30 on window reset."""
        for _ in range(15):
            await limiter.check_rate_limit("user-1")

        state = limiter.get_bucket_state("user-1")
        assert state["tokens"] == 15

        # Expire the window
        bucket = limiter._buckets["user-1"]
        bucket.window_start = time.time() - 61

        await limiter.check_rate_limit("user-1")
        state = limiter.get_bucket_state("user-1")
        assert state["tokens"] == 29  # Full refill minus the 1 just consumed

    @pytest.mark.asyncio
    async def test_retry_after_reflects_time_remaining(self, limiter: RateLimiter):
        """retry_after decreases as time passes within the window."""
        for _ in range(30):
            await limiter.check_rate_limit("user-1")

        # Simulate being 50 seconds into the window
        bucket = limiter._buckets["user-1"]
        bucket.window_start = time.time() - 50

        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter.check_rate_limit("user-1")

        # Should be approximately 10 seconds remaining
        assert exc_info.value.retry_after <= 11
        assert exc_info.value.retry_after >= 1


class TestConsecutiveRateLimiting:
    """Tests for investigation alert on sustained rate limiting (Req 3.3)."""

    @pytest.mark.asyncio
    async def test_alert_triggered_after_threshold_exceeded(self):
        """Investigation alert fires after >10 consecutive minutes of rate limiting."""
        alert_mock = AsyncMock()
        limiter = RateLimiter(alert_callback=alert_mock)

        user_id = "user-abusive"
        base_time = time.time()

        # Simulate rate limiting for 11 consecutive minutes by directly
        # manipulating bucket state and using the correct patch target.
        with patch("chatbot.api.rate_limiter.time.time") as mock_time:
            # First: create and exhaust the bucket at minute 0
            mock_time.return_value = base_time
            for _ in range(30):
                await limiter.check_rate_limit(user_id)

            # Now simulate being rate-limited in each consecutive minute
            for minute in range(11):
                current_time = base_time + (minute * 60) + 30
                mock_time.return_value = current_time

                # Keep the bucket exhausted within its current window
                bucket = limiter._buckets[user_id]
                bucket.tokens = 0
                bucket.window_start = current_time  # fresh window, no tokens

                try:
                    await limiter.check_rate_limit(user_id)
                except RateLimitExceeded:
                    pass

        # Alert should have been triggered
        assert alert_mock.called
        alert_mock.assert_called_with(user_id, 11)

    @pytest.mark.asyncio
    async def test_no_alert_under_threshold(self):
        """No alert when rate-limited for fewer than 10 consecutive minutes."""
        alert_mock = AsyncMock()
        limiter = RateLimiter(alert_callback=alert_mock)

        user_id = "user-normal"
        base_time = time.time()

        with patch("chatbot.api.rate_limiter.time.time") as mock_time:
            # Create and exhaust the bucket
            mock_time.return_value = base_time
            for _ in range(30):
                await limiter.check_rate_limit(user_id)

            # Simulate rate limiting for 5 consecutive minutes (under threshold)
            for minute in range(5):
                current_time = base_time + (minute * 60) + 30
                mock_time.return_value = current_time

                bucket = limiter._buckets[user_id]
                bucket.tokens = 0
                bucket.window_start = current_time

                try:
                    await limiter.check_rate_limit(user_id)
                except RateLimitExceeded:
                    pass

        alert_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_consecutive_counter_resets_on_successful_request(self, limiter: RateLimiter):
        """Consecutive rate-limit counter resets when user makes a successful request."""
        user_id = "user-1"
        for _ in range(30):
            await limiter.check_rate_limit(user_id)

        # One rate-limited request
        try:
            await limiter.check_rate_limit(user_id)
        except RateLimitExceeded:
            pass

        state = limiter.get_bucket_state(user_id)
        assert state["consecutive_limited_minutes"] >= 1

        # Expire window, make successful request
        bucket = limiter._buckets[user_id]
        bucket.window_start = time.time() - 61

        await limiter.check_rate_limit(user_id)

        state = limiter.get_bucket_state(user_id)
        assert state["consecutive_limited_minutes"] == 0


class TestConcurrentRequests:
    """Tests for thread safety with concurrent requests."""

    @pytest.mark.asyncio
    async def test_concurrent_requests_respect_limit(self):
        """Concurrent requests from same user don't exceed the limit."""
        limiter = RateLimiter()

        async def make_request() -> bool:
            try:
                await limiter.check_rate_limit("user-concurrent")
                return True
            except RateLimitExceeded:
                return False

        # Fire 50 concurrent requests — only 30 should succeed
        tasks = [make_request() for _ in range(50)]
        results = await asyncio.gather(*tasks)

        successes = sum(1 for r in results if r)
        failures = sum(1 for r in results if not r)

        assert successes == 30
        assert failures == 20


class TestCustomConfiguration:
    """Tests for configurable rate limiter parameters."""

    @pytest.mark.asyncio
    async def test_custom_max_requests(self):
        """Custom max_requests value is respected."""
        limiter = RateLimiter(max_requests=5)

        for _ in range(5):
            await limiter.check_rate_limit("user-1")

        with pytest.raises(RateLimitExceeded):
            await limiter.check_rate_limit("user-1")

    @pytest.mark.asyncio
    async def test_custom_window_seconds(self):
        """Custom window_seconds value is respected."""
        limiter = RateLimiter(window_seconds=10)

        for _ in range(30):
            await limiter.check_rate_limit("user-1")

        # Expire the short window
        bucket = limiter._buckets["user-1"]
        bucket.window_start = time.time() - 11

        await limiter.check_rate_limit("user-1")  # Should succeed


class TestSingleton:
    """Tests for the module-level singleton."""

    def test_get_rate_limiter_returns_singleton(self):
        """get_rate_limiter returns the same instance on repeated calls."""
        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()
        assert limiter1 is limiter2

    def test_reset_rate_limiter_clears_singleton(self):
        """reset_rate_limiter creates a new instance on next call."""
        limiter1 = get_rate_limiter()
        reset_rate_limiter()
        limiter2 = get_rate_limiter()
        assert limiter1 is not limiter2
