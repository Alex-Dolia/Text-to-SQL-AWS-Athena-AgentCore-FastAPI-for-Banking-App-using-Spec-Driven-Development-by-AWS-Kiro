"""Per-user token bucket rate limiter for the FastAPI auth layer.

Implements a fixed-window token bucket (30 requests per 60-second window)
with automatic refill on window reset. Tracks consecutive rate-limited
minutes per user and triggers investigation alerts when threshold exceeded.

Requirements: 3.1, 3.2, 3.3, 3.4
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class _UserBucket:
    """Per-user rate limit state for a single window."""

    tokens: int = 30
    window_start: float = 0.0
    consecutive_limited_minutes: int = 0
    last_limited_minute: float = 0.0


class RateLimitExceeded(Exception):
    """Raised when a user exceeds their rate limit allowance.

    Attributes:
        retry_after: Seconds remaining until the window resets (1-60).
        message: User-facing error message.
    """

    def __init__(self, retry_after: int, message: str) -> None:
        self.retry_after = retry_after
        self.message = message
        super().__init__(message)


class RateLimiter:
    """Token bucket rate limiter with per-user tracking.

    Each authenticated user gets 30 requests per 60-second window.
    When the window resets, the full allowance is restored. If a user
    is continuously rate-limited for >10 consecutive minutes, an
    investigation alert is triggered.

    Thread-safe via asyncio.Lock for concurrent request handling.
    """

    MAX_REQUESTS_PER_WINDOW: int = 30
    WINDOW_SECONDS: int = 60
    ALERT_THRESHOLD_MINUTES: int = 10

    def __init__(
        self,
        max_requests: int | None = None,
        window_seconds: int | None = None,
        alert_threshold_minutes: int | None = None,
        alert_callback: object | None = None,
    ) -> None:
        """Initialize the rate limiter.

        Args:
            max_requests: Override max requests per window (default 30).
            window_seconds: Override window duration in seconds (default 60).
            alert_threshold_minutes: Override alert threshold (default 10).
            alert_callback: Async callable invoked when investigation alert
                triggers. Signature: async def callback(user_id: str, minutes: int).
        """
        self._max_requests = max_requests or self.MAX_REQUESTS_PER_WINDOW
        self._window_seconds = window_seconds or self.WINDOW_SECONDS
        self._alert_threshold = alert_threshold_minutes or self.ALERT_THRESHOLD_MINUTES
        self._alert_callback = alert_callback
        self._buckets: dict[str, _UserBucket] = {}
        self._lock = asyncio.Lock()

    async def check_rate_limit(self, user_id: str) -> None:
        """Check and consume a rate limit token for the given user.

        If the user has tokens remaining in the current window, one token
        is consumed and the method returns normally. If no tokens remain,
        raises RateLimitExceeded with the appropriate retry_after value.

        Args:
            user_id: The authenticated user's unique identifier (sub claim).

        Raises:
            RateLimitExceeded: When the user has exceeded 30 requests in the
                current 60-second window. Contains retry_after (seconds until
                reset) and a user-facing error message.
        """
        async with self._lock:
            now = time.time()
            bucket = self._get_or_create_bucket(user_id, now)

            # Check if window has reset — refill tokens
            elapsed = now - bucket.window_start
            if elapsed >= self._window_seconds:
                self._refill_bucket(bucket, now)

            # Attempt to consume a token
            if bucket.tokens > 0:
                bucket.tokens -= 1
                # User made a successful request — reset consecutive counter
                self._reset_consecutive_tracking(bucket)
                return

            # Rate limit exceeded
            retry_after = self._calculate_retry_after(bucket, now)
            await self._track_consecutive_limiting(user_id, bucket, now)

            raise RateLimitExceeded(
                retry_after=retry_after,
                message=(
                    f"Rate limit exceeded. You have made more than "
                    f"{self._max_requests} requests in the last "
                    f"{self._window_seconds} seconds. "
                    f"Please retry after {retry_after} seconds."
                ),
            )

    def _get_or_create_bucket(self, user_id: str, now: float) -> _UserBucket:
        """Get or initialize a user's rate limit bucket."""
        if user_id not in self._buckets:
            self._buckets[user_id] = _UserBucket(
                tokens=self._max_requests,
                window_start=now,
            )
        return self._buckets[user_id]

    def _refill_bucket(self, bucket: _UserBucket, now: float) -> None:
        """Refill the bucket to full capacity and reset the window.

        Requirement 3.2: When the 60-second window resets, restore full
        30-request allowance.
        """
        bucket.tokens = self._max_requests
        bucket.window_start = now

    def _calculate_retry_after(self, bucket: _UserBucket, now: float) -> int:
        """Calculate seconds remaining until the window resets.

        Returns a value between 1 and window_seconds (inclusive).
        Requirement 3.1: Retry-After header specifies 1 to 60 seconds.
        """
        elapsed = now - bucket.window_start
        remaining = self._window_seconds - elapsed
        # Clamp to [1, window_seconds]
        return max(1, min(self._window_seconds, int(remaining) + 1))

    def _reset_consecutive_tracking(self, bucket: _UserBucket) -> None:
        """Reset consecutive rate-limit tracking when user succeeds."""
        bucket.consecutive_limited_minutes = 0
        bucket.last_limited_minute = 0.0

    async def _track_consecutive_limiting(
        self, user_id: str, bucket: _UserBucket, now: float
    ) -> None:
        """Track consecutive minutes of rate limiting and trigger alert.

        Requirement 3.3: If continuously rate-limited for >10 consecutive
        minutes, trigger investigation alert.
        """
        current_minute = int(now // 60)
        last_minute = int(bucket.last_limited_minute // 60) if bucket.last_limited_minute else 0

        if bucket.last_limited_minute == 0.0:
            # First time being rate-limited
            bucket.consecutive_limited_minutes = 1
            bucket.last_limited_minute = now
        elif current_minute == last_minute:
            # Same minute — already counted
            pass
        elif current_minute == last_minute + 1:
            # Consecutive minute
            bucket.consecutive_limited_minutes += 1
            bucket.last_limited_minute = now
        else:
            # Gap in rate limiting — reset counter
            bucket.consecutive_limited_minutes = 1
            bucket.last_limited_minute = now

        # Check if alert threshold exceeded
        if bucket.consecutive_limited_minutes > self._alert_threshold:
            await self._trigger_investigation_alert(user_id, bucket.consecutive_limited_minutes)

    async def _trigger_investigation_alert(self, user_id: str, minutes: int) -> None:
        """Trigger an investigation alert for sustained rate limiting.

        Requirement 3.3: If continuously rate-limited for >10 consecutive
        minutes, trigger investigation alert to the operations team.
        """
        logger.warning(
            "INVESTIGATION_ALERT: User %s has been continuously rate-limited "
            "for %d consecutive minutes (threshold: %d minutes)",
            user_id,
            minutes,
            self._alert_threshold,
        )
        if self._alert_callback:
            try:
                await self._alert_callback(user_id, minutes)  # type: ignore[operator]
            except Exception:
                logger.exception(
                    "Failed to execute alert callback for user %s", user_id
                )

    def get_bucket_state(self, user_id: str) -> dict | None:
        """Get current bucket state for a user (for diagnostics/testing).

        Returns None if user has no bucket, otherwise returns a dict with
        tokens, window_start, and consecutive_limited_minutes.
        """
        bucket = self._buckets.get(user_id)
        if bucket is None:
            return None
        return {
            "tokens": bucket.tokens,
            "window_start": bucket.window_start,
            "consecutive_limited_minutes": bucket.consecutive_limited_minutes,
        }

    def reset(self) -> None:
        """Clear all rate limit state (for testing)."""
        self._buckets.clear()


# Module-level singleton instance
_rate_limiter: RateLimiter | None = None


def get_rate_limiter(
    alert_callback: object | None = None,
) -> RateLimiter:
    """Get or create the module-level RateLimiter singleton."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(alert_callback=alert_callback)
    return _rate_limiter


def reset_rate_limiter() -> None:
    """Reset the module-level singleton (for testing)."""
    global _rate_limiter
    _rate_limiter = None
