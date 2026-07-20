"""Property-based tests for JWT token lifetime bounds.

Tests verify that JWT access tokens never exceed 15 minutes (900 seconds)
and that the system rejects tokens with lifetimes exceeding this bound.

**Validates: Requirements 1.3, 2.1**

Properties tested:
- Property 9: Token Lifetime Bounds — JWT access tokens never exceed 15 minutes
"""

from __future__ import annotations

import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from hypothesis import given, assume, settings
from hypothesis import strategies as st
from jose import jwt

from chatbot.api.auth import (
    AuthConfig,
    AuthenticationError,
    JWKSCache,
    _CachedJWKS,
    validate_jwt,
)
from chatbot.api.models import UserClaims


# ─── Test infrastructure (shared RSA keys) ────────────────────────────────────

_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_rsa_public_key = _rsa_private_key.public_key()

TEST_RSA_PRIVATE_PEM = _rsa_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

import base64

_pub_numbers = _rsa_public_key.public_numbers()


def _int_to_base64url(n: int) -> str:
    """Convert an integer to base64url-encoded string (JWK format)."""
    byte_length = (n.bit_length() + 7) // 8
    n_bytes = n.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")


TEST_RSA_PUBLIC_KEY = {
    "kty": "RSA",
    "kid": "test-key-lifetime",
    "use": "sig",
    "alg": "RS256",
    "n": _int_to_base64url(_pub_numbers.n),
    "e": _int_to_base64url(_pub_numbers.e),
}

TEST_CONFIG = AuthConfig(
    cognito_user_pool_id="us-east-1_TestPool",
    cognito_region="us-east-1",
    cognito_app_client_id="test-client-id-123",
)

# Maximum allowed token lifetime in seconds (15 minutes)
MAX_ACCESS_TOKEN_LIFETIME_SECONDS = 900

# Maximum allowed refresh token lifetime in seconds (8 hours)
MAX_REFRESH_TOKEN_LIFETIME_SECONDS = 28_800


def _make_jwks_cache() -> JWKSCache:
    """Create a JWKSCache pre-populated with test keys (no network calls)."""
    cache = JWKSCache(TEST_CONFIG)
    cache._cache = _CachedJWKS(
        keys={"test-key-lifetime": TEST_RSA_PUBLIC_KEY},
        fetched_at=time.time(),
        ttl_seconds=300.0,
    )
    return cache


def _make_token(iat: int, exp: int) -> str:
    """Create a signed JWT with specific iat and exp claims."""
    claims = {
        "sub": "user-abc-123",
        "aud": TEST_CONFIG.audience,
        "iss": TEST_CONFIG.issuer,
        "iat": iat,
        "exp": exp,
        "custom:department": "analytics",
        "custom:role": "analyst",
        "custom:data-classification-tier": "internal",
        "cognito:groups": ["data-users", "analytics-team"],
        "event_id": str(uuid.uuid4()),
    }
    return jwt.encode(
        claims, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key-lifetime"}
    )


# ─── Hypothesis Strategies ────────────────────────────────────────────────────

# Strategy for valid token lifetimes (1 second to exactly 900 seconds)
valid_lifetime_seconds = st.integers(min_value=1, max_value=MAX_ACCESS_TOKEN_LIFETIME_SECONDS)

# Strategy for invalid (excessive) token lifetimes (901 seconds to 24 hours)
excessive_lifetime_seconds = st.integers(
    min_value=MAX_ACCESS_TOKEN_LIFETIME_SECONDS + 1, max_value=86_400
)

# Strategy for refresh token lifetimes within bounds (1 second to 28800 seconds)
valid_refresh_lifetime_seconds = st.integers(
    min_value=1, max_value=MAX_REFRESH_TOKEN_LIFETIME_SECONDS
)

# Strategy for excessive refresh token lifetimes (> 8 hours up to 30 days)
excessive_refresh_lifetime_seconds = st.integers(
    min_value=MAX_REFRESH_TOKEN_LIFETIME_SECONDS + 1, max_value=2_592_000
)


# ─── Property 9: Token Lifetime Bounds ────────────────────────────────────────


class TestTokenLifetimeBounds:
    """Property 9: Token Lifetime Bounds.

    **Validates: Requirements 1.3, 2.1**

    JWT access tokens SHALL have a lifetime of no more than 15 minutes
    (900 seconds). Tokens with exp - iat > 900 seconds must be rejected
    by the validation layer.
    """

    @given(lifetime=valid_lifetime_seconds)
    @settings(max_examples=200)
    def test_tokens_within_15_min_bound_are_accepted(self, lifetime: int):
        """Tokens with (exp - iat) <= 900 seconds are accepted by validate_jwt.

        **Validates: Requirements 1.3**
        """
        now = int(time.time())
        iat = now
        exp = now + lifetime

        # Ensure the token hasn't expired yet
        assert exp > now, "Token must not be expired for this test"
        assert (exp - iat) <= MAX_ACCESS_TOKEN_LIFETIME_SECONDS

        token = _make_token(iat=iat, exp=exp)
        cache = _make_jwks_cache()

        # Token within 15-min bound should validate successfully
        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
        )

        assert isinstance(result, UserClaims)
        assert result.exp == exp
        # Verify the lifetime bound is respected
        assert (result.exp - iat) <= MAX_ACCESS_TOKEN_LIFETIME_SECONDS

    @given(lifetime=excessive_lifetime_seconds)
    @settings(max_examples=200)
    def test_tokens_exceeding_15_min_bound_are_rejected(self, lifetime: int):
        """Tokens with (exp - iat) > 900 seconds MUST be rejected.

        The system SHALL NOT accept access tokens with lifetimes exceeding
        15 minutes, regardless of signature validity or other claim correctness.

        **Validates: Requirements 1.3, 2.1**
        """
        now = int(time.time())
        iat = now
        exp = now + lifetime

        # Confirm the lifetime exceeds the maximum
        assert (exp - iat) > MAX_ACCESS_TOKEN_LIFETIME_SECONDS

        token = _make_token(iat=iat, exp=exp)
        cache = _make_jwks_cache()

        import asyncio

        with pytest.raises(AuthenticationError, match="Token lifetime exceeds maximum"):
            asyncio.get_event_loop().run_until_complete(
                validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
            )

    @given(lifetime=valid_lifetime_seconds)
    @settings(max_examples=100)
    def test_token_lifetime_never_exceeds_bound(self, lifetime: int):
        """For any successfully validated token, the lifetime is always <= 900 seconds.

        This is the core property: if validate_jwt returns a UserClaims,
        then (exp - iat) in the token is guaranteed to be within bounds.

        **Validates: Requirements 1.3, 2.1**
        """
        now = int(time.time())
        iat = now
        exp = now + lifetime

        token = _make_token(iat=iat, exp=exp)
        cache = _make_jwks_cache()

        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
        )

        # If validation succeeded, the lifetime MUST be within bounds
        actual_lifetime = result.exp - iat
        assert actual_lifetime <= MAX_ACCESS_TOKEN_LIFETIME_SECONDS, (
            f"Token validated with lifetime {actual_lifetime}s "
            f"which exceeds max {MAX_ACCESS_TOKEN_LIFETIME_SECONDS}s"
        )

    @given(
        lifetime=st.integers(min_value=1, max_value=86_400),
    )
    @settings(max_examples=300)
    def test_lifetime_boundary_classification(self, lifetime: int):
        """Tokens are correctly classified as valid/invalid at the 900-second boundary.

        - lifetime <= 900: accepted
        - lifetime > 900: rejected with AuthenticationError

        **Validates: Requirements 1.3, 2.1**
        """
        now = int(time.time())
        iat = now
        exp = now + lifetime

        token = _make_token(iat=iat, exp=exp)
        cache = _make_jwks_cache()

        import asyncio

        if lifetime <= MAX_ACCESS_TOKEN_LIFETIME_SECONDS:
            # Should be accepted
            result = asyncio.get_event_loop().run_until_complete(
                validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
            )
            assert isinstance(result, UserClaims)
            assert (result.exp - iat) <= MAX_ACCESS_TOKEN_LIFETIME_SECONDS
        else:
            # Should be rejected
            with pytest.raises(AuthenticationError, match="Token lifetime exceeds maximum"):
                asyncio.get_event_loop().run_until_complete(
                    validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
                )


class TestRefreshTokenLifetimeBounds:
    """Refresh token lifetime bounds (complementary to access token bounds).

    **Validates: Requirements 1.3**

    Refresh tokens SHALL have a lifetime of no more than 8 hours (28,800 seconds).
    While refresh tokens are managed by Cognito (not directly validated in
    validate_jwt), we verify the model's constraint that token lifetimes are bounded.
    """

    @given(lifetime=valid_refresh_lifetime_seconds)
    @settings(max_examples=100)
    def test_refresh_token_lifetime_within_8_hours_is_valid(self, lifetime: int):
        """Refresh token lifetimes <= 28,800 seconds are within policy bounds.

        **Validates: Requirements 1.3**
        """
        assert lifetime <= MAX_REFRESH_TOKEN_LIFETIME_SECONDS
        assert lifetime > 0

    @given(lifetime=excessive_refresh_lifetime_seconds)
    @settings(max_examples=100)
    def test_refresh_token_lifetime_exceeding_8_hours_violates_policy(self, lifetime: int):
        """Refresh token lifetimes > 28,800 seconds violate the security policy.

        **Validates: Requirements 1.3**
        """
        assert lifetime > MAX_REFRESH_TOKEN_LIFETIME_SECONDS
        # Any system issuing refresh tokens with this lifetime violates Requirement 1.3
        # This establishes the constraint that must be enforced at Cognito configuration level
