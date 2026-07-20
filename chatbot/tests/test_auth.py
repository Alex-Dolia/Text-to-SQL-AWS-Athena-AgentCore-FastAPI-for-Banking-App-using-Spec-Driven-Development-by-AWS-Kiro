"""Unit tests for JWT validation module (chatbot/api/auth.py).

Tests validate_jwt() with valid tokens, expired tokens, wrong audience,
wrong issuer, invalid signatures, and missing claims.

Requirements: 1.1, 1.2, 1.4, 1.5, 2.1, 18.2, 18.6
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jose import jwt

from chatbot.api.auth import (
    AuthConfig,
    AuthenticationError,
    JWKSCache,
    _CachedJWKS,
    validate_jwt,
)
from chatbot.api.models import UserClaims


# --- Test helpers ---

# Generate a real RSA key pair for testing
_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_rsa_public_key = _rsa_private_key.public_key()

# PEM format for python-jose signing
TEST_RSA_PRIVATE_PEM = _rsa_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

TEST_RSA_PUBLIC_PEM = _rsa_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# JWK format for the JWKS cache (public key only, used for verification)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
import base64

_pub_numbers = _rsa_public_key.public_numbers()


def _int_to_base64url(n: int) -> str:
    """Convert an integer to base64url-encoded string (JWK format)."""
    byte_length = (n.bit_length() + 7) // 8
    n_bytes = n.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")


TEST_RSA_PUBLIC_KEY = {
    "kty": "RSA",
    "kid": "test-key-1",
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


def make_test_token(
    claims: dict | None = None,
    key: bytes | None = None,
    algorithm: str = "RS256",
    headers: dict | None = None,
) -> str:
    """Create a signed JWT for testing."""
    now = int(time.time())
    default_claims = {
        "sub": "user-abc-123",
        "aud": TEST_CONFIG.audience,
        "iss": TEST_CONFIG.issuer,
        "exp": now + 900,  # 15 minutes from now
        "iat": now,
        "custom:department": "analytics",
        "custom:role": "analyst",
        "custom:data-classification-tier": "internal",
        "cognito:groups": ["data-users", "analytics-team"],
        "event_id": str(uuid.uuid4()),
    }
    if claims:
        default_claims.update(claims)

    signing_key = key or TEST_RSA_PRIVATE_PEM
    token_headers = headers or {"kid": "test-key-1"}

    return jwt.encode(default_claims, signing_key, algorithm=algorithm, headers=token_headers)


def make_mock_jwks_cache(keys: dict | None = None) -> JWKSCache:
    """Create a JWKSCache with pre-loaded keys (no network calls)."""
    cache = JWKSCache(TEST_CONFIG)
    # Pre-populate cache so no HTTP calls are needed
    cache._cache = _CachedJWKS(
        keys=keys or {"test-key-1": TEST_RSA_PUBLIC_KEY},
        fetched_at=time.time(),
        ttl_seconds=300.0,
    )
    return cache


# --- Tests ---


class TestValidateJWT:
    """Tests for validate_jwt() core functionality."""

    @pytest.mark.asyncio
    async def test_valid_token_returns_user_claims(self):
        """Valid token with all required claims returns UserClaims."""
        token = make_test_token()
        cache = make_mock_jwks_cache()

        result = await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)

        assert isinstance(result, UserClaims)
        assert result.sub == "user-abc-123"
        assert result.department == "analytics"
        assert result.role == "analyst"
        assert result.data_classification_tier == "internal"
        assert result.groups == ["data-users", "analytics-team"]
        assert result.exp > 0

    @pytest.mark.asyncio
    async def test_empty_token_raises_error(self):
        """Empty token string raises AuthenticationError."""
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Token is required"):
            await validate_jwt("", config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_whitespace_only_token_raises_error(self):
        """Whitespace-only token raises AuthenticationError."""
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Token is required"):
            await validate_jwt("   ", config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_expired_token_raises_error(self):
        """Token with exp in the past raises AuthenticationError."""
        token = make_test_token(claims={"exp": int(time.time()) - 3600})
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Token has expired"):
            await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_wrong_audience_raises_error(self):
        """Token with wrong audience raises AuthenticationError."""
        token = make_test_token(claims={"aud": "wrong-client-id"})
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Invalid token audience"):
            await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_wrong_issuer_raises_error(self):
        """Token with wrong issuer raises AuthenticationError."""
        token = make_test_token(claims={"iss": "https://wrong-issuer.example.com"})
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Invalid token issuer"):
            await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_invalid_signature_raises_error(self):
        """Token signed with wrong key raises AuthenticationError."""
        # Tamper with the token to invalidate signature
        token = make_test_token()
        # Corrupt the signature portion
        parts = token.split(".")
        corrupted_sig = parts[2][:-5] + "XXXXX"
        tampered_token = f"{parts[0]}.{parts[1]}.{corrupted_sig}"
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Invalid token signature"):
            await validate_jwt(tampered_token, config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_malformed_token_raises_error(self):
        """Completely malformed token raises AuthenticationError."""
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Invalid token format"):
            await validate_jwt("not.a.valid.jwt.token", config=TEST_CONFIG, jwks_cache=cache)


class TestMissingRequiredClaims:
    """Tests for missing required claims — must return specific error (Req 1.5)."""

    @pytest.mark.asyncio
    async def test_missing_department_raises_error(self):
        """Token without custom:department raises specific error."""
        claims = {
            "custom:role": "analyst",
            "custom:data-classification-tier": "internal",
            "cognito:groups": ["team"],
            "event_id": str(uuid.uuid4()),
        }
        # Remove default department by not including it
        token = make_test_token(claims={"custom:department": None})
        # Need to create token without the claim entirely
        now = int(time.time())
        raw_claims = {
            "sub": "user-abc-123",
            "aud": TEST_CONFIG.audience,
            "iss": TEST_CONFIG.issuer,
            "exp": now + 900,
            "iat": now,
            "custom:role": "analyst",
            "custom:data-classification-tier": "internal",
            "cognito:groups": ["team"],
            "event_id": str(uuid.uuid4()),
        }
        token = jwt.encode(
            raw_claims, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key-1"}
        )
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Missing required claim: department"):
            await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_missing_role_raises_error(self):
        """Token without custom:role raises specific error."""
        now = int(time.time())
        raw_claims = {
            "sub": "user-abc-123",
            "aud": TEST_CONFIG.audience,
            "iss": TEST_CONFIG.issuer,
            "exp": now + 900,
            "iat": now,
            "custom:department": "analytics",
            "custom:data-classification-tier": "internal",
            "cognito:groups": ["team"],
            "event_id": str(uuid.uuid4()),
        }
        token = jwt.encode(
            raw_claims, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key-1"}
        )
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Missing required claim: role"):
            await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_missing_data_classification_tier_raises_error(self):
        """Token without custom:data-classification-tier raises specific error."""
        now = int(time.time())
        raw_claims = {
            "sub": "user-abc-123",
            "aud": TEST_CONFIG.audience,
            "iss": TEST_CONFIG.issuer,
            "exp": now + 900,
            "iat": now,
            "custom:department": "analytics",
            "custom:role": "analyst",
            "cognito:groups": ["team"],
            "event_id": str(uuid.uuid4()),
        }
        token = jwt.encode(
            raw_claims, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key-1"}
        )
        cache = make_mock_jwks_cache()

        with pytest.raises(
            AuthenticationError, match="Missing required claim: data_classification_tier"
        ):
            await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_missing_groups_raises_error(self):
        """Token without groups claim raises specific error."""
        now = int(time.time())
        raw_claims = {
            "sub": "user-abc-123",
            "aud": TEST_CONFIG.audience,
            "iss": TEST_CONFIG.issuer,
            "exp": now + 900,
            "iat": now,
            "custom:department": "analytics",
            "custom:role": "analyst",
            "custom:data-classification-tier": "internal",
            "event_id": str(uuid.uuid4()),
        }
        token = jwt.encode(
            raw_claims, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key-1"}
        )
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Missing required claim: groups"):
            await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)

    @pytest.mark.asyncio
    async def test_empty_department_raises_error(self):
        """Token with empty custom:department raises specific error."""
        token = make_test_token(claims={"custom:department": ""})
        cache = make_mock_jwks_cache()

        with pytest.raises(AuthenticationError, match="Missing required claim: department"):
            await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)


class TestClaimMapping:
    """Tests for custom claim mapping from Cognito names to UserClaims fields."""

    @pytest.mark.asyncio
    async def test_maps_custom_department(self):
        """custom:department maps to UserClaims.department."""
        token = make_test_token(claims={"custom:department": "risk-management"})
        cache = make_mock_jwks_cache()

        result = await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
        assert result.department == "risk-management"

    @pytest.mark.asyncio
    async def test_maps_custom_role(self):
        """custom:role maps to UserClaims.role."""
        token = make_test_token(claims={"custom:role": "manager"})
        cache = make_mock_jwks_cache()

        result = await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
        assert result.role == "manager"

    @pytest.mark.asyncio
    async def test_maps_custom_data_classification_tier(self):
        """custom:data-classification-tier maps to UserClaims.data_classification_tier."""
        token = make_test_token(claims={"custom:data-classification-tier": "confidential"})
        cache = make_mock_jwks_cache()

        result = await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
        assert result.data_classification_tier == "confidential"

    @pytest.mark.asyncio
    async def test_maps_cognito_groups(self):
        """cognito:groups maps to UserClaims.groups."""
        token = make_test_token(
            claims={"cognito:groups": ["admin", "data-eng", "elevated_cost"]}
        )
        cache = make_mock_jwks_cache()

        result = await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
        assert result.groups == ["admin", "data-eng", "elevated_cost"]

    @pytest.mark.asyncio
    async def test_maps_custom_groups_as_fallback(self):
        """custom:groups used when cognito:groups is absent."""
        now = int(time.time())
        raw_claims = {
            "sub": "user-abc-123",
            "aud": TEST_CONFIG.audience,
            "iss": TEST_CONFIG.issuer,
            "exp": now + 900,
            "iat": now,
            "custom:department": "analytics",
            "custom:role": "analyst",
            "custom:data-classification-tier": "internal",
            "custom:groups": ["team-a", "team-b"],
            "event_id": str(uuid.uuid4()),
        }
        token = jwt.encode(
            raw_claims, TEST_RSA_PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key-1"}
        )
        cache = make_mock_jwks_cache()

        result = await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
        assert result.groups == ["team-a", "team-b"]

    @pytest.mark.asyncio
    async def test_session_id_from_event_id(self):
        """event_id from Cognito token maps to session_id."""
        event_id = str(uuid.uuid4())
        token = make_test_token(claims={"event_id": event_id})
        cache = make_mock_jwks_cache()

        result = await validate_jwt(token, config=TEST_CONFIG, jwks_cache=cache)
        assert result.session_id == event_id


class TestJWKSCache:
    """Tests for JWKS key caching behavior."""

    @pytest.mark.asyncio
    async def test_cache_returns_keys_without_network_when_fresh(self):
        """Cached keys returned without HTTP call when within TTL."""
        cache = make_mock_jwks_cache()
        keys = await cache.get_signing_keys()
        assert "test-key-1" in keys

    @pytest.mark.asyncio
    async def test_cache_refreshes_after_ttl_expires(self):
        """Keys are re-fetched after TTL expires."""
        cache = JWKSCache(TEST_CONFIG, ttl_seconds=300.0)
        # Set cache with expired TTL
        cache._cache = _CachedJWKS(
            keys={"test-key-1": TEST_RSA_PUBLIC_KEY},
            fetched_at=time.time() - 400,  # Expired
            ttl_seconds=300.0,
        )

        # Mock the HTTP client to return fresh keys
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = lambda: None
        mock_response.json.return_value = {"keys": [TEST_RSA_PUBLIC_KEY]}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        cache._http_client = mock_client

        keys = await cache.get_signing_keys()
        assert "test-key-1" in keys
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_falls_back_to_stale_keys_on_network_error(self):
        """If JWKS fetch fails but stale keys exist, use stale keys."""
        cache = JWKSCache(TEST_CONFIG, ttl_seconds=300.0)
        # Set cache with expired TTL but valid keys
        cache._cache = _CachedJWKS(
            keys={"test-key-1": TEST_RSA_PUBLIC_KEY},
            fetched_at=time.time() - 400,  # Expired
            ttl_seconds=300.0,
        )

        # Mock HTTP client that fails
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Network error")
        cache._http_client = mock_client

        keys = await cache.get_signing_keys()
        assert "test-key-1" in keys  # Falls back to stale

    @pytest.mark.asyncio
    async def test_cache_raises_when_no_keys_and_network_fails(self):
        """Raises AuthenticationError if no cached keys and fetch fails."""
        cache = JWKSCache(TEST_CONFIG)
        # Empty cache, no keys
        cache._cache = _CachedJWKS(keys={}, fetched_at=0.0, ttl_seconds=300.0)

        # Mock HTTP client that fails
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Network error")
        cache._http_client = mock_client

        with pytest.raises(AuthenticationError, match="authentication service unavailable"):
            await cache.get_signing_keys()

    @pytest.mark.asyncio
    async def test_get_key_for_token_with_unknown_kid(self):
        """Token with unknown kid triggers refresh, then raises if still not found."""
        cache = JWKSCache(TEST_CONFIG, ttl_seconds=300.0)
        cache._cache = _CachedJWKS(
            keys={"test-key-1": TEST_RSA_PUBLIC_KEY},
            fetched_at=time.time(),
            ttl_seconds=300.0,
        )

        # Create token with different kid
        token = make_test_token(headers={"kid": "unknown-key-99"})

        # Mock refresh that still doesn't have the key
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = lambda: None
        mock_response.json.return_value = {"keys": [TEST_RSA_PUBLIC_KEY]}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        cache._http_client = mock_client

        with pytest.raises(AuthenticationError, match="Token signed with unrecognized key"):
            await cache.get_key_for_token(token)


class TestAuthConfig:
    """Tests for AuthConfig configuration."""

    def test_issuer_url_format(self):
        """Issuer URL correctly constructed from region and pool ID."""
        config = AuthConfig(
            cognito_user_pool_id="us-west-2_AbcDef123",
            cognito_region="us-west-2",
            cognito_app_client_id="client-xyz",
        )
        assert config.issuer == "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_AbcDef123"

    def test_jwks_url_format(self):
        """JWKS URL appends well-known path to issuer."""
        config = AuthConfig(
            cognito_user_pool_id="eu-west-1_Pool99",
            cognito_region="eu-west-1",
            cognito_app_client_id="client-abc",
        )
        expected = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Pool99/.well-known/jwks.json"
        assert config.jwks_url == expected

    def test_audience_is_app_client_id(self):
        """Audience is the Cognito app client ID."""
        config = AuthConfig(
            cognito_user_pool_id="us-east-1_Pool1",
            cognito_region="us-east-1",
            cognito_app_client_id="my-client-id",
        )
        assert config.audience == "my-client-id"
