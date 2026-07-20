"""JWT validation module for the FastAPI auth layer.

Validates RS256-signed JWTs from Amazon Cognito, enforcing signature,
expiry, audience, and issuer checks. Extracts and maps custom claims
to the UserClaims model. Implements JWKS key caching with 5-minute TTL
for ≤15ms validation at P95.

Requirements: 1.1, 1.2, 1.4, 1.5, 2.1, 18.2, 18.6
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError

from chatbot.api.models import UserClaims


class AuthenticationError(Exception):
    """Raised when JWT validation fails.

    Contains a specific reason indicating which validation check failed,
    without exposing internal system details (Requirement 1.8, 2.4).
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass
class AuthConfig:
    """Configuration for JWT validation, loaded from environment variables."""

    cognito_user_pool_id: str = field(
        default_factory=lambda: os.environ.get("COGNITO_USER_POOL_ID", "")
    )
    cognito_region: str = field(
        default_factory=lambda: os.environ.get("COGNITO_REGION", "us-east-1")
    )
    cognito_app_client_id: str = field(
        default_factory=lambda: os.environ.get("COGNITO_APP_CLIENT_ID", "")
    )

    @property
    def issuer(self) -> str:
        """Cognito issuer URL derived from region and user pool ID."""
        return f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.cognito_user_pool_id}"

    @property
    def jwks_url(self) -> str:
        """JWKS endpoint URL for fetching signing keys."""
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def audience(self) -> str:
        """Expected audience claim (Cognito app client ID)."""
        return self.cognito_app_client_id


@dataclass
class _CachedJWKS:
    """Internal cache for JWKS keys with TTL."""

    keys: dict[str, Any] = field(default_factory=dict)
    fetched_at: float = 0.0
    ttl_seconds: float = 300.0  # 5-minute TTL


class JWKSCache:
    """JWKS key cache with 5-minute TTL for fast JWT validation.

    Fetches keys from Cognito's /.well-known/jwks.json endpoint and caches
    them to achieve ≤15ms validation at P95 (Requirement 18.6).
    """

    def __init__(self, config: AuthConfig, ttl_seconds: float = 300.0) -> None:
        self._config = config
        self._cache = _CachedJWKS(ttl_seconds=ttl_seconds)
        self._http_client: httpx.AsyncClient | None = None

    async def get_signing_keys(self) -> dict[str, Any]:
        """Get cached JWKS keys, refreshing if TTL expired.

        Returns:
            Dict mapping key ID (kid) to key data.

        Raises:
            AuthenticationError: If JWKS endpoint is unreachable.
        """
        now = time.time()
        if self._cache.keys and (now - self._cache.fetched_at) < self._cache.ttl_seconds:
            return self._cache.keys

        return await self._refresh_keys()

    async def _refresh_keys(self) -> dict[str, Any]:
        """Fetch fresh JWKS keys from Cognito endpoint."""
        try:
            if self._http_client is None:
                self._http_client = httpx.AsyncClient(timeout=5.0)

            response = await self._http_client.get(self._config.jwks_url)
            response.raise_for_status()
            jwks_data = response.json()

            # Index keys by kid for fast lookup
            keys: dict[str, Any] = {}
            for key in jwks_data.get("keys", []):
                kid = key.get("kid")
                if kid:
                    keys[kid] = key

            self._cache.keys = keys
            self._cache.fetched_at = time.time()
            return keys

        except (httpx.HTTPError, httpx.TimeoutException, Exception) as e:
            # If we have cached keys (even expired), use them as fallback
            if self._cache.keys:
                return self._cache.keys
            raise AuthenticationError(
                "Unable to validate token: authentication service unavailable"
            ) from e

    async def get_key_for_token(self, token: str) -> dict[str, Any]:
        """Get the specific signing key for a token based on its kid header.

        Args:
            token: The JWT token string.

        Returns:
            The signing key matching the token's kid header.

        Raises:
            AuthenticationError: If the key is not found.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except JWTError as e:
            raise AuthenticationError("Invalid token format") from e

        kid = unverified_header.get("kid")
        if not kid:
            raise AuthenticationError("Token missing key identifier (kid)")

        keys = await self.get_signing_keys()

        if kid not in keys:
            # Key not found — try refreshing in case of key rotation
            keys = await self._refresh_keys()
            if kid not in keys:
                raise AuthenticationError("Token signed with unrecognized key")

        return keys[kid]

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


# Module-level singleton instances (initialized on first use)
_config: AuthConfig | None = None
_jwks_cache: JWKSCache | None = None


def get_auth_config() -> AuthConfig:
    """Get or create the module-level AuthConfig singleton."""
    global _config
    if _config is None:
        _config = AuthConfig()
    return _config


def get_jwks_cache(config: AuthConfig | None = None) -> JWKSCache:
    """Get or create the module-level JWKSCache singleton."""
    global _jwks_cache
    if _jwks_cache is None:
        _jwks_cache = JWKSCache(config or get_auth_config())
    return _jwks_cache


def reset_singletons() -> None:
    """Reset module-level singletons (for testing)."""
    global _config, _jwks_cache
    _config = None
    _jwks_cache = None


# Required custom claims that must be present in the token
REQUIRED_CUSTOM_CLAIMS = ("custom:department", "custom:role", "custom:data-classification-tier")

# Claim mapping: Cognito custom claim name → UserClaims field name
CLAIM_MAPPING = {
    "custom:department": "department",
    "custom:role": "role",
    "custom:data-classification-tier": "data_classification_tier",
}


async def validate_jwt(
    token: str,
    config: AuthConfig | None = None,
    jwks_cache: JWKSCache | None = None,
) -> UserClaims:
    """Validate JWT and extract user claims.

    Performs RS256 signature validation, expiry check, audience and issuer
    verification, then extracts and maps custom claims to UserClaims.

    Args:
        token: Bearer JWT token string.
        config: Optional AuthConfig (uses module singleton if not provided).
        jwks_cache: Optional JWKSCache (uses module singleton if not provided).

    Returns:
        UserClaims with validated and mapped claims.

    Raises:
        AuthenticationError: With specific reason if any validation check fails.
            - "Token is required" — empty token
            - "Invalid token format" — malformed JWT
            - "Token has expired" — exp < now
            - "Invalid token audience" — aud mismatch
            - "Invalid token issuer" — iss mismatch
            - "Invalid token signature" — RS256 verification failed
            - "Missing required claim: <claim>" — required custom claim absent
    """
    if not token or not token.strip():
        raise AuthenticationError("Token is required")

    auth_config = config or get_auth_config()
    cache = jwks_cache or get_jwks_cache(auth_config)

    # Get the signing key for this token
    signing_key = await cache.get_key_for_token(token)

    # Decode and validate the JWT
    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=auth_config.audience,
            issuer=auth_config.issuer,
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_sub": True,
            },
        )
    except ExpiredSignatureError as e:
        raise AuthenticationError("Token has expired") from e
    except JWTError as e:
        error_msg = str(e).lower()
        if "audience" in error_msg:
            raise AuthenticationError("Invalid token audience") from e
        if "issuer" in error_msg:
            raise AuthenticationError("Invalid token issuer") from e
        if "signature" in error_msg or "verification" in error_msg:
            raise AuthenticationError("Invalid token signature") from e
        raise AuthenticationError("Invalid token signature") from e

    # Validate token lifetime bounds (Requirement 1.3)
    # Access tokens SHALL NOT exceed 15 minutes (900 seconds)
    _validate_token_lifetime(payload)

    # Validate required claims are present
    _validate_required_claims(payload)

    # Extract and map claims to UserClaims
    return _extract_user_claims(payload)


# Maximum allowed access token lifetime: 15 minutes (Requirement 1.3)
MAX_ACCESS_TOKEN_LIFETIME_SECONDS = 900


def _validate_token_lifetime(payload: dict[str, Any]) -> None:
    """Validate that the token lifetime does not exceed the maximum bound.

    Access tokens SHALL NOT have a lifetime exceeding 15 minutes (900 seconds).
    Lifetime is calculated as (exp - iat).

    Raises:
        AuthenticationError: If token lifetime exceeds 900 seconds.
    """
    exp = payload.get("exp")
    iat = payload.get("iat")

    if exp is None or iat is None:
        # If iat is missing, we cannot validate lifetime — but exp is already
        # validated by the JWT library. Skip lifetime check if iat missing.
        return

    lifetime = exp - iat
    if lifetime > MAX_ACCESS_TOKEN_LIFETIME_SECONDS:
        raise AuthenticationError(
            f"Token lifetime exceeds maximum allowed ({MAX_ACCESS_TOKEN_LIFETIME_SECONDS}s)"
        )


def _validate_required_claims(payload: dict[str, Any]) -> None:
    """Validate that all required custom claims are present in the token payload.

    Raises:
        AuthenticationError: Specifying which required claim is missing.
    """
    for claim in REQUIRED_CUSTOM_CLAIMS:
        if claim not in payload or payload[claim] is None or payload[claim] == "":
            # Map the technical claim name to a user-friendly name
            friendly_name = CLAIM_MAPPING.get(claim, claim)
            raise AuthenticationError(f"Missing required claim: {friendly_name}")

    # Validate groups claim (can be list from cognito:groups)
    if "cognito:groups" not in payload and "custom:groups" not in payload:
        raise AuthenticationError("Missing required claim: groups")

    # Validate sub claim
    if "sub" not in payload or not payload["sub"]:
        raise AuthenticationError("Missing required claim: sub")


def _extract_user_claims(payload: dict[str, Any]) -> UserClaims:
    """Extract and map JWT claims to the UserClaims model.

    Maps Cognito custom claim names to UserClaims fields:
    - "custom:department" → department
    - "custom:role" → role
    - "custom:data-classification-tier" → data_classification_tier
    - "cognito:groups" or "custom:groups" → groups

    Args:
        payload: Decoded JWT payload dict.

    Returns:
        UserClaims with all fields populated from the token.

    Raises:
        AuthenticationError: If claims cannot be mapped to valid UserClaims.
    """
    # Extract groups — prefer cognito:groups, fall back to custom:groups
    groups = payload.get("cognito:groups") or payload.get("custom:groups", [])
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]

    # Extract session_id — use Cognito's event_id or jti, or generate from sub
    session_id = (
        payload.get("event_id")
        or payload.get("jti")
        or payload.get("custom:session_id")
        or ""
    )

    try:
        return UserClaims(
            sub=payload["sub"],
            department=payload["custom:department"],
            role=payload["custom:role"],
            data_classification_tier=payload["custom:data-classification-tier"],
            groups=groups,
            session_id=session_id,
            exp=payload["exp"],
        )
    except (KeyError, ValueError) as e:
        raise AuthenticationError(f"Invalid token claims: {e}") from e
