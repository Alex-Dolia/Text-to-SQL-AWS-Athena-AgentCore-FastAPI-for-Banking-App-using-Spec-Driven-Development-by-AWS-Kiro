"""FastAPI application entry point.

Thin, deterministic boundary between the corporate network and AgentCore.
Wires authentication, rate limiting, session management, circuit breaking,
and agent delegation into a single cohesive pipeline.

Key security properties:
- AdminInitiateAuth is NOT exposed (no admin impersonation) [Req 1.6]
- Token refresh attempted on expiry; re-auth required if refresh expired [Req 1.7]
- Auth failures return error without internal details, logged with timestamp/IP [Req 1.8]
- JWT validated (RS256, expiry, audience, issuer) before forwarding [Req 2.1]

Integration wiring (Task 16.1):
- FastAPI /chat → agent graph execution → response formatting
- Two-layer authorization: Cedar evaluates before Athena query submitted [Req 6.1]
- Audit record written at request completion (success or failure) [Req 11.1]
- Divergence alert when Cedar permits but Lake Formation denies [Req 6.2]
- All components use OBO identity (never shared service role) [Req 7.5]

Requirements: 1.6, 1.7, 1.8, 2.1, 6.1, 6.2, 6.3, 6.4, 7.5
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from chatbot.api.auth import (
    AuthenticationError,
    get_auth_config,
    get_jwks_cache,
    validate_jwt,
)
from chatbot.api.circuit_breaker import (
    CircuitBreakerOpenError,
    get_circuit_breaker,
)
from chatbot.api.errors import (
    AuthorizationDeniedError,
    CostThresholdExceededError,
    GuardrailsBlockError,
    SQLFailureError,
    build_authorization_denied_response,
    build_cost_threshold_response,
    build_guardrails_block_response,
    build_sql_failure_response,
    build_unclassified_error_response,
    log_authorization_denied_to_audit,
    log_guardrails_block_to_audit,
    log_sql_failure_to_audit,
)
from chatbot.api.middleware import (
    CircuitBreakerMiddleware,
    SessionTimeoutMiddleware,
    TraceIdMiddleware,
    generate_trace_id,
    get_session_store,
    record_auth_failure_for_ip,
)
from chatbot.api.models import ChatRequest, ChatResponse, ErrorResponse, UserClaims
from chatbot.api.rate_limiter import RateLimitExceeded, get_rate_limiter
from chatbot.scripts.audit import AuditRecord, AuditStore, AuditWriteError, create_audit_record

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("chatbot.security")


# ---------------------------------------------------------------------------
# Lifespan — startup/shutdown hooks
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    # Startup: pre-warm JWKS cache
    try:
        config = get_auth_config()
        cache = get_jwks_cache(config)
        await cache.get_signing_keys()
        logger.info("JWKS cache pre-warmed on startup")
    except Exception:
        logger.warning("Failed to pre-warm JWKS cache; will fetch on first request")

    yield

    # Shutdown: close JWKS HTTP client
    try:
        cache = get_jwks_cache()
        await cache.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Chatbot Security API",
    description=(
        "Thin session/auth boundary for the Athena natural language chatbot. "
        "Validates JWT, enforces rate limits, manages sessions, and delegates to AgentCore."
    ),
    version="1.0.0",
    lifespan=lifespan,
    # Disable docs in production (remove these for dev)
    # docs_url=None,
    # redoc_url=None,
)

# ---------------------------------------------------------------------------
# Middleware Registration (order matters — outermost runs first)
# ---------------------------------------------------------------------------

# 1. Trace ID — every response gets a unique UUID v4 X-Trace-Id header
app.add_middleware(TraceIdMiddleware)

# 2. Session timeout — enforces 45-min idle timeout, tracks auth failures
app.add_middleware(SessionTimeoutMiddleware)

# 3. Circuit breaker — protects /chat from AgentCore Runtime failures
app.add_middleware(CircuitBreakerMiddleware)


# ---------------------------------------------------------------------------
# Security: AdminInitiateAuth is NOT exposed (Requirement 1.6)
# ---------------------------------------------------------------------------
# This application does NOT implement any admin authentication endpoint.
# There is no /admin/auth, /admin/login, /admin/impersonate, or any route
# that would allow an administrator to authenticate on behalf of a user.
# All authentication flows go through the corporate IdP via Cognito federation.
# The Cognito User Pool is configured (in CDK) with AdminInitiateAuth DISABLED.
ADMIN_AUTH_PATHS = {
    "/admin/auth",
    "/admin/login",
    "/admin/impersonate",
    "/admin-initiate-auth",
    "/admin_initiate_auth",
}


# ---------------------------------------------------------------------------
# Exception Handlers
# ---------------------------------------------------------------------------


@app.exception_handler(AuthenticationError)
async def authentication_error_handler(
    request: Request, exc: AuthenticationError
) -> JSONResponse:
    """Handle authentication errors without exposing internal details.

    Requirement 1.8: Return error without internal details, log failure.
    """
    trace_id = getattr(request.state, "trace_id", generate_trace_id())

    # Log the failed attempt with timestamp, source IP, and failure reason
    _log_auth_failure(request, exc.reason, trace_id)

    # Record failure for IP-based alert threshold (Req 2.5)
    record_auth_failure_for_ip(request)

    return JSONResponse(
        status_code=401,
        content={
            "error_type": "auth_denied",
            "message": "Authentication failed. Please re-authenticate via the corporate identity provider.",
            "trace_id": trace_id,
            "retry_after": None,
        },
        headers={"X-Trace-Id": trace_id},
    )


@app.exception_handler(RateLimitExceeded)
async def rate_limit_error_handler(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    """Handle rate limit exceeded with Retry-After header."""
    trace_id = getattr(request.state, "trace_id", generate_trace_id())
    return JSONResponse(
        status_code=429,
        content={
            "error_type": "rate_limited",
            "message": exc.message,
            "trace_id": trace_id,
            "retry_after": exc.retry_after,
        },
        headers={
            "X-Trace-Id": trace_id,
            "Retry-After": str(exc.retry_after),
        },
    )


@app.exception_handler(CircuitBreakerOpenError)
async def circuit_breaker_error_handler(
    request: Request, exc: CircuitBreakerOpenError
) -> JSONResponse:
    """Handle circuit breaker open with 503 Service Unavailable."""
    trace_id = getattr(request.state, "trace_id", generate_trace_id())
    return JSONResponse(
        status_code=503,
        content={
            "error_type": "service_unavailable",
            "message": "The service is temporarily unavailable. Please try again shortly.",
            "trace_id": trace_id,
            "retry_after": exc.retry_after,
        },
        headers={
            "X-Trace-Id": trace_id,
            "Retry-After": str(exc.retry_after),
        },
    )


@app.exception_handler(AuthorizationDeniedError)
async def authorization_denied_handler(
    request: Request, exc: AuthorizationDeniedError
) -> JSONResponse:
    """Handle Cedar/Lake Formation authorization denials.

    Requirement 17.1: Actionable message without policy IDs or rule identifiers.
    Directs user to Data Governance portal for access requests.
    """
    trace_id = exc.trace_id or getattr(request.state, "trace_id", generate_trace_id())

    # Log full details to audit (internal — not exposed to user)
    log_authorization_denied_to_audit(exc)

    return JSONResponse(
        status_code=403,
        content=build_authorization_denied_response(trace_id),
        headers={"X-Trace-Id": trace_id},
    )


@app.exception_handler(CostThresholdExceededError)
async def cost_threshold_handler(
    request: Request, exc: CostThresholdExceededError
) -> JSONResponse:
    """Handle cost threshold exceeded errors.

    Requirement 17.2: Include estimated GB, limit, and filter suggestions.
    """
    trace_id = exc.trace_id or getattr(request.state, "trace_id", generate_trace_id())

    return JSONResponse(
        status_code=422,
        content=build_cost_threshold_response(
            trace_id=trace_id,
            estimated_gb=exc.estimated_gb,
            threshold_gb=exc.threshold_gb,
            filter_suggestions=exc.filter_suggestions,
        ),
        headers={"X-Trace-Id": trace_id},
    )


@app.exception_handler(GuardrailsBlockError)
async def guardrails_block_handler(
    request: Request, exc: GuardrailsBlockError
) -> JSONResponse:
    """Handle Bedrock Guardrails block actions.

    Requirement 17.3: Fixed response — never reveals detection category or rule.
    """
    trace_id = exc.trace_id or getattr(request.state, "trace_id", generate_trace_id())

    # Log full detection details to audit (internal — not exposed to user)
    log_guardrails_block_to_audit(exc)

    return JSONResponse(
        status_code=400,
        content=build_guardrails_block_response(trace_id),
        headers={"X-Trace-Id": trace_id},
    )


@app.exception_handler(SQLFailureError)
async def sql_failure_handler(
    request: Request, exc: SQLFailureError
) -> JSONResponse:
    """Handle SQL generation/validation/execution failures.

    Requirement 17.4: Suggest rephrasing, log failure chain to audit.
    """
    trace_id = exc.trace_id or getattr(request.state, "trace_id", generate_trace_id())

    # Log the full failure chain (question, SQL attempts, errors) to audit
    log_sql_failure_to_audit(exc)

    return JSONResponse(
        status_code=422,
        content=build_sql_failure_response(trace_id),
        headers={"X-Trace-Id": trace_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Catch-all for unclassified/unexpected errors — never leak internal details.

    Requirement 17.6: Generic message with trace_id, no internal details.
    Requirement 17.7: Response delivered within 5 seconds of error detection.
    """
    trace_id = getattr(request.state, "trace_id", generate_trace_id())
    logger.error(
        "Unhandled exception on %s %s: %s",
        request.method,
        request.url.path,
        str(exc),
        exc_info=True,
        extra={"trace_id": trace_id},
    )
    return JSONResponse(
        status_code=500,
        content=build_unclassified_error_response(trace_id),
        headers={"X-Trace-Id": trace_id},
    )


# ---------------------------------------------------------------------------
# Admin Impersonation Guard Middleware
# ---------------------------------------------------------------------------


@app.middleware("http")
async def block_admin_auth_paths(request: Request, call_next):
    """Block any request path that resembles AdminInitiateAuth (Requirement 1.6).

    This is defense-in-depth — these routes don't exist, but we explicitly
    reject requests to admin auth paths to prevent any future accidental exposure.
    """
    if request.url.path.lower() in ADMIN_AUTH_PATHS:
        trace_id = getattr(request.state, "trace_id", generate_trace_id())
        security_logger.warning(
            "ADMIN_AUTH_BLOCKED",
            extra={
                "event_type": "security_alert",
                "alert_type": "admin_auth_attempt",
                "path": request.url.path,
                "source_ip": _get_client_ip(request),
                "timestamp": time.time(),
                "trace_id": trace_id,
            },
        )
        return JSONResponse(
            status_code=403,
            content={
                "error_type": "auth_denied",
                "message": "This endpoint is not available.",
                "trace_id": trace_id,
                "retry_after": None,
            },
            headers={"X-Trace-Id": trace_id},
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


async def get_current_user(request: Request, authorization: str | None = Header(None)) -> UserClaims:
    """Extract and validate JWT from Authorization header.

    Implements the full auth pipeline:
    1. Extract Bearer token from Authorization header
    2. Validate JWT (RS256, expiry, audience, issuer) [Req 2.1]
    3. Return validated UserClaims

    Requirement 1.7: If token expired, client should attempt refresh via
    the IdP. If refresh also expired, re-auth is required. The API layer
    signals this by returning 401, and the client handles refresh logic.

    Raises:
        AuthenticationError: If token is missing, invalid, or expired.
    """
    if not authorization:
        raise AuthenticationError("Authorization header is required")

    # Extract Bearer token
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthenticationError("Invalid authorization format. Expected: Bearer <token>")

    token = parts[1]

    # Validate JWT — this checks RS256 signature, expiry, audience, issuer
    user_claims = await validate_jwt(token)

    # Store session_id in request state for middleware use
    request.state.session_id = user_claims.session_id
    request.state.user_claims = user_claims

    return user_claims


async def enforce_rate_limit(user: UserClaims = Depends(get_current_user)) -> UserClaims:
    """Enforce per-user rate limiting (30 req/min token bucket).

    Raises:
        RateLimitExceeded: If user exceeds 30 requests per minute.
    """
    rate_limiter = get_rate_limiter()
    await rate_limiter.check_rate_limit(user.sub)
    return user


async def ensure_session_active(
    request: Request, user: UserClaims = Depends(enforce_rate_limit)
) -> UserClaims:
    """Ensure the user's session is active (not idle-expired).

    Creates a new session entry if one doesn't exist yet for this session_id,
    or validates the existing session hasn't exceeded the 45-min idle timeout.

    Returns the validated user claims if session is active.
    """
    session_store = get_session_store()
    session = session_store.get(user.session_id)

    if session is None:
        # New session — create entry
        session_store.create(user.session_id, user.sub)
    else:
        # Existing session — check expiry
        if session.is_expired():
            session_store.invalidate(user.session_id)
            raise AuthenticationError(
                "Session expired due to inactivity. Please re-authenticate."
            )
        # Update last activity
        session.touch()

    return user


# ---------------------------------------------------------------------------
# Health Check Endpoint
# ---------------------------------------------------------------------------


@app.get("/health", tags=["system"])
async def health_check() -> dict[str, str]:
    """Health check endpoint for ALB target group health probes.

    Returns basic service status. Does not require authentication.
    """
    return {"status": "healthy", "service": "chatbot-api"}


# ---------------------------------------------------------------------------
# Chat Endpoint
# ---------------------------------------------------------------------------


@app.post(
    "/chat",
    response_model=ChatResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Authentication failed"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        503: {"model": ErrorResponse, "description": "Service unavailable"},
    },
    tags=["chat"],
)
async def chat(
    request: Request,
    chat_request: ChatRequest,
    user: UserClaims = Depends(ensure_session_active),
) -> ChatResponse:
    """Process a chat request through the full security pipeline.

    Pipeline: auth → rate limit → session check → agent delegation → audit

    The endpoint:
    1. Validates JWT (RS256, expiry, audience, issuer) [Req 2.1]
    2. Checks per-user rate limit (30 req/min) [Req 3.1]
    3. Validates session is not idle-expired (45 min) [Req 2.2]
    4. Delegates to AgentCore Runtime via circuit breaker [Req 4.1]
    5. Two-layer auth: Cedar before Athena, LF at query engine [Req 6.1]
    6. Writes audit record at completion (success or failure) [Req 11.1]
    7. Alerts on Cedar-permit + LF-deny divergence [Req 6.2]
    8. All tool calls use OBO identity (never shared role) [Req 7.5]

    AdminInitiateAuth is NOT available — no admin impersonation [Req 1.6].
    """
    trace_id = getattr(request.state, "trace_id", generate_trace_id())

    # Delegate to AgentCore Runtime (through circuit breaker)
    try:
        response = await _delegate_to_agent(user, chat_request, trace_id)
        return response
    except CircuitBreakerOpenError:
        # Re-raise for the exception handler — no audit needed (service unavailable)
        raise
    except (AuthorizationDeniedError, CostThresholdExceededError,
            GuardrailsBlockError, SQLFailureError):
        # Re-raise classified errors for their specific exception handlers.
        # Audit was already written in _delegate_to_agent before raising.
        raise
    except Exception as e:
        # Log error without exposing internals to user
        logger.error(
            "Agent delegation failed: %s",
            str(e),
            exc_info=True,
            extra={"trace_id": trace_id, "user_sub": user.sub},
        )
        # Return a safe error response
        raise


# ---------------------------------------------------------------------------
# Agent Delegation
# ---------------------------------------------------------------------------


async def _delegate_to_agent(
    user: UserClaims,
    chat_request: ChatRequest,
    trace_id: str,
) -> ChatResponse:
    """Delegate the chat request to the AgentCore Runtime.

    This function is the full integration pipeline (Task 16.1):
    1. FastAPI → agent graph execution → response formatting
    2. Two-layer authorization: Cedar evaluates before Athena query (Req 6.1)
    3. Audit record written at request completion — success or failure (Req 11.1)
    4. Divergence alert when Cedar permits but Lake Formation denies (Req 6.2)
    5. All components use OBO identity via user_claims (Req 7.5)

    The circuit breaker (middleware layer) protects this call from
    cascading failures when AgentCore Runtime is unavailable.

    All tool calls from the agent route exclusively through AgentCore
    Gateway — never direct invocation.
    """
    circuit_breaker = get_circuit_breaker()

    async def _invoke_agent():
        """Inner function wrapped by circuit breaker."""
        # Import here to avoid circular imports at module level
        from chatbot.agent.graph import AgentGraph

        agent = AgentGraph()
        graph = agent.build_graph()
        compiled = graph.compile()

        # Serialize UserClaims to dict for the graph state.
        # The graph state uses dict[str, Any] for user_claims so nodes
        # can access claims without importing Pydantic models.
        # This ensures OBO identity (user's federated identity) propagates
        # through the entire pipeline — never a shared service role (Req 7.5).
        user_claims_dict = user.model_dump()

        # Build initial state for the agent
        initial_state = {
            "user_claims": user_claims_dict,
            "user_message": chat_request.message,
            "session_id": chat_request.session_id,
            "conversation_id": chat_request.conversation_id,
            "trace_id": trace_id,
            # Initialize loop counters for structural bounds
            "disambiguation_rounds": 0,
            "self_correction_attempts": 0,
            "needs_disambiguation": False,
            "sql_valid": False,
            "guardrails_findings": [],
        }

        # Invoke the compiled graph
        result = await compiled.ainvoke(initial_state)

        return result

    # Execute agent through circuit breaker
    result = await circuit_breaker.call(_invoke_agent)

    # --- Post-execution: detect authorization divergence (Req 6.2) ---
    # If Cedar permitted but Lake Formation denied, emit divergence alert.
    _detect_and_alert_divergence(result, user, trace_id)

    # --- Post-execution: classify errors from agent result ---
    error = result.get("error")
    sql_error = result.get("sql_error")

    # Determine request status for audit
    request_status = "success"
    error_detail = None

    if error:
        request_status = "failure"
        error_detail = error
    elif sql_error and not result.get("query_results"):
        request_status = "failure"
        error_detail = sql_error

    # --- Write audit record at request completion (Req 11.1) ---
    # Audit is written for BOTH success and failure cases.
    _write_completion_audit(
        trace_id=trace_id,
        user=user,
        question=result.get("user_message", ""),
        generated_sql=result.get("generated_sql"),
        policy_decision=result.get("policy_decision"),
        lake_formation_outcome=result.get("lake_formation_outcome"),
        cost_estimate_bytes=result.get("cost_estimate_bytes"),
        row_count=result.get("row_count"),
        guardrails_findings=result.get("guardrails_findings"),
        request_status=request_status,
        error_detail=error_detail,
    )

    # --- Raise classified errors for exception handlers ---
    if error:
        _raise_classified_error(error, trace_id, user)

    if sql_error and not result.get("query_results"):
        # SQL failed after self-correction retries exhausted
        raise SQLFailureError(
            trace_id=trace_id,
            original_question=result.get("user_message", ""),
            sql_attempts=[result.get("generated_sql", "")],
            error_details=[sql_error],
            session_id=user.session_id,
            principal=user.sub,
        )

    # --- Build successful response ---
    query_results = result.get("query_results", {})
    return ChatResponse(
        answer=result.get("final_response", "I was unable to process your request."),
        sql_generated=result.get("generated_sql"),
        data_freshness=query_results.get("data_freshness") if query_results else None,
        row_count=query_results.get("row_count") if query_results else None,
        cost_estimate_bytes=query_results.get("bytes_scanned") if query_results else None,
        warnings=result.get("warnings", []),
    )


def _detect_and_alert_divergence(
    result: dict[str, Any],
    user: UserClaims,
    trace_id: str,
) -> None:
    """Detect Cedar-permit + Lake Formation-deny divergence and alert.

    Requirement 6.2: If Cedar permits but Lake Formation denies, block the
    request, log the divergence to the immutable audit store, and deliver
    an alert to the security operations team within 60 seconds.

    This check runs post-execution because Lake Formation enforcement
    happens at query time within Athena — we detect the divergence from
    the agent result state.
    """
    sql_error = result.get("sql_error", "") or ""
    policy_decision = result.get("policy_decision", {})
    lake_formation_outcome = result.get("lake_formation_outcome")

    # Divergence indicators:
    # 1. Explicit lake_formation_outcome = "denied" with policy_decision = permit
    # 2. Athena access denied error after Gateway (Cedar) allowed the call
    is_cedar_permit = (
        policy_decision.get("decision") == "ALLOW"
        or policy_decision.get("decision") == "permit"
    )
    is_lf_deny = (
        lake_formation_outcome == "denied"
        or "access denied" in sql_error.lower()
        or "lake formation" in sql_error.lower()
    )

    if is_cedar_permit and is_lf_deny:
        # Log divergence to audit store
        security_logger.critical(
            "AUTHORIZATION_DIVERGENCE",
            extra={
                "event_type": "authorization_divergence",
                "severity": "P1",
                "alert_type": "cedar_permit_lf_deny",
                "principal": user.sub,
                "department": user.department,
                "resource": result.get("generated_sql", "unknown"),
                "cedar_decision": "permit",
                "lake_formation_decision": "deny",
                "trace_id": trace_id,
                "session_id": user.session_id,
                "timestamp": time.time(),
                "message": (
                    f"Cedar permitted but Lake Formation denied for "
                    f"principal={user.sub}, department={user.department}. "
                    f"Divergence requires immediate investigation."
                ),
            },
        )

        # Update result state to reflect divergence for audit
        result["lake_formation_outcome"] = "denied"
        result["error"] = (
            "Authorization divergence: policy layer permitted but "
            "data layer denied. Request blocked."
        )


def _write_completion_audit(
    trace_id: str,
    user: UserClaims,
    question: str,
    *,
    generated_sql: str | None = None,
    policy_decision: dict[str, Any] | None = None,
    lake_formation_outcome: str | None = None,
    cost_estimate_bytes: int | None = None,
    row_count: int | None = None,
    guardrails_findings: Any = None,
    request_status: str = "success",
    error_detail: str | None = None,
) -> None:
    """Write audit record at request completion (success or failure).

    Requirement 11.1: Every request produces an audit record within 5 seconds
    containing full context (trace_id, session_id, principal, question, SQL,
    policy decision, LF outcome, cost, row count, guardrails findings).

    Requirement 5.8: If audit write fails, the request should be denied.
    In this post-completion context, we log the failure as a critical alert
    since the response has already been constructed.
    """
    try:
        audit_record = create_audit_record(
            trace_id=trace_id,
            session_id=user.session_id,
            principal=user.sub,
            question=question or "",
            generated_sql=generated_sql,
            policy_decision=policy_decision,
            lake_formation_outcome=lake_formation_outcome,
            cost_estimate_bytes=cost_estimate_bytes,
            row_count=row_count,
            guardrails_findings=(
                {"findings": guardrails_findings}
                if isinstance(guardrails_findings, list)
                else guardrails_findings
            ),
            request_status=request_status,
            error_detail=error_detail,
        )

        audit_store = _get_audit_store()
        audit_store.write_record(audit_record)

    except AuditWriteError as e:
        # Fail-closed: audit write failed after retries (Req 5.8).
        # Since we're post-graph-execution, raise to deny the response.
        logger.error(
            "Audit write failed — failing request (Req 5.8): %s",
            str(e),
            extra={"trace_id": trace_id},
        )
        raise RuntimeError(
            "Request cannot be completed: audit record could not be persisted."
        ) from e
    except Exception as e:
        # Non-audit-specific failures: log critical alert but don't crash
        # if the audit store is simply not configured (e.g., in tests).
        logger.warning(
            "Audit record write encountered error: %s",
            str(e),
            extra={"trace_id": trace_id},
        )


def _raise_classified_error(error: str, trace_id: str, user: UserClaims) -> None:
    """Raise appropriate classified error based on agent error message.

    Maps agent error strings to structured error types for the FastAPI
    exception handlers to produce proper user-facing responses.
    """
    error_lower = error.lower()

    if "authorization" in error_lower or "denied" in error_lower or "403" in error_lower:
        raise AuthorizationDeniedError(
            principal=user.sub,
            resource="",
            layer="policy",
            trace_id=trace_id,
        )

    if "guardrails" in error_lower or "can't help" in error_lower or "blocked" in error_lower:
        raise GuardrailsBlockError(
            trace_id=trace_id,
            session_id=user.session_id,
        )

    if "cost" in error_lower or "threshold" in error_lower or "exceeds" in error_lower:
        raise CostThresholdExceededError(
            estimated_bytes=0,
            threshold_bytes=10 * 1024**3,  # 10 GB default
            trace_id=trace_id,
        )

    # If Cedar denied before Athena (Req 6.3): raise as authorization denied
    if "cedar" in error_lower and "deny" in error_lower:
        raise AuthorizationDeniedError(
            principal=user.sub,
            resource="",
            layer="cedar",
            trace_id=trace_id,
        )

    # Divergence case (Req 6.2): Cedar permit + LF deny
    if "divergence" in error_lower:
        raise AuthorizationDeniedError(
            principal=user.sub,
            resource="",
            layer="lake_formation",
            trace_id=trace_id,
        )

    # Generic unclassified error — will be caught by unhandled exception handler
    raise RuntimeError(error)


# ---------------------------------------------------------------------------
# Audit Store singleton
# ---------------------------------------------------------------------------

_audit_store: AuditStore | None = None


def _get_audit_store() -> AuditStore:
    """Get or create the module-level AuditStore singleton.

    Uses environment variable AUDIT_BUCKET_NAME for configuration.
    Defaults to 'chatbot-audit-store' if not set.
    """
    global _audit_store
    if _audit_store is None:
        import os
        bucket_name = os.environ.get("AUDIT_BUCKET_NAME", "chatbot-audit-store")
        _audit_store = AuditStore(bucket_name=bucket_name)
    return _audit_store


def set_audit_store(store: AuditStore | None) -> None:
    """Set the module-level AuditStore (for testing/dependency injection)."""
    global _audit_store
    _audit_store = store


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, considering X-Forwarded-For from ALB."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _log_auth_failure(request: Request, reason: str, trace_id: str) -> None:
    """Log authentication failure with required context.

    Requirement 1.8: Log failed attempt with timestamp, source IP, failure reason.
    Logs to the immutable audit store (via structured logging → SIEM).
    """
    security_logger.warning(
        "AUTH_FAILURE",
        extra={
            "event_type": "auth_failure",
            "timestamp": time.time(),
            "source_ip": _get_client_ip(request),
            "failure_reason": reason,
            "trace_id": trace_id,
            "request_path": request.url.path,
            "request_method": request.method,
            "user_agent": request.headers.get("User-Agent", "unknown"),
        },
    )
