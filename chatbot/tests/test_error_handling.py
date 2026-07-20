"""Unit tests for structured error handling (chatbot/api/errors.py).

Task 10.2: Write unit tests for error handling
- Test each error type returns correct message format
- Test no security internals leaked in error responses
- Test trace_id present in all error responses
- Test error response time within 5 seconds

Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7
"""

from __future__ import annotations

import time
import uuid

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from chatbot.api.errors import (
    AuthorizationDeniedError,
    CostThresholdExceededError,
    ERROR_RESPONSE_DEADLINE_SECONDS,
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SENSITIVE_TERMS = [
    "cedar",
    "policy_id",
    "lake_formation",
    "grant",
    "rule_id",
    "arn:",
    "lambda",
    "stack trace",
    "Traceback",
    "internal server",
    "sg-",
    "vpc-",
    "subnet-",
]


def _assert_no_internals_leaked(response_body: dict) -> None:
    """Assert no security-sensitive terms appear in user-facing fields."""
    message = response_body.get("message", "").lower()
    error_type = response_body.get("error_type", "").lower()
    for term in SENSITIVE_TERMS:
        assert term.lower() not in message, (
            f"Security internal '{term}' leaked in message: {message}"
        )
        assert term.lower() not in error_type, (
            f"Security internal '{term}' leaked in error_type: {error_type}"
        )


def _assert_trace_id_present(response_body: dict) -> None:
    """Assert trace_id is present and non-empty in response."""
    assert "trace_id" in response_body, "trace_id missing from error response"
    assert response_body["trace_id"], "trace_id is empty"
    assert len(response_body["trace_id"]) > 0


def _make_trace_id() -> str:
    return str(uuid.uuid4())


# ===========================================================================
# Section 1: Response Builder Tests — Correct Message Format
# ===========================================================================


class TestAuthorizationDeniedResponse:
    """Requirement 17.1: Auth denial returns actionable message directing
    to Data Governance portal without policy IDs or rule identifiers."""

    def test_message_directs_to_data_governance_portal(self):
        trace_id = _make_trace_id()
        resp = build_authorization_denied_response(trace_id)
        assert "Data Governance" in resp["message"]
        assert "not available" in resp["message"]

    def test_error_type_is_auth_denied(self):
        resp = build_authorization_denied_response(_make_trace_id())
        assert resp["error_type"] == "auth_denied"

    def test_trace_id_included(self):
        trace_id = _make_trace_id()
        resp = build_authorization_denied_response(trace_id)
        _assert_trace_id_present(resp)
        assert resp["trace_id"] == trace_id

    def test_no_internals_leaked(self):
        resp = build_authorization_denied_response(_make_trace_id())
        _assert_no_internals_leaked(resp)

    def test_no_policy_id_in_response(self):
        """Even when error has policy_id set, it must not appear in response."""
        trace_id = _make_trace_id()
        resp = build_authorization_denied_response(trace_id)
        assert "POL-" not in resp["message"]
        assert "policy" not in resp["message"].lower() or "permissions" in resp["message"].lower()

    def test_retry_after_is_none(self):
        resp = build_authorization_denied_response(_make_trace_id())
        assert resp["retry_after"] is None


class TestCostThresholdResponse:
    """Requirement 17.2: Cost threshold error includes estimated GB,
    limit, and filter suggestions."""

    def test_includes_estimated_gb(self):
        trace_id = _make_trace_id()
        resp = build_cost_threshold_response(
            trace_id=trace_id,
            estimated_gb=15.3,
            threshold_gb=10.0,
            filter_suggestions=["Add date filter"],
        )
        assert "15.3" in resp["message"]

    def test_includes_threshold_limit(self):
        resp = build_cost_threshold_response(
            trace_id=_make_trace_id(),
            estimated_gb=20.0,
            threshold_gb=10.0,
            filter_suggestions=["Add date filter"],
        )
        assert "10.0" in resp["message"]

    def test_includes_filter_suggestions(self):
        suggestions = ["Add a date range filter", "Use partition keys"]
        resp = build_cost_threshold_response(
            trace_id=_make_trace_id(),
            estimated_gb=12.0,
            threshold_gb=10.0,
            filter_suggestions=suggestions,
        )
        assert "date range" in resp["message"].lower() or "partition" in resp["message"].lower()

    def test_error_type_is_cost_exceeded(self):
        resp = build_cost_threshold_response(
            trace_id=_make_trace_id(),
            estimated_gb=12.0,
            threshold_gb=10.0,
            filter_suggestions=["Filter"],
        )
        assert resp["error_type"] == "cost_exceeded"

    def test_trace_id_included(self):
        trace_id = _make_trace_id()
        resp = build_cost_threshold_response(
            trace_id=trace_id,
            estimated_gb=12.0,
            threshold_gb=10.0,
            filter_suggestions=["Filter"],
        )
        _assert_trace_id_present(resp)
        assert resp["trace_id"] == trace_id

    def test_no_internals_leaked(self):
        resp = build_cost_threshold_response(
            trace_id=_make_trace_id(),
            estimated_gb=12.0,
            threshold_gb=10.0,
            filter_suggestions=["Add date filter"],
        )
        _assert_no_internals_leaked(resp)


class TestGuardrailsBlockResponse:
    """Requirement 17.3: Guardrails block returns fixed response without
    revealing detection category or rule triggered."""

    def test_fixed_response_message(self):
        trace_id = _make_trace_id()
        resp = build_guardrails_block_response(trace_id)
        expected = (
            "I can't help with that request. "
            "Please rephrase your question about the data."
        )
        assert resp["message"] == expected

    def test_error_type_is_out_of_scope(self):
        resp = build_guardrails_block_response(_make_trace_id())
        assert resp["error_type"] == "out_of_scope"

    def test_trace_id_included(self):
        trace_id = _make_trace_id()
        resp = build_guardrails_block_response(trace_id)
        _assert_trace_id_present(resp)
        assert resp["trace_id"] == trace_id

    def test_no_detection_category_revealed(self):
        """Response must not reveal what triggered the block."""
        resp = build_guardrails_block_response(_make_trace_id())
        msg = resp["message"].lower()
        assert "injection" not in msg
        assert "jailbreak" not in msg
        assert "toxic" not in msg
        assert "pii" not in msg
        assert "guardrail" not in msg

    def test_no_internals_leaked(self):
        resp = build_guardrails_block_response(_make_trace_id())
        _assert_no_internals_leaked(resp)


class TestSQLFailureResponse:
    """Requirement 17.4: SQL failure suggests rephrasing without
    revealing SQL internals."""

    def test_suggests_rephrasing(self):
        trace_id = _make_trace_id()
        resp = build_sql_failure_response(trace_id)
        msg = resp["message"].lower()
        assert "rephras" in msg or "simpler" in msg

    def test_error_type_is_sql_failed(self):
        resp = build_sql_failure_response(_make_trace_id())
        assert resp["error_type"] == "sql_failed"

    def test_trace_id_included(self):
        trace_id = _make_trace_id()
        resp = build_sql_failure_response(trace_id)
        _assert_trace_id_present(resp)
        assert resp["trace_id"] == trace_id

    def test_no_sql_internals_in_message(self):
        """Response must not contain SQL statements or error details."""
        resp = build_sql_failure_response(_make_trace_id())
        msg = resp["message"]
        assert "SELECT" not in msg
        assert "FROM" not in msg
        assert "syntax error" not in msg.lower()
        assert "parse" not in msg.lower()

    def test_no_internals_leaked(self):
        resp = build_sql_failure_response(_make_trace_id())
        _assert_no_internals_leaked(resp)

    def test_includes_support_reference(self):
        trace_id = _make_trace_id()
        resp = build_sql_failure_response(trace_id)
        assert trace_id in resp["message"]


class TestUnclassifiedErrorResponse:
    """Requirement 17.6: Unclassified error returns generic message
    with trace_id, no internal details."""

    def test_generic_message(self):
        trace_id = _make_trace_id()
        resp = build_unclassified_error_response(trace_id)
        assert "unexpected error" in resp["message"].lower()

    def test_error_type_is_internal_error(self):
        resp = build_unclassified_error_response(_make_trace_id())
        assert resp["error_type"] == "internal_error"

    def test_trace_id_included(self):
        trace_id = _make_trace_id()
        resp = build_unclassified_error_response(trace_id)
        _assert_trace_id_present(resp)
        assert resp["trace_id"] == trace_id

    def test_trace_id_in_message_for_support(self):
        trace_id = _make_trace_id()
        resp = build_unclassified_error_response(trace_id)
        assert trace_id in resp["message"]

    def test_no_stack_traces(self):
        resp = build_unclassified_error_response(_make_trace_id())
        msg = resp["message"]
        assert "Traceback" not in msg
        assert "File " not in msg
        assert "line " not in msg

    def test_no_internals_leaked(self):
        resp = build_unclassified_error_response(_make_trace_id())
        _assert_no_internals_leaked(resp)


# ===========================================================================
# Section 2: trace_id Present in ALL Error Responses (Requirement 17.5)
# ===========================================================================


class TestTraceIdInAllResponses:
    """Requirement 17.5: Every error response includes a unique trace_id."""

    def test_authorization_denied_has_trace_id(self):
        trace_id = _make_trace_id()
        resp = build_authorization_denied_response(trace_id)
        assert resp["trace_id"] == trace_id

    def test_cost_threshold_has_trace_id(self):
        trace_id = _make_trace_id()
        resp = build_cost_threshold_response(
            trace_id=trace_id,
            estimated_gb=12.0,
            threshold_gb=10.0,
            filter_suggestions=["Filter"],
        )
        assert resp["trace_id"] == trace_id

    def test_guardrails_block_has_trace_id(self):
        trace_id = _make_trace_id()
        resp = build_guardrails_block_response(trace_id)
        assert resp["trace_id"] == trace_id

    def test_sql_failure_has_trace_id(self):
        trace_id = _make_trace_id()
        resp = build_sql_failure_response(trace_id)
        assert resp["trace_id"] == trace_id

    def test_unclassified_error_has_trace_id(self):
        trace_id = _make_trace_id()
        resp = build_unclassified_error_response(trace_id)
        assert resp["trace_id"] == trace_id


# ===========================================================================
# Section 3: No Security Internals Leaked (Requirements 17.1, 17.3, 17.6)
# ===========================================================================


class TestNoSecurityInternalsLeaked:
    """Verify that internal details (policy IDs, Cedar rules, Lake Formation
    grants, ARNs, infrastructure details) never appear in user-facing responses."""

    def test_auth_denied_hides_cedar_policy_id(self):
        """Even if error object has policy_id, response doesn't expose it."""
        err = AuthorizationDeniedError(
            principal="user-123",
            resource="analytics/transactions",
            layer="cedar",
            policy_id="POL-FORBID-PCI-001",
            trace_id=_make_trace_id(),
        )
        resp = build_authorization_denied_response(err.trace_id)
        assert "POL-FORBID-PCI-001" not in resp["message"]
        assert "cedar" not in resp["message"].lower()
        assert "analytics/transactions" not in resp["message"]

    def test_auth_denied_hides_lake_formation_details(self):
        err = AuthorizationDeniedError(
            principal="user-456",
            resource="pci_cardholder/cards",
            layer="lake_formation",
            trace_id=_make_trace_id(),
        )
        resp = build_authorization_denied_response(err.trace_id)
        assert "lake_formation" not in resp["message"].lower()
        assert "pci_cardholder" not in resp["message"]

    def test_guardrails_hides_detection_category(self):
        """Response doesn't reveal what type of content was blocked."""
        err = GuardrailsBlockError(
            trace_id=_make_trace_id(),
            detection_category="PROMPT_INJECTION",
            scan_direction="INPUT",
            confidence_score=0.98,
            content_hash="abc123hash",
        )
        resp = build_guardrails_block_response(err.trace_id)
        assert "PROMPT_INJECTION" not in resp["message"]
        assert "INPUT" not in resp["message"]
        assert "abc123hash" not in resp["message"]
        assert "0.98" not in resp["message"]

    def test_sql_failure_hides_sql_attempts(self):
        """Response doesn't reveal generated SQL or error details."""
        err = SQLFailureError(
            trace_id=_make_trace_id(),
            original_question="Show me all PCI transactions",
            sql_attempts=[
                "SELECT * FROM pci_cardholder.cards",
                "SELECT card_number FROM pci_cardholder.cards LIMIT 10",
            ],
            error_details=[
                "AccessDeniedException: User not authorized",
                "LakeFormation: permission denied on table cards",
            ],
            session_id="sess-abc",
            principal="user-evil",
        )
        resp = build_sql_failure_response(err.trace_id)
        assert "pci_cardholder" not in resp["message"]
        assert "card_number" not in resp["message"]
        assert "AccessDeniedException" not in resp["message"]
        assert "LakeFormation" not in resp["message"]
        assert "user-evil" not in resp["message"]

    def test_unclassified_hides_exception_details(self):
        """Generic error response doesn't include exception message."""
        resp = build_unclassified_error_response(_make_trace_id())
        assert "NullPointerException" not in resp["message"]
        assert "connection refused" not in resp["message"].lower()
        assert "timeout" not in resp["message"].lower()


# ===========================================================================
# Section 4: Error Response Time Within 5 Seconds (Requirement 17.7)
# ===========================================================================


class TestErrorResponseTime:
    """Requirement 17.7: All error responses returned within 5 seconds
    of detecting the error condition."""

    def test_deadline_constant_is_5_seconds(self):
        """Verify the configured deadline matches the requirement."""
        assert ERROR_RESPONSE_DEADLINE_SECONDS == 5.0

    def test_authorization_denied_response_time(self):
        """Authorization denied response builds in well under 5 seconds."""
        start = time.monotonic()
        build_authorization_denied_response(_make_trace_id())
        elapsed = time.monotonic() - start
        assert elapsed < ERROR_RESPONSE_DEADLINE_SECONDS

    def test_cost_threshold_response_time(self):
        """Cost threshold response builds in well under 5 seconds."""
        start = time.monotonic()
        build_cost_threshold_response(
            trace_id=_make_trace_id(),
            estimated_gb=15.0,
            threshold_gb=10.0,
            filter_suggestions=[
                "Add date range filter",
                "Use partition keys",
                "Select fewer columns",
            ],
        )
        elapsed = time.monotonic() - start
        assert elapsed < ERROR_RESPONSE_DEADLINE_SECONDS

    def test_guardrails_block_response_time(self):
        """Guardrails block response builds in well under 5 seconds."""
        start = time.monotonic()
        build_guardrails_block_response(_make_trace_id())
        elapsed = time.monotonic() - start
        assert elapsed < ERROR_RESPONSE_DEADLINE_SECONDS

    def test_sql_failure_response_time(self):
        """SQL failure response builds in well under 5 seconds."""
        start = time.monotonic()
        build_sql_failure_response(_make_trace_id())
        elapsed = time.monotonic() - start
        assert elapsed < ERROR_RESPONSE_DEADLINE_SECONDS

    def test_unclassified_error_response_time(self):
        """Unclassified error response builds in well under 5 seconds."""
        start = time.monotonic()
        build_unclassified_error_response(_make_trace_id())
        elapsed = time.monotonic() - start
        assert elapsed < ERROR_RESPONSE_DEADLINE_SECONDS


# ===========================================================================
# Section 5: FastAPI Exception Handler Integration Tests
# ===========================================================================


def _create_test_app() -> FastAPI:
    """Create a minimal FastAPI app with the error exception handlers
    from main.py to test handler integration."""
    from chatbot.api.main import app
    return app


class TestFastAPIExceptionHandlers:
    """Test exception handlers registered on the FastAPI app produce
    correct HTTP responses with trace_id and no leaked internals."""

    @pytest.fixture
    def test_app(self) -> FastAPI:
        """Build a minimal test app with exception handlers.

        Uses a middleware-based catch-all for unhandled exceptions to mirror
        the production app behavior where ServerErrorMiddleware intercepts
        before the generic Exception handler for non-HTTP exceptions.
        """
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request as StarletteRequest
        from starlette.responses import Response

        from chatbot.api.main import (
            authorization_denied_handler,
            cost_threshold_handler,
            guardrails_block_handler,
            sql_failure_handler,
        )

        app = FastAPI(debug=False)

        @app.get("/trigger-auth-denied")
        async def trigger_auth_denied():
            raise AuthorizationDeniedError(
                principal="user-001",
                resource="finance/accounts",
                layer="cedar",
                policy_id="POL-ANALYSTS-FINANCE-001",
                trace_id="test-trace-auth-001",
            )

        @app.get("/trigger-cost-exceeded")
        async def trigger_cost_exceeded():
            raise CostThresholdExceededError(
                estimated_bytes=15 * 1024**3,
                threshold_bytes=10 * 1024**3,
                trace_id="test-trace-cost-001",
            )

        @app.get("/trigger-guardrails-block")
        async def trigger_guardrails_block():
            raise GuardrailsBlockError(
                trace_id="test-trace-guard-001",
                detection_category="PROMPT_INJECTION",
                scan_direction="INPUT",
                confidence_score=0.95,
                content_hash="deadbeef",
            )

        @app.get("/trigger-sql-failure")
        async def trigger_sql_failure():
            raise SQLFailureError(
                trace_id="test-trace-sql-001",
                original_question="Show me secret data",
                sql_attempts=["SELECT * FROM secrets"],
                error_details=["AccessDenied: user not permitted"],
                session_id="sess-001",
                principal="user-bad",
            )

        @app.get("/trigger-unclassified")
        async def trigger_unclassified():
            raise RuntimeError(
                "Internal: connection to vpc-abc123 refused on sg-fastapi"
            )

        app.add_exception_handler(
            AuthorizationDeniedError, authorization_denied_handler
        )
        app.add_exception_handler(
            CostThresholdExceededError, cost_threshold_handler
        )
        app.add_exception_handler(
            GuardrailsBlockError, guardrails_block_handler
        )
        app.add_exception_handler(SQLFailureError, sql_failure_handler)

        # Middleware-based catch-all for unhandled exceptions (mirrors
        # production behavior where ServerErrorMiddleware handles these)
        @app.middleware("http")
        async def catch_unhandled_errors(request: Request, call_next):
            try:
                return await call_next(request)
            except Exception as exc:
                trace_id = str(uuid.uuid4())
                return JSONResponse(
                    status_code=500,
                    content=build_unclassified_error_response(trace_id),
                    headers={"X-Trace-Id": trace_id},
                )

        return app

    @pytest.mark.asyncio
    async def test_auth_denied_returns_403_with_trace_id(self, test_app):
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/trigger-auth-denied")
            assert resp.status_code == 403
            body = resp.json()
            assert body["error_type"] == "auth_denied"
            _assert_trace_id_present(body)
            _assert_no_internals_leaked(body)
            assert "POL-ANALYSTS-FINANCE-001" not in body["message"]

    @pytest.mark.asyncio
    async def test_cost_exceeded_returns_422_with_trace_id(self, test_app):
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/trigger-cost-exceeded")
            assert resp.status_code == 422
            body = resp.json()
            assert body["error_type"] == "cost_exceeded"
            _assert_trace_id_present(body)
            assert "15.0" in body["message"]
            assert "10.0" in body["message"]

    @pytest.mark.asyncio
    async def test_guardrails_block_returns_400_with_fixed_message(self, test_app):
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/trigger-guardrails-block")
            assert resp.status_code == 400
            body = resp.json()
            assert body["error_type"] == "out_of_scope"
            assert body["message"] == GuardrailsBlockError.FIXED_RESPONSE
            _assert_trace_id_present(body)
            assert "PROMPT_INJECTION" not in body["message"]
            assert "deadbeef" not in body["message"]

    @pytest.mark.asyncio
    async def test_sql_failure_returns_422_with_trace_id(self, test_app):
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/trigger-sql-failure")
            assert resp.status_code == 422
            body = resp.json()
            assert body["error_type"] == "sql_failed"
            _assert_trace_id_present(body)
            _assert_no_internals_leaked(body)
            assert "secrets" not in body["message"].lower()
            assert "AccessDenied" not in body["message"]

    @pytest.mark.asyncio
    async def test_unclassified_returns_500_with_trace_id(self, test_app):
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/trigger-unclassified")
            assert resp.status_code == 500
            body = resp.json()
            assert body["error_type"] == "internal_error"
            _assert_trace_id_present(body)
            _assert_no_internals_leaked(body)
            # Must not expose the internal error message
            assert "vpc-abc123" not in body["message"]
            assert "sg-fastapi" not in body["message"]
            assert "connection" not in body["message"].lower()

    @pytest.mark.asyncio
    async def test_all_error_responses_have_trace_id_header(self, test_app):
        """All error responses include X-Trace-Id in response headers."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            endpoints = [
                "/trigger-auth-denied",
                "/trigger-cost-exceeded",
                "/trigger-guardrails-block",
                "/trigger-sql-failure",
                "/trigger-unclassified",
            ]
            for endpoint in endpoints:
                resp = await client.get(endpoint)
                assert "x-trace-id" in resp.headers, (
                    f"X-Trace-Id header missing from {endpoint}"
                )
                assert len(resp.headers["x-trace-id"]) > 0


# ===========================================================================
# Section 6: Error Class Construction Tests
# ===========================================================================


class TestErrorClasses:
    """Test error class construction stores internal details without exposing."""

    def test_authorization_error_stores_policy_id_internally(self):
        err = AuthorizationDeniedError(
            principal="user-123",
            resource="db/table",
            layer="cedar",
            policy_id="POL-001",
            trace_id="trace-x",
        )
        assert err.policy_id == "POL-001"
        assert err.principal == "user-123"
        assert err.trace_id == "trace-x"
        assert err.detected_at > 0

    def test_cost_threshold_computes_gb_properties(self):
        err = CostThresholdExceededError(
            estimated_bytes=15 * 1024**3,
            threshold_bytes=10 * 1024**3,
            trace_id="trace-y",
        )
        assert err.estimated_gb == 15.0
        assert err.threshold_gb == 10.0
        assert len(err.filter_suggestions) > 0

    def test_guardrails_stores_detection_details_internally(self):
        err = GuardrailsBlockError(
            trace_id="trace-z",
            detection_category="JAILBREAK",
            scan_direction="OUTPUT",
            confidence_score=0.99,
            content_hash="hash123",
            session_id="sess-1",
        )
        assert err.detection_category == "JAILBREAK"
        assert err.scan_direction == "OUTPUT"
        assert err.confidence_score == 0.99
        assert err.content_hash == "hash123"
        assert err.session_id == "sess-1"

    def test_sql_failure_stores_attempts_internally(self):
        err = SQLFailureError(
            trace_id="trace-w",
            original_question="bad question",
            sql_attempts=["SELECT 1", "SELECT 2"],
            error_details=["err1", "err2"],
            session_id="sess-2",
            principal="user-bad",
        )
        assert err.sql_attempts == ["SELECT 1", "SELECT 2"]
        assert err.error_details == ["err1", "err2"]
        assert err.principal == "user-bad"
