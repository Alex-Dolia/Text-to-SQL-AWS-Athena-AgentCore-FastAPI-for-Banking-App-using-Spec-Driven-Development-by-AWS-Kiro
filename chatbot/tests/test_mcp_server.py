"""Unit tests for MCP server entry point and tool registration.

Tests cover:
- Tool registration (all 4 tools present)
- Gateway enforcement (reject direct invocations)
- Valid gateway context passes enforcement
- Tool not found handling
- Tool invocation result structure
"""

from __future__ import annotations

import pytest

from chatbot.api.models import UserClaims
from chatbot.mcp_server.server import (
    GATEWAY_ISSUER,
    GatewayEnforcementError,
    MCPServer,
    ToolInvocationContext,
    ToolInvocationResult,
    ToolNotFoundError,
    create_mcp_server,
)


@pytest.fixture
def server() -> MCPServer:
    """Create a fresh MCP server instance."""
    return MCPServer()


@pytest.fixture
def valid_user_claims() -> UserClaims:
    """Create valid user claims for testing."""
    return UserClaims(
        sub="user-123",
        department="analytics",
        role="analyst",
        data_classification_tier="internal",
        groups=["analysts", "data-team"],
        session_id="12345678-1234-4234-8234-123456789012",
        exp=9999999999,
    )


@pytest.fixture
def valid_context(valid_user_claims: UserClaims) -> ToolInvocationContext:
    """Create a valid gateway invocation context."""
    return ToolInvocationContext(
        user_claims=valid_user_claims,
        gateway_signature=f"{GATEWAY_ISSUER}:valid-signature-abc123",
        gateway_request_id="req-001",
    )


class TestToolRegistration:
    """Tests for tool registration at server initialization."""

    def test_all_four_tools_registered(self, server: MCPServer) -> None:
        """All four expected tools are registered."""
        expected_tools = {"list_tables", "get_schema", "estimate_cost", "run_query"}
        assert set(server.registered_tools) == expected_tools

    def test_tool_count(self, server: MCPServer) -> None:
        """Exactly 4 tools are registered."""
        assert len(server.registered_tools) == 4

    def test_get_tool_definitions_returns_all(self, server: MCPServer) -> None:
        """get_tool_definitions returns all registered tool definitions."""
        definitions = server.get_tool_definitions()
        assert len(definitions) == 4
        names = {d.name for d in definitions}
        assert names == {"list_tables", "get_schema", "estimate_cost", "run_query"}

    def test_tool_definitions_have_descriptions(self, server: MCPServer) -> None:
        """Each tool definition has a non-empty description."""
        for tool_def in server.get_tool_definitions():
            assert tool_def.description
            assert len(tool_def.description) > 10

    def test_tool_definitions_have_input_schemas(self, server: MCPServer) -> None:
        """Each tool definition has an input schema."""
        for tool_def in server.get_tool_definitions():
            assert tool_def.input_schema is not None
            assert tool_def.input_schema.get("type") == "object"

    def test_factory_function_creates_server(self) -> None:
        """create_mcp_server factory returns a configured MCPServer."""
        server = create_mcp_server()
        assert isinstance(server, MCPServer)
        assert len(server.registered_tools) == 4


class TestGatewayEnforcement:
    """Tests for AgentCore Gateway enforcement (Requirements 10.4, 5.1)."""

    async def test_missing_gateway_signature_rejected(
        self, server: MCPServer, valid_user_claims: UserClaims
    ) -> None:
        """Requests without gateway signature are rejected."""
        context = ToolInvocationContext(
            user_claims=valid_user_claims,
            gateway_signature="",
            gateway_request_id="req-001",
        )
        result = await server.invoke_tool("list_tables", context)
        assert result.success is False
        assert result.error_code == "gateway_bypass_rejected"
        assert "gateway" in result.error.lower()

    async def test_missing_gateway_request_id_rejected(
        self, server: MCPServer, valid_user_claims: UserClaims
    ) -> None:
        """Requests without gateway request ID are rejected."""
        context = ToolInvocationContext(
            user_claims=valid_user_claims,
            gateway_signature=f"{GATEWAY_ISSUER}:some-sig",
            gateway_request_id="",
        )
        result = await server.invoke_tool("list_tables", context)
        assert result.success is False
        assert result.error_code == "gateway_bypass_rejected"

    async def test_invalid_gateway_signature_format_rejected(
        self, server: MCPServer, valid_user_claims: UserClaims
    ) -> None:
        """Requests with invalid gateway signature format are rejected."""
        context = ToolInvocationContext(
            user_claims=valid_user_claims,
            gateway_signature="invalid-issuer:some-signature",
            gateway_request_id="req-001",
        )
        result = await server.invoke_tool("list_tables", context)
        assert result.success is False
        assert result.error_code == "gateway_bypass_rejected"
        assert "did not originate from AgentCore Gateway" in result.error

    async def test_direct_invocation_without_any_headers_rejected(
        self, server: MCPServer, valid_user_claims: UserClaims
    ) -> None:
        """Completely unadorned requests (no gateway headers) are rejected."""
        context = ToolInvocationContext(
            user_claims=valid_user_claims,
            gateway_signature="",
            gateway_request_id="",
        )
        result = await server.invoke_tool("run_query", context)
        assert result.success is False
        assert result.error_code == "gateway_bypass_rejected"

    async def test_valid_gateway_context_passes_enforcement(
        self, server: MCPServer, valid_context: ToolInvocationContext
    ) -> None:
        """Valid gateway context passes enforcement (tool may fail due to AWS access)."""
        result = await server.invoke_tool("list_tables", valid_context)
        # Gateway enforcement passed — the tool runs but may fail due to
        # missing AWS credentials/services in test environment.
        # The key assertion: it does NOT fail with gateway_bypass_rejected.
        assert result.error_code != "gateway_bypass_rejected"


class TestToolInvocation:
    """Tests for tool invocation routing and error handling."""

    async def test_unknown_tool_returns_not_found(
        self, server: MCPServer, valid_context: ToolInvocationContext
    ) -> None:
        """Requesting a non-existent tool returns tool_not_found error."""
        result = await server.invoke_tool("nonexistent_tool", valid_context)
        assert result.success is False
        assert result.error_code == "tool_not_found"
        assert "nonexistent_tool" in result.error

    async def test_tool_stub_list_tables(
        self, server: MCPServer, valid_context: ToolInvocationContext
    ) -> None:
        """list_tables tool runs (may fail without AWS but not gateway_bypass)."""
        result = await server.invoke_tool("list_tables", valid_context)
        # Tool is now implemented; without AWS it may fail, but not with gateway bypass
        assert result.error_code != "gateway_bypass_rejected"

    async def test_tool_stub_get_schema(
        self, server: MCPServer, valid_context: ToolInvocationContext
    ) -> None:
        """get_schema tool runs (may fail without AWS but not gateway_bypass)."""
        result = await server.invoke_tool(
            "get_schema", valid_context, {"database": "mydb", "table": "mytable"}
        )
        # Tool is now implemented; without AWS it may fail, but not with gateway bypass
        assert result.error_code != "gateway_bypass_rejected"

    async def test_tool_stub_estimate_cost(
        self, server: MCPServer, valid_context: ToolInvocationContext
    ) -> None:
        """estimate_cost requires sql and identity credentials."""
        result = await server.invoke_tool(
            "estimate_cost", valid_context, {"sql": "SELECT 1"}
        )
        # Without obo_token or athena_client, identity delegation cannot proceed
        assert result.success is False
        assert result.error_code == "invalid_arguments"
        assert "obo_token" in result.error or "identity" in result.error.lower()

    async def test_tool_stub_run_query(
        self, server: MCPServer, valid_context: ToolInvocationContext
    ) -> None:
        """run_query requires sql and identity credentials."""
        result = await server.invoke_tool(
            "run_query", valid_context, {"sql": "SELECT 1"}
        )
        # Without obo_token or athena_client, identity delegation cannot proceed
        assert result.success is False
        assert result.error_code == "invalid_arguments"
        assert "obo_token" in result.error or "identity" in result.error.lower()

    async def test_invocation_result_has_execution_time(
        self, server: MCPServer, valid_context: ToolInvocationContext
    ) -> None:
        """Invocation result includes execution time in milliseconds."""
        result = await server.invoke_tool("list_tables", valid_context)
        assert result.execution_time_ms >= 0

    async def test_gateway_enforcement_runs_before_tool_lookup(
        self, server: MCPServer, valid_user_claims: UserClaims
    ) -> None:
        """Gateway enforcement is checked before tool name is validated.

        Even if the tool name doesn't exist, missing gateway credentials
        should result in gateway_bypass_rejected (not tool_not_found).
        """
        context = ToolInvocationContext(
            user_claims=valid_user_claims,
            gateway_signature="",
            gateway_request_id="req-001",
        )
        result = await server.invoke_tool("nonexistent_tool", context)
        assert result.error_code == "gateway_bypass_rejected"


class TestGatewayEnforcementError:
    """Tests for the GatewayEnforcementError exception class."""

    def test_default_message(self) -> None:
        """GatewayEnforcementError has a default message."""
        err = GatewayEnforcementError()
        assert "Direct tool invocation rejected" in err.message
        assert err.error_code == "gateway_bypass_rejected"

    def test_custom_reason(self) -> None:
        """GatewayEnforcementError accepts a custom reason."""
        err = GatewayEnforcementError(reason="Custom reason")
        assert "Custom reason" in err.message
        assert err.reason == "Custom reason"


class TestToolNotFoundError:
    """Tests for the ToolNotFoundError exception class."""

    def test_includes_tool_name(self) -> None:
        """ToolNotFoundError includes the tool name in its message."""
        err = ToolNotFoundError("my_tool")
        assert "my_tool" in err.message
        assert err.error_code == "tool_not_found"
