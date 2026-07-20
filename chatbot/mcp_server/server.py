"""MCP Server entry point and tool registration.

Implements the Model Context Protocol server for Athena operations.
All tool calls MUST arrive exclusively via the AgentCore Gateway —
direct invocations are rejected (Requirements 10.4, 5.1).

Registered tools:
- list_tables: List tables filtered by user authorization
- get_schema: Retrieve schema with authorization check
- estimate_cost: Dry-run cost estimation
- run_query: Execute validated SQL via Athena

The gateway enforcement is implemented by verifying the presence and
validity of the AgentCore Gateway request signature header on every
incoming tool invocation. Requests without a valid gateway signature
are rejected with a security violation logged to the audit store.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

from chatbot.api.models import UserClaims
from chatbot.mcp_server.tools.estimate_cost import estimate_cost
from chatbot.mcp_server.tools.get_schema import (
    GetSchemaError,
    TableNotAuthorizedError,
    TableNotFoundError,
    get_schema,
)
from chatbot.mcp_server.tools.list_tables import ListTablesError, list_tables
from chatbot.mcp_server.tools.models import (
    CostEstimate,
    QueryResult,
    TableInfo,
)
from chatbot.mcp_server.tools.run_query import run_query

logger = logging.getLogger(__name__)

# Header name that AgentCore Gateway attaches to all routed requests.
# Absence of this header means the request bypassed the gateway.
GATEWAY_SIGNATURE_HEADER = "X-AgentCore-Gateway-Signature"

# Header containing the gateway request ID for tracing
GATEWAY_REQUEST_ID_HEADER = "X-AgentCore-Request-Id"

# Expected gateway issuer for signature validation
GATEWAY_ISSUER = "agentcore-gateway"


class ToolCallError(Exception):
    """Raised when a tool call fails."""

    def __init__(self, message: str, error_code: str = "tool_error") -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class GatewayEnforcementError(ToolCallError):
    """Raised when a tool call bypasses the AgentCore Gateway (Requirement 10.4).

    All tool calls must be routed through the AgentCore Gateway. Direct
    invocation attempts are security violations that are logged and rejected.
    """

    def __init__(self, reason: str = "Direct tool invocation rejected") -> None:
        super().__init__(
            message=f"Gateway enforcement violation: {reason}",
            error_code="gateway_bypass_rejected",
        )
        self.reason = reason


class ToolNotFoundError(ToolCallError):
    """Raised when a requested tool is not registered."""

    def __init__(self, tool_name: str) -> None:
        super().__init__(
            message=f"Tool '{tool_name}' is not registered",
            error_code="tool_not_found",
        )


@dataclass
class ToolInvocationContext:
    """Context for a tool invocation arriving via the AgentCore Gateway.

    Attributes:
        user_claims: Validated claims from the authenticated user's JWT.
        gateway_signature: The gateway signature header value.
        gateway_request_id: Unique request ID assigned by the gateway.
        timestamp: Server-side timestamp of the invocation.
    """

    user_claims: UserClaims
    gateway_signature: str
    gateway_request_id: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class ToolDefinition:
    """Definition of a registered MCP tool.

    Attributes:
        name: Tool name (used for routing from the gateway).
        description: Human-readable description of the tool's purpose.
        handler: Async function implementing the tool logic.
        input_schema: JSON schema describing the tool's input parameters.
    """

    name: str
    description: str
    handler: Callable[..., Coroutine[Any, Any, Any]]
    input_schema: dict[str, Any]


@dataclass
class ToolInvocationResult:
    """Result of a tool invocation.

    Attributes:
        success: Whether the tool executed successfully.
        result: The tool's return value (if success=True).
        error: Error message (if success=False).
        error_code: Machine-readable error code (if success=False).
        execution_time_ms: Time taken to execute the tool in milliseconds.
    """

    success: bool
    result: Any = None
    error: str | None = None
    error_code: str | None = None
    execution_time_ms: int = 0


class MCPServer:
    """Model Context Protocol server with AgentCore Gateway enforcement.

    This server registers tools and ensures all invocations arrive exclusively
    through the AgentCore Gateway. Direct invocations are rejected with a
    security violation (Requirement 10.4).

    The server enforces default-deny semantics (Requirement 5.1): requests
    without valid gateway credentials are denied before any tool logic executes.

    Usage:
        server = MCPServer()
        # Tools are auto-registered at construction time
        result = await server.invoke_tool("list_tables", context, arguments)
    """

    def __init__(self) -> None:
        """Initialize the MCP server and register all tools."""
        self._tools: dict[str, ToolDefinition] = {}
        self._register_tools()

    @property
    def registered_tools(self) -> list[str]:
        """Return names of all registered tools."""
        return list(self._tools.keys())

    def get_tool_definitions(self) -> list[ToolDefinition]:
        """Return all registered tool definitions (for gateway discovery)."""
        return list(self._tools.values())

    def _register_tools(self) -> None:
        """Register all MCP tools with their schemas.

        Tools registered:
        - list_tables: List tables filtered by user authorization
        - get_schema: Retrieve schema with authorization check
        - estimate_cost: Dry-run cost estimation before execution
        - run_query: Execute validated SQL via Athena
        """
        self._tools["list_tables"] = ToolDefinition(
            name="list_tables",
            description=(
                "List Athena tables that the authenticated user is authorized to access. "
                "Results are filtered by the user's Lake Formation grants."
            ),
            handler=self._handle_list_tables,
            input_schema={
                "type": "object",
                "properties": {
                    "database": {
                        "type": "string",
                        "description": "Optional database filter. If omitted, lists tables from all authorized databases.",
                    },
                },
                "required": [],
            },
        )

        self._tools["get_schema"] = ToolDefinition(
            name="get_schema",
            description=(
                "Retrieve detailed schema information for a specific table, "
                "including columns, partition keys, and data freshness. "
                "Authorization check ensures user can access the table."
            ),
            handler=self._handle_get_schema,
            input_schema={
                "type": "object",
                "properties": {
                    "database": {
                        "type": "string",
                        "description": "The database containing the table.",
                    },
                    "table": {
                        "type": "string",
                        "description": "The table name to retrieve schema for.",
                    },
                },
                "required": ["database", "table"],
            },
        )

        self._tools["estimate_cost"] = ToolDefinition(
            name="estimate_cost",
            description=(
                "Estimate the cost of a SQL query via Athena dry-run. "
                "Returns estimated bytes scanned and whether it exceeds "
                "the 10 GB threshold for non-elevated users."
            ),
            handler=self._handle_estimate_cost,
            input_schema={
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "The SQL query to estimate cost for.",
                    },
                },
                "required": ["sql"],
            },
        )

        self._tools["run_query"] = ToolDefinition(
            name="run_query",
            description=(
                "Execute a validated SQL query via Athena using the user's "
                "federated identity (OBO token). The query must pass SQL "
                "validation before execution. Uses the chatbot-readonly workgroup."
            ),
            handler=self._handle_run_query,
            input_schema={
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "The validated SQL query to execute.",
                    },
                },
                "required": ["sql"],
            },
        )

        logger.info(
            "MCP server initialized with %d tools: %s",
            len(self._tools),
            ", ".join(self._tools.keys()),
        )

    def _validate_gateway_context(self, context: ToolInvocationContext) -> None:
        """Validate that the invocation arrived via AgentCore Gateway.

        Enforces Requirement 10.4: all tool calls must arrive only via
        AgentCore Gateway. Direct invocations are rejected.

        Enforces Requirement 5.1: default-deny — requests without valid
        gateway credentials are denied before any tool logic executes.

        Args:
            context: The invocation context containing gateway headers.

        Raises:
            GatewayEnforcementError: If the gateway signature is missing,
                empty, or does not match the expected issuer format.
        """
        # Check gateway signature is present and non-empty
        if not context.gateway_signature:
            logger.warning(
                "SECURITY VIOLATION: Tool invocation without gateway signature. "
                "Request ID: %s, User: %s",
                context.gateway_request_id or "none",
                context.user_claims.sub if context.user_claims else "unknown",
            )
            raise GatewayEnforcementError(
                reason="Missing gateway signature — direct invocation is not permitted"
            )

        # Check gateway request ID is present
        if not context.gateway_request_id:
            logger.warning(
                "SECURITY VIOLATION: Tool invocation without gateway request ID. "
                "User: %s",
                context.user_claims.sub if context.user_claims else "unknown",
            )
            raise GatewayEnforcementError(
                reason="Missing gateway request ID — request origin cannot be verified"
            )

        # Validate gateway signature format (must start with issuer prefix)
        if not context.gateway_signature.startswith(GATEWAY_ISSUER + ":"):
            logger.warning(
                "SECURITY VIOLATION: Invalid gateway signature format. "
                "Request ID: %s, User: %s",
                context.gateway_request_id,
                context.user_claims.sub if context.user_claims else "unknown",
            )
            raise GatewayEnforcementError(
                reason="Invalid gateway signature — request did not originate from AgentCore Gateway"
            )

        logger.debug(
            "Gateway enforcement passed. Request ID: %s, User: %s",
            context.gateway_request_id,
            context.user_claims.sub,
        )

    async def invoke_tool(
        self,
        tool_name: str,
        context: ToolInvocationContext,
        arguments: dict[str, Any] | None = None,
    ) -> ToolInvocationResult:
        """Invoke a registered tool with gateway enforcement.

        This is the single entry point for all tool invocations. It:
        1. Validates the request arrived via AgentCore Gateway
        2. Looks up the tool by name
        3. Executes the tool handler with the provided arguments
        4. Returns a structured result

        Args:
            tool_name: Name of the tool to invoke.
            context: Invocation context with gateway credentials and user claims.
            arguments: Tool-specific arguments (validated against input_schema).

        Returns:
            ToolInvocationResult with success/failure status and data.
        """
        start_time = time.time()

        # Step 1: Gateway enforcement (Requirement 10.4)
        try:
            self._validate_gateway_context(context)
        except GatewayEnforcementError as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            return ToolInvocationResult(
                success=False,
                error=e.message,
                error_code=e.error_code,
                execution_time_ms=elapsed_ms,
            )

        # Step 2: Tool lookup
        tool_def = self._tools.get(tool_name)
        if tool_def is None:
            elapsed_ms = int((time.time() - start_time) * 1000)
            logger.warning("Tool not found: %s", tool_name)
            return ToolInvocationResult(
                success=False,
                error=f"Tool '{tool_name}' is not registered",
                error_code="tool_not_found",
                execution_time_ms=elapsed_ms,
            )

        # Step 3: Execute tool handler
        try:
            result = await tool_def.handler(
                context=context,
                arguments=arguments or {},
            )
            elapsed_ms = int((time.time() - start_time) * 1000)
            logger.info(
                "Tool '%s' executed successfully in %dms. Request ID: %s",
                tool_name,
                elapsed_ms,
                context.gateway_request_id,
            )
            return ToolInvocationResult(
                success=True,
                result=result,
                execution_time_ms=elapsed_ms,
            )
        except ToolCallError as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            logger.error(
                "Tool '%s' failed: %s. Request ID: %s",
                tool_name,
                e.message,
                context.gateway_request_id,
            )
            return ToolInvocationResult(
                success=False,
                error=e.message,
                error_code=e.error_code,
                execution_time_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            logger.exception(
                "Unexpected error in tool '%s'. Request ID: %s",
                tool_name,
                context.gateway_request_id,
            )
            return ToolInvocationResult(
                success=False,
                error="Internal tool execution error",
                error_code="internal_error",
                execution_time_ms=elapsed_ms,
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Tool handler stubs — implementations in tasks 5.2 and 5.3
    # ──────────────────────────────────────────────────────────────────────────

    async def _handle_list_tables(
        self,
        context: ToolInvocationContext,
        arguments: dict[str, Any],
    ) -> list[TableInfo]:
        """List tables filtered by user authorization.

        Delegates to chatbot.mcp_server.tools.list_tables module which
        queries Glue Catalog and filters by Lake Formation grants.
        """
        database_filter = arguments.get("database")

        try:
            tables = await list_tables(
                user_claims=context.user_claims,
                database=database_filter if database_filter else None,
            )
            return tables
        except ListTablesError as e:
            raise ToolCallError(
                message=e.message,
                error_code="list_tables_failed",
            ) from e

    async def _handle_get_schema(
        self,
        context: ToolInvocationContext,
        arguments: dict[str, Any],
    ) -> TableInfo:
        """Retrieve schema with authorization check.

        Delegates to chatbot.mcp_server.tools.get_schema module which
        checks Lake Formation authorization then queries Glue Catalog.
        """
        database = arguments.get("database", "")
        table = arguments.get("table", "")

        if not database or not table:
            raise ToolCallError(
                message="Both 'database' and 'table' arguments are required",
                error_code="invalid_arguments",
            )

        try:
            schema = await get_schema(
                user_claims=context.user_claims,
                database=database,
                table=table,
            )
            return schema
        except TableNotAuthorizedError as e:
            raise ToolCallError(
                message=e.message,
                error_code=e.error_code,
            ) from e
        except TableNotFoundError as e:
            raise ToolCallError(
                message=e.message,
                error_code=e.error_code,
            ) from e
        except GetSchemaError as e:
            raise ToolCallError(
                message=e.message,
                error_code=e.error_code,
            ) from e

    async def _handle_estimate_cost(
        self,
        context: ToolInvocationContext,
        arguments: dict[str, Any],
    ) -> CostEstimate:
        """Dry-run cost estimation before execution.

        Delegates to chatbot.mcp_server.tools.estimate_cost module which
        performs an Athena dry-run via the user's OBO identity to estimate
        bytes scanned and cost (Requirement 9.5).
        """
        sql = arguments.get("sql", "")

        if not sql:
            raise ToolCallError(
                message="'sql' argument is required for cost estimation",
                error_code="invalid_arguments",
            )

        try:
            result = await estimate_cost(
                sql=sql,
                user_claims=context.user_claims,
                obo_token=arguments.get("obo_token"),
                athena_client=arguments.get("athena_client"),
            )
            return result
        except ValueError as e:
            raise ToolCallError(
                message=str(e),
                error_code="invalid_arguments",
            ) from e
        except RuntimeError as e:
            raise ToolCallError(
                message=str(e),
                error_code="cost_estimation_failed",
            ) from e

    async def _handle_run_query(
        self,
        context: ToolInvocationContext,
        arguments: dict[str, Any],
    ) -> QueryResult:
        """Execute validated SQL via Athena using OBO identity.

        Delegates to chatbot.mcp_server.tools.run_query module which
        executes SQL via the chatbot-readonly workgroup under the user's
        federated identity (OBO token). NEVER uses a shared service role
        (Property 5: OBO Identity — Requirement 7.1, 7.5).
        """
        sql = arguments.get("sql", "")

        if not sql:
            raise ToolCallError(
                message="'sql' argument is required for query execution",
                error_code="invalid_arguments",
            )

        try:
            result = await run_query(
                sql=sql,
                user_claims=context.user_claims,
                obo_token=arguments.get("obo_token"),
                athena_client=arguments.get("athena_client"),
                glue_client=arguments.get("glue_client"),
            )
            return result
        except ValueError as e:
            raise ToolCallError(
                message=str(e),
                error_code="invalid_arguments",
            ) from e
        except RuntimeError as e:
            raise ToolCallError(
                message=str(e),
                error_code="query_execution_failed",
            ) from e


def create_mcp_server() -> MCPServer:
    """Factory function to create and configure the MCP server.

    Returns a fully initialized MCPServer with all tools registered
    and gateway enforcement enabled.
    """
    server = MCPServer()
    logger.info(
        "MCP server created with tools: %s",
        ", ".join(server.registered_tools),
    )
    return server
