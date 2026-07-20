# Implementation Plan: Chatbot Security Architecture

## Overview

This plan implements a production chatbot security architecture for a Tier-1 bank enabling natural language Athena queries. The implementation follows the project structure `chatbot/{api, agent, mcp_server, policies, infra, tests, scripts}/` using Python (FastAPI, LangGraph) with `pyproject.toml` and AWS CDK (TypeScript) for infrastructure. Tasks are ordered to build foundational layers first (networking, security, data models) before application logic, with testing integrated alongside implementation.

## Tasks

- [x] 1. Project scaffolding and core data models
  - [x] 1.1 Initialize project structure and pyproject.toml
    - Create directory structure: `chatbot/{api, agent, mcp_server, policies, infra, tests, scripts}/`
    - Create `pyproject.toml` with pinned dependencies (fastapi, uvicorn, pydantic, python-jose, langgraph, boto3, opensearch-py, httpx, circuitbreaker)
    - Add dev dependencies (pytest, pytest-asyncio, hypothesis, ruff, mypy, moto)
    - Create `chatbot/api/Dockerfile` and `chatbot/agent/Dockerfile` stubs
    - _Requirements: 18.4, 18.5_

  - [x] 1.2 Define core Pydantic models and data classes
    - Create `chatbot/api/models.py` with `UserClaims`, `ChatRequest`, `ChatResponse`, `ErrorResponse`
    - Create `chatbot/agent/state.py` with `AgentState` dataclass
    - Create `chatbot/mcp_server/tools/models.py` with `TableInfo`, `ColumnInfo`, `CostEstimate`, `QueryResult`
    - Implement validation rules (UUID v4 session_id, tier hierarchy, claim validation)
    - _Requirements: 1.4, 2.1, 9.9, 17.5_

  - [x] 1.3 Define Cedar policy schema and base policies
    - Create `chatbot/policies/schema.cedarschema` with Principal (User), Resource (Table), Action types
    - Create `chatbot/policies/base.cedar` with default-deny and universal forbid rules (PCI databases)
    - Create `chatbot/policies/analysts.cedar` with analyst role permits (ABAC on department, tier)
    - Create `chatbot/policies/managers.cedar` with manager role permits
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 6.5_

  - [x] 1.4 Write property tests for data model tier hierarchy
    - **Property 2: Default-Deny Authorization** — verify no access without explicit Cedar permit
    - **Property 3: Forbid Always Wins** — verify forbid overrides any permit
    - **Validates: Requirements 5.1, 5.2**

- [x] 2. Authentication and session management (FastAPI layer)
  - [x] 2.1 Implement JWT validation module
    - Create `chatbot/api/auth.py` with `validate_jwt()` function
    - Validate RS256 signature, expiry, audience, issuer using python-jose
    - Extract and map custom claims (department, role, data-classification-tier, groups)
    - Reject tokens with missing required claims (return specific error)
    - Cache JWKS keys with 5-min TTL for ≤15ms validation at P95
    - _Requirements: 1.1, 1.2, 1.4, 1.5, 2.1, 18.2, 18.6_

  - [x] 2.2 Write property test for JWT token lifetime bounds
    - **Property 9: Token Lifetime Bounds** — JWT access tokens never exceed 15 minutes
    - **Validates: Requirements 1.3, 2.1**

  - [x] 2.3 Implement rate limiting middleware
    - Create token bucket rate limiter in `chatbot/api/auth.py` (30 req/min per user)
    - Return HTTP 429 with `Retry-After` header when exceeded
    - Implement bucket refill logic on 60-second window reset
    - Trigger investigation alert after 10 consecutive minutes of rate limiting
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [x] 2.4 Implement session management and idle timeout
    - Create `chatbot/api/middleware.py` with session timeout enforcement (45-min idle)
    - Track last activity timestamp server-side
    - Return HTTP 401 on expired session with re-authentication message
    - Generate UUID v4 trace_id for every response
    - Log security alert when auth failures exceed 5/min from same IP
    - _Requirements: 2.2, 2.3, 2.4, 2.5_

  - [x] 2.5 Implement circuit breaker for AgentCore Runtime
    - Add circuit breaker to `chatbot/api/middleware.py` using circuitbreaker library
    - Open on >50% failures in 30s window (min 5 requests)
    - Return HTTP 503 within 200ms when open
    - Half-open after 60s, allow 1 probe request
    - Close on successful probe, re-open on failed probe
    - Trigger P2 alert on state transition closed→open
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

  - [x] 2.6 Create FastAPI application entry point
    - Create `chatbot/api/main.py` with FastAPI app, routes, middleware registration
    - Wire `/chat` endpoint connecting auth → rate limit → session → agent delegation
    - Ensure AdminInitiateAuth is not exposed (no admin impersonation)
    - Include health check endpoint
    - _Requirements: 1.6, 1.7, 1.8, 2.1_

  - [x] 2.7 Write unit tests for auth, rate limiting, circuit breaker
    - Test JWT validation: valid token, expired, wrong audience, wrong issuer, invalid signature, missing claims
    - Test rate limiter: under limit, at limit, over limit, bucket refill, concurrent requests
    - Test circuit breaker: closed→open, open→half-open, half-open→closed, half-open→open
    - Test session timeout: active session, idle expiry, re-authentication flow
    - _Requirements: 2.1, 2.2, 3.1, 4.1_

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. SQL validation engine
  - [x] 4.1 Implement SQL AST parser and validation logic
    - Create `chatbot/mcp_server/validation.py` with `validate_sql()` function
    - Parse SQL into AST and reject non-SELECT statements
    - Extract all table references (including subqueries, CTEs, JOINs)
    - Check table authorization against user's pre-computed authorized set
    - Enforce ordered evaluation: parse → statement type → authorization → partition → columns → cost → LIMIT
    - _Requirements: 9.1, 9.2, 9.8, 9.9_

  - [x] 4.2 Implement partition filter and column validation
    - Add partition filter check: reject queries on partitioned tables without WHERE on partition key
    - Add SELECT * rejection on tables with >50 columns
    - Implement LIMIT injection (default 10,000) when no explicit LIMIT present
    - _Requirements: 9.3, 9.4, 9.6_

  - [x] 4.3 Implement cost estimation and full-scan protection
    - Add cost estimation via Athena dry-run (reject if >10 GB without elevated_cost group)
    - Reject full table scans on tables >1 TB without elevated_cost entitlement
    - Return structured `ValidationResult` with modified SQL (LIMIT injected)
    - _Requirements: 9.5, 9.7_

  - [x] 4.4 Write property test for SQL safety invariant
    - **Property 11: SQL Safety Invariant** — only validated SELECT with LIMIT and within cost threshold executes
    - Use Hypothesis to generate varied SQL strings and verify non-SELECT always rejected
    - **Validates: Requirements 9.1, 9.2, 9.6**

  - [x] 4.5 Write unit tests for SQL validation edge cases
    - Test: INSERT/UPDATE/DELETE/DROP/ALTER/CREATE all rejected
    - Test: missing partition filter on partitioned table rejected
    - Test: SELECT * on wide table rejected
    - Test: cost threshold block with/without elevated_cost group
    - Test: LIMIT injection on valid queries
    - Test: unauthorized table references in subqueries/CTEs/JOINs
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8_

- [x] 5. MCP Server tool implementations
  - [x] 5.1 Implement MCP server entry point and tool registration
    - Create `chatbot/mcp_server/server.py` with MCP protocol server setup
    - Register tools: `list_tables`, `get_schema`, `estimate_cost`, `run_query`
    - Ensure all tool calls arrive only via AgentCore Gateway (reject direct invocation)
    - _Requirements: 10.4, 5.1_

  - [x] 5.2 Implement list_tables and get_schema tools
    - Create `chatbot/mcp_server/tools/list_tables.py` — list tables filtered by user authorization
    - Create `chatbot/mcp_server/tools/get_schema.py` — retrieve schema with authorization check
    - Query Glue Catalog for metadata, filter by Lake Formation grants
    - Return `TableInfo` models with column descriptions, partition keys, freshness
    - _Requirements: 16.3, 6.4, 7.5_

  - [x] 5.3 Implement estimate_cost and run_query tools
    - Create `chatbot/mcp_server/tools/estimate_cost.py` — dry-run cost estimation
    - Create `chatbot/mcp_server/tools/run_query.py` — execute validated SQL via Athena
    - All queries use dedicated `chatbot-readonly` workgroup
    - Execute as user's federated identity (OBO token, never shared service role)
    - Include data freshness from Glue Catalog partition timestamps
    - _Requirements: 7.1, 7.5, 7.6, 9.5_

  - [x] 5.4 Write property test for OBO identity enforcement
    - **Property 5: OBO Identity — Never Shared Role** — every Athena query runs as user's federated identity
    - **Validates: Requirements 7.1, 7.5**

  - [x] 5.5 Write unit tests for MCP server tools
    - Test list_tables returns only authorized tables for user
    - Test get_schema rejects unauthorized table access
    - Test run_query uses OBO token identity (not service role)
    - Test run_query with chatbot-readonly workgroup
    - Test estimate_cost returns threshold warnings
    - _Requirements: 7.1, 7.5, 7.6, 16.3_

- [x] 6. LangGraph agent orchestration
  - [x] 6.1 Implement agent graph definition with bounded loops
    - Create `chatbot/agent/graph.py` with `AgentGraph.build_graph()` method
    - Define all nodes statically: intent_classify, glossary_resolve, schema_retrieve, disambiguate, sql_generate, validate_sql, tool_call, self_correct, output_scan, format_respond
    - Implement conditional edges with structural bounds (disambiguation ≤3, self-correction ≤2)
    - Ensure all tool calls route exclusively through AgentCore Gateway
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

  - [x] 6.2 Implement agent node functions
    - Create `chatbot/agent/nodes/intent_classify.py` — Claude Haiku, 2s budget
    - Create `chatbot/agent/nodes/glossary_resolve.py` — business term resolution
    - Create `chatbot/agent/nodes/schema_retrieve.py` — RAG retrieval from OpenSearch, filtered by user auth
    - Create `chatbot/agent/nodes/disambiguate.py` — clarification questions (max 3 rounds)
    - Create `chatbot/agent/nodes/sql_generate.py` — Claude Sonnet, temperature=0
    - Create `chatbot/agent/nodes/validate_sql.py` — delegates to validation engine
    - Create `chatbot/agent/nodes/tool_call.py` — routes through AgentCore Gateway
    - Create `chatbot/agent/nodes/self_correct.py` — SQL rewrite on error (max 2 retries)
    - Create `chatbot/agent/nodes/output_scan.py` — Guardrails output scan, PII redaction
    - Create `chatbot/agent/nodes/format_respond.py` — format response with data freshness
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 8.1, 8.3_

  - [x] 6.3 Write property tests for bounded loops and gateway routing
    - **Property 6: Bounded Loops** — disambiguation ≤3, self-correction ≤2
    - **Property 1: No Tool Call Bypasses Gateway** — all tool calls route through Gateway
    - **Validates: Requirements 10.2, 10.3, 10.4**

  - [x] 6.4 Write unit tests for agent graph nodes and edges
    - Test each node function individually
    - Test conditional edge logic (should_disambiguate, should_self_correct)
    - Test loop bound enforcement at graph structure level
    - Test schema retrieval filtering by user authorization
    - _Requirements: 10.1, 10.2, 10.3, 10.5_

- [x] 7. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Content safety and guardrails integration
  - [x] 8.1 Implement Bedrock Guardrails integration
    - Create guardrails scanning module in `chatbot/agent/nodes/output_scan.py`
    - Scan EVERY model call: input direction (user message + SQL) and output direction (results + narrative)
    - Configure STANDARD tier with all content filters at HIGH threshold
    - Implement ANONYMIZE action for PII entities (all 31 types)
    - Handle guardrails unavailability: fail-closed within 5 seconds
    - _Requirements: 8.1, 8.2, 8.4_

  - [x] 8.2 Implement PII redaction and session termination logic
    - Apply PII redaction unless user's role permits viewing that PII category (via Cedar policy)
    - Implement session termination after 3+ BLOCK actions in a single session
    - Log security event to audit store and SIEM on session termination
    - Require re-authentication after terminated session
    - _Requirements: 8.3, 8.5_

  - [x] 8.3 Write property test for guardrails coverage
    - **Property 7: Guardrails on Every Model Call** — input AND output scanning on every model invocation
    - **Validates: Requirements 8.1**

  - [x] 8.4 Write unit tests for guardrails and PII handling
    - Test prompt injection detection → BLOCK response (no detection category revealed)
    - Test PII redaction in query results
    - Test session termination after 3 blocks
    - Test fail-closed on guardrails unavailability
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 9. Audit trail and observability
  - [x] 9.1 Implement immutable audit record writer
    - Create `chatbot/scripts/audit.py` (shared audit module) with `AuditStore` class
    - Write records to S3 with Object Lock (Compliance mode, 7-year retention)
    - Include full audit context: timestamp, trace_id, session_id, principal, question, SQL, policy decision, LF outcome, cost, row count, guardrails findings
    - Implement retry logic (3 attempts) with alert on failure
    - Ensure no silent audit drops — fail the request if audit cannot be written
    - _Requirements: 11.1, 11.2, 11.5, 11.6, 5.8_

  - [x] 9.2 Implement audit query capability and cross-region replication
    - Add `query_by_principal()` for DSAR response / investigation
    - Support date range queries returning results within 60 seconds for 90-day spans
    - Configure cross-region replication with RPO ≤15 minutes
    - _Requirements: 11.3, 11.4_

  - [x] 9.3 Write property test for audit completeness
    - **Property 8: Audit Completeness** — every request produces an immutable audit record
    - **Validates: Requirements 11.1, 5.5, 5.8**

  - [x] 9.4 Write unit tests for audit store
    - Test audit record creation with all required fields
    - Test retry logic on write failure
    - Test alert emission after 3 failed retries
    - Test query_by_principal returns correct results within SLA
    - _Requirements: 11.1, 11.4, 11.6_

- [x] 10. Error handling and user-facing responses
  - [x] 10.1 Implement structured error handling across all components
    - Create error handler in `chatbot/api/main.py` covering all classified error types
    - Auth denial: actionable message without policy IDs/rule identifiers
    - Cost threshold: include estimated GB, limit, and filter suggestions
    - Guardrails block: fixed response "I can't help with that request..."
    - SQL failure: suggest rephrasing, log failure chain to audit
    - Include trace_id in every error response
    - Unclassified errors: generic message with trace_id, no internal details
    - All errors returned within 5 seconds of detection
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7_

  - [x] 10.2 Write unit tests for error handling
    - Test each error type returns correct message format
    - Test no security internals leaked in error responses
    - Test trace_id present in all error responses
    - Test error response time within 5 seconds
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7_

- [x] 11. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Reconciliation, kill switch, and deprovisioning
  - [x] 12.1 Implement daily permission reconciliation
    - Create `chatbot/scripts/reconciliation.py` with `reconcile_permissions()` function
    - Fetch all Cedar permits and Lake Formation grants
    - Compare (principal, table) tuples bidirectionally
    - On divergence: trigger P1 alert, fail-close affected principals within 5 minutes
    - On job failure: assume breach, block all requests, trigger P1 alert
    - On healthy: record status in audit store, emit CloudWatch metric
    - Complete within 60 minutes of invocation
    - _Requirements: 13.1, 13.2, 13.3, 13.4_

  - [x] 12.2 Write property test for reconciliation fail-closed
    - **Property 10: Reconciliation Fail-Closed** — failure or divergence blocks all affected requests
    - **Property 4: Two-Layer Authorization Independence** — query executes only if BOTH layers allow
    - **Validates: Requirements 13.2, 13.3, 6.1**

  - [x] 12.3 Implement administrative kill switch
    - Create `chatbot/scripts/kill_switch.py` with enable/disable Gateway target API
    - Disable target within 5 minutes of API call → all requests get HTTP 503
    - Block 100% new requests; allow in-flight to complete (no new tool calls)
    - Log audit entry: operator identity, reason (10-500 chars), target, timestamp
    - Restrict invocation to security-operations role (Cedar policy)
    - Re-enablement restores target within 5 minutes with audit log
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

  - [x] 12.4 Implement user deprovisioning webhook
    - Create Lambda handler for IdP deprovisioning webhook
    - Revoke all Cognito tokens (access + refresh) within 5 minutes of event
    - Delete OBO token vault entry in Secrets Manager within same 5-minute SLA
    - Write audit record with all timestamps (event, revocation, deletion, status)
    - Implement retry logic: 3 retries within SLA, P1 alert if all exhausted
    - _Requirements: 15.1, 15.2, 15.3, 15.4_

  - [x] 12.5 Write property test for deprovisioning SLA
    - **Property 12: Deprovisioning SLA** — token revocation completes within 5 minutes of IdP event
    - **Validates: Requirements 15.1, 15.2, 7.3**

  - [x] 12.6 Write unit tests for reconciliation, kill switch, deprovisioning
    - Test reconciliation: healthy, divergent (both directions), job failure, timeout
    - Test kill switch: activation, re-enablement, unauthorized attempt, audit logging
    - Test deprovisioning: successful flow, retry on failure, P1 alert on exhaustion
    - _Requirements: 13.1, 13.2, 13.3, 14.1, 14.4, 15.1, 15.4_

- [x] 13. Schema synchronization and vector store
  - [x] 13.1 Implement schema re-indexing pipeline
    - Create `chatbot/scripts/reindex_vectors.py` for EventBridge-triggered re-indexing
    - Index schema embeddings to OpenSearch Serverless on Glue Catalog changes
    - Re-index within 60 minutes of table creation/modification events
    - Remove embeddings on table deletion within 60 minutes
    - Include business glossary terms, synonyms, Lake Formation tags
    - Implement retry: 3 attempts with exponential backoff, alert on failure
    - _Requirements: 16.1, 16.2, 16.4_

  - [x] 13.2 Implement authorization-filtered RAG retrieval
    - Add user-authorization filtering to schema retrieval in `chatbot/agent/nodes/schema_retrieve.py`
    - Filter by lake_formation_tags before selecting top-k results
    - If no schemas match user's grants, inform user (no unfiltered context to LLM)
    - Configure OpenSearch Serverless as vector type with VPC-only access
    - _Requirements: 16.3, 16.5, 10.5_

  - [x] 13.3 Write unit tests for schema sync and RAG retrieval
    - Test re-indexing on create/modify/delete events
    - Test authorization filtering returns only user-permitted schemas
    - Test no unfiltered schema context passed to LLM
    - Test retry and alert on re-index failure
    - _Requirements: 16.1, 16.2, 16.3, 16.4_

- [x] 14. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 15. Infrastructure as Code (AWS CDK TypeScript)
  - [x] 15.1 Initialize CDK project and create networking stack
    - Create `chatbot/infra/bin/app.ts` CDK app entry point
    - Create `chatbot/infra/lib/networking-stack.ts`: VPC, private subnets (2+ AZs), VPC PrivateLink endpoints (Bedrock, Athena, Glue, S3, Secrets Manager, KMS, CloudWatch, OpenSearch, Cognito)
    - Configure security groups: sg-alb (corporate CIDR → 443), sg-fastapi (sg-alb → 8000), sg-vpce (443 from sg-fastapi)
    - Enforce TLS 1.2+ on all endpoints, reject TLS 1.0/1.1
    - Attach VPC endpoint policies restricting allowed actions/resources
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

  - [x] 15.2 Create security stack
    - Create `chatbot/infra/lib/security-stack.ts`: 5 KMS CMKs (datalake, audit, opensearch, queryresults, gateway)
    - Configure Cognito User Pool: SAML 2.0/OIDC federation, MFA enforced, custom claim mapping, no AdminInitiateAuth, 15-min access token, 8-hr refresh token
    - Configure Secrets Manager for OBO token vault (90-day rotation)
    - Create IAM roles with least privilege (no "allow all")
    - _Requirements: 1.1, 1.3, 1.6, 7.2, 12.1_

  - [x] 15.3 Create data stack
    - Create `chatbot/infra/lib/data-stack.ts`: S3 data lake buckets (SSE-KMS), S3 audit bucket (Object Lock Compliance mode, 7-year retention, cross-region replication)
    - Configure Glue Catalog for table metadata
    - Configure Lake Formation: table/column/row/cell permissions
    - Create OpenSearch Serverless vector collection (VPC-only, no public endpoint)
    - Create Athena `chatbot-readonly` workgroup with bytes-scanned limits
    - _Requirements: 11.2, 11.3, 16.5, 6.4, 6.5_

  - [x] 15.4 Create compute stack
    - Create `chatbot/infra/lib/compute-stack.ts`: ECS Fargate service (FastAPI) with multi-AZ, internal ALB (HTTPS 443, ACM cert)
    - Configure auto-scaling: min 2, max 10 tasks; scale out on response time >1s or CPU >60%; scale in on response time <500ms and CPU <30%
    - Configure AgentCore Runtime (1 vCPU, 2 GB memory)
    - Add EventBridge rules: daily reconciliation schedule, Glue catalog change events
    - Add Lambda for deprovisioning webhook
    - _Requirements: 18.4, 18.5, 13.1, 15.1_

  - [x] 15.5 Create observability stack
    - Create `chatbot/infra/lib/observability-stack.ts`: CloudWatch dashboards, alarms, SIEM subscription filters
    - Configure alarms: circuit breaker open (P2), reconciliation failure (P1), sustained rate limiting, auth failure spike, network path detection (P1)
    - Escalation: P0 alert if assume-breach posture >4 hours
    - Export logs to bank SIEM (Splunk/QRadar) via subscription filters
    - _Requirements: 12.6, 13.5, 4.5, 2.5, 18.1_

  - [x] 15.6 Create shared constants and CDK configuration
    - Create `chatbot/infra/lib/shared/constants.ts` with cross-stack constants
    - Create `chatbot/infra/cdk.json` and `chatbot/infra/tsconfig.json`
    - Ensure stack dependency order: Networking → Security → Data → Compute → Observability (no circular deps)
    - _Requirements: 12.1, 12.5_

  - [x] 15.7 Write CDK snapshot/unit tests
    - Test stack synthesis produces expected resources
    - Test no public internet paths in networking stack
    - Test Object Lock configuration on audit bucket
    - Test security group rules enforce directional flow
    - _Requirements: 12.1, 12.6, 11.2_

- [x] 16. Integration wiring and end-to-end flow
  - [x] 16.1 Wire FastAPI to LangGraph agent with full pipeline
    - Connect FastAPI `/chat` endpoint → agent graph execution → response formatting
    - Ensure two-layer authorization sequence: Cedar evaluates before Athena query submitted
    - Wire audit record writing at request completion (success or failure)
    - Wire divergence alert when Cedar permits but Lake Formation denies
    - Ensure all components use OBO identity (never shared service role)
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 7.5_

  - [x] 16.2 Implement Cedar policy evaluation integration
    - Wire AgentCore Gateway policy evaluation for all tool calls
    - Source principal claims exclusively from validated JWT (never user input or LLM content)
    - Log decision (permit/deny), policy ID, version to audit store before returning
    - Fail-closed on policy engine unavailable or evaluation error
    - Fail-closed if audit write fails (deny in-flight request)
    - _Requirements: 5.1, 5.2, 5.3, 5.5, 5.6, 5.7, 5.8_

  - [x] 16.3 Write integration tests for end-to-end flows
    - Test authorized query: API → Agent → Gateway → Policy → OBO → Athena → response
    - Test denied query: Cedar deny → 403, audit recorded
    - Test two-layer divergence: Policy allow + LF deny → block + alert
    - Test jailbreak attempt: Guardrails block → audit, no query executed
    - Test deprovisioning: webhook → token revocation → session terminated
    - Test reconciliation divergence → fail-closed → P1 alert
    - _Requirements: 6.1, 6.2, 8.2, 15.1, 13.2_

- [x] 17. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at logical boundaries
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- Infrastructure (CDK TypeScript) and application code (Python) are implemented in sequence to avoid circular dependencies
- The project uses Python (FastAPI, LangGraph) for application logic and AWS CDK (TypeScript) for infrastructure-as-code
- Cedar policies are defined declaratively and validated in CI/CD (`cedar validate`)
- All property-based tests use the Hypothesis library (Python)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["1.4", "2.1", "4.1"] },
    { "id": 3, "tasks": ["2.2", "2.3", "2.4", "4.2"] },
    { "id": 4, "tasks": ["2.5", "2.6", "4.3"] },
    { "id": 5, "tasks": ["2.7", "4.4", "4.5"] },
    { "id": 6, "tasks": ["5.1", "6.1"] },
    { "id": 7, "tasks": ["5.2", "5.3", "6.2"] },
    { "id": 8, "tasks": ["5.4", "5.5", "6.3", "6.4"] },
    { "id": 9, "tasks": ["8.1", "9.1"] },
    { "id": 10, "tasks": ["8.2", "8.3", "9.2"] },
    { "id": 11, "tasks": ["8.4", "9.3", "9.4", "10.1"] },
    { "id": 12, "tasks": ["10.2", "12.1", "12.3", "12.4", "13.1"] },
    { "id": 13, "tasks": ["12.2", "12.5", "12.6", "13.2"] },
    { "id": 14, "tasks": ["13.3", "15.1"] },
    { "id": 15, "tasks": ["15.2", "15.3"] },
    { "id": 16, "tasks": ["15.4", "15.5"] },
    { "id": 17, "tasks": ["15.6", "15.7"] },
    { "id": 18, "tasks": ["16.1", "16.2"] },
    { "id": 19, "tasks": ["16.3"] }
  ]
}
```
