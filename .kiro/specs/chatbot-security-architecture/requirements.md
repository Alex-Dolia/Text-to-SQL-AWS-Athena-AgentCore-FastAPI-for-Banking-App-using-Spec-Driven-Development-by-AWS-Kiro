# Requirements Document

## Introduction

This document defines the requirements for a production chatbot security architecture enabling business users at a Tier-1 bank to query several hundred Amazon Athena tables in natural language. The system implements defense-in-depth across authentication, authorization, content safety, and audit — ensuring no single control serves as the sole barrier to unauthorized access.

## Glossary

- **OBO (On-Behalf-Of)**: Token exchange mechanism where a workload identity obtains a scoped token representing the end user's federated identity
- **Cedar**: AWS policy language used for deterministic authorization with default-deny and forbid-wins semantics
- **Lake Formation**: AWS service providing fine-grained column/row/cell-level access control on data lake resources
- **AgentCore**: AWS managed runtime for hosting and orchestrating AI agents with built-in policy, identity, and observability
- **MCP (Model Context Protocol)**: Protocol for exposing tool interfaces to AI agents
- **Guardrails**: Amazon Bedrock feature providing content safety scanning (prompt injection, PII, toxic content)
- **LangGraph**: Framework for building AI agent orchestration as explicit, auditable state graphs
- **ABAC**: Attribute-Based Access Control — authorization decisions based on user/resource attributes
- **PII**: Personally Identifiable Information
- **DSAR**: Data Subject Access Request (GDPR/UK GDPR)

## Requirements

### Requirement 1: Federated Authentication with MFA

**User Story:** As a security architect, I want all chatbot users authenticated via corporate identity provider federation with mandatory MFA, so that only verified employees can access the system.

#### Acceptance Criteria

1. WHEN a user initiates authentication, THE System SHALL redirect to the corporate IdP via Amazon Cognito using SAML 2.0 or OIDC federation.
2. WHEN the corporate IdP returns a successful authentication response, THE System SHALL verify that the MFA claim is present and marked as completed in the SAML assertion or OIDC token — sessions where MFA was not completed SHALL be rejected with an error message indicating that multi-factor authentication is required.
3. WHEN Cognito issues tokens after successful authentication, THE System SHALL set the JWT access token lifetime to no more than 15 minutes (900 seconds) and the refresh token lifetime to no more than 8 hours (28,800 seconds).
4. WHEN Cognito processes a SAML assertion or OIDC token from the IdP, THE System SHALL map the following custom claims into the Cognito ID token: department, role, data-classification-tier, and groups.
5. IF any of the required claims (department, role, data-classification-tier, groups) are missing from the IdP assertion, THEN THE System SHALL deny authentication and return an error message indicating which required identity attributes were not provided by the IdP.
6. THE System SHALL NOT expose or enable the AdminInitiateAuth API action in the Cognito User Pool configuration — no administrator SHALL be able to authenticate on behalf of a user.
7. IF a user's access token expires during an active session, THEN THE System SHALL attempt a token refresh using the refresh token; IF the refresh token is also expired or revoked, THEN THE System SHALL require the user to re-authenticate via the corporate IdP.
8. WHEN an authentication attempt fails (invalid credentials, IdP unavailable, or MFA not completed), THE System SHALL return an error message indicating the reason for failure without exposing internal system details, and SHALL log the failed attempt including the timestamp, source IP, and failure reason to the immutable audit store.

### Requirement 2: JWT Validation and Session Management

**User Story:** As a platform engineer, I want the API gateway to enforce strict JWT validation and session boundaries, so that only valid, unexpired tokens grant access and idle sessions are terminated.

#### Acceptance Criteria

1. WHEN an incoming request contains a Bearer JWT, THE FastAPI layer SHALL validate the RS256 signature, expiry (exp claim), audience (aud claim), and issuer (iss claim) and SHALL forward the request to the target route handler only if all four checks pass.
2. WHILE a session is validated, WHEN no authenticated API request has been received from that session for more than 45 minutes (measured by server-side timestamp of last request), THE system SHALL invalidate the session token and return HTTP 401 on the next request, requiring the user to re-authenticate.
3. WHEN the system generates a response to any incoming request, THE system SHALL include a unique trace_id (UUID v4 format) in the response header for end-to-end request correlation.
4. IF JWT validation fails due to an expired token, invalid RS256 signature, non-matching audience, or non-matching issuer, THEN THE system SHALL return HTTP 401 with a response body containing an error message indicating the specific failure reason and directing the user to re-authenticate.
5. WHEN authentication failures from a single IP address exceed 5 within a rolling 60-second window, THE system SHALL log a security alert event and notify the configured alerting channel within 10 seconds of threshold breach.

### Requirement 3: Rate Limiting

**User Story:** As a platform engineer, I want per-user rate limiting on API requests, so that no single user can overwhelm the system or perform denial-of-service attacks.

#### Acceptance Criteria

1. WHEN an authenticated user exceeds 30 requests per minute across all API endpoints, THE System SHALL reject subsequent requests with HTTP 429 and include a Retry-After header specifying the number of seconds (1 to 60) remaining until the user's request allowance resets.
2. WHEN the rate-limited user's 60-second request window resets, THE System SHALL restore the user's full 30-request allowance and accept new requests normally.
3. IF a single user has been continuously rate-limited (receiving HTTP 429 responses on every subsequent request attempt) for more than 10 consecutive minutes, THEN THE System SHALL trigger an investigation alert to the operations team.
4. WHEN a request is rejected due to rate limiting, THE System SHALL return a response body containing an error message indicating the rate limit has been exceeded and the time remaining until reset.

### Requirement 4: Circuit Breaker for Runtime Availability

**User Story:** As a platform engineer, I want a circuit breaker protecting the API from cascading failures when the AgentCore Runtime is unavailable, so that the system fails gracefully rather than hanging.

#### Acceptance Criteria

1. IF more than 50% of requests to the AgentCore Runtime have failed (connection refused, timeout exceeding 5 seconds, or HTTP 5xx response) within a rolling 30-second window with a minimum of 5 requests, THEN WHEN a new request arrives, THE circuit breaker SHALL open and return HTTP 503 with a response body indicating Runtime unavailability within 200 milliseconds.
2. WHILE the circuit breaker is in the open state, WHEN 60 seconds have elapsed since the circuit opened, THE circuit breaker SHALL transition to half-open state and permit exactly 1 probe request to the AgentCore Runtime.
3. WHILE the circuit breaker is in the half-open state, WHEN the probe request receives an HTTP 2xx response from the AgentCore Runtime within 5 seconds, THE circuit breaker SHALL transition to the closed state and resume routing all requests to the Runtime.
4. WHILE the circuit breaker is in the half-open state, IF the probe request fails (connection refused, timeout exceeding 5 seconds, or HTTP 5xx response), THEN THE circuit breaker SHALL transition back to the open state and restart the 60-second wait period.
5. WHEN the circuit breaker transitions from closed to open, THE system SHALL trigger a P2 operational alert containing the failure rate percentage and the timestamp of the state transition.
6. WHILE the circuit breaker is in the open state, WHEN a request arrives, THE circuit breaker SHALL return HTTP 503 within 200 milliseconds without forwarding the request to the AgentCore Runtime.

### Requirement 5: Deterministic Cedar Authorization with Default-Deny

**User Story:** As a security architect, I want all tool invocations authorized by deterministic Cedar policies at the AgentCore Gateway boundary, so that authorization cannot be bypassed by prompt injection or jailbroken models.

#### Acceptance Criteria

1. IF no explicit Cedar permit policy matches the principal/action/resource combination for a tool invocation request, THEN THE AgentCore Gateway SHALL deny the request and return an authorization-denied response to the caller.
2. IF a tool invocation request matches both a permit and a forbid Cedar policy, THEN THE AgentCore Gateway SHALL deny the request regardless of how many permit policies match.
3. THE AgentCore Gateway SHALL source principal claims for Cedar policy evaluation exclusively from the cryptographically validated JWT — never from user-supplied input or LLM-generated content.
4. WHEN a Cedar policy is created or modified, THE CI/CD pipeline SHALL require approval from at least one reviewer who is not the policy author and SHALL pass `cedar validate` before the policy is deployed.
5. WHEN a Cedar policy evaluation completes, THE AgentCore Gateway SHALL log the decision (permit/deny), the determining policy ID, and the policy version to the immutable audit store before returning the response to the caller.
6. THE AgentCore Gateway SHALL complete each Cedar policy evaluation within 30 milliseconds at the 99th percentile under normal operating load.
7. IF the Cedar policy engine is unavailable or returns an evaluation error, THEN THE AgentCore Gateway SHALL deny the request (fail-closed) and return a service-unavailable indication to the caller.
8. IF writing to the immutable audit store fails, THEN THE AgentCore Gateway SHALL deny the in-flight request and return an error indication to the caller rather than proceeding without an audit record.

### Requirement 6: Two-Layer Authorization Independence

**User Story:** As a security architect, I want authorization enforced independently at both the Cedar policy layer and Lake Formation, so that a bug or misconfiguration in one layer cannot grant unauthorized access.

#### Acceptance Criteria

1. WHEN a query targeting an Athena table is executed, THE System SHALL have obtained an explicit authorization decision from both AgentCore Policy (Cedar) and Lake Formation in sequence — Cedar SHALL evaluate the tool-call request before the query is submitted to Athena, and Lake Formation SHALL enforce permissions at the query engine level — if either layer returns a deny decision, THE System SHALL block the query and return an authorization-denied response to the user within 5 seconds.
2. IF AgentCore Policy (Cedar) permits a request but Lake Formation denies it, THEN THE System SHALL block the request, log the divergence to the immutable audit store, and deliver an alert to the security operations team within 60 seconds indicating which principal, resource, and policy produced the conflicting decisions.
3. IF AgentCore Policy (Cedar) denies a request, THEN THE System SHALL block the request before submitting any query to Athena — Lake Formation SHALL NOT be consulted for requests already denied by Cedar.
4. WHEN a query executes against Athena, THE System SHALL enforce Lake Formation column-level, row-level, and cell-level permissions using the authenticated end user's federated identity propagated via On-Behalf-Of (OBO) token exchange — permissions SHALL NOT be evaluated using a shared service role or application-level identity.
5. THE System SHALL ensure that Cedar policy evaluation and Lake Formation grant enforcement share no common configuration store or policy definition source, so that a single misconfiguration cannot simultaneously compromise both layers.

### Requirement 7: On-Behalf-Of Identity for Athena Queries

**User Story:** As a security architect, I want every Athena query to execute under the requesting user's federated identity rather than a shared service role, so that Lake Formation per-user permissions function correctly and all queries are attributable.

#### Acceptance Criteria

1. WHEN an OBO token exchange is initiated for a tool call routed through the AgentCore Gateway, THE System SHALL produce a token that contains exactly one user federated identity ARN and the originating session identifier, and SHALL NOT associate the token with a shared service account or workload identity.
2. THE System SHALL store OBO tokens in AWS Secrets Manager with a maximum time-to-live of 90 days, after which the token SHALL be automatically rotated and the prior token invalidated within 60 seconds.
3. WHEN a user deprovisioning webhook is received from the corporate IdP, THE System SHALL revoke all OBO tokens for that user and terminate all active sessions associated with that user within 5 minutes of webhook receipt.
4. IF a user deprovisioning webhook delivery fails or is not acknowledged, THEN THE System SHALL retry delivery up to 3 times at 60-second intervals and, if still unacknowledged, SHALL flag the user for manual revocation review within 15 minutes.
5. WHEN an Athena query is submitted, THE System SHALL set the query execution identity to the requesting user's federated identity ARN and SHALL NOT execute the query under the AgentCore workload identity under any circumstance.
6. IF the OBO token exchange fails or the OBO token is expired or invalid at query submission time, THEN THE System SHALL reject the Athena query without executing it, SHALL NOT fall back to a shared service identity, and SHALL return an error indication stating that identity delegation failed.

### Requirement 8: Content Safety via Bedrock Guardrails

**User Story:** As a security architect, I want every model invocation scanned for prompt injection, jailbreak attempts, PII exposure, and toxic content, so that the chatbot cannot be weaponized against the organization.

#### Acceptance Criteria

1. WHEN any model call is invoked (SQL generation, summarization, or intent classification), THE System SHALL scan both the INPUT direction (user message and generated SQL) and the OUTPUT direction (query results and model narrative) through Bedrock Guardrails at the STANDARD tier with all content filter categories (prompt injection, jailbreak, toxicity, misconduct) set to HIGH threshold — no model call SHALL bypass scanning in either direction.
2. IF Bedrock Guardrails returns a BLOCK action for prompt injection, jailbreak, or toxic content detected in either direction, THEN THE System SHALL return a refusal message to the user that does not reveal the specific detection category or rule triggered, SHALL preserve the user's session state so subsequent valid requests can continue, and SHALL log the full Guardrails findings (scan direction, matched category, confidence score, and blocked content hash) to the immutable audit store.
3. WHEN the output scan detects PII entities in query results or model narrative, THE System SHALL apply the ANONYMIZE action to all detected PII entities before displaying results to the user, unless the user's role includes an explicit grant for that specific PII category as defined in the Cedar policy set.
4. IF the Bedrock Guardrails service is unavailable or fails to return a scan result within 5 seconds, THEN THE System SHALL fail closed by blocking the model call from completing, returning a service-unavailability message to the user, and logging the failure to the audit store.
5. IF a user triggers 3 or more BLOCK actions within a single session, THEN THE System SHALL terminate the session, log a security event to the audit store and SIEM, and require the user to re-authenticate before starting a new session.

### Requirement 9: SQL Safety Validation

**User Story:** As a security architect, I want all LLM-generated SQL validated deterministically before execution, so that only safe, bounded, cost-controlled SELECT queries reach Athena.

#### Acceptance Criteria

1. WHEN SQL generated by the LLM is submitted for validation, IF the SQL cannot be parsed into a valid abstract syntax tree, THEN THE System SHALL reject the statement and return an error indicating the SQL is malformed.
2. WHEN SQL generated by the LLM is submitted for validation, IF the statement type is not SELECT (e.g., INSERT, UPDATE, DELETE, DROP, ALTER, CREATE), THEN THE System SHALL reject the statement and return an error indicating only SELECT is permitted.
3. WHEN a SELECT statement targets a partitioned table, IF no WHERE clause condition references at least one partition key column, THEN THE System SHALL reject the statement and return an error specifying which partition key filters are required.
4. WHEN a SELECT statement targets a table with more than 50 columns, IF the statement uses SELECT * instead of explicit column names, THEN THE System SHALL reject the statement and return an error indicating the user must specify explicit column names.
5. WHEN the estimated bytes scanned for a validated SELECT exceeds 10 GB, IF the user does not belong to the elevated_cost group, THEN THE System SHALL reject the query and return an error suggesting the user add date or partition filters to reduce scan size.
6. WHEN a validated SELECT statement does not include an explicit LIMIT clause, THEN THE System SHALL inject LIMIT 10000 before execution.
7. WHEN a SELECT targets a table whose total stored size exceeds 1 TB and no WHERE clause restricts the scan to a subset of partitions, IF the user does not belong to the elevated_cost group, THEN THE System SHALL reject the query and return an error indicating full table scans on tables exceeding 1 TB require the elevated_cost entitlement.
8. WHEN SQL validation checks table references including tables in subqueries, common table expressions, and JOINs, IF any referenced table is not in the user's pre-computed authorized table set, THEN THE System SHALL reject the query and return an error indicating which table is unauthorized.
9. WHEN multiple validation rules fail for a single SQL statement, THE System SHALL reject the statement and return the error from the first failing rule in the evaluation order: parse validity, statement type, table authorization, partition filter, column selection, scan size, and LIMIT injection.

### Requirement 10: Agent Orchestration with Bounded Loops

**User Story:** As a security architect, I want the agent orchestration to be an explicit, auditable state graph with structurally bounded loops, so that all execution paths are visible to security review and runaway loops are impossible.

#### Acceptance Criteria

1. WHEN the LangGraph agent graph is constructed, THE System SHALL define all nodes and edges statically in the graph definition — no nodes, edges, or paths SHALL be created dynamically at runtime.
2. WHEN the disambiguation loop executes due to ambiguous user intent, THE System SHALL be structurally bounded to a maximum of 3 clarification rounds, enforced by graph edge conditions rather than runtime counters. IF the disambiguation loop reaches 3 rounds without resolution, THEN THE System SHALL terminate the loop, inform the user that clarification could not be resolved, and suggest the user refine their question with more specific terms.
3. WHEN the SQL self-correction retry loop executes due to a query execution error, THE System SHALL be structurally bounded to a maximum of 2 retry attempts, enforced by graph edge conditions rather than runtime counters. IF the retry loop exhausts 2 attempts without producing a valid query, THEN THE System SHALL terminate the loop, inform the user that the query could not be generated, and log the failure for review.
4. WHEN any tool call is dispatched from the agent, THE System SHALL route it exclusively through the AgentCore Gateway. IF a tool invocation is attempted outside the Gateway boundary, THEN THE System SHALL reject the call, log the violation to the audit store, and return an error to the agent graph without executing the tool.
5. WHEN the agent queries OpenSearch for schema retrieval via RAG, THE System SHALL filter results to include only schemas matching the authenticated user's Lake Formation grants. IF no schemas match the user's grants for the given query, THEN THE System SHALL inform the user that no accessible tables match their question and SHALL NOT pass unfiltered schema context to the LLM.

### Requirement 11: Immutable Audit Trail

**User Story:** As a compliance officer, I want an immutable, tamper-proof audit trail independent of operational telemetry that meets 7-year regulatory retention, so that all access decisions and queries are forensically traceable.

#### Acceptance Criteria

1. WHEN a request processed by the system completes (success or failure), THE System SHALL write an audit record within 5 seconds of completion containing: timestamp, trace_id, session_id, principal, original question (up to 10,000 characters), generated SQL, policy decision with policy ID and version, Lake Formation outcome, cost estimates, row count, and guardrails findings.
2. THE System SHALL apply S3 Object Lock in Compliance mode with a 7-year retention period to all audit records such that records cannot be deleted or overwritten by any account including the root account.
3. THE System SHALL replicate audit records to a secondary AWS region with a Recovery Point Objective of 15 minutes or less.
4. WHEN a DSAR or compliance investigation is initiated, THE System SHALL support querying audit records by principal and date range and return results within 60 seconds for queries spanning up to 90 days of records.
5. WHEN operational telemetry data is purged from AgentCore Observability, THE System SHALL retain all compliance audit trail records with zero record loss and no disruption to audit query availability.
6. IF an audit record fails to write after 3 retry attempts, THEN THE System SHALL emit an alert to the compliance monitoring channel and queue the record for retry, ensuring no audit event is silently dropped.

### Requirement 12: Network Isolation via VPC PrivateLink

**User Story:** As a network security engineer, I want all inter-service communication to occur exclusively over VPC PrivateLink with no public internet paths, so that data never traverses the public internet.

#### Acceptance Criteria

1. WHEN a connection is established between the system and any AWS service (Bedrock, Athena, Glue, S3, Secrets Manager, KMS, CloudWatch, OpenSearch, Cognito), THE System SHALL route exclusively through VPC PrivateLink interface endpoints with private DNS enabled — no NAT gateway or internet gateway paths SHALL exist in the VPC route tables for these services.
2. THE System SHALL enforce TLS 1.2 or higher on all PrivateLink endpoint connections and SHALL reject any connection attempt using TLS 1.0 or TLS 1.1.
3. THE System SHALL restrict inbound traffic to the internal Application Load Balancer to only the corporate CIDR range, enforced via security group rules on the ALB.
4. THE System SHALL restrict inbound traffic to the FastAPI ECS tasks on port 8000 to only the ALB security group, enforced via security group rules on the ECS tasks.
5. THE System SHALL attach VPC endpoint policies to each PrivateLink endpoint that restrict allowed actions and resources to only those required by the system, denying all other API calls at the endpoint boundary.
6. IF a network path to the public internet (NAT gateway, internet gateway, or public IP assignment) is detected for any component that communicates with the listed AWS services, THEN THE System SHALL generate a P1 security alert to the security operations team within 5 minutes of detection.

### Requirement 13: Daily Permission Reconciliation

**User Story:** As a security architect, I want a daily automated reconciliation comparing Cedar policy permits against Lake Formation grants, so that authorization drift between the two layers is detected and contained before it can be exploited.

#### Acceptance Criteria

1. WHEN the daily EventBridge schedule triggers the reconciliation job, THE System SHALL compare every (principal, action, table) tuple that has a Cedar permit against the corresponding Lake Formation grants, and vice versa, and SHALL complete the comparison within 60 minutes of invocation.
2. IF a divergence is detected where a Cedar permit exists without a corresponding Lake Formation grant, or a Lake Formation grant exists without a corresponding Cedar permit, THEN THE System SHALL trigger a P1 alert to the security operations team and SHALL fail-close (block) all requests for the affected principals within 5 minutes of detection, maintaining the block until an authorized security operator explicitly clears the divergence through the administrative interface.
3. IF the reconciliation job does not complete within 60 minutes of invocation, or terminates with an unhandled error, THEN THE System SHALL block all agent requests system-wide (assume breach posture), trigger a P1 alert to the security operations team, and maintain the block until the reconciliation job subsequently completes successfully with no divergences found.
4. WHEN reconciliation completes and zero divergences are found, THE System SHALL record a healthy-status entry in the immutable audit store and emit a CloudWatch metric indicating successful reconciliation with a timestamp.
5. IF the system is operating in assume-breach posture (all requests blocked due to reconciliation failure per criterion 3) for more than 4 hours, THEN THE System SHALL escalate to a P0 alert notifying the on-call security architect in addition to the security operations team.

### Requirement 14: Kill Switch

**User Story:** As a security operations engineer, I want an administrative kill switch that can immediately disable all chatbot access, so that a security incident can be contained within minutes.

#### Acceptance Criteria

1. WHEN an administrator invokes the kill switch API, THE System SHALL disable the specified Gateway target such that all subsequent user requests receive HTTP 503 with a response body indicating that the chatbot has been temporarily disabled, within 5 minutes of the API call.
2. WHEN the kill switch is activated, THE System SHALL reject 100% of new user requests to the disabled Gateway target — in-flight requests that have already passed the Gateway SHALL be allowed to complete but no new tool calls SHALL be initiated for those sessions.
3. WHEN the kill switch is activated, THE System SHALL record an immutable audit entry to the audit store containing: the operator identity, a mandatory reason field (minimum 10 characters, maximum 500 characters), the target identifier, and an ISO 8601 timestamp.
4. THE System SHALL restrict kill switch invocation to principals holding a designated security-operations role as defined in the Cedar policy set — unauthorized attempts SHALL receive HTTP 403 and be logged to the audit store.
5. WHEN an administrator invokes the kill switch re-enablement API, THE System SHALL restore the Gateway target to active status within 5 minutes, resume accepting user requests, and log the re-enablement event (operator identity, reason, timestamp) to the immutable audit store.

### Requirement 15: User Deprovisioning

**User Story:** As an identity management engineer, I want user deprovisioning from the corporate IdP to immediately revoke all chatbot access, so that departing employees cannot access sensitive data after their employment ends.

#### Acceptance Criteria

1. WHEN the Lambda webhook receives a deprovisioning event from the corporate IdP, THE System SHALL revoke all Cognito access tokens and refresh tokens for the identified user within 5 minutes of event receipt.
2. WHEN Cognito token revocation completes for a deprovisioned user, THE System SHALL delete the user's OBO token vault entry in Secrets Manager within the same 5-minute SLA measured from the original IdP event receipt.
3. WHEN all revocation steps (Cognito token revocation and Secrets Manager deletion) complete, THE System SHALL write an audit record to the immutable audit store containing: user principal, IdP event timestamp, Cognito revocation completion timestamp, Secrets Manager deletion completion timestamp, and final status (success or partial failure).
4. IF the Lambda webhook fails to process the deprovisioning event or any revocation step fails, THEN THE System SHALL retry the failed operation up to 3 times within the 5-minute SLA, and IF all retries are exhausted, THEN THE System SHALL generate a P1 alert to the security operations team and log the failure to the immutable audit store.

### Requirement 16: Schema Synchronization and RAG Retrieval

**User Story:** As a data platform engineer, I want the vector store schema embeddings to stay synchronized with the Glue Catalog and filtered by user authorization, so that the agent only retrieves schemas the user is permitted to access.

#### Acceptance Criteria

1. WHEN an EventBridge event indicates a table creation or modification in the AWS Glue Catalog, THE System SHALL re-index the corresponding schema embedding in OpenSearch Serverless within 60 minutes of the event timestamp.
2. WHEN an EventBridge event indicates a table deletion in the AWS Glue Catalog, THE System SHALL remove the corresponding schema embedding from OpenSearch Serverless within 60 minutes of the event timestamp.
3. WHEN a user submits a RAG retrieval request, THE System SHALL filter candidate schemas to only those matching the authenticated user's Lake Formation grants (via lake_formation_tags) before selecting the top-k results for inclusion in the LLM context.
4. IF the schema re-indexing pipeline fails to complete within 60 minutes, THEN THE System SHALL generate an alert to the operations team and retry the indexing operation a maximum of 3 times with exponential backoff.
5. THE System SHALL configure the OpenSearch Serverless collection as a vector type collection with VPC-only access — no public endpoint SHALL exist for the collection.

### Requirement 17: Error Handling and User Guidance

**User Story:** As a business user, I want clear, actionable error messages when my requests are denied or fail, so that I understand what went wrong and how to fix it without exposing security internals.

#### Acceptance Criteria

1. IF a Cedar or Lake Formation policy denial occurs, THEN THE System SHALL return a message stating that access to the requested data is not available and directing the user to the Data Governance portal, without revealing policy IDs, Cedar policy source, rule identifiers, or Lake Formation grant details.
2. IF a cost threshold exceeded error occurs, THEN THE System SHALL return a message stating the estimated scan size in GB, the configured threshold limit, and a suggestion to add date or partition filters to narrow the query scope.
3. IF Bedrock Guardrails blocks a request, THEN THE System SHALL return the fixed response "I can't help with that request. Please rephrase your question about the data." without revealing the guardrail rule triggered, the detection category, or the content that caused the block.
4. IF SQL self-correction fails after the maximum of 2 retries, THEN THE System SHALL return a message suggesting the user rephrase the question or ask a simpler version, and SHALL log the failure chain (original question, generated SQL attempts, and error details) to the audit store.
5. WHEN any error response is returned to the user, THE System SHALL include a unique trace_id value in the response body that the user can reference when contacting support.
6. IF an error occurs that does not match any of the classified error types (policy denial, cost threshold, guardrails block, SQL failure, rate limit, or system unavailability), THEN THE System SHALL return a generic message stating that an unexpected error occurred and providing the trace_id for support reference, without revealing internal stack traces, service names, or infrastructure details.
7. THE System SHALL return all error responses within 5 seconds of detecting the error condition, measured from the point the error is identified to the point the user-facing message is delivered.

### Requirement 18: Performance and Latency Targets

**User Story:** As a platform engineer, I want end-to-end query latency within defined bounds, so that business users get timely responses without the system consuming excessive resources.

#### Acceptance Criteria

1. WHILE the system is under normal load (up to 200 concurrent sessions), WHEN a query scanning less than 1 GB of data executes the full pipeline (authentication through response delivery), THE System SHALL complete with a P95 end-to-end latency not exceeding 30 seconds and a P99 latency not exceeding 45 seconds.
2. WHILE JWKS keys are cached in memory, WHEN JWT validation is performed on an incoming request, THE System SHALL complete validation within 15 milliseconds at P95.
3. WHILE compiled Cedar policies are loaded, WHEN a policy evaluation is triggered for a tool-call authorization decision, THE System SHALL complete evaluation within 30 milliseconds at P95.
4. WHEN the FastAPI ECS service's average response time exceeds 1 second over a 60-second evaluation window OR average CPU utilization exceeds 60% over a 60-second evaluation window, THE System SHALL scale out by adding at least 1 additional task within 120 seconds, maintaining a minimum of 2 tasks and a maximum of 10 tasks.
5. WHEN the FastAPI ECS service's average response time falls below 500 milliseconds AND average CPU utilization falls below 30% over a 300-second evaluation window, THE System SHALL scale in by removing tasks, while maintaining a minimum of 2 running tasks at all times.
6. IF the JWKS key cache is empty or expired at the time of JWT validation, THEN THE System SHALL retrieve keys and complete validation within 500 milliseconds at P95, and SHALL cache the retrieved keys for subsequent requests.
