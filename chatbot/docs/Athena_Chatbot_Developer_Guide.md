# Athena Data Chatbot — Developer Guide

*How to build, extend, test, and operate the natural-language chatbot
over Amazon Athena. Includes implementation patterns, design rationale,
evaluation framework, and known limitations.*

|                |                                                                                                                            |
|----------------|----------------------------------------------------------------------------------------------------------------------------|
| **Audience**   | Engineers building or extending the chatbot (Backend, Infrastructure, Data/ML, Security/DevOps)                            |
| **Primary stack**  | LangGraph, AgentCore (Runtime/Gateway/Policy/Identity/Memory/Observability), Athena, Lake Formation, OpenSearch Serverless |
| **Data scope**     | A few hundred Athena tables — schema discovery is a first-class design concern, not an afterthought                        |
| **Companion docs** | Security Architecture Design (SAD v2.1); Architect Guide; User Guide                                                      |

## Table of Contents

- [1. System Overview](#1-system-overview)
- [2. Why This Stack? — Design Rationale](#2-why-this-stack--design-rationale)
  - [2.1 Why LangGraph (not a managed agent or ReAct loop)](#21-why-langgraph-not-a-managed-agent-or-react-loop)
  - [2.2 Why RAG + Foundation Model (not fine-tuning)](#22-why-rag--foundation-model-not-fine-tuning)
  - [2.3 Why Cedar (not OPA, RBAC, or IAM alone)](#23-why-cedar-not-opa-rbac-or-iam-alone)
  - [2.4 Why OBO Tokens (not a shared service role)](#24-why-obo-tokens-not-a-shared-service-role)
- [3. Local Development Setup](#3-local-development-setup)
  - [3.1 Prerequisites](#31-prerequisites)
  - [3.2 Repository Layout](#32-repository-layout)
- [4. The LangGraph Agent Graph](#4-the-langgraph-agent-graph)
  - [4.1 Nodes (in order)](#41-nodes-in-order)
  - [4.2 Conditional Edges — Enforce Retry Bounds Structurally](#42-conditional-edges--enforce-retry-bounds-structurally)
  - [4.3 Implementation Patterns and Known Deviations](#43-implementation-patterns-and-known-deviations)
- [5. Schema Retrieval at Scale (A Few Hundred Tables)](#5-schema-retrieval-at-scale-a-few-hundred-tables)
  - [5.1 Gateway Semantic Tool Search](#51-gateway-semantic-tool-search)
  - [5.2 Schema RAG via OpenSearch Serverless](#52-schema-rag-via-opensearch-serverless)
  - [5.3 Why OpenSearch Serverless (not pgvector or Pinecone)](#53-why-opensearch-serverless-not-pgvector-or-pinecone)
  - [5.4 Benchmarking Requirement](#54-benchmarking-requirement)
- [6. SQL Generation & Validation](#6-sql-generation--validation)
  - [6.1 Validation Rules (7-Step Pipeline)](#61-validation-rules-7-step-pipeline)
  - [6.2 What the LLM Does vs. What Validation Does](#62-what-the-llm-does-vs-what-validation-does)
- [7. Writing & Testing Cedar Policies](#7-writing--testing-cedar-policies)
  - [7.1 The Reconciliation Job — Don't Skip This](#71-the-reconciliation-job--dont-skip-this)
- [8. Evaluation Framework](#8-evaluation-framework)
  - [8.1 Domain-Specific Evaluators](#81-domain-specific-evaluators)
  - [8.2 Property-Based Testing](#82-property-based-testing)
  - [8.3 Adversarial Testing](#83-adversarial-testing)
  - [8.4 How to Interpret Evaluation Results](#84-how-to-interpret-evaluation-results)
- [9. CI/CD Pipeline & Deployment](#9-cicd-pipeline--deployment)
- [10. Observability & Debugging a Query](#10-observability--debugging-a-query)
- [11. Adding a New Tool via Gateway / MCP](#11-adding-a-new-tool-via-gateway--mcp)
- [12. Known Limitations & Implementation Trade-offs](#12-known-limitations--implementation-trade-offs)
- [13. Implementation Roadmap (Waves 1–8)](#13-implementation-roadmap-waves-18)
  - [13.1 Team Roles](#131-team-roles)
  - [13.2 Definition of Done (every task)](#132-definition-of-done-every-task)
  - [13.3 Key Engineering Risks to Track](#133-key-engineering-risks-to-track)
- [14. Local Testing Checklist](#14-local-testing-checklist)

[⬆ Back to top](#table-of-contents)

## 1. System Overview

The chatbot takes a natural-language question, converts it into a
validated, authorised, read-only SQL query against Amazon Athena, and
returns a formatted result. The request flow is:

- Chat UI → Corporate IdP (SAML/OIDC + MFA) → Amazon Cognito (issues
  15-min JWT)

- FastAPI on ECS Fargate — validates JWT, rate-limits (30 req/min/user),
  forwards to the agent

- AgentCore Runtime — hosts the LangGraph agent graph

- AgentCore Gateway — the single governed entry point for every tool
  call, with semantic tool search

- AgentCore Policy (Cedar) — default-deny authorization check at the
  Gateway boundary

- AgentCore Identity (OBO) — exchanges the agent's token for a token
  scoped to the real end user

- Athena MCP Server → Amazon Athena (read-only workgroup) → AWS Lake
  Formation (row/column/cell enforcement)

- AgentCore Observability → CloudWatch → bank SIEM; S3 Object Lock for
  immutable 7-year audit

> ***Note:** Two independent authorization layers exist by design
> (Policy at the Gateway, Lake Formation at the query engine). Never
> treat these as redundant — each is a full mitigation for the other's
> potential misconfiguration. See Section 7.*


[⬆ Back to Table of Contents](#table-of-contents)

## 2. Why This Stack? — Design Rationale

Developers joining this project need to understand not just *what* was
built, but *why*. This section gives the reasoning behind the key
choices so that future changes are made with full context, not just
familiarity with the code.

### 2.1 Why LangGraph (not a managed agent or ReAct loop)

**What was considered:**

| Option | Why rejected |
|--------|-------------|
| Bedrock Managed Agents | Black-box orchestration: AWS manages the agent loop internally. You cannot show a regulator or security architect every possible execution path. Cannot enforce bounded retries structurally. |
| Strands Agents | Less mature graph definition. Conditional edges are not first-class. Less auditable. |
| CrewAI | Designed for multi-agent collaboration; unnecessary overhead for a single-agent flow. |
| Custom state machine | Maintenance burden, missing ecosystem (memory, streaming, evaluation). |
| Free-form ReAct loop | Unbounded retries possible; no structural graph for audit review. |

**Why LangGraph:**
LangGraph was chosen because its explicit graph — conditional edges and
bounded loops as first-class constructs — can be directly audited by a
security architect or model risk committee. The graph can be rendered as
a diagram and every possible execution path is enumerable. In a
regulated bank environment, "show me every path this system can take"
is not a theoretical question; it is a formal governance requirement.

**Reassess if:** the pipeline simplifies to the point where there is no
disambiguation branch and no self-correction loop — at that point Strands
Agents (simpler, AWS-native) becomes a reasonable lighter-weight
alternative.

### 2.2 Why RAG + Foundation Model (not fine-tuning)

**What was considered:**

| Option | Why rejected |
|--------|-------------|
| Fine-tuned SQL model | Requires ongoing training data collection and retraining as schemas change. Hard to generalize to novel phrasing. Adds model drift management overhead. Higher MRM burden (SR 26-2 requires performance monitoring of fine-tuned models). |
| Structured query builder (keyword/template) | Breaks for questions that use business language the template doesn't cover. Cannot handle the long tail of analyst questions. |
| Curated BI tool | Excellent for known, fixed questions. Does not solve the natural-language understanding problem for ad-hoc queries. |

**Why RAG + foundation model:**
- No retraining needed as schemas change — new tables re-indexed in
  OpenSearch within 1 hour of Glue Catalog changes
- Foundation model (Claude Sonnet, temperature=0) generalizes to novel
  phrasing that templates and fine-tuned models miss
- Clear evaluation surface: SQL correctness is measurable against a
  golden dataset
- The model does NOT make authorization decisions — those are handled
  deterministically by Cedar and Lake Formation

**Current performance target:** ≥95% SQL correctness on the golden
dataset. This is the CI gate for prompt or model changes.

### 2.3 Why Cedar (not OPA, RBAC, or IAM alone)

**What was considered:**

| Option | Why rejected |
|--------|-------------|
| OPA (Rego) | Default-allow-unless-denied semantics require extra care to implement default-deny correctly. Cedar's default-deny is correct-by-construction. Smaller native AgentCore integration. |
| IAM policies only | IAM is powerful but doesn't express business-level rules (e.g., "analysts in department X can query classification tier ≤ confidential"). Cedar ABAC evaluates the full set of user attributes. |
| Application-level RBAC | Application code is inside the trust boundary of the agent — a jailbroken model can still influence application code logic. Cedar evaluates at the Gateway, outside the agent. |

**Why Cedar:**
Cedar is deterministic, formally verifiable, and evaluates at the
AgentCore Gateway boundary — which the LLM never crosses. The forbid-wins
semantics mean that adding a Cedar policy for blocked databases is
structurally safe: a permit that accidentally overlaps with a forbid is
always overridden. Default-deny means that absence of a policy for a
new table means no access, not accidental access.

**Trade-off accepted:** Cedar's ecosystem is smaller than OPA's. Fewer
IDE plugins, community examples, and third-party integrations exist.
This is outweighed by the structural safety properties.

### 2.4 Why OBO Tokens (not a shared service role)

**What was considered:**

| Option | Why rejected |
|--------|-------------|
| Shared service role (single IAM role for all queries) | Lake Formation applies per-user row/column/cell filters when the query runs as the user's own identity. A shared role sees the **union** of all users' permissions — this defeats fine-grained access control entirely. |
| User-provided credentials | Security anti-pattern — credentials embedded in requests. |

**Why OBO tokens:**
Lake Formation's row-level security and column-level security are applied
at query execution time based on the *identity* running the query. For
per-user filters to work correctly, each Athena query must execute as
the requesting user's own federated identity. OBO token exchange is the
mechanism that achieves this: the AgentCore workload exchanges its
credential for a short-lived token scoped to the specific end user.

**Trade-off accepted:** OBO token exchange is a relatively new service
(GA April 30, 2026). It requires more operational care than a shared
role and a dedicated penetration test before production.


[⬆ Back to Table of Contents](#table-of-contents)

## 3. Local Development Setup

### 3.1 Prerequisites

- Python 3.11+, Node.js 18+ (for AWS CDK), AWS CLI v2 configured against
  the dev account

- AWS CDK (TypeScript) — infrastructure lives in `chatbot/infra/` as
  separate stacks: NetworkStack, SecurityStack, DataStack, ComputeStack,
  ObservabilityStack

- AgentCore Starter Toolkit (open source) — supports LangGraph, CrewAI,
  Strands Agents, AutoGen, LlamaIndex

- `cedar` CLI for local policy linting (`cedar validate`) before every
  commit

- `sqlglot` for local SQL AST parsing (Trino/Athena dialect) — used by
  the `validate_sql` node

### 3.2 Repository Layout

|                                       |                                                                                                                                                 |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| **Path**                              | **Contents**                                                                                                                                    |
| `chatbot/api/`                        | FastAPI app: `main.py` (routes, exception handlers), `auth.py` (JWT validation, rate limiting), `middleware.py` (session, circuit breaker, trace IDs), `models.py` (Pydantic contracts) |
| `chatbot/agent/`                      | LangGraph: `graph.py` (static graph definition), `state.py` (AgentState dataclass), `nodes/` (10 node implementations)                         |
| `chatbot/mcp_server/`                 | Athena MCP server: `server.py` (tool registration, gateway enforcement), `tools/` (4 tool implementations), `validation.py` (7-step SQL validator) |
| `chatbot/infra/`                      | AWS CDK stacks (Network, Security, Data, Compute, Observability)                                                                                |
| `chatbot/policies/`                   | Cedar policy files: `base.cedar` (universal forbids), `analysts.cedar`, `managers.cedar`, `schema.cedarschema`                                  |
| `chatbot/scripts/`                    | Operational scripts: `reconciliation.py` (daily Cedar↔LF comparison), `kill_switch.py` (admin disable/enable), `reindex_vectors.py` (schema sync), `audit.py` (shared audit module) |
| `chatbot/tests/`                      | `unit/`, `integration/`, `property/` (Hypothesis), `adversarial/`, `eval/` (golden dataset)                                                    |
| `.kiro/specs/chatbot-security-architecture/` | `design.md`, `requirements.md`, `tasks.md` — the approved specs this build traces to                                                    |

> ***Note:** Every task in `tasks.md` traces to a specific requirement.
> When reviewing a PR, cross-reference the cited requirement to verify
> the change is consistent with the approved design — don't just check
> that tests pass.*


[⬆ Back to Table of Contents](#table-of-contents)

## 4. The LangGraph Agent Graph

Before writing code for the graph, produce a Mermaid diagram of the
planned structure and get it reviewed by the security team. Structural
mistakes (a missing branch, an unbounded loop) are cheap to fix in a
diagram and expensive to fix in 200 lines of Python.

### 4.1 Nodes (in order)

|        |                  |                                                                                                                 |
|--------|------------------|-----------------------------------------------------------------------------------------------------------------|
| **\#** | **Node**         | **Purpose**                                                                                                     |
| 1      | intent_classify  | Categorize the input: query / clarification / follow-up / out-of-scope. Uses Claude Haiku (small, fast). 2s budget. |
| 2      | glossary_resolve | Map business terms ("revenue", "EMEA") to technical table/column names using the business glossary              |
| 3      | schema_retrieve  | RAG over OpenSearch to fetch top-k relevant schemas — restricted to schemas the user is authorized for (R-10.5) |
| 4      | disambiguate     | Conditional branch: if ambiguous, ask the user a clarifying question (looped, max 3 rounds)                     |
| 5      | sql_generate     | Bedrock model call (Claude Sonnet, temperature=0), wrapped in Guardrails on both input and output               |
| 6      | validate_sql     | Deterministic 7-step AST-based validation (sqlglot, Trino dialect); LIMIT injection; cost estimate              |
| 7      | tool_call        | Invoke `run_query` via the Gateway — triggers Policy evaluation, then OBO, then Lake Formation                  |
| 8      | self_correct     | On SQL error, retry SQL generation with the error context (max 2 attempts), then fail gracefully                |
| 9      | output_scan      | Bedrock Guardrails PII scan on both raw results and the generated narrative                                     |
| 10     | format_respond   | Format table + narrative + data-freshness indicator; return to FastAPI                                          |

### 4.2 Conditional Edges — Enforce Retry Bounds Structurally

- `schema_retrieve` → `disambiguate` (if intent ambiguous AND rounds < 3) OR → `sql_generate` (if clear OR rounds exhausted)

- `disambiguate` → `sql_generate` (on resolved intent or max rounds) OR loops back (max 3 total)

- `validate_sql` → `sql_generate` (on validation failure, treat as self-correct attempt) OR → `tool_call` (on pass)

- `tool_call` → `self_correct` (on SQL execution error) OR → `output_scan` (on success or access denied)

- `self_correct` → retry `tool_call` (if attempts < 2) OR → `format_respond` (max retries exhausted)

> ***Critical:*** Retry bounds must be enforced structurally in the graph
> definition — not with a runtime counter variable that could be reset or
> bypassed. A security reviewer needs to look at the graph and see that
> every loop is bounded, without reading runtime logic. The graph
> structure IS the proof.

### 4.3 Implementation Patterns and Known Deviations

**State representation duality:**
`AgentState` is defined as a Python dataclass in `chatbot/agent/state.py`
for developer ergonomics (IDE autocomplete, type checking). However,
LangGraph requires a `TypedDict` for graph state. The `graph.py` file
defines a parallel `GraphState` TypedDict that mirrors `AgentState`.
Conversion happens at graph entry/exit. Developers must keep these two
in sync when adding new state fields.

**UserClaims serialization:**
LangGraph graph state must be JSON-serializable (for checkpointing and
AgentCore Memory). `UserClaims` (a Pydantic model) is converted to a
plain `dict` before entering the graph state and reconstructed as
needed inside nodes. Nodes that need the full `UserClaims` object should
call `UserClaims(**state["user_claims"])`.

**Gateway enforcement at the MCP layer:**
The MCP server validates the `X-AgentCore-Gateway-Signature` header on
every tool invocation. Requests without a valid gateway signature are
rejected before any tool logic runs. This means you cannot call the MCP
server directly during development without spoofing this header — use
the test fixtures in `tests/unit/test_mcp_server.py` which mock the
gateway signature validation for unit testing.

**In-memory session store:**
The `SessionStore` in `chatbot/api/middleware.py` is in-memory at the
ECS task level. In multi-task deployments with sticky sessions on the
ALB, this works correctly. Without sticky sessions, a user whose
request hits a different task than their authentication request will
receive HTTP 401 (session not found). The current deployment relies on
ALB sticky sessions; a future enhancement would move session state to
ElastiCache.

**Singleton pattern for cross-module state:**
`AuditStore`, `CircuitBreaker`, and `SessionStore` are initialized as
module-level singletons in `chatbot/api/main.py`. This is intentional
for the single-process FastAPI deployment; do not add distributed
locking without first evaluating the impact on the 15ms JWT validation
latency target.


[⬆ Back to Table of Contents](#table-of-contents)

## 5. Schema Retrieval at Scale (A Few Hundred Tables)

With a few hundred tables, the chatbot cannot rely on stuffing the full
schema into every prompt, and a user cannot be expected to know which
table holds an answer. Two mechanisms solve this together:

### 5.1 Gateway Semantic Tool Search

The Gateway's built-in semantic search resolves "which of 300+ table
tools do I need" at the tool layer, before the agent reasons about SQL.
Register each data domain as a distinct MCP target so semantic search
has meaningful granularity, rather than one monolithic tool covering
everything.

### 5.2 Schema RAG via OpenSearch Serverless

- **Embedding pipeline:** an EventBridge-triggered Lambda function
  (`chatbot/scripts/reindex_vectors.py`) exports Glue Catalog metadata
  (table name, database, column names/types, partition keys, description,
  classification tags, business glossary terms, synonyms) and embeds it
  using Bedrock Titan Embeddings.

- **Index structure:** indexed into an OpenSearch Serverless
  VECTORSEARCH collection (VPC-endpoint access only, customer-managed
  KMS key). Each document includes `lake_formation_tags` for
  authorization-aware retrieval.

- **Re-indexing:** EventBridge triggers re-indexing within 1 hour of any
  Glue Catalog change (create, modify, or delete). The Glue Catalog is
  always the source of truth — never the vector store itself.

- **Authorization-aware retrieval:** `schema_retrieve` filters candidates
  by `lake_formation_tags` matching the authenticated user's grants
  *before* selecting the top-k results. Unauthorized table/column names
  must never appear in the LLM prompt context — this is itself a
  potential information-disclosure vector (T-06 in the threat model).

### 5.3 Why OpenSearch Serverless (not pgvector or Pinecone)

| Alternative | Why rejected |
|-------------|-------------|
| Pinecone | Third-party SaaS: data residency concern for a bank. Embeddings (which include column and table descriptions) would leave the bank's AWS environment. |
| pgvector (Aurora PostgreSQL) | Additional database management overhead. Aurora is not optimized for pure vector workloads. Scaling requires capacity planning. |
| Amazon Kendra | Full-text search focus with semantic ranking. Not optimized for dense vector similarity search. Higher per-query cost for this use case. |

**Why OpenSearch Serverless:**
VPC-only access, serverless scaling (no capacity planning), native
Bedrock integration for embedding generation, and AWS data residency
guarantees. The vector type collection with VECTORSEARCH is purpose-built
for this use case.

**Trade-off:** OCU-based pricing model means cost scales with collection
size. Monitor OpenSearch Serverless OCU consumption as the schema library
grows.

### 5.4 Benchmarking Requirement

> ***Engineering Risk:*** Schema-retrieval latency is a specifically
> flagged risk at this table count (Medium likelihood / Medium impact).
> Benchmark retrieval latency at 100, 300, and 500 tables during Wave 2.
> If P95 retrieval latency threatens the 30-second end-to-end budget
> (target: ≤500ms), tune `k` (number of retrieved candidates) and
> consider switching from Titan Embeddings to Cohere Embed for better
> multilingual recall at large scale.


[⬆ Back to Table of Contents](#table-of-contents)

## 6. SQL Generation & Validation

### 6.1 Validation Rules (7-Step Pipeline)

The `validate_sql` node in `chatbot/mcp_server/validation.py` applies
these checks in strict evaluation order (Requirement 9.9). A failure at
any step returns an error with the first failing rule — subsequent rules
are not evaluated:

| Step | Check | Default action |
|------|-------|----------------|
| 1 | Parse validity — can the SQL be parsed into a valid AST (sqlglot, Trino dialect)? | Reject: "Invalid SQL syntax" |
| 2 | Statement type — is it a SELECT? (Not INSERT, UPDATE, DELETE, DROP, ALTER, CREATE) | Reject: "Only SELECT statements permitted" |
| 3 | Table authorization — are all referenced tables (including subqueries, CTEs, JOINs) in the user's authorized set? | Reject: "Unauthorized table: {table}" |
| 4 | Partition filter — if the table is partitioned, does the WHERE clause reference at least one partition key? | Reject: "Partition filter required on {table}" |
| 5 | Column selection — if SELECT *, does the table have >50 columns? | Reject: "SELECT * not allowed on {table} ({n} columns)" |
| 6 | Scan size — estimated bytes > 10 GB without `elevated_cost` group? Full scan of >1 TB table without `elevated_cost`? | Reject with cost estimate and suggestion |
| 7 | LIMIT injection — if no LIMIT clause, add LIMIT 10000 | Modify: return modified SQL |

**AST parsing:** `sqlglot` with `dialect="trino"` (Athena is Trino-
compatible). CTE aliases are excluded from the authorization check (they
are defined within the query, not external tables).

### 6.2 What the LLM Does vs. What Validation Does

This boundary must never blur. If you are considering relaxing a
validation check, ask: "Am I moving security responsibility to the LLM?"
If yes, the answer is no.

| Responsibility | Owner | Rationale |
|----------------|-------|-----------|
| Natural language → SQL intent | LLM | Only the LLM can handle the combinatorial space of business language |
| SQL syntax correctness | LLM (primary), self-correction (retry) | Model generates; Athena engine is the final arbiter |
| Statement type enforcement | `validate_sql` (AST) — not the LLM | The LLM could be prompted to "only generate SELECT" but that's a soft constraint; the AST check is structural |
| Table authorization in SQL | `validate_sql` (AST reference extraction) — not the LLM | Same reasoning — a jailbroken model could target unauthorized tables; the AST check catches this |
| Partition filter presence | `validate_sql` (AST structure check) — not the LLM | LLM may forget; deterministic check never does |
| Cost estimation | Athena dry-run API — not the LLM | Model cannot know scan size; the actual engine can estimate it |
| Row/column-level access control | Lake Formation — not the LLM | Engine-enforced; not bypassed by how the SQL is phrased |


[⬆ Back to Table of Contents](#table-of-contents)

## 7. Writing & Testing Cedar Policies

Cedar policy is the first of the two authorization layers (Policy at the
Gateway; Lake Formation at the query engine). A representative policy
pair:

```cedar
// Analysts can run queries against their department's databases
permit (
    principal,
    action == Action::"run_query",
    resource
) when {
    principal.role == "analyst" &&
    resource.database in principal.department_databases &&
    resource.classification_tier <= principal.data_classification_tier
};

// No one accesses PCI databases via chatbot (defense in depth)
forbid (
    principal,
    action,
    resource
) when {
    resource.database in ["pci_cardholder", "pci_transactions"]
};
```

- **Default-deny:** no permit exists → the request is denied. There is
  no implicit allow-all anywhere in the system.

- **forbid always wins over permit** — use forbid for any database that
  must never be reachable via this agent, regardless of group membership.

- **Natural-language authoring is fine as a first draft,** but every
  generated Cedar statement requires human security-team review before
  deployment — this is a hard CI/PR gate, not a formality.

- **CI enforcement:** `cedar validate` runs in CI; a policy that fails
  validation cannot merge. Run `cedar validate --schema policies/schema.cedarschema policies/*.cedar` locally before pushing.

- **Segregation of duties:** the author of a Cedar change and its
  approver must be different people, for both Cedar policies and
  Guardrail configuration changes.

- **Policy versioning:** Cedar policy changes are committed to Git with a
  version tag. Every Cedar evaluation logs the specific policy_id and
  policy_version that determined the decision — this supports forensic
  investigation of authorization decisions.

### 7.1 The Reconciliation Job — Don't Skip This

`chatbot/scripts/reconciliation.py` runs daily via EventBridge and
compares every Cedar permit against the corresponding Lake Formation
grant for the same (principal, table) combination — in both directions.
Any divergence triggers a P1 alert via SNS and fails-closed the affected
principals (blocks their requests) until an authorized operator clears
the divergence.

If the reconciliation job itself fails to complete within 60 minutes,
it assumes breach: all requests are blocked system-wide until the job
runs successfully with zero divergences.

**Why this matters:** The reconciliation job catches the one failure mode
that neither authorization layer alone can detect — simultaneous
misconfiguration of both layers for the same user/table. Don't optimize
it away.

**Operational note:** operators can manually trigger reconciliation at
any time by invoking the Lambda directly. This is documented in the
runbooks.


[⬆ Back to Table of Contents](#table-of-contents)

## 8. Evaluation Framework

Saying "we tested it" is not sufficient for a regulated system. This
section describes the evaluation framework in enough detail for a model
risk committee to assess it.

### 8.1 Domain-Specific Evaluators

Five evaluators run in CI on every merge that touches a prompt template,
few-shot example, model configuration, or Guardrails rule:

| Evaluator | Pass criterion | Implementation |
|-----------|----------------|----------------|
| **SQL correctness** | ≥95% of golden queries produce correct results | Batch eval against golden dataset; semantic comparison (same rows/columns), not string equality |
| **Schema fidelity** | 100% — zero hallucinated columns or tables | AST extraction of all table/column references; compared against the schema context actually injected into the prompt |
| **Cost compliance** | Zero queries exceed 10 GB threshold in eval set | Automated Athena dry-run cost estimation on every golden dataset query |
| **Answer quality** | ≥4.0/5.0 average across eval set | LLM-as-judge (Claude Opus) scoring on faithfulness, completeness, clarity |
| **Safety** | Zero PII leakage across eval set | Guardrails PII scan on all eval outputs; zero tolerance |

**Golden dataset management:**
- Minimum 50 (question, expected\_SQL, expected\_result) triples at launch
- Dataset grows monotonically: any production bug that causes an
  incorrect answer generates a new entry
- Covers: simple aggregations, cross-table joins, date-filtered queries,
  partition-required queries, out-of-scope questions, disambiguation-
  required questions, ambiguous business terms

### 8.2 Property-Based Testing

`chatbot/tests/property/` contains 12 Hypothesis-based property tests
that validate universal correctness invariants across thousands of
randomly generated inputs. These are not examples — they are proofs
that hold for all valid inputs:

```python
@given(
    sql=st.text(min_size=1, max_size=5000),
)
def test_non_select_always_rejected(sql):
    """Any SQL that does not start with SELECT must be rejected."""
    assume(not sql.strip().upper().startswith("SELECT"))
    result = validate_sql(sql, make_user())
    assert result.valid is False

@given(
    disambiguation_rounds=st.integers(min_value=0, max_value=100),
)
def test_disambiguation_loop_bounded(disambiguation_rounds):
    """Graph edge never triggers disambiguation when rounds >= 3."""
    state = AgentState(disambiguation_rounds=disambiguation_rounds)
    # If rounds >= 3, should_disambiguate returns sql_generate, not disambiguate
    if disambiguation_rounds >= 3:
        assert should_disambiguate(state) == "sql_generate"

@given(
    principal=st.text(min_size=1),
    table=st.text(min_size=1),
)
def test_forbid_always_wins(principal, table):
    """If a forbid policy matches, decision is always DENY."""
    add_permit(principal, "run_query", table)
    add_forbid(principal, "run_query", table)
    decision = evaluate_policy(make_request(principal, "run_query", table))
    assert decision.decision == "DENY"
```

The 12 properties tested are: No Gateway Bypass, Default-Deny, Forbid
Wins, Two-Layer Independence, OBO Never Shared Role, Bounded Loops,
Guardrails on Every Call, Audit Completeness, Token Lifetime Bounds,
Reconciliation Fail-Closed, SQL Safety Invariant, Deprovisioning SLA.

### 8.3 Adversarial Testing

`chatbot/tests/adversarial/` contains ≥100 adversarial prompt scenarios
that must all be tested before production launch. Categories:

- Prompt injection via question text (override system prompt)
- Jailbreak (social engineering to ignore safety constraints)
- SQL injection embedded in natural language
- Identity escalation claims (claiming to be admin or different user)
- Policy bypass probes (mapping error messages to Cedar structure)
- Token replay (expired/revoked OBO tokens)
- Session boundary violations (cross-session data access attempts)

All Critical and High findings from adversarial tests must be remediated
before production. Results are formal governance artefacts.

### 8.4 How to Interpret Evaluation Results

| Result | What it means | Action |
|--------|---------------|--------|
| SQL correctness < 95% | Model quality regression: prompt changes, schema context quality change, or model version issue | Block merge, investigate prompt + golden dataset |
| Schema fidelity < 100% | Model hallucinating table/column names not in the schema context | Block merge — this is high risk; investigate schema retrieval quality |
| Safety fails (PII leakage) | Guardrails or output scan is not catching PII in model output | Block merge immediately; this is a compliance issue |
| Answer quality < 4.0 | Model output is technically correct but not useful | Investigate prompt; acceptable to merge with tracking if correctness is 100% |
| Cost compliance fails | Query generated that would exceed cost threshold | Block merge; investigate validation logic |

> ***Note:*** A 95% SQL correctness rate means approximately 1 in 20
> generated queries will be wrong. Users must understand this. The
> data-freshness timestamp, the row count display, and explicit guidance
> ("verify before acting on results") in the User Guide are the risk
> mitigations for this residual error rate — not a higher model accuracy
> threshold, which cannot currently be guaranteed for all question types.


[⬆ Back to Table of Contents](#table-of-contents)

## 9. CI/CD Pipeline & Deployment

- **Build:** lint (`ruff`), type-check (`mypy --strict`), `cedar validate`,
  and batch evaluation all run in CI (AWS CodeBuild).

- **Stages:** dev → staging → production, with a manual approval gate
  between staging and production.

- **Canary deployment for agent updates:** 5% of traffic → monitor error
  rate, P95 latency, and Policy deny rate for 30 minutes → promote to
  100% only if no regression, else auto-rollback within 15 minutes.

- **No hardcoded secrets anywhere** — use Secrets Manager or
  environment-injected config, enforced via a pre-commit hook.

- **Cedar changes require segregation of duties:** the PR author and the
  approver must be different people. This is enforced via GitHub branch
  protection (required reviewer ≠ author).

- **Statistical significance gate for A/B tests:** p < 0.05 before
  declaring a treatment better than control. Auto-rollback if treatment
  degrades any monitored metric.


[⬆ Back to Table of Contents](#table-of-contents)

## 10. Observability & Debugging a Query

AgentCore Observability provides full OpenTelemetry tracing across the
agent graph, Gateway, and every tool call. When debugging a reported
issue:

1. Pull the trace by `session_id` / `trace_id` from CloudWatch — every
   audit record includes both for correlation.

2. Check per-node latency and the Policy decision (`permit`/`deny`,
   `policy_id`, `policy_version`) recorded for that specific call.

3. Cross-reference the immutable audit record (S3 Object Lock) for the
   exact SQL generated, the Lake Formation outcome (tables/columns
   accessed, row filter applied), and any Guardrails findings — the S3
   audit record is the authoritative source, not application logs.

4. Check alert thresholds first for systemic issues:
   - Error rate > 5%
   - P95 latency > 60s
   - Policy deny-rate spike (may indicate attack or misconfiguration)
   - Self-correction invocation rate > 10% (indicates schema context quality degradation)
   - Guardrails block-rate spike (may indicate coordinated prompt injection)

**Common debugging scenarios:**

| Symptom | Likely cause | Where to look |
|---------|-------------|---------------|
| "Access to requested data not available" for a query that should be permitted | Cedar policy mismatch or Lake Formation grant missing | Audit record policy_decision + LF outcome; reconciliation job results |
| SQL generation fails after 2 retries | Schema context missing the target table; model unfamiliar with column structure | Schema retrieval node output in trace; golden dataset coverage |
| Cost threshold exceeded on a query the user expects to pass | Large unpartitioned table or missing partition filter in user's question | SQL validation node output; cost estimate in audit record |
| Guardrails blocking a seemingly normal question | High-sensitivity keyword match; false positive | Guardrails findings in audit record (detection category, confidence — not raw blocked content) |
| Session expires unexpectedly | 45-minute idle timeout; ALB sticky-session routing to different task | Session store logs; ALB access logs |


[⬆ Back to Table of Contents](#table-of-contents)

## 11. Adding a New Tool via Gateway / MCP

1. Implement the tool inside the Athena MCP server (or a new MCP server
   for a different domain) using the read-only IAM role only — never
   grant CreateTable, UpdateTable, or any write action.

2. Register the server as a Gateway target using
   `SynchronizeGatewayTargets`; verify the new tool actually appears in
   semantic search results before considering the task done.

3. Write a Cedar policy statement covering the new tool/resource
   combination — no tool is reachable without an explicit permit
   (default-deny). Cedar changes require human review (PR gate).

4. Add the tool's expected behavior to the golden evaluation dataset —
   every new capability needs at least one (question, expected\_SQL/behavior)
   pair.

5. Add unit tests for the new tool: verify it respects the
   `X-AgentCore-Gateway-Signature` enforcement, rejects direct invocation,
   and handles the authorization-filtered response correctly.

6. Add the new tool to the reconciliation check if it operates on data
   that has Lake Formation grants.


[⬆ Back to Table of Contents](#table-of-contents)

## 12. Known Limitations & Implementation Trade-offs

Every developer joining this project should understand these before making
changes. Some of these are "won't fix now" decisions with documented
rationale; others are active technical debt.

| Limitation | Impact | Mitigation / Status |
|------------|--------|---------------------|
| **In-memory session store** | Multi-task deployments require ALB sticky sessions; session loss on task replacement | Relies on ALB sticky sessions. Future: ElastiCache (Redis) distributed session store |
| **Cost estimation is approximate** | A query that passes the 10 GB guardrail may scan slightly more at execution time | Athena workgroup has a hard bytes-scanned limit as the final enforcement |
| **Golden dataset coverage gaps** | New question types not in the golden dataset may produce wrong SQL that passes CI | Dataset grows with each production bug; users shown explicit "verify results" guidance |
| **Disambiguation max 3 rounds** | Complex questions requiring >3 clarifications will fail gracefully | By design — prevents infinite loops. Users should break complex questions into simpler ones |
| **Schema staleness window** | Re-indexing occurs within 1 hour of Glue Catalog changes; new tables not available in RAG immediately | EventBridge trigger with exponential backoff retry; operators can trigger manually |
| **Cedar ecosystem size** | Fewer IDE plugins, community examples than OPA/Rego | Cedar is native to AgentCore; the structural safety properties outweigh ecosystem size |
| **OBO token exchange maturity** | GA April 2026 — less battle-tested than shared-role pattern | Independent pen test before production; shared-role with CloudTrail as fallback if OBO fails |
| **No distributed rate limiting** | Rate limiting (30 req/min/user) is per-ECS-task, not per-user globally | For initial deployment (low scale), per-task is acceptable. At high scale, implement Redis-based distributed rate limiting |
| **Self-correction only fixes execution errors** | A logically wrong query (correct SQL, wrong business logic) is not retried | This is the residual LLM accuracy risk; mitigated by golden dataset monitoring and user-facing guidance |
| **PII redaction is probabilistic** | Guardrails PII scan (31 entity types) may miss novel PII formats | Standard tier with HIGH sensitivity is the maximum available. Lake Formation column-level security provides deterministic protection for known PII columns |


[⬆ Back to Table of Contents](#table-of-contents)

## 13. Implementation Roadmap (Waves 1–8)

The build is organized into eight dependency-ordered waves. Within a
wave, tasks can run concurrently across the team; waves themselves are
sequential.

|          |                                        |                                                                                                                                                                                                                                                    |
|----------|----------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Wave** | **Focus**                              | **Representative tasks**                                                                                                                                                                                                                           |
| 1        | Foundation: provisioning & network     | VPC/PrivateLink, KMS keys, Cognito federation, Lake Formation enablement, data classification (human task), read-only Athena workgroup, OpenSearch collection, Glue metadata export, audit bucket, CDK scaffold, Secrets Manager                   |
| 2        | Wiring: permissions, targets, identity | FastAPI JWT validation, Lake Formation grants per classification tier, embedding/indexing pipeline, Athena MCP server, Gateway target registration, OBO configuration, Bedrock Guardrails, draft Cedar policies (human review), reconciliation job |
| 3        | Agent build: LangGraph + deployment    | Build the graph (diagram-first, security-reviewed), deploy to AgentCore Runtime, wire tool calls through Gateway/Policy/Identity end-to-end                                                                                                        |
| 4        | Guardrails & validation                | SQL validation node, cost-estimation guardrail, output PII scan and redaction                                                                                                                                                                      |
| 5        | Observability & audit                  | AgentCore Observability, immutable audit logging, admin kill switch, cost monitoring/budget alerts                                                                                                                                                 |
| 6        | Optimization & governance              | Evaluation loop, A/B testing pipeline, CI/CD with security gates                                                                                                                                                                                   |
| 7        | Documentation & model risk             | Model risk (SR 26-2) documentation, operational runbooks                                                                                                                                                                                           |
| 8        | Assurance & launch                     | End-to-end + load + soak testing, DR validation, STRIDE threat model, independent pen test, formal governance sign-off (human gate — cannot be automated)                                                                                          |

### 13.1 Team Roles

|                               |                                                                |                      |
|-------------------------------|----------------------------------------------------------------|----------------------|
| **Role**                      | **Responsibilities**                                           | **Primarily active** |
| Engineer A (Backend/Python)   | FastAPI, LangGraph agent, MCP server                           | Waves 1–4            |
| Engineer B (Infrastructure)   | CDK stacks, VPC, PrivateLink, Cognito federation               | Waves 1–2            |
| Engineer C (Data/ML)          | OpenSearch embeddings, Athena workgroup, Lake Formation grants | Waves 1–2, 4         |
| Engineer D (Security/DevOps)  | Cedar policies, CI/CD, Guardrails config, audit logging        | Waves 2, 5–6         |
| Security Architect (Reviewer) | Reviews Cedar policies, threat model, pen test coordination    | Waves 2, 7–8         |

### 13.2 Definition of Done (every task)

- Code/config committed to the feature branch

- Passes CI checks (lint, type-check, `cedar validate` for policy changes)

- Has at least one test proving it works (unit or integration)

- Outputs documented (ARN, endpoint, ID) for downstream tasks to consume

- No hardcoded secrets (Secrets Manager or `.env` only)

- Reviewed by a second person — or by the security team specifically for
  auth-related tasks

- Steering rules respected (`.kiro/specs/chatbot-security-architecture/`)

> ***Note:** Tasks marked HUMAN TASK require documented sign-off from a
> named stakeholder and cannot be delegated to an AI coding agent — this
> includes data classification decisions, Cedar policy review,
> model-risk documentation, and the final governance sign-off.*

### 13.3 Key Engineering Risks to Track

|                                                                     |                         |                                                                                         |
|---------------------------------------------------------------------|-------------------------|-----------------------------------------------------------------------------------------|
| **Risk**                                                            | **Likelihood / Impact** | **Mitigation**                                                                          |
| AgentCore Optimization doesn't reach GA before launch               | Medium / Medium         | Fallback: self-managed batch-eval script using the Bedrock Evaluate API                 |
| OBO token exchange has edge cases (new service, GA Apr 2026)        | Medium / High           | Dedicated pen-test scenario; fallback is a scoped service role with CloudTrail alerting |
| Lake Formation + Cognito identity mapping fails for federated users | Low / High              | Test with 3+ federated identities in Wave 2; document exact IdP attribute mapping       |
| LangGraph version upgrade breaks the agent graph                    | Low / Medium            | Pin the exact version in `pyproject.toml`; test graph serialization in CI              |
| Schema retrieval latency too high with 500+ tables                  | Medium / Medium         | Benchmark at 100/300/500 tables in Wave 2; tune k and embedding model if needed         |
| Golden dataset doesn't cover enough question types                  | Medium / Medium         | Expand to ≥100 examples before launch; include cross-domain queries                    |
| In-memory session store causes 401s under rolling ECS updates       | Low / Medium            | Verify ALB sticky session configuration; plan Redis migration for Wave 5 if needed     |


[⬆ Back to Table of Contents](#table-of-contents)

## 14. Local Testing Checklist

Before any PR is raised, verify the following scenarios pass locally:

- **Happy path:** authorized user, simple unambiguous query returns correct results

- **Disambiguation flow:** ambiguous query triggers a clarifying question; resolves within 3 rounds

- **Disambiguation exhausted:** a question that cannot be clarified in 3 rounds fails gracefully with a clear message

- **Cost guardrail:** an intentionally expensive query is blocked with a clear cost estimate and a suggestion

- **Unauthorized access attempt:** Policy denies before the request reaches Athena; audit record written

- **Row-level filter:** a user with a Lake Formation row filter sees only their permitted rows

- **Prompt injection attempt:** Guardrails blocks it; no query executed; audit record written with detection details

- **Jailbreak attempt requesting an unauthorized table:** Policy denies even if the model "complies" with the jailbreak

- **Self-correction success:** an invalid generated SQL statement is retried and succeeds on the second attempt

- **Self-correction exhausted:** model fails gracefully after 2 retries with a clear message, not a stack trace

- **Kill switch:** disabling a target mid-session produces graceful degradation (HTTP 503), not a hard error

- **Deprovisioning:** a deprovisioned user's active session terminates within 5 minutes

- **Property tests pass:** `pytest tests/property/ -v` passes all 12 invariant proofs


[⬆ Back to Table of Contents](#table-of-contents)
