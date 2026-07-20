# Athena Data Chatbot

A production-grade, bank-security-level chatbot enabling business users to query several hundred Amazon Athena tables in natural language. Built on AWS AgentCore, LangGraph, and Cedar with defense-in-depth across authentication, authorization, content safety, and audit.

## Overview

Users ask questions in plain English ("What were total deposits in consumer banking last quarter?"). The system translates the question into a validated, authorized, read-only SQL query, executes it under the user's own federated identity, and returns a formatted result — all without the user needing to know table names, column names, or SQL.

**Key security properties:**
- Two independent authorization layers (Cedar policy + Lake Formation) — a bug in either one alone cannot expose unauthorized data
- Every Athena query runs as the requesting user's federated identity (OBO token exchange), never a shared service role
- All tool calls route through AgentCore Gateway; the agent process has no IAM role for Athena
- Immutable 7-year audit trail (S3 Object Lock, Compliance mode)
- Deterministic SQL safety validation (SELECT-only, LIMIT injection, partition filters, cost guardrails)

## Architecture

```
Corporate IdP (SAML/OIDC + MFA)
        │
Amazon Cognito (15-min JWT)
        │
Internal ALB (corporate CIDR only)
        │
FastAPI / ECS Fargate
  • JWT validation (RS256, JWKS cached)
  • Rate limiting (30 req/min/user)
  • Session management (45-min idle timeout)
  • Circuit breaker (fail-closed on AgentCore unavailability)
        │
AgentCore Runtime — LangGraph Agent
  intent_classify → glossary_resolve → schema_retrieve
  → [disambiguate ≤3] → sql_generate → validate_sql
  → tool_call → [self_correct ≤2] → output_scan → format_respond
        │
AgentCore Gateway
  • Cedar policy evaluation (default-deny, forbid-wins)
  • OBO token exchange (per-user federated identity)
        │
Athena MCP Server → Amazon Athena (read-only workgroup)
                         │
                   Lake Formation (table/column/row/cell)
                         │
                     S3 Data Lake
```

All inter-service communication is over VPC PrivateLink — no public internet paths.

## How the Text-to-SQL Workflow Works

This section walks through exactly what happens — step by step, with the
relevant code — when a user sends a natural-language question.

### Overview: 10 Nodes, 2 Bounded Loops

The agent is an explicit LangGraph state graph. There are exactly 10
nodes, all statically defined in `agent/graph.py`. Every possible
execution path is enumerable. No paths are created at runtime.

```
START
  │
  ▼
① intent_classify          Claude Haiku, 2s budget → actionable / ambiguous / out_of_scope
  │
  ▼
② glossary_resolve         maps "revenue" → "net_revenue_usd", "EMEA" → region list
  │
  ▼
③ schema_retrieve          kNN vector search in OpenSearch, pre-filtered by user's LF grants
  │
  ▼ [conditional edge: should_disambiguate]
  ├─ needs clarification AND rounds < 3 ──► ④ disambiguate ──► loops back to ①
  │                                              max 3 rounds, then → ⑩ format_respond
  └─ intent clear OR rounds exhausted ───────────────────────────────────────────────────┐
                                                                                         │
  ▼                                                                                      │
⑤ sql_generate             Claude Sonnet, temperature=0, schema context injected ◄───────┘
  │
  ▼
⑥ validate_sql             deterministic 7-step AST check (sqlglot/Trino)
  │
  ▼ [conditional edge: after_validate_sql]
  ├─ valid ────────────────────────────────────────────────────────────────────────────┐
  ├─ invalid AND attempts < 2 ──► ⑧ self_correct ──► loops back to ⑥                 │
  └─ invalid AND attempts = 2 ──► ⑩ format_respond (give up)                          │
                                                                                       │
  ▼                                                                                    │
⑦ tool_call                AgentCore Gateway → Cedar → OBO → MCP → Athena ◄───────────┘
  │
  ▼ [conditional edge: should_self_correct]
  ├─ SQL error AND attempts < 2 ──► ⑧ self_correct ──► back to ⑥ validate_sql
  └─ success OR attempts = 2 ─────────────────────────────────────────────────────────┐
                                                                                       │
  ▼                                                                                    │
⑨ output_scan              Bedrock Guardrails OUTPUT scan → PII redaction ◄────────────┘
  │
  ▼
⑩ format_respond           attach data-freshness timestamp, format table + narrative
  │
  ▼
END
```

---

### Step 1 — Intent Classification (`agent/nodes/intent_classify.py`)

**Model:** Claude 3 Haiku (`anthropic.claude-3-haiku-20240307-v1:0`)
**Budget:** 2-second hard timeout (no retries within budget)
**Temperature:** 0 — deterministic

```python
# Three possible outcomes:
INTENT_ACTIONABLE  = "actionable"   # → proceeds to glossary_resolve
INTENT_AMBIGUOUS   = "ambiguous"    # → triggers disambiguation loop (max 3 rounds)
INTENT_OUT_OF_SCOPE = "out_of_scope" # → format_respond with "outside scope" message
```

The prompt asks the model to respond with a JSON object only:
`{"intent": "<category>", "reason": "<brief explanation>"}`.
Any unparseable response defaults to `ambiguous` — the safer fallback.

Haiku is used here (not Sonnet) because the classification task is
simple and the cost and latency difference is significant at query
volume. The 2-second budget keeps this step from dominating the 30-second
end-to-end latency target.

---

### Step 2 — Glossary Resolution (`agent/nodes/glossary_resolve.py`)

Maps business vocabulary to canonical technical names before schema
retrieval, so the vector search receives enriched terms rather than raw
business jargon.

Examples:
- "revenue" → "net_revenue_usd" or "gross_revenue_gbp" (from glossary)
- "EMEA" → `["GB", "DE", "FR", "IT", "ES", ...]` (region expansion)
- "last quarter" → `2026-01-01` to `2026-03-31` (date range resolution)

The resolved terms are carried in `state["resolved_terms"]` and
concatenated with the user message for embedding generation in the next
step.

---

### Step 3 — Schema Retrieval via RAG (`agent/nodes/schema_retrieve.py`)

**Vector store:** OpenSearch Serverless (VPC-only, `VECTORSEARCH` collection)
**Embedding model:** Amazon Titan Embeddings v2 (`amazon.titan-embed-text-v2:0`)
**Top-k:** 5 schemas retrieved per query

```python
# The query text is enriched with resolved glossary terms before embedding
query_text = f"{user_message} {' '.join(resolved_terms.values())}"
embedding = _generate_embedding(query_text)   # Titan Embeddings → 1536-dim vector

# Authorization filter is applied BEFORE top-k selection
authorized_tags = _get_user_authorized_tags(user_claims)
# e.g. {"department": ["consumer_banking", "shared"],
#        "classification_tier": ["public", "internal", "confidential"]}

# kNN query with pre-filter — only authorized schemas are candidates
query = {
    "query": {
        "bool": {
            "must":   [{"knn": {"embedding_vector": {"vector": embedding, "k": 5}}}],
            "filter": [{"terms": {f"lake_formation_tags.{k}": v}}
                       for k, v in authorized_tags.items()]
        }
    }
}
```

**Security property:** the authorization filter runs *inside* the
OpenSearch query — unauthorized table names never enter the candidate set
and therefore never appear in the LLM prompt context. This prevents
schema enumeration by users who don't have access to a table. If
`authorized_tags` is empty (no grants derivable), the function returns
zero schemas and the request terminates — default-deny.

---

### Step 4 — Disambiguation Loop (`agent/nodes/disambiguate.py`)

**Trigger:** `needs_disambiguation = True` after intent classification
**Bound:** maximum 3 rounds, enforced by graph edge condition (not a runtime counter)

```python
def should_disambiguate(state) -> Literal["disambiguate", "sql_generate"]:
    rounds = state.get("disambiguation_rounds", 0)
    needs_clarification = state.get("needs_disambiguation", False)
    if needs_clarification and rounds < 3:   # structural bound
        return "disambiguate"
    return "sql_generate"   # proceed regardless after 3 rounds
```

After 3 rounds without resolution, the edge from `disambiguate` routes
to `format_respond` with a message asking the user to rephrase — not
back to `intent_classify`. The loop cannot run a 4th time regardless of
what the model returns.

---

### Step 5 — SQL Generation (`agent/nodes/sql_generate.py`)

**Model:** Claude Sonnet 4 (`anthropic.claude-sonnet-4-20250514`)
**Temperature:** 0 — deterministic, reproducible output

The prompt includes:
- The user's question
- Resolved business terms (from Step 2)
- Up to 5 retrieved table schemas (from Step 3) with column names, types, descriptions, and partition keys

```
You are a SQL expert for Amazon Athena (Presto/Trino dialect).
Generate a SQL SELECT query based on the user's natural language question.

RULES:
- Generate ONLY SELECT statements.
- Use the table and column names from the provided schemas.
- Include appropriate WHERE clauses for partitioned tables.
- Do NOT use SELECT * on tables with many columns.
- Use proper Athena/Presto SQL syntax.

User question: {user_message}
Resolved business terms: {resolved_terms}
Available table schemas: {schemas_context}

Respond with ONLY the SQL query.
```

The model responds with raw SQL. Any markdown code-block wrappers are
stripped. The result flows directly to `validate_sql` — it is never
executed here.

**Why temperature=0:** ensures the same question on the same schema
context produces the same SQL. This is important for the golden dataset
evaluator (comparing generated SQL to expected SQL) and for
reproducibility during debugging.

---

### Step 6 — SQL Validation (`mcp_server/validation.py`)

The generated SQL goes through a deterministic 7-step pipeline using
`sqlglot` (Trino/Athena dialect). This is NOT an LLM step — it is
deterministic code that runs the same way every time:

```
Step 1: Parse into AST  ──► fail → "Invalid SQL syntax"
Step 2: Statement type  ──► non-SELECT → "Only SELECT statements permitted"
Step 3: Table auth      ──► unknown table → "Unauthorized table: {table}"
         (checks subqueries, CTEs, JOINs — extracts all references from AST)
Step 4: Partition filter ──► partitioned table + no partition WHERE → reject
Step 5: Column selection ──► SELECT * on >50 columns → reject
Step 6: Scan size check  ──► >10 GB estimate without elevated_cost → reject
         (Athena dry-run API call for actual engine estimate)
Step 7: LIMIT injection  ──► adds "LIMIT 10000" if no LIMIT clause
                         ──► returns modified_sql with LIMIT
```

Table references are extracted from the full AST including nested
subqueries and CTEs. CTE aliases defined within the query itself are
excluded from the authorization check.

```python
# Example: this query fails at Step 3 for a marketing analyst
"SELECT * FROM hr.compensation WHERE year = 2024"
# → Step 2 would catch SELECT * first (if hr.compensation has >50 columns)
# → Step 3 catches unauthorized table regardless
# Even if both passed, Lake Formation would deny the query at execution time
```

---

### Step 7 — Tool Call via AgentCore Gateway (`agent/nodes/tool_call.py`)

This is the only way a query reaches Athena. The agent has no direct
IAM access to Athena — it can only call the Gateway.

```
agent/nodes/tool_call.py
        │  calls run_query via AgentCore Gateway
        ▼
AgentCore Gateway
        │  ① Cedar policy evaluation (deterministic, 30ms P95)
        │     principal = JWT claims (dept, role, tier, groups)
        │     action    = "run_query"
        │     resource  = "database/table"
        │     → DENY (default-deny, forbid-wins) or ALLOW
        │
        │  ② OBO token exchange (per-user federated identity)
        │     workload identity → user's federated ARN
        │     stored in Secrets Manager, 90-day rotation
        ▼
MCP Server (mcp_server/tools/run_query.py)
        │  validates X-AgentCore-Gateway-Signature header
        │  (rejects direct calls — gateway enforcement)
        ▼
Amazon Athena (chatbot-readonly workgroup)
        │  executes query AS the user's federated identity (OBO token)
        │  NOT as a shared service role
        ▼
AWS Lake Formation
        │  enforces table/column/row/cell permissions
        │  for the specific user identity
        │  (engine-level, cannot be bypassed by application code)
        ▼
S3 Data Lake → results returned
```

The Cedar evaluation log entry is written to the immutable audit store
*before* the response is returned, containing: permit/deny decision,
determining policy ID, and policy version (Requirement 5.5).

---

### Step 8 — Self-Correction Loop (`agent/nodes/self_correct.py`)

**Trigger:** Athena execution error (not a validation failure — those are caught in Step 6)
**Model:** Claude Sonnet, temperature=0
**Bound:** maximum 2 retries, enforced by graph edge condition

```python
def should_self_correct(state) -> Literal["self_correct", "output_scan"]:
    attempts = state.get("self_correction_attempts", 0)
    has_error = state.get("sql_error") is not None
    if has_error and attempts < 2:     # structural bound
        return "self_correct"
    return "output_scan"               # proceed regardless after 2 attempts
```

The self-correction prompt includes:
- Original user question
- The failed SQL
- The Athena error message
- Original schema context

The corrected SQL flows back to `validate_sql` (Step 6) — it must pass
all 7 validation steps again before being sent to the Gateway. A
self-corrected query that tries to drop a table still fails at Step 2.

After 2 failed retries, the user receives: *"I wasn't able to generate a
working query for your question. Could you try rephrasing it?"* All 3
SQL attempts and their Athena error codes are logged to the audit store
for evaluation loop analysis.

---

### Step 9 — Output Scan (`agent/nodes/output_scan.py`)

**Service:** Amazon Bedrock Guardrails (STANDARD tier)
**Direction:** OUTPUT — scans query results and the model narrative
**PII action:** ANONYMIZE (redact to `[REDACTED]`)
**Content filters:** HIGH threshold on all categories

The output scan runs on:
1. The raw query results from Athena (rows + columns)
2. The generated natural-language narrative that will be shown to the user

If 31 PII entity types are detected (NAME, EMAIL, SSN, CREDIT_CARD,
PHONE, etc.), they are replaced with `[REDACTED]` in the response —
unless the user's Cedar policy includes an explicit PII view grant for
that category.

If Guardrails is unavailable or fails to respond within 5 seconds, the
request is failed-closed: the results are not shown and the user
receives a service-unavailability message (Requirement 8.4).

---

### Step 10 — Format Response (`agent/nodes/format_respond.py`)

The final node:
- Attaches the `data_freshness` timestamp from the Glue Catalog partition
  metadata (e.g., "Data current as of 2026-07-19 06:00 UTC")
- Formats results as a table + plain-English narrative
- Attaches row count and cost estimate in bytes
- Includes `trace_id` (UUID v4) for support reference
- Writes the full audit record to S3 Object Lock (synchronously —
  request fails if the audit write fails, per Requirement 5.8)

---

### Concrete Example: End-to-End

**User asks:** `"What were total deposits in consumer banking last quarter?"`

| Step | What happens | Output |
|------|-------------|--------|
| ① intent_classify | Haiku: clear data query | `intent = "actionable"` |
| ② glossary_resolve | "deposits" → `deposit_amount`, "last quarter" → `2026-01-01..2026-03-31` | `resolved_terms = {...}` |
| ③ schema_retrieve | kNN search + filter by `department=consumer_banking`, `tier≤confidential` | `consumer_banking.deposits` schema returned |
| ④ disambiguate | Skipped — intent is clear | — |
| ⑤ sql_generate | Claude Sonnet generates: | See SQL below |
| ⑥ validate_sql | Parse ✓, SELECT ✓, auth ✓, partition filter ✓, columns ✓, cost ~450MB ✓, LIMIT injected | `valid=True`, adds `LIMIT 10000` |
| ⑦ tool_call | Cedar: ALLOW (analyst + consumer\_banking + tier≤confidential) → OBO exchange → Athena runs as `jane-doe@bank.com` → LF: SELECT on deposits table | Results returned: 3 rows |
| ⑧ self_correct | Skipped — query succeeded | — |
| ⑨ output_scan | Guardrails OUTPUT: no PII detected in account\_type + deposit aggregates | Results pass through |
| ⑩ format_respond | Table + narrative + "Data current as of 2026-07-19 06:00 UTC" | Final response |

**Generated SQL (Step 5, then LIMIT injected at Step 6):**
```sql
SELECT
    account_type,
    SUM(deposit_amount) AS total_deposits,
    COUNT(*)            AS transaction_count
FROM consumer_banking.deposits
WHERE partition_date BETWEEN '2026-01-01' AND '2026-03-31'
GROUP BY account_type
LIMIT 10000
```

**Total wall time (P95, <1 GB scan):** ~24 seconds

---

### What the LLM Controls vs. What Is Deterministic

This boundary is the most important architectural property in the system:

| Component | Controlled by | Can be bypassed by a jailbroken model? |
|-----------|--------------|---------------------------------------|
| Natural language → SQL intent | LLM (Claude Sonnet) | N/A — this is what the LLM is *for* |
| SQL syntax | LLM (primary), self-correction (retry) | Yes — but Athena rejects invalid SQL |
| Statement type (SELECT only) | `validate_sql` — deterministic AST | **No** — AST check runs before execution |
| Table authorization in SQL | `validate_sql` — AST reference extraction | **No** — AST check + Cedar + Lake Formation |
| Access control (who can see what) | Cedar policy + Lake Formation | **No** — Cedar never reads the prompt; Lake Formation is engine-level |
| Cost limits | Athena dry-run API | **No** — Athena engine provides the estimate |
| PII in results | Bedrock Guardrails | **No** (probabilistic, but independent of the model generating the SQL) |
| Audit record | S3 Object Lock | **No** — written by infrastructure, not by agent code |

The LLM translates language to SQL. Every security control operates
independently of that translation.

## Repository Layout

```
chatbot/
├── api/                    # FastAPI session/auth layer
│   ├── main.py             # Routes, exception handlers, middleware wiring
│   ├── auth.py             # JWT validation (RS256), rate limiting
│   ├── middleware.py       # Session timeout, circuit breaker, trace IDs
│   ├── models.py           # Pydantic request/response models
│   └── Dockerfile
├── agent/                  # LangGraph agent orchestration
│   ├── graph.py            # Static graph definition (all nodes + bounded edges)
│   ├── state.py            # AgentState dataclass
│   └── nodes/              # 10 node implementations
│       ├── intent_classify.py
│       ├── glossary_resolve.py
│       ├── schema_retrieve.py
│       ├── disambiguate.py
│       ├── sql_generate.py
│       ├── validate_sql.py
│       ├── tool_call.py
│       ├── self_correct.py
│       ├── output_scan.py
│       └── format_respond.py
├── mcp_server/             # Athena MCP server (tool implementations)
│   ├── server.py           # MCP server, tool registration, gateway enforcement
│   ├── validation.py       # 7-step SQL validation engine (sqlglot/Trino)
│   └── tools/
│       ├── list_tables.py
│       ├── get_schema.py
│       ├── estimate_cost.py
│       └── run_query.py
├── policies/               # Cedar authorization policies
│   ├── schema.cedarschema  # Cedar type schema
│   ├── base.cedar          # Default-deny + universal forbids (PCI databases)
│   ├── analysts.cedar      # Analyst role permits (ABAC)
│   └── managers.cedar      # Manager role permits
├── infra/                  # AWS CDK (TypeScript) — 5 stacks
│   └── lib/
│       ├── networking-stack.ts   # VPC, PrivateLink endpoints, security groups
│       ├── security-stack.ts     # KMS CMKs, Cognito, Secrets Manager, IAM
│       ├── data-stack.ts         # S3, Glue, Lake Formation, OpenSearch, Athena
│       ├── compute-stack.ts      # ECS Fargate, AgentCore Runtime, EventBridge
│       └── observability-stack.ts # CloudWatch, alarms, SIEM export
├── scripts/                # Operational scripts
│   ├── reconciliation.py   # Daily Cedar ↔ Lake Formation permission comparison
│   ├── kill_switch.py      # Admin disable/enable Gateway target
│   ├── reindex_vectors.py  # Schema re-indexing pipeline (EventBridge triggered)
│   └── audit.py            # Shared immutable audit store module
├── tests/
│   ├── unit/               # Component unit tests
│   ├── integration/        # End-to-end flow tests
│   ├── property/           # Hypothesis property-based correctness proofs
│   └── adversarial/        # Prompt injection / jailbreak test suite
├── docs/
│   ├── Athena_Chatbot_Architect_Guide.md
│   ├── Athena_Chatbot_Developer_Guide.md
│   └── Athena_Chatbot_User_Guide.md
└── pyproject.toml          # Python dependencies (pinned)
```

## Prerequisites

- Python 3.11+
- Node.js 18+ (for AWS CDK)
- AWS CLI v2, configured against the target account
- [`cedar` CLI](https://github.com/cedar-policy/cedar) for local policy validation
- AWS CDK: `npm install -g aws-cdk`

## Local Setup

```bash
# Install Python dependencies
pip install -e ".[dev]"

# Install CDK dependencies
cd infra && npm install && cd ..

# Validate Cedar policies
cedar validate --schema policies/schema.cedarschema policies/*.cedar

# Run unit tests
pytest tests/unit/ -v

# Run property-based tests (correctness invariant proofs)
pytest tests/property/ -v

# Run all tests
pytest
```

## SQL Validation Rules

The `validate_sql` node applies these checks in order before any query reaches Athena. A failure at any step stops evaluation:

| # | Check | Default action |
|---|-------|----------------|
| 1 | Parse validity (sqlglot, Trino dialect) | Reject |
| 2 | SELECT-only statement type | Reject |
| 3 | Table authorization (all references, including CTEs/JOINs) | Reject |
| 4 | Partition filter required on partitioned tables | Reject |
| 5 | No `SELECT *` on tables with >50 columns | Reject |
| 6 | Estimated scan ≤10 GB (or `elevated_cost` group) | Reject |
| 7 | LIMIT injection (adds `LIMIT 10000` if absent) | Modify |

## Cedar Authorization

Cedar policies are evaluated at the AgentCore Gateway boundary — before the agent can reach any tool. The default is deny; access requires an explicit `permit`. `forbid` always overrides `permit`.

```cedar
// Analysts can query tables in their department's databases
permit (
    principal,
    action == Action::"run_query",
    resource
) when {
    principal.role == "analyst" &&
    resource.database in principal.department_databases &&
    resource.classification_tier <= principal.data_classification_tier
};

// No access to PCI databases via this chatbot, regardless of other permits
forbid (
    principal,
    action,
    resource
) when {
    resource.database in ["pci_cardholder", "pci_transactions"]
};
```

Cedar changes require:
- `cedar validate` passing in CI
- PR approval by a reviewer who is **not** the policy author (segregation of duties)

## Evaluation Framework

Five evaluators run in CI on every change to a prompt, few-shot example, model config, or Guardrails rule:

| Evaluator | Pass criterion |
|-----------|----------------|
| SQL correctness | ≥95% of golden queries produce correct results |
| Schema fidelity | 100% — zero hallucinated tables or columns |
| Cost compliance | 0 queries exceed threshold in evaluation set |
| Answer quality | ≥4.0/5.0 (LLM-as-judge) |
| Safety | 0 PII leakage in model outputs |

12 property-based tests (Hypothesis) prove universal correctness invariants — see `tests/property/`.

## Key Architectural Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Orchestration framework | LangGraph | Explicit, auditable graph; bounded loops are structural (not runtime counters); every execution path is enumerable for security review |
| Agent hosting | AgentCore Runtime | No CPU charge during I/O wait (~80% of wall time); ~60-70% cheaper than Fargate for this workload; native session management |
| Authorization | Cedar (two layers: Gateway + Lake Formation) | Defense-in-depth; independent layers; Cedar default-deny + forbid-wins; Lake Formation enforces at query engine level |
| Identity propagation | OBO token exchange | Per-user Lake Formation grants require the query to run as the actual user's federated identity, not a shared service role |
| Tool protocol | MCP via AgentCore Gateway | Semantic tool search at scale; Policy + OBO integration; standardized protocol |
| Vector store | OpenSearch Serverless | VPC-only access; managed scaling; AWS data residency guarantees |
| SQL approach | RAG + foundation model (Claude Sonnet, temperature=0) | Handles novel phrasing without retraining; schema context stays current via Glue Catalog sync |
| Audit storage | S3 Object Lock (Compliance mode) | 7-year immutable retention; cannot be deleted even by root account |

## Infrastructure Deployment

CDK stacks deploy in this dependency order (no circular dependencies):

```
NetworkingStack → SecurityStack → DataStack → ComputeStack → ObservabilityStack
```

```bash
cd infra
cdk synth          # Synthesize CloudFormation templates
cdk diff           # Preview changes
cdk deploy --all   # Deploy all stacks (requires appropriate IAM permissions)
```

## Operational Controls

| Control | How to invoke | SLA |
|---------|--------------|-----|
| Kill switch (disable chatbot) | `python scripts/kill_switch.py disable --target <id> --reason "<reason>"` | Effective within 5 minutes |
| Kill switch (re-enable) | `python scripts/kill_switch.py enable --target <id> --reason "<reason>"` | Effective within 5 minutes |
| Manual reconciliation | Invoke the reconciliation Lambda directly | Completes within 60 minutes |
| Schema re-index | Invoke `reindex_vectors.py` or trigger via EventBridge | Completes within 60 minutes |

Kill switch operations require the `security-operations` Cedar role and are logged to the immutable audit store.

## Daily Reconciliation

A daily EventBridge-scheduled job compares every Cedar permit against the corresponding Lake Formation grant for the same (principal, table) combination. Any divergence:
- Triggers a P1 SNS alert to the security operations team
- Fails-closed the affected principals (blocks their requests) within 5 minutes
- Remains blocked until an authorized operator explicitly clears the divergence

If the reconciliation job fails to complete within 60 minutes, all requests are blocked (assume-breach posture).

## Documentation

| Document | Audience | Location |
|----------|----------|----------|
| Architect Guide | Security architects, model risk | `docs/Athena_Chatbot_Architect_Guide.md` |
| Developer Guide | Engineers building or extending the chatbot | `docs/Athena_Chatbot_Developer_Guide.md` |
| User Guide | Business users and analysts | `docs/Athena_Chatbot_User_Guide.md` |
| Requirements | All | `.kiro/specs/chatbot-security-architecture/requirements.md` |
| Design | All | `.kiro/specs/chatbot-security-architecture/design.md` |

## Compliance Notes

This codebase implements technical controls. The following require formal human sign-off before production launch:
- InfoSec review of the AgentCore shared-responsibility model
- SR 26-2 Model Risk Management attestation
- EU AI Act classification assessment (if EU deployment)
- Independent penetration test (Gateway bypass, OBO cross-user token, 100+ adversarial prompts)
- Cedar policy completeness certification (data governance team)
- GDPR/UK GDPR data residency legal review

The final production launch gate is a human governance decision — it cannot be automated or delegated to any tooling.
