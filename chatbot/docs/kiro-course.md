# Use Kiro to Build a Bank-Grade Chatbot over Athena

A step-by-step course: install Kiro, create spec files (requirements → design → tasks), and let Kiro implement a production Python chatbot that queries Athena tables — using SDD with human approval gates at every phase.

- Level: Zero → Principal
- Date: July 2026
- Output: Production Python Project
- Stack: AgentCore + LangGraph + Cedar + Lake Formation

## Course Roadmap

This course follows the SDD workflow: plan first, Kiro builds second.

| Phase | Sections | What you learn | Output |
|-------|----------|----------------|--------|
| **Foundation** | 00 | SDD concepts, EARS, how to generate spec files | Kiro installed, workflow understood |
| **Configure** | 01 | Steering, hooks, MCP servers | Security rules + automation in place |
| **Build** | 02 | Architecture, auth, tests, implementation | Complete `chatbot/` Python project |
| **Ship** | 03 | MVP scoping, governance, cheat sheet | Production-ready, approved system |

## Acronym Glossary

This course uses a number of acronyms before (or without) always spelling them out inline. Reference table below.

| Term | Stands for | Where it's used |
|------|-----------|-----------------|
| **SDD** | Spec-Driven Development | The overall workflow this course teaches |
| **EARS** | Easy Approach to Requirements Syntax | How `requirements.md` is written |
| **STRIDE** | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege | Threat-modeling framework used in `design.md` |
| **ADR** | Architecture Decision Record | Design rationale captured in `design.md` |
| **OBO** | On-Behalf-Of (token exchange) | AgentCore Identity — queries run as the authenticated user, not a shared service role |
| **CPM** | Critical Path Method | How `tasks.md` groups work into dependency-ordered waves |
| **MCP** | Model Context Protocol | Tool-calling standard used both by Kiro (dev-time) and the chatbot's Gateway (runtime) |

## 00 — Foundation

### Vibe vs Spec: Why SDD for a Bank Chatbot

Kiro offers two session types. This course uses **Spec** exclusively.

- **Vibe:** "Chat first, then build." Explore ideas, iterate. Great for prototypes. *Not used in this course.*
- **Spec (THIS COURSE):** "Plan first, then build." Create requirements and design before coding. Required for regulated systems.

#### The SDD Workflow (4 phases, 3 approval gates)

```
REQUIREMENTS  →  DESIGN  →  TASKS  →  IMPLEMENTATION
 (what)          (how)       (plan)      (code)
    |               |            |            |
 [approve]      [approve]   [approve]    [verify]
```

No code is written until all three spec files are approved. [Source: kiro.dev/docs/specs](https://kiro.dev/docs/specs/)

> **Why SDD for NatWest?** A bank chatbot touching financial data needs formal requirements, a reviewed security architecture, and audit-ready decisions — before a line of code exists. Spec mode enforces this.

### Install Kiro & Start a Project

1. Download from [kiro.dev](https://kiro.dev) (IDE or CLI)
2. Sign in with corporate SSO (IAM Identity Center for banks)
3. Create & open project: `mkdir chatbot && cd chatbot`
4. `.kiro/` appears automatically on first use:

```
chatbot/
├── .kiro/
│   ├── specs/       # Feature specs (requirements, design, tasks)
│   ├── steering/    # Persistent project rules
│   ├── hooks/       # Automated triggers
│   └── settings/    # MCP server config
```

[Docs: Your first project](https://kiro.dev/docs/getting-started/first-project/)

### EARS Notation: How Requirements Are Written

Kiro generates requirements in **EARS** (Easy Approach to Requirements Syntax) — every requirement is testable. [Wikipedia](https://en.wikipedia.org/wiki/Easy_Approach_to_Requirements_Syntax)

```
WHEN a user submits a question
THE SYSTEM SHALL perform semantic retrieval to identify the top-k tables

IF the model cannot produce valid SQL after 2 retries
THEN THE SYSTEM SHALL fail gracefully and inform the user
```

| Pattern | Syntax | Use when |
|---------|--------|----------|
| Ubiquitous | `THE SYSTEM SHALL [behavior]` | Always true |
| Event-driven | `WHEN [event] THE SYSTEM SHALL [response]` | Triggered by event |
| Unwanted | `IF [condition] THEN THE SYSTEM SHALL [response]` | Error/edge cases |

[Source: Jama Software — Adopting EARS](https://www.jamasoftware.com/requirements-management-guide/writing-requirements/adopting-the-ears-notation-to-improve-requirements-engineering/)
