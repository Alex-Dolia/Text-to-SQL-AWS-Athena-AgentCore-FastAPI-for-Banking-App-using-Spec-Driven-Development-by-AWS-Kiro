"""Agent graph node implementations.

Each node is a function that takes GraphState (dict) and returns GraphState (dict).
All nodes are statically defined and wired into the LangGraph state graph.

Node modules:
- intent_classify: Claude Haiku classification with 2s budget
- glossary_resolve: Business term resolution via OpenSearch
- schema_retrieve: RAG retrieval from OpenSearch, filtered by user auth
- disambiguate: Clarification questions (max 3 rounds)
- sql_generate: Claude Sonnet SQL generation, temperature=0
- validate_sql: Delegates to deterministic validation engine
- tool_call: Routes through AgentCore Gateway
- self_correct: SQL rewrite on error (max 2 retries)
- output_scan: Guardrails output scan, PII redaction
- format_respond: Format response with data freshness
"""

from chatbot.agent.nodes.disambiguate import disambiguate
from chatbot.agent.nodes.format_respond import format_respond
from chatbot.agent.nodes.glossary_resolve import glossary_resolve
from chatbot.agent.nodes.intent_classify import intent_classify
from chatbot.agent.nodes.output_scan import output_scan, scan_input, scan_output
from chatbot.agent.nodes.schema_retrieve import schema_retrieve
from chatbot.agent.nodes.self_correct import self_correct
from chatbot.agent.nodes.sql_generate import sql_generate
from chatbot.agent.nodes.tool_call import tool_call
from chatbot.agent.nodes.validate_sql import validate_sql_node

__all__ = [
    "intent_classify",
    "glossary_resolve",
    "schema_retrieve",
    "disambiguate",
    "sql_generate",
    "validate_sql_node",
    "tool_call",
    "self_correct",
    "output_scan",
    "scan_input",
    "scan_output",
    "format_respond",
]
