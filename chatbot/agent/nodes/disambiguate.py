"""Disambiguation node for generating clarification questions.

When user intent is ambiguous, this node generates a clarification question
to narrow the query. Bounded to a maximum of 3 rounds via graph edge
conditions (Requirement 10.2).

If the maximum rounds are reached, the graph terminates the loop and
suggests the user refine their question with more specific terms.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Use Haiku for fast disambiguation question generation
HAIKU_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"

# Maximum disambiguation rounds (structural bound, Requirement 10.2)
MAX_DISAMBIGUATION_ROUNDS = 3

# Bedrock client configuration
_bedrock_config = Config(
    read_timeout=5,
    connect_timeout=2,
    retries={"max_attempts": 1},
)

DISAMBIGUATION_PROMPT = """You are a data analytics chatbot assistant. The user's query is ambiguous
and cannot be translated to SQL without clarification.

Based on the user's message and the available table schemas, generate ONE clear, concise
clarification question to help narrow down their intent.

User message: {user_message}

Available schemas:
{schemas_context}

Previously resolved terms: {resolved_terms}

Disambiguation round: {round_number} of {max_rounds}

Generate a single clarification question. Be specific about what information you need.
If this is round {max_rounds}, make this your final attempt to understand the intent.

Respond with ONLY a JSON object: {{"question": "<your clarification question>", "options": ["<option1>", "<option2>", ...]}}
The options should be 2-4 specific choices the user can pick from to clarify their intent."""


def disambiguate(state: dict[str, Any]) -> dict[str, Any]:
    """Generate a clarification question for ambiguous user intent.

    Increments the disambiguation_rounds counter. The graph edge condition
    enforces the structural bound of 3 rounds maximum (Requirement 10.2).

    If max rounds are reached after this invocation, the graph will route
    to format_respond with a message suggesting the user refine their question.

    Args:
        state: GraphState dictionary containing user_message, retrieved_schemas,
               resolved_terms, and disambiguation_rounds.

    Returns:
        Updated state with incremented disambiguation_rounds and a
        clarification question in final_response (for relay to user).
    """
    user_message = state.get("user_message", "")
    retrieved_schemas = state.get("retrieved_schemas", [])
    resolved_terms = state.get("resolved_terms", {})
    current_rounds = state.get("disambiguation_rounds", 0)

    # Increment disambiguation counter
    new_rounds = current_rounds + 1

    # If we've hit the maximum, provide a terminal message
    if new_rounds >= MAX_DISAMBIGUATION_ROUNDS:
        logger.info(
            "Disambiguation reached max rounds (%d). Terminating loop.",
            MAX_DISAMBIGUATION_ROUNDS,
        )
        return {
            **state,
            "disambiguation_rounds": new_rounds,
            "needs_disambiguation": False,
            "final_response": (
                "I wasn't able to determine your exact intent after multiple attempts. "
                "Could you please refine your question with more specific terms? "
                "For example, include the table name, time period, or specific metrics "
                "you're looking for."
            ),
        }

    # Build schemas context for the prompt
    schemas_context = ""
    if retrieved_schemas:
        schema_summaries = []
        for schema in retrieved_schemas[:5]:  # Limit context size
            summary = f"- {schema.get('database', '')}.{schema.get('table_name', '')}: {schema.get('description', 'No description')}"
            schema_summaries.append(summary)
        schemas_context = "\n".join(schema_summaries)
    else:
        schemas_context = "No schemas retrieved."

    # Build resolved terms context
    terms_context = json.dumps(resolved_terms) if resolved_terms else "None"

    try:
        client = boto3.client("bedrock-runtime", config=_bedrock_config)

        prompt = DISAMBIGUATION_PROMPT.format(
            user_message=user_message,
            schemas_context=schemas_context,
            resolved_terms=terms_context,
            round_number=new_rounds,
            max_rounds=MAX_DISAMBIGUATION_ROUNDS,
        )

        response = client.invoke_model(
            modelId=HAIKU_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 200,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,  # Slight creativity for question variety
                }
            ),
        )

        response_body = json.loads(response["body"].read())
        content = response_body.get("content", [{}])[0].get("text", "")

        # Parse the clarification question
        try:
            result = json.loads(content)
            question = result.get("question", "Could you please clarify your question?")
        except (json.JSONDecodeError, TypeError):
            question = content.strip() if content.strip() else "Could you please clarify your question?"

        logger.info(
            "Generated disambiguation question (round %d/%d): %s",
            new_rounds,
            MAX_DISAMBIGUATION_ROUNDS,
            question[:100],
        )

        return {
            **state,
            "disambiguation_rounds": new_rounds,
            "needs_disambiguation": True,
            "final_response": question,
        }

    except (ClientError, Exception) as e:
        logger.error("Disambiguation question generation failed: %s", e)
        # On failure, don't block — proceed without disambiguation
        return {
            **state,
            "disambiguation_rounds": new_rounds,
            "needs_disambiguation": False,
            "final_response": (
                "I'm having trouble understanding your question. "
                "Could you please rephrase it with more specific details?"
            ),
        }
