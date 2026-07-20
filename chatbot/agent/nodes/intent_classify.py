"""Intent classification node using Claude Haiku with 2-second budget.

Classifies user intent to determine if the query is actionable (can be
translated to SQL) or needs disambiguation (Requirement 10.1, 10.2).

Uses Claude 3 Haiku via Amazon Bedrock for fast classification with a
strict 2-second timeout budget to maintain low latency.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Bedrock model ID for Claude 3 Haiku (fast, cost-effective classification)
HAIKU_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"

# Timeout budget for intent classification (Requirement 10.1)
CLASSIFICATION_TIMEOUT_SECONDS = 2

# Bedrock client configuration with timeout
_bedrock_config = Config(
    read_timeout=CLASSIFICATION_TIMEOUT_SECONDS,
    connect_timeout=1,
    retries={"max_attempts": 0},  # No retries within 2s budget
)

# Intent categories
INTENT_ACTIONABLE = "actionable"  # Can be translated to SQL
INTENT_AMBIGUOUS = "ambiguous"  # Needs user clarification
INTENT_OUT_OF_SCOPE = "out_of_scope"  # Not a data query

CLASSIFICATION_PROMPT = """You are an intent classifier for a data analytics chatbot.
Classify the user's message into one of three categories:

1. "actionable" — The message is a clear data query that can be translated to SQL.
   Examples: "Show me total sales by region last quarter", "How many active users in December?"

2. "ambiguous" — The message relates to data but is too vague to generate SQL without clarification.
   Examples: "Show me the data", "What about sales?", "Can you query that table?"

3. "out_of_scope" — The message is not a data query (greeting, off-topic, general question).
   Examples: "Hello", "What's the weather?", "Tell me a joke"

Respond with ONLY a JSON object: {"intent": "<category>", "reason": "<brief explanation>"}

User message: {user_message}"""


def _create_bedrock_client() -> Any:
    """Create a Bedrock Runtime client with timeout configuration."""
    return boto3.client(
        "bedrock-runtime",
        config=_bedrock_config,
    )


def intent_classify(state: dict[str, Any]) -> dict[str, Any]:
    """Classify user intent using Claude Haiku with a 2-second budget.

    Determines whether the user's message is:
    - actionable: can be translated directly to SQL
    - ambiguous: needs disambiguation (triggers disambiguation loop)
    - out_of_scope: not a data query

    Args:
        state: GraphState dictionary containing user_message and user_claims.

    Returns:
        Updated state with 'intent' and 'needs_disambiguation' fields set.
    """
    user_message = state.get("user_message", "")
    if not user_message:
        return {
            **state,
            "intent": INTENT_OUT_OF_SCOPE,
            "needs_disambiguation": False,
            "error": "Empty user message",
        }

    start_time = time.time()

    try:
        client = _create_bedrock_client()

        prompt = CLASSIFICATION_PROMPT.format(user_message=user_message)

        # Invoke Claude Haiku via Bedrock
        response = client.invoke_model(
            modelId=HAIKU_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 100,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0,  # Deterministic classification
                }
            ),
        )

        elapsed = time.time() - start_time
        logger.info("Intent classification completed in %.2fs", elapsed)

        # Parse response
        response_body = json.loads(response["body"].read())
        content = response_body.get("content", [{}])[0].get("text", "")

        # Extract intent from JSON response
        try:
            result = json.loads(content)
            intent = result.get("intent", INTENT_AMBIGUOUS)
        except (json.JSONDecodeError, TypeError):
            # If model response isn't valid JSON, default to ambiguous
            logger.warning("Failed to parse intent classification response: %s", content)
            intent = INTENT_AMBIGUOUS

        # Validate intent is a known category
        if intent not in (INTENT_ACTIONABLE, INTENT_AMBIGUOUS, INTENT_OUT_OF_SCOPE):
            intent = INTENT_AMBIGUOUS

        needs_disambiguation = intent == INTENT_AMBIGUOUS

        return {
            **state,
            "intent": intent,
            "needs_disambiguation": needs_disambiguation,
        }

    except ClientError as e:
        elapsed = time.time() - start_time
        logger.error(
            "Bedrock API error during intent classification (%.2fs): %s",
            elapsed,
            str(e),
        )
        # On timeout or API error, default to ambiguous to allow disambiguation
        return {
            **state,
            "intent": INTENT_AMBIGUOUS,
            "needs_disambiguation": True,
            "error": f"Intent classification failed: {e}",
        }
    except Exception as e:
        elapsed = time.time() - start_time
        logger.exception(
            "Unexpected error during intent classification (%.2fs)", elapsed
        )
        return {
            **state,
            "intent": INTENT_AMBIGUOUS,
            "needs_disambiguation": True,
            "error": f"Intent classification error: {e}",
        }
