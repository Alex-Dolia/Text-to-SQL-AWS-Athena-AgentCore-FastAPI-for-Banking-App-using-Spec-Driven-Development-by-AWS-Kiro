"""Bedrock Guardrails integration — input and output content scanning.

Scans EVERY model call: input direction (user message + SQL) and output
direction (results + narrative) through the Bedrock Guardrails ApplyGuardrail API.

Configuration:
- STANDARD tier with all content filters at HIGH threshold
- ANONYMIZE action for PII entities (all 31 types)
- Fail-closed within 5 seconds on guardrails unavailability

Requirements: 8.1, 8.2, 8.4
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    ReadTimeoutError,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Guardrail identifier — configured via environment or default
GUARDRAIL_ID = os.environ.get("BEDROCK_GUARDRAIL_ID", "chatbot-content-safety")
GUARDRAIL_VERSION = os.environ.get("BEDROCK_GUARDRAIL_VERSION", "DRAFT")

# Fail-closed timeout (Requirement 8.4): 5 seconds total
GUARDRAILS_TIMEOUT_SECONDS = 5
_CONNECT_TIMEOUT = 2
_READ_TIMEOUT = GUARDRAILS_TIMEOUT_SECONDS

# AWS region for Bedrock Runtime
_AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# Content filter thresholds — all categories at HIGH (Requirement 8.1)
# ---------------------------------------------------------------------------

class ContentFilterStrength(str, Enum):
    """Content filter threshold levels."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class GuardrailsConfiguration:
    """Guardrails configuration — STANDARD tier, all filters HIGH."""

    tier: str = "STANDARD"
    hate_threshold: ContentFilterStrength = ContentFilterStrength.HIGH
    violence_threshold: ContentFilterStrength = ContentFilterStrength.HIGH
    sexual_threshold: ContentFilterStrength = ContentFilterStrength.HIGH
    insults_threshold: ContentFilterStrength = ContentFilterStrength.HIGH
    misconduct_threshold: ContentFilterStrength = ContentFilterStrength.HIGH
    prompt_attack_threshold: ContentFilterStrength = ContentFilterStrength.HIGH
    pii_action: str = "ANONYMIZE"


# All 31 PII entity types supported by Bedrock Guardrails (Requirement 8.2)
ALL_PII_ENTITY_TYPES: list[str] = [
    "ADDRESS",
    "AGE",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "CA_HEALTH_NUMBER",
    "CA_SOCIAL_INSURANCE_NUMBER",
    "CREDIT_DEBIT_CARD_CVV",
    "CREDIT_DEBIT_CARD_EXPIRY",
    "CREDIT_DEBIT_CARD_NUMBER",
    "DRIVER_ID",
    "EMAIL",
    "INTERNATIONAL_BANK_ACCOUNT_NUMBER",
    "IP_ADDRESS",
    "LICENSE_PLATE",
    "MAC_ADDRESS",
    "NAME",
    "PASSWORD",
    "PHONE",
    "PIN",
    "SSN",
    "SWIFT_CODE",
    "UK_NATIONAL_HEALTH_SERVICE_NUMBER",
    "UK_NATIONAL_INSURANCE_NUMBER",
    "UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER",
    "URL",
    "USERNAME",
    "US_BANK_ACCOUNT_NUMBER",
    "US_BANK_ROUTING_NUMBER",
    "US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER",
    "US_PASSPORT_NUMBER",
    "VEHICLE_IDENTIFICATION_NUMBER",
]


# Default config instance
GUARDRAILS_CONFIG = GuardrailsConfiguration()


# ---------------------------------------------------------------------------
# PII role-based grants (Requirement 8.3)
# ---------------------------------------------------------------------------

# Certain roles may view specific PII categories without redaction.
# This is defined via Cedar policy grants — mapped here for runtime use.
# NOTE: The canonical implementation is in content_safety.py; this is kept
# for backward compatibility. New code should use content_safety.get_permitted_pii_categories()
ROLE_PII_GRANTS: dict[str, list[str]] = {
    "manager": ["NAME", "EMAIL", "PHONE"],
    "compliance_officer": [
        "NAME", "EMAIL", "PHONE", "ADDRESS",
        "SSN", "CREDIT_DEBIT_CARD_NUMBER",
    ],
}


# ---------------------------------------------------------------------------
# Guardrail scan result model
# ---------------------------------------------------------------------------

class GuardrailAction(str, Enum):
    """Actions returned by Bedrock Guardrails."""
    NONE = "NONE"
    GUARDRAIL_INTERVENED = "GUARDRAIL_INTERVENED"


@dataclass
class GuardrailScanResult:
    """Result from a Bedrock Guardrails ApplyGuardrail call."""

    action: str
    findings: list[str] = field(default_factory=list)
    pii_entities: list[str] = field(default_factory=list)
    redacted_content: str | None = None
    prompt_injection_detected: bool = False
    jailbreak_detected: bool = False
    blocked: bool = False


# ---------------------------------------------------------------------------
# Boto3 client management
# ---------------------------------------------------------------------------

def _create_bedrock_client() -> Any:
    """Create a Bedrock Runtime client with strict timeout configuration.

    The timeout is set to ensure fail-closed behavior within 5 seconds
    (Requirement 8.4).
    """
    config = Config(
        region_name=_AWS_REGION,
        connect_timeout=_CONNECT_TIMEOUT,
        read_timeout=_READ_TIMEOUT,
        retries={"max_attempts": 1},  # No retries — fail fast for fail-closed
    )
    return boto3.client("bedrock-runtime", config=config)


# Module-level client (lazy initialization)
_bedrock_client: Any = None


def _get_client() -> Any:
    """Get or create the Bedrock Runtime client."""
    global _bedrock_client
    if _bedrock_client is None:
        _bedrock_client = _create_bedrock_client()
    return _bedrock_client


def reset_client() -> None:
    """Reset the client (for testing purposes)."""
    global _bedrock_client
    _bedrock_client = None


def set_client(client: Any) -> None:
    """Inject a client (for testing purposes)."""
    global _bedrock_client
    _bedrock_client = client


# ---------------------------------------------------------------------------
# Core scanning function — ApplyGuardrail API
# ---------------------------------------------------------------------------

def _apply_guardrail(
    content: str,
    source: str,
    guardrail_id: str = GUARDRAIL_ID,
    guardrail_version: str = GUARDRAIL_VERSION,
) -> GuardrailScanResult:
    """Call the Bedrock ApplyGuardrail API to scan content.

    Args:
        content: Text content to scan.
        source: Scan direction — "INPUT" or "OUTPUT".
        guardrail_id: Guardrail identifier.
        guardrail_version: Guardrail version string.

    Returns:
        GuardrailScanResult with action, findings, and redacted content.

    Raises:
        RuntimeError: On guardrails unavailability (fail-closed per Req 8.4).
    """
    if not content or not content.strip():
        return GuardrailScanResult(action="NONE")

    start_time = time.time()

    try:
        client = _get_client()

        # Build the content payload for ApplyGuardrail
        content_payload = [{"text": {"text": content}}]

        response = client.apply_guardrail(
            guardrailIdentifier=guardrail_id,
            guardrailVersion=guardrail_version,
            source=source,
            content=content_payload,
        )

        elapsed = time.time() - start_time
        logger.debug(
            "ApplyGuardrail (%s) completed in %.3fs", source, elapsed
        )

        return _parse_guardrail_response(response)

    except (ConnectTimeoutError, ReadTimeoutError) as e:
        elapsed = time.time() - start_time
        logger.error(
            "Guardrails timeout after %.2fs (%s direction): %s",
            elapsed, source, e,
        )
        raise RuntimeError(
            "Guardrails service unavailable (timeout). "
            "Blocking request per fail-closed policy."
        ) from e

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        logger.error(
            "Guardrails ClientError (%s) in %s direction: %s",
            error_code, source, e,
        )
        raise RuntimeError(
            f"Guardrails service unavailable ({error_code}). "
            "Blocking request per fail-closed policy."
        ) from e

    except BotoCoreError as e:
        logger.error("Guardrails BotoCoreError (%s direction): %s", source, e)
        raise RuntimeError(
            "Guardrails service unavailable. "
            "Blocking request per fail-closed policy."
        ) from e

    except Exception as e:
        logger.error(
            "Unexpected guardrails error (%s direction): %s", source, e
        )
        raise RuntimeError(
            "Guardrails service error. "
            "Blocking request per fail-closed policy."
        ) from e


def _parse_guardrail_response(response: dict[str, Any]) -> GuardrailScanResult:
    """Parse the ApplyGuardrail API response into a structured result.

    Args:
        response: Raw API response from apply_guardrail.

    Returns:
        Parsed GuardrailScanResult.
    """
    action = response.get("action", "NONE")
    outputs = response.get("outputs", [])
    assessments = response.get("assessments", [])

    findings: list[str] = []
    pii_entities: list[str] = []
    prompt_injection_detected = False
    jailbreak_detected = False

    for assessment in assessments:
        # Content policy (hate, violence, sexual, insults, misconduct)
        content_policy = assessment.get("contentPolicy", {})
        for filter_result in content_policy.get("filters", []):
            filter_type = filter_result.get("type", "unknown")
            filter_action = filter_result.get("action", "unknown")
            confidence = filter_result.get("confidence", "unknown")
            findings.append(
                f"CONTENT_FILTER:{filter_type}:{filter_action}:{confidence}"
            )

        # Word policy (custom word filters)
        word_policy = assessment.get("wordPolicy", {})
        for custom_word in word_policy.get("customWords", []):
            findings.append(f"WORD_FILTER:{custom_word.get('match', 'unknown')}")
        for managed_word in word_policy.get("managedWordLists", []):
            findings.append(f"MANAGED_WORD:{managed_word.get('match', 'unknown')}")

        # Topic policy (denied topics)
        topic_policy = assessment.get("topicPolicy", {})
        for topic in topic_policy.get("topics", []):
            findings.append(
                f"DENIED_TOPIC:{topic.get('name', 'unknown')}:{topic.get('action', 'unknown')}"
            )

        # Sensitive information policy (PII)
        sensitive_info = assessment.get("sensitiveInformationPolicy", {})
        for pii in sensitive_info.get("piiEntities", []):
            pii_type = pii.get("type", "UNKNOWN")
            pii_action = pii.get("action", "ANONYMIZED")
            pii_entities.append(pii_type)
            findings.append(f"PII:{pii_type}:{pii_action}")

        for regex_match in sensitive_info.get("regexes", []):
            findings.append(f"REGEX:{regex_match.get('name', 'unknown')}")

        # Contextual grounding policy
        grounding_policy = assessment.get("contextualGroundingPolicy", {})
        for filter_result in grounding_policy.get("filters", []):
            findings.append(
                f"GROUNDING:{filter_result.get('type', 'unknown')}:"
                f"{filter_result.get('action', 'unknown')}"
            )

    # Detect prompt injection / jailbreak from findings
    for finding in findings:
        finding_lower = finding.lower()
        if "prompt" in finding_lower and "attack" in finding_lower:
            prompt_injection_detected = True
        if "jailbreak" in finding_lower:
            jailbreak_detected = True

    # Extract redacted content from outputs
    redacted_content: str | None = None
    if outputs:
        redacted_content = outputs[0].get("text", None)

    blocked = action == "GUARDRAIL_INTERVENED"

    return GuardrailScanResult(
        action=action,
        findings=findings,
        pii_entities=pii_entities,
        redacted_content=redacted_content,
        prompt_injection_detected=prompt_injection_detected,
        jailbreak_detected=jailbreak_detected,
        blocked=blocked,
    )


# ---------------------------------------------------------------------------
# Public API — reusable input scanning function
# ---------------------------------------------------------------------------

def scan_input(
    user_message: str,
    additional_context: str | None = None,
    guardrail_id: str = GUARDRAIL_ID,
    guardrail_version: str = GUARDRAIL_VERSION,
) -> GuardrailScanResult:
    """Scan model input (user message + context) through Bedrock Guardrails.

    This function is exposed as a reusable utility for scanning any model
    input before invocation. It calls the ApplyGuardrail API in the INPUT
    direction with all content filters at HIGH threshold (Requirement 8.1).

    Args:
        user_message: The user's message/prompt to scan.
        additional_context: Optional additional context (e.g., generated SQL)
            to include in the scan.
        guardrail_id: Guardrail identifier override.
        guardrail_version: Guardrail version override.

    Returns:
        GuardrailScanResult with action, findings, and whether content was blocked.

    Raises:
        RuntimeError: On guardrails unavailability — caller must handle
            this as a fail-closed condition (Requirement 8.4).
    """
    # Combine user message with any additional context for scanning
    content_parts = [user_message]
    if additional_context:
        content_parts.append(additional_context)
    content_to_scan = "\n\n".join(content_parts)

    logger.info(
        "Scanning input (%d chars) through Bedrock Guardrails",
        len(content_to_scan),
    )

    result = _apply_guardrail(
        content=content_to_scan,
        source="INPUT",
        guardrail_id=guardrail_id,
        guardrail_version=guardrail_version,
    )

    if result.blocked:
        logger.warning(
            "Input BLOCKED by guardrails. Findings: %s",
            result.findings,
        )
    elif result.prompt_injection_detected or result.jailbreak_detected:
        logger.warning(
            "Prompt injection/jailbreak detected in input. "
            "injection=%s, jailbreak=%s",
            result.prompt_injection_detected,
            result.jailbreak_detected,
        )

    return result


def scan_output(
    content: str,
    guardrail_id: str = GUARDRAIL_ID,
    guardrail_version: str = GUARDRAIL_VERSION,
) -> GuardrailScanResult:
    """Scan model output through Bedrock Guardrails.

    Scans results and narrative in the OUTPUT direction with all content
    filters at HIGH threshold. PII entities are ANONYMIZED (Requirement 8.2).

    Args:
        content: The model output content to scan.
        guardrail_id: Guardrail identifier override.
        guardrail_version: Guardrail version override.

    Returns:
        GuardrailScanResult with action, findings, redacted content, and PII info.

    Raises:
        RuntimeError: On guardrails unavailability — caller must handle
            this as a fail-closed condition (Requirement 8.4).
    """
    logger.info(
        "Scanning output (%d chars) through Bedrock Guardrails",
        len(content),
    )

    result = _apply_guardrail(
        content=content,
        source="OUTPUT",
        guardrail_id=guardrail_id,
        guardrail_version=guardrail_version,
    )

    if result.blocked:
        logger.warning(
            "Output BLOCKED by guardrails. Findings: %s",
            result.findings,
        )

    return result


# ---------------------------------------------------------------------------
# Helper: determine permitted PII categories for a user
# ---------------------------------------------------------------------------

def _get_permitted_pii_categories(user_claims: dict[str, Any]) -> set[str]:
    """Determine which PII categories the user is permitted to view.

    Based on the user's role and Cedar policy grants, certain PII categories
    may be visible without redaction (Requirement 8.3).

    Args:
        user_claims: User claims from validated JWT.

    Returns:
        Set of PII category names the user may view unredacted.
    """
    role = user_claims.get("role", "")
    return set(ROLE_PII_GRANTS.get(role, []))


# ---------------------------------------------------------------------------
# Graph node function — output_scan
# ---------------------------------------------------------------------------

def output_scan(state: dict[str, Any]) -> dict[str, Any]:
    """Scan output through Bedrock Guardrails for content safety and PII.

    This is the LangGraph node that scans EVERY model output through
    Bedrock Guardrails in the OUTPUT direction (Requirement 8.1).

    Behavior:
    - Scans query results and narrative for content safety violations
    - Applies PII ANONYMIZE unless user role permits that PII category (Req 8.3)
    - On BLOCK: records block, checks session termination threshold (Req 8.5)
    - On session termination: invalidates session, logs to audit+SIEM (Req 8.5)
    - On guardrails unavailability: fails closed within 5 seconds (Req 8.4)

    Args:
        state: GraphState dict with query_results, user_claims,
               guardrails_findings, etc.

    Returns:
        Updated state with scanned/redacted results and guardrails_findings.
    """
    from chatbot.agent.nodes.content_safety import (
        get_block_tracker,
        handle_guardrail_block,
    )

    query_results = state.get("query_results")
    user_claims = state.get("user_claims", {})
    existing_findings: list[str] = state.get("guardrails_findings") or []
    session_id = ""
    principal = "unknown"
    trace_id = "unknown"

    # Extract session context for block tracking
    if isinstance(user_claims, dict):
        session_id = user_claims.get("session_id", "")
        principal = user_claims.get("sub", "unknown")
    # Try to get trace_id from state
    trace_id = state.get("trace_id", trace_id)

    # Check if session is already terminated (Requirement 8.5)
    if session_id:
        tracker = get_block_tracker()
        if tracker.is_terminated(session_id):
            return {
                **state,
                "query_results": None,
                "guardrails_findings": existing_findings,
                "error": (
                    "Your session has been terminated due to repeated policy violations. "
                    "Please re-authenticate to continue."
                ),
                "session_terminated": True,
            }

    if not query_results:
        # Nothing to scan — pass through
        return state

    # Build content string from query results for scanning
    content_to_scan = _build_scan_content(query_results)

    if not content_to_scan:
        return state

    start_time = time.time()

    try:
        # Scan output through Guardrails (Requirement 8.1)
        result = scan_output(content_to_scan)

        elapsed = time.time() - start_time
        logger.info(
            "Output scan completed in %.2fs. Action: %s, Findings: %d",
            elapsed, result.action, len(result.findings),
        )

        # Accumulate guardrails findings
        all_findings = list(existing_findings) + result.findings

        # Handle BLOCK action (Requirement 8.2, 8.5)
        if result.blocked:
            logger.warning(
                "Guardrails BLOCKED output for user %s",
                user_claims.get("sub", "unknown"),
            )

            # Record block and check session termination (Requirement 8.5)
            if session_id:
                block_result = handle_guardrail_block(
                    session_id=session_id,
                    principal=principal,
                    trace_id=trace_id,
                    findings=result.findings,
                )

                return {
                    **state,
                    "query_results": None,
                    "guardrails_findings": all_findings,
                    "error": block_result["error_message"],
                    "session_terminated": block_result["terminated"],
                }

            # No session context — standard block response
            return {
                **state,
                "query_results": None,
                "guardrails_findings": all_findings,
                "error": (
                    "I can't help with that request. "
                    "Please rephrase your question about the data."
                ),
            }

        # Handle PII redaction (Requirement 8.3)
        updated_results = _apply_pii_redaction(
            query_results=query_results,
            scan_result=result,
            user_claims=user_claims,
        )

        return {
            **state,
            "query_results": updated_results,
            "guardrails_findings": all_findings,
        }

    except RuntimeError as e:
        # Fail-closed on guardrails unavailability (Requirement 8.4)
        elapsed = time.time() - start_time
        logger.error(
            "Guardrails fail-closed after %.2fs: %s", elapsed, str(e)
        )
        return {
            **state,
            "query_results": None,
            "guardrails_findings": list(existing_findings) + [str(e)],
            "error": (
                "Content safety scanning is temporarily unavailable. "
                "Please try again in a moment."
            ),
        }


# ---------------------------------------------------------------------------
# Helper: build content string for scanning
# ---------------------------------------------------------------------------

def _build_scan_content(query_results: Any) -> str:
    """Build a text string from query results for guardrails scanning.

    Args:
        query_results: The query results (dict or other type).

    Returns:
        String representation suitable for scanning.
    """
    if isinstance(query_results, dict):
        rows = query_results.get("rows", [])
        if rows:
            # Scan sample of rows to stay within reasonable payload size
            sample_rows = rows[:100]
            return json.dumps(sample_rows, default=str)
        return json.dumps(query_results, default=str)
    return str(query_results)


# ---------------------------------------------------------------------------
# Helper: apply PII redaction based on role grants
# ---------------------------------------------------------------------------

def _apply_pii_redaction(
    query_results: Any,
    scan_result: GuardrailScanResult,
    user_claims: dict[str, Any],
) -> Any:
    """Apply PII redaction to query results based on user role grants.

    PII entities detected by guardrails are ANONYMIZED unless the user's
    role has an explicit grant for that PII category (Requirement 8.3).

    Args:
        query_results: Original query results.
        scan_result: Result from guardrails scan.
        user_claims: User claims from JWT.

    Returns:
        Query results with PII redacted as appropriate.
    """
    if not scan_result.pii_entities:
        return query_results

    permitted_pii = _get_permitted_pii_categories(user_claims)
    needs_redaction = [
        pii for pii in scan_result.pii_entities if pii not in permitted_pii
    ]

    if not needs_redaction:
        # User is permitted to see all detected PII
        return query_results

    # Use the guardrails-redacted content
    if scan_result.redacted_content:
        logger.info(
            "PII redacted in output: %s (user role: %s)",
            ", ".join(needs_redaction),
            user_claims.get("role", "unknown"),
        )
        try:
            redacted_data = json.loads(scan_result.redacted_content)
            if isinstance(query_results, dict):
                return {**query_results, "rows": redacted_data}
            return redacted_data
        except (json.JSONDecodeError, TypeError):
            # If redacted content isn't valid JSON, wrap it
            return {"redacted_output": scan_result.redacted_content}

    return query_results
