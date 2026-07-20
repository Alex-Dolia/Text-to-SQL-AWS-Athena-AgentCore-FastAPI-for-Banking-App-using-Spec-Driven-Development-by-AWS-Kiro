// Base Cedar Policies — Default-Deny and Universal Forbid Rules
//
// These policies implement the foundational security posture:
//   1. Default-deny: Cedar's built-in behavior — no access without explicit permit
//   2. Forbid-wins: explicit forbid rules that override any permits (defense in depth)
//
// Requirements: 5.1 (default-deny), 5.2 (forbid-wins), 6.5 (layer independence)
//
// NOTE: Cedar is default-deny by design — if no permit policy matches,
// the request is denied. No explicit "deny all" rule is needed.
// The forbid rules below provide defense-in-depth for critical resources.

// ─── Universal Forbid: PCI Databases ─────────────────────────────────────────
// No principal may access PCI cardholder or transaction databases via the chatbot
// under any circumstances. This is a defense-in-depth control — even if a permit
// policy is misconfigured to allow access, this forbid rule overrides it.
//
// Forbid-wins semantics (Requirement 5.2): if both a permit and forbid match,
// the request is DENIED regardless of how many permits match.

forbid(
    principal,
    action,
    resource
) when {
    resource.database == "pci_cardholder"
};

forbid(
    principal,
    action,
    resource
) when {
    resource.database == "pci_transactions"
};

// ─── Universal Forbid: Classification Tier Enforcement ───────────────────────
// No principal may access resources above their classification tier.
// This provides a backstop even if role-specific permits are too broad.
// Tier hierarchy: public(1) < internal(2) < confidential(3) < restricted(4)

forbid(
    principal,
    action,
    resource
) when {
    resource.classification_tier > principal.data_classification_tier
};
