// Cedar Policy — Kill Switch Access Control
//
// Restricts kill switch invocation to principals with the security-operations role.
// This is a defense-in-depth control: the application code also validates the role,
// but the Cedar policy provides an additional authoritative enforcement point at
// the Gateway boundary.
//
// Requirement 14.4: restrict invocation to security-operations role.
//                   Unauthorized attempts receive HTTP 403 and are logged.

// ─── Permit: Only security-operations role can invoke kill switch ─────────────
// The kill switch is a high-impact administrative action. Only principals
// explicitly assigned the security-operations role may activate or deactivate it.

permit(
    principal,
    action == Chatbot::Action::"kill_switch",
    resource
) when {
    principal.role == "security-operations"
};

// NOTE: Default-deny semantics mean that any principal without an explicit
// permit above will be denied. No explicit forbid is needed, but the
// application code also validates the role for defense in depth.
