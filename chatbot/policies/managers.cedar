// Cedar Policies — Manager Role Permits
//
// Grants for users with role == "manager". Managers have broader access than
// analysts — they can access tables across all databases in their department's
// authorized set at their classification tier, without additional restrictions.
// Managers can also access tables across departments if they are in the
// "cross_department_access" group (for oversight/reporting purposes).
//
// Requirements: 5.1 (explicit permit required), 5.3 (claims from JWT only)
//
// ABAC attributes used:
//   - principal.role: must be "manager"
//   - principal.department_databases: set of databases the manager's department owns
//   - principal.data_classification_tier: max tier the manager is cleared for
//   - principal.groups: group memberships (e.g., "cross_department_access")
//   - resource.database: the database the target table belongs to
//   - resource.classification_tier: the table's data classification level

// ─── Permit: Managers can run queries on their department's tables ─────────────

permit(
    principal,
    action == Chatbot::Action::"run_query",
    resource
) when {
    principal.role == "manager" &&
    principal.department_databases.contains(resource.database) &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Managers can list tables in their department's databases ──────────

permit(
    principal,
    action == Chatbot::Action::"list_tables",
    resource
) when {
    principal.role == "manager" &&
    principal.department_databases.contains(resource.database) &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Managers can get schema for their department's tables ─────────────

permit(
    principal,
    action == Chatbot::Action::"get_schema",
    resource
) when {
    principal.role == "manager" &&
    principal.department_databases.contains(resource.database) &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Managers can estimate cost for their department's tables ──────────

permit(
    principal,
    action == Chatbot::Action::"estimate_cost",
    resource
) when {
    principal.role == "manager" &&
    principal.department_databases.contains(resource.database) &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Cross-department managers can run queries on any table ────────────
// Managers in the "cross_department_access" group can query tables outside
// their department's databases, still bounded by classification tier.

permit(
    principal,
    action == Chatbot::Action::"run_query",
    resource
) when {
    principal.role == "manager" &&
    principal.groups.contains("cross_department_access") &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Cross-department managers can list any tables ─────────────────────

permit(
    principal,
    action == Chatbot::Action::"list_tables",
    resource
) when {
    principal.role == "manager" &&
    principal.groups.contains("cross_department_access") &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Cross-department managers can get schema for any table ────────────

permit(
    principal,
    action == Chatbot::Action::"get_schema",
    resource
) when {
    principal.role == "manager" &&
    principal.groups.contains("cross_department_access") &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Cross-department managers can estimate cost for any table ─────────

permit(
    principal,
    action == Chatbot::Action::"estimate_cost",
    resource
) when {
    principal.role == "manager" &&
    principal.groups.contains("cross_department_access") &&
    resource.classification_tier <= principal.data_classification_tier
};
