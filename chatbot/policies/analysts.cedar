// Cedar Policies — Analyst Role Permits
//
// Grants for users with role == "analyst". Analysts can query, list, inspect,
// and estimate cost for tables within their department's authorized databases,
// subject to ABAC constraints on department and classification tier.
//
// Requirements: 5.1 (explicit permit required), 5.3 (claims from JWT only)
//
// ABAC attributes used:
//   - principal.role: must be "analyst"
//   - principal.department_databases: set of databases the analyst's department owns
//   - principal.data_classification_tier: max tier the analyst is cleared for
//   - resource.database: the database the target table belongs to
//   - resource.classification_tier: the table's data classification level

// ─── Permit: Analysts can run queries on their department's tables ────────────
// The analyst must be querying a table whose database is in their department's
// authorized set, and the table's classification tier must be at or below the
// analyst's clearance level.

permit(
    principal,
    action == Chatbot::Action::"run_query",
    resource
) when {
    principal.role == "analyst" &&
    principal.department_databases.contains(resource.database) &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Analysts can list tables in their department's databases ─────────

permit(
    principal,
    action == Chatbot::Action::"list_tables",
    resource
) when {
    principal.role == "analyst" &&
    principal.department_databases.contains(resource.database) &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Analysts can get schema for their department's tables ────────────

permit(
    principal,
    action == Chatbot::Action::"get_schema",
    resource
) when {
    principal.role == "analyst" &&
    principal.department_databases.contains(resource.database) &&
    resource.classification_tier <= principal.data_classification_tier
};

// ─── Permit: Analysts can estimate cost for their department's tables ─────────

permit(
    principal,
    action == Chatbot::Action::"estimate_cost",
    resource
) when {
    principal.role == "analyst" &&
    principal.department_databases.contains(resource.database) &&
    resource.classification_tier <= principal.data_classification_tier
};
