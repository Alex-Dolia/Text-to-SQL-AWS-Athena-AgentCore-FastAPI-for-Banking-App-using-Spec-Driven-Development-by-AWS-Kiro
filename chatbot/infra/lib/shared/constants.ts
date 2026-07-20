/**
 * Cross-stack constants for the Chatbot Security Architecture CDK infrastructure.
 *
 * These constants are shared across all stacks to ensure consistency
 * and avoid hard-coded values scattered throughout the codebase.
 *
 * Stack dependency order (no circular dependencies):
 *   Networking → Security → Data → Compute → Observability
 *
 * Validates: Requirements 12.1 (VPC PrivateLink routing), 12.5 (endpoint policies)
 */

// ---------------------------------------------------------------------------
// Project Naming
// ---------------------------------------------------------------------------

/** Base prefix for all resource names */
export const PROJECT_PREFIX = 'chatbot';

/** Stack names used for cross-stack references */
export const STACK_NAMES = {
  NETWORKING: 'ChatbotNetworkingStack',
  SECURITY: 'ChatbotSecurityStack',
  DATA: 'ChatbotDataStack',
  COMPUTE: 'ChatbotComputeStack',
  OBSERVABILITY: 'ChatbotObservabilityStack',
} as const;

/**
 * Stack deployment order — enforced via addDependency() in bin/app.ts.
 * No circular dependencies permitted.
 *
 * 1. Networking  (VPC, PrivateLink endpoints, security groups)
 * 2. Security    (KMS, Cognito, Secrets Manager, IAM roles)
 * 3. Data        (S3, Glue, Lake Formation, OpenSearch, Athena workgroup)
 * 4. Compute     (ECS Fargate, ALB, Lambda, EventBridge)
 * 5. Observability (Dashboards, Alarms, SIEM subscription filters)
 */
export const STACK_DEPLOYMENT_ORDER = [
  STACK_NAMES.NETWORKING,
  STACK_NAMES.SECURITY,
  STACK_NAMES.DATA,
  STACK_NAMES.COMPUTE,
  STACK_NAMES.OBSERVABILITY,
] as const;

// ---------------------------------------------------------------------------
// Networking Constants (Req 12.1, 12.2, 12.3, 12.4, 12.5)
// ---------------------------------------------------------------------------

export const NETWORKING = {
  /** VPC name identifier */
  VPC_NAME: `${PROJECT_PREFIX}-vpc`,

  /** Maximum availability zones for the VPC */
  MAX_AZS: 2,

  /** CIDR mask for private isolated subnets */
  SUBNET_CIDR_MASK: 24,

  /** Default corporate CIDR range (context-overridable) */
  DEFAULT_CORPORATE_CIDR: '10.0.0.0/8',

  /** Minimum TLS version enforced on all endpoints (Req 12.2) */
  MIN_TLS_VERSION: '1.2',

  /** Security group names */
  SECURITY_GROUPS: {
    ALB: 'sg-alb',
    FASTAPI: 'sg-fastapi',
    VPCE: 'sg-vpce',
  },

  /** Port configurations */
  PORTS: {
    HTTPS: 443,
    FASTAPI: 8000,
  },
} as const;

// ---------------------------------------------------------------------------
// Security Constants (Req 1.1, 1.3, 1.6, 7.2)
// ---------------------------------------------------------------------------

export const SECURITY = {
  /** KMS key aliases */
  KMS_ALIASES: {
    DATALAKE: `${PROJECT_PREFIX}/datalake`,
    AUDIT: `${PROJECT_PREFIX}/audit`,
    OPENSEARCH: `${PROJECT_PREFIX}/opensearch`,
    QUERY_RESULTS: `${PROJECT_PREFIX}/queryresults`,
    GATEWAY: `${PROJECT_PREFIX}/gateway`,
  },

  /** KMS key pending deletion window in days */
  KMS_PENDING_WINDOW_DAYS: 30,

  /** Cognito User Pool configuration */
  COGNITO: {
    USER_POOL_NAME: `${PROJECT_PREFIX}-user-pool`,
    /** JWT access token lifetime — max 15 minutes (Req 1.3) */
    ACCESS_TOKEN_VALIDITY_MINUTES: 15,
    /** ID token lifetime — match access token */
    ID_TOKEN_VALIDITY_MINUTES: 15,
    /** Refresh token lifetime — max 8 hours (Req 1.3) */
    REFRESH_TOKEN_VALIDITY_HOURS: 8,
    /** Minimum password length */
    MIN_PASSWORD_LENGTH: 16,
    /** Temporary password validity in days */
    TEMP_PASSWORD_VALIDITY_DAYS: 1,
    /** Required custom claims from IdP (Req 1.4) */
    REQUIRED_CLAIMS: ['department', 'role', 'data_classification_tier', 'groups'],
  },

  /** OBO Token Vault configuration (Req 7.2) */
  OBO_TOKEN_VAULT: {
    SECRET_NAME: `${PROJECT_PREFIX}/obo-token-vault`,
    /** Rotation period in days */
    ROTATION_DAYS: 90,
  },

  /** IAM role names (least privilege, no "allow all") */
  IAM_ROLES: {
    FASTAPI_TASK: `${PROJECT_PREFIX}-fastapi-task-role`,
    AGENTCORE_RUNTIME: `${PROJECT_PREFIX}-agentcore-runtime-role`,
    RECONCILIATION: `${PROJECT_PREFIX}-reconciliation-role`,
    DEPROVISIONING: `${PROJECT_PREFIX}-deprovisioning-role`,
    LAKEFORMATION_ADMIN: `${PROJECT_PREFIX}-lakeformation-admin`,
    AUDIT_REPLICATION: `${PROJECT_PREFIX}-audit-replication-role`,
  },
} as const;

// ---------------------------------------------------------------------------
// Data Constants (Req 11.2, 11.3, 16.5, 6.4)
// ---------------------------------------------------------------------------

export const DATA = {
  /** S3 bucket name patterns (account and region appended at deploy time) */
  BUCKET_NAMES: {
    DATALAKE: `${PROJECT_PREFIX}-datalake`,
    AUDIT: `${PROJECT_PREFIX}-audit`,
    AUDIT_REPLICA: `${PROJECT_PREFIX}-audit-replica`,
    QUERY_RESULTS: `${PROJECT_PREFIX}-query-results`,
  },

  /** Audit trail configuration (Req 11.2, 11.3) */
  AUDIT: {
    /** Object Lock retention mode — Compliance (cannot be deleted, even by root) */
    OBJECT_LOCK_MODE: 'COMPLIANCE',
    /** Retention period in years (Req 11.2) */
    RETENTION_YEARS: 7,
    /** Cross-region replication RPO in minutes (Req 11.3) */
    REPLICATION_RPO_MINUTES: 15,
  },

  /** Glue Catalog configuration */
  GLUE: {
    DATABASE_NAME: 'chatbot_datalake',
  },

  /** OpenSearch Serverless configuration (Req 16.5) */
  OPENSEARCH: {
    COLLECTION_NAME: `${PROJECT_PREFIX}-schema-vectors`,
    COLLECTION_TYPE: 'VECTORSEARCH',
    /** Network policy name */
    NETWORK_POLICY_NAME: `${PROJECT_PREFIX}-vectors-network`,
    /** Encryption policy name */
    ENCRYPTION_POLICY_NAME: `${PROJECT_PREFIX}-vectors-encryption`,
    /** Data access policy name */
    DATA_ACCESS_POLICY_NAME: `${PROJECT_PREFIX}-vectors-access`,
  },

  /** Athena workgroup configuration (Req 9.5) */
  ATHENA: {
    WORKGROUP_NAME: `${PROJECT_PREFIX}-readonly`,
    /** Bytes-scanned limit per query — 10 GB in bytes */
    BYTES_SCANNED_CUTOFF: 10_737_418_240,
    /** Query results expiration in days */
    RESULTS_EXPIRATION_DAYS: 7,
    /** Engine version */
    ENGINE_VERSION: 'Athena engine version 3',
  },
} as const;

// ---------------------------------------------------------------------------
// Compute Constants (Req 18.4, 18.5, 13.1, 15.1)
// ---------------------------------------------------------------------------

export const COMPUTE = {
  /** ECS Cluster name */
  CLUSTER_NAME: `${PROJECT_PREFIX}-cluster`,

  /** FastAPI ECS Fargate service configuration */
  FASTAPI: {
    SERVICE_NAME: `${PROJECT_PREFIX}-fastapi`,
    /** Container port */
    CONTAINER_PORT: 8000,
    /** CPU units (0.5 vCPU) */
    CPU: 512,
    /** Memory in MiB (1 GB) */
    MEMORY_MIB: 1024,
    /** Health check path */
    HEALTH_CHECK_PATH: '/health',
    /** Health check interval in seconds */
    HEALTH_CHECK_INTERVAL_SECONDS: 30,
  },

  /** AgentCore Runtime configuration */
  AGENTCORE: {
    SERVICE_NAME: `${PROJECT_PREFIX}-agentcore`,
    /** CPU units (1 vCPU as per design: 1 vCPU, 2 GB memory) */
    CPU: 1024,
    /** Memory in MiB (2 GB as per design) */
    MEMORY_MIB: 2048,
  },

  /** Auto-scaling configuration (Req 18.5) */
  AUTOSCALING: {
    /** Minimum task count (multi-AZ) */
    MIN_CAPACITY: 2,
    /** Maximum task count */
    MAX_CAPACITY: 10,
    /** Scale out when response time exceeds this (seconds) */
    SCALE_OUT_RESPONSE_TIME_SECONDS: 1,
    /** Scale in when response time below this (seconds) */
    SCALE_IN_RESPONSE_TIME_SECONDS: 0.5,
    /** Scale out when CPU exceeds this percentage */
    SCALE_OUT_CPU_PERCENT: 60,
    /** Scale in when CPU below this percentage */
    SCALE_IN_CPU_PERCENT: 30,
    /** Cooldown period in seconds */
    COOLDOWN_SECONDS: 300,
  },

  /** Lambda configurations */
  LAMBDA: {
    /** Deprovisioning webhook Lambda */
    DEPROVISIONING: {
      FUNCTION_NAME: `${PROJECT_PREFIX}-deprovisioning-webhook`,
      /** Timeout in seconds (within 5-minute SLA) */
      TIMEOUT_SECONDS: 300,
      MEMORY_MB: 256,
      RUNTIME: 'python3.12',
    },
    /** Reconciliation Lambda */
    RECONCILIATION: {
      FUNCTION_NAME: `${PROJECT_PREFIX}-reconciliation`,
      /** Timeout in seconds (within 60-minute SLA) */
      TIMEOUT_SECONDS: 3600,
      MEMORY_MB: 512,
      RUNTIME: 'python3.12',
    },
  },

  /** EventBridge schedule configurations (Req 13.1) */
  EVENTBRIDGE: {
    /** Daily reconciliation schedule (UTC midnight) */
    RECONCILIATION_SCHEDULE: 'cron(0 0 * * ? *)',
    /** Glue Catalog change event source */
    GLUE_EVENT_SOURCE: 'aws.glue',
  },
} as const;

// ---------------------------------------------------------------------------
// Observability Constants (Req 12.6, 13.5, 4.5, 2.5)
// ---------------------------------------------------------------------------

export const OBSERVABILITY = {
  /** SNS topic names for alerts */
  SNS_TOPICS: {
    P0_CRITICAL: `${PROJECT_PREFIX}-p0-critical-alerts`,
    P1_SECURITY: `${PROJECT_PREFIX}-p1-security-alerts`,
    P2_OPERATIONAL: `${PROJECT_PREFIX}-p2-operational-alerts`,
  },

  /** CloudWatch alarm configuration */
  ALARMS: {
    /** Circuit breaker open → P2 alert (Req 4.5) */
    CIRCUIT_BREAKER_OPEN: {
      NAME: `${PROJECT_PREFIX}-circuit-breaker-open`,
      EVALUATION_PERIODS: 1,
      PERIOD_SECONDS: 60,
    },
    /** Reconciliation failure → P1 alert (Req 13.2) */
    RECONCILIATION_FAILURE: {
      NAME: `${PROJECT_PREFIX}-reconciliation-failure`,
      EVALUATION_PERIODS: 1,
      PERIOD_SECONDS: 300,
    },
    /** Auth failure spike → alert (Req 2.5) */
    AUTH_FAILURE_SPIKE: {
      NAME: `${PROJECT_PREFIX}-auth-failure-spike`,
      THRESHOLD: 5,
      PERIOD_SECONDS: 60,
    },
    /** Network public path detected → P1 alert (Req 12.6) */
    NETWORK_PUBLIC_PATH: {
      NAME: `${PROJECT_PREFIX}-network-public-path`,
      EVALUATION_PERIODS: 1,
      PERIOD_SECONDS: 300,
    },
    /** Assume breach > 4 hours → P0 escalation (Req 13.5) */
    ASSUME_BREACH_ESCALATION: {
      NAME: `${PROJECT_PREFIX}-assume-breach-escalation`,
      THRESHOLD_HOURS: 4,
    },
  },

  /** CloudWatch dashboard names */
  DASHBOARDS: {
    SYSTEM_HEALTH: `${PROJECT_PREFIX}-system-health`,
    SECURITY: `${PROJECT_PREFIX}-security`,
    PERFORMANCE: `${PROJECT_PREFIX}-performance`,
  },

  /** Log group retention in days */
  LOG_RETENTION_DAYS: 90,

  /** CloudWatch metric namespace */
  METRIC_NAMESPACE: `${PROJECT_PREFIX}/security`,
} as const;

// ---------------------------------------------------------------------------
// Application-Level Constants
// ---------------------------------------------------------------------------

export const APPLICATION = {
  /** Rate limiting (Req 3.1) */
  RATE_LIMIT: {
    /** Requests per minute per user */
    REQUESTS_PER_MINUTE: 30,
    /** Window size in seconds */
    WINDOW_SECONDS: 60,
    /** Sustained rate limit threshold for investigation alert (minutes) */
    SUSTAINED_LIMIT_ALERT_MINUTES: 10,
  },

  /** Session management (Req 2.2) */
  SESSION: {
    /** Idle timeout in minutes */
    IDLE_TIMEOUT_MINUTES: 45,
  },

  /** Circuit breaker (Req 4.1-4.6) */
  CIRCUIT_BREAKER: {
    /** Failure rate threshold to open circuit */
    FAILURE_RATE_THRESHOLD_PERCENT: 50,
    /** Minimum requests in window before evaluating */
    MIN_REQUESTS: 5,
    /** Rolling window size in seconds */
    WINDOW_SECONDS: 30,
    /** Time to wait before half-open probe (seconds) */
    RECOVERY_TIMEOUT_SECONDS: 60,
    /** Maximum response time from open circuit (milliseconds) */
    MAX_RESPONSE_TIME_MS: 200,
    /** Request timeout to AgentCore Runtime (seconds) */
    REQUEST_TIMEOUT_SECONDS: 5,
  },

  /** Agent orchestration bounds (Req 10.2, 10.3) */
  AGENT: {
    /** Maximum disambiguation rounds */
    MAX_DISAMBIGUATION_ROUNDS: 3,
    /** Maximum SQL self-correction retries */
    MAX_SELF_CORRECTION_RETRIES: 2,
  },

  /** Guardrails (Req 8.4, 8.5) */
  GUARDRAILS: {
    /** Timeout for guardrails scan (seconds) */
    SCAN_TIMEOUT_SECONDS: 5,
    /** Block threshold for session termination (Req 8.5) */
    SESSION_BLOCK_THRESHOLD: 3,
  },

  /** Deprovisioning SLA (Req 15.1, 15.2) */
  DEPROVISIONING: {
    /** Maximum time to complete revocation (minutes) */
    SLA_MINUTES: 5,
    /** Maximum retry attempts */
    MAX_RETRIES: 3,
    /** Retry interval (seconds) */
    RETRY_INTERVAL_SECONDS: 60,
  },

  /** Reconciliation (Req 13.1) */
  RECONCILIATION: {
    /** Maximum job duration (minutes) */
    MAX_DURATION_MINUTES: 60,
    /** Fail-close timeout for affected principals (minutes) */
    FAIL_CLOSE_TIMEOUT_MINUTES: 5,
  },

  /** Audit record limits (Req 11.1) */
  AUDIT: {
    /** Maximum original question length (characters) */
    MAX_QUESTION_LENGTH: 10_000,
    /** Write timeout (seconds) */
    WRITE_TIMEOUT_SECONDS: 5,
    /** Maximum retry attempts before alert */
    MAX_WRITE_RETRIES: 3,
    /** DSAR query SLA for 90-day span (seconds) */
    DSAR_QUERY_SLA_SECONDS: 60,
  },
} as const;

// ---------------------------------------------------------------------------
// CfnOutput Export Names (for cross-stack references)
// ---------------------------------------------------------------------------

export const EXPORTS = {
  VPC_ID: 'ChatbotVpcId',
  SG_ALB_ID: 'ChatbotSgAlbId',
  SG_FASTAPI_ID: 'ChatbotSgFastapiId',
  SG_VPCE_ID: 'ChatbotSgVpceId',
  USER_POOL_ID: 'ChatbotUserPoolId',
  USER_POOL_CLIENT_ID: 'ChatbotUserPoolClientId',
  DATALAKE_KEY_ARN: 'ChatbotDatalakeKeyArn',
  AUDIT_KEY_ARN: 'ChatbotAuditKeyArn',
  OPENSEARCH_KEY_ARN: 'ChatbotOpenSearchKeyArn',
  QUERY_RESULTS_KEY_ARN: 'ChatbotQueryResultsKeyArn',
  GATEWAY_KEY_ARN: 'ChatbotGatewayKeyArn',
  OBO_TOKEN_VAULT_ARN: 'ChatbotOboTokenVaultArn',
  DATALAKE_BUCKET_ARN: 'ChatbotDatalakeBucketArn',
  AUDIT_BUCKET_ARN: 'ChatbotAuditBucketArn',
  QUERY_RESULTS_BUCKET_ARN: 'ChatbotQueryResultsBucketArn',
  GLUE_DATABASE_NAME: 'ChatbotGlueDatabaseName',
  OPENSEARCH_COLLECTION_NAME: 'ChatbotOpenSearchCollectionName',
  OPENSEARCH_COLLECTION_ENDPOINT: 'ChatbotOpenSearchCollectionEndpoint',
  ATHENA_WORKGROUP_NAME: 'ChatbotAthenaWorkgroupName',
} as const;
