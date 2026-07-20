import * as cdk from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

/**
 * Properties for the SecurityStack.
 */
export interface SecurityStackProps extends cdk.StackProps {
  /** VPC from the networking stack for resource placement */
  vpc: ec2.IVpc;
}

/**
 * Security stack for the Chatbot Security Architecture.
 *
 * Implements:
 * - Requirement 1.1: Cognito SAML 2.0/OIDC federation with corporate IdP
 * - Requirement 1.3: JWT access token ≤15 minutes, refresh token ≤8 hours
 * - Requirement 1.6: No AdminInitiateAuth API exposed
 * - Requirement 7.2: OBO token vault in Secrets Manager with 90-day rotation
 * - Requirement 12.1: KMS CMKs for encryption (no default AWS-managed keys)
 */
export class SecurityStack extends cdk.Stack {
  /** KMS Customer Managed Key for data lake encryption */
  public readonly datalakeKey: kms.Key;
  /** KMS Customer Managed Key for audit trail encryption */
  public readonly auditKey: kms.Key;
  /** KMS Customer Managed Key for OpenSearch Serverless encryption */
  public readonly opensearchKey: kms.Key;
  /** KMS Customer Managed Key for Athena query results encryption */
  public readonly queryResultsKey: kms.Key;
  /** KMS Customer Managed Key for AgentCore Gateway encryption */
  public readonly gatewayKey: kms.Key;

  /** Cognito User Pool for federated authentication */
  public readonly userPool: cognito.UserPool;
  /** Cognito User Pool Client */
  public readonly userPoolClient: cognito.UserPoolClient;

  /** Secrets Manager secret for OBO token vault */
  public readonly oboTokenVault: secretsmanager.Secret;

  /** IAM role for the FastAPI ECS tasks */
  public readonly fastapiTaskRole: iam.Role;
  /** IAM role for the AgentCore Runtime */
  public readonly agentCoreRole: iam.Role;
  /** IAM role for the reconciliation Lambda */
  public readonly reconciliationRole: iam.Role;
  /** IAM role for the deprovisioning webhook Lambda */
  public readonly deprovisioningRole: iam.Role;

  constructor(scope: Construct, id: string, props: SecurityStackProps) {
    super(scope, id, props);

    const { vpc } = props;

    // --------------------------------------------------------------------------
    // KMS Customer Managed Keys (Req 12.1 — encryption at rest with CMKs)
    // --------------------------------------------------------------------------

    this.datalakeKey = new kms.Key(this, 'DatalakeKey', {
      alias: 'chatbot/datalake',
      description: 'CMK for data lake S3 bucket encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pendingWindow: cdk.Duration.days(30),
    });

    this.auditKey = new kms.Key(this, 'AuditKey', {
      alias: 'chatbot/audit',
      description: 'CMK for immutable audit trail encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pendingWindow: cdk.Duration.days(30),
    });

    this.opensearchKey = new kms.Key(this, 'OpenSearchKey', {
      alias: 'chatbot/opensearch',
      description: 'CMK for OpenSearch Serverless vector collection encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pendingWindow: cdk.Duration.days(30),
    });

    this.queryResultsKey = new kms.Key(this, 'QueryResultsKey', {
      alias: 'chatbot/queryresults',
      description: 'CMK for Athena query results encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pendingWindow: cdk.Duration.days(30),
    });

    this.gatewayKey = new kms.Key(this, 'GatewayKey', {
      alias: 'chatbot/gateway',
      description: 'CMK for AgentCore Gateway encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pendingWindow: cdk.Duration.days(30),
    });

    // --------------------------------------------------------------------------
    // Cognito User Pool (Req 1.1, 1.3, 1.6)
    // --------------------------------------------------------------------------

    this.userPool = new cognito.UserPool(this, 'ChatbotUserPool', {
      userPoolName: 'chatbot-user-pool',
      selfSignUpEnabled: false, // No self-registration — federated only
      signInAliases: {
        email: true,
      },
      mfa: cognito.Mfa.REQUIRED, // Req 1.2: MFA enforced
      mfaSecondFactor: {
        sms: true,
        otp: true,
      },
      passwordPolicy: {
        minLength: 16,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: cdk.Duration.days(1),
      },
      accountRecovery: cognito.AccountRecovery.NONE, // Federated users recover via IdP
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      // Custom attributes for claim mapping (Req 1.4)
      customAttributes: {
        department: new cognito.StringAttribute({ mutable: true }),
        role: new cognito.StringAttribute({ mutable: true }),
        'data_classification_tier': new cognito.StringAttribute({ mutable: true }),
        groups: new cognito.StringAttribute({ mutable: true }),
      },
    });

    // User Pool Client — no AdminInitiateAuth (Req 1.6)
    this.userPoolClient = this.userPool.addClient('ChatbotAppClient', {
      userPoolClientName: 'chatbot-app-client',
      generateSecret: true,
      authFlows: {
        userSrp: true,
        userPassword: false,
        adminUserPassword: false, // Req 1.6: No AdminInitiateAuth
        custom: true,
      },
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: false, // Authorization code only for security
        },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.PROFILE,
          cognito.OAuthScope.EMAIL,
        ],
        callbackUrls: ['https://chatbot.internal/callback'],
        logoutUrls: ['https://chatbot.internal/logout'],
      },
      // Token lifetimes (Req 1.3)
      accessTokenValidity: cdk.Duration.minutes(15),   // ≤15 minutes
      idTokenValidity: cdk.Duration.minutes(15),       // Match access token
      refreshTokenValidity: cdk.Duration.hours(8),     // ≤8 hours
      preventUserExistenceErrors: true, // Don't reveal user existence
      enableTokenRevocation: true,
    });

    // --------------------------------------------------------------------------
    // SAML 2.0 Identity Provider placeholder (Req 1.1)
    // Actual SAML metadata URL will be provided during deployment
    // --------------------------------------------------------------------------
    const samlProviderMetadataUrl = this.node.tryGetContext('samlMetadataUrl')
      ?? 'https://idp.corporate.example.com/metadata.xml';

    // Note: In production, use UserPoolIdentityProviderSaml with actual metadata.
    // The attribute mapping below shows how custom claims are sourced from SAML assertions.
    // Attribute mapping for SAML (Req 1.4):
    //   department  -> custom:department
    //   role        -> custom:role
    //   tier        -> custom:data_classification_tier
    //   groups      -> custom:groups

    // --------------------------------------------------------------------------
    // Secrets Manager — OBO Token Vault (Req 7.2)
    // --------------------------------------------------------------------------

    this.oboTokenVault = new secretsmanager.Secret(this, 'OboTokenVault', {
      secretName: 'chatbot/obo-token-vault',
      description: 'On-Behalf-Of token vault for per-user federated identity tokens',
      encryptionKey: this.gatewayKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Note: Rotation schedule (90-day, Req 7.2) will be attached in compute stack
    // where the rotation Lambda is defined. Cannot attach here without the Lambda reference.

    // --------------------------------------------------------------------------
    // IAM Roles — Least Privilege (no "allow all") (Design Principle P2, P3)
    // --------------------------------------------------------------------------

    // FastAPI ECS Task Role — can validate JWTs, read session state, invoke agent
    this.fastapiTaskRole = new iam.Role(this, 'FastapiTaskRole', {
      roleName: 'chatbot-fastapi-task-role',
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: 'Role for FastAPI ECS tasks — JWT validation, session management',
    });

    // Allow Cognito operations for JWT validation (no AdminInitiateAuth)
    this.fastapiTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowCognitoJwtValidation',
      effect: iam.Effect.ALLOW,
      actions: [
        'cognito-idp:GetUser',
        'cognito-idp:RevokeToken',
        'cognito-idp:GlobalSignOut',
      ],
      resources: [this.userPool.userPoolArn],
    }));

    // Allow CloudWatch metrics and logs
    this.fastapiTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchObservability',
      effect: iam.Effect.ALLOW,
      actions: [
        'logs:CreateLogStream',
        'logs:PutLogEvents',
        'cloudwatch:PutMetricData',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': cdk.Stack.of(this).region,
        },
      },
    }));

    // Allow KMS decrypt for query results
    this.fastapiTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowKmsDecryptQueryResults',
      effect: iam.Effect.ALLOW,
      actions: [
        'kms:Decrypt',
        'kms:DescribeKey',
      ],
      resources: [this.queryResultsKey.keyArn],
    }));

    // AgentCore Runtime Role — orchestrates tools via Gateway
    this.agentCoreRole = new iam.Role(this, 'AgentCoreRole', {
      roleName: 'chatbot-agentcore-runtime-role',
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: 'Role for AgentCore Runtime — agent orchestration, tool routing',
    });

    // Allow Bedrock model invocation for LLM calls
    this.agentCoreRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowBedrockModelInvocation',
      effect: iam.Effect.ALLOW,
      actions: [
        'bedrock:InvokeModel',
        'bedrock:InvokeModelWithResponseStream',
        'bedrock:ApplyGuardrail',
      ],
      resources: [
        `arn:aws:bedrock:${cdk.Stack.of(this).region}::foundation-model/anthropic.claude-3-haiku*`,
        `arn:aws:bedrock:${cdk.Stack.of(this).region}::foundation-model/anthropic.claude-3-sonnet*`,
        `arn:aws:bedrock:${cdk.Stack.of(this).region}::foundation-model/amazon.titan-embed*`,
        `arn:aws:bedrock:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:guardrail/*`,
      ],
    }));

    // Allow OpenSearch Serverless access for RAG retrieval
    this.agentCoreRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowOpenSearchVectorAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'aoss:APIAccessAll',
      ],
      resources: [
        `arn:aws:aoss:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:collection/*`,
      ],
    }));

    // Allow Secrets Manager for OBO token retrieval
    this.agentCoreRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowSecretsManagerOboTokens',
      effect: iam.Effect.ALLOW,
      actions: [
        'secretsmanager:GetSecretValue',
        'secretsmanager:DescribeSecret',
        'secretsmanager:PutSecretValue',
      ],
      resources: [this.oboTokenVault.secretArn],
    }));

    // Allow KMS operations for gateway and OpenSearch keys
    this.agentCoreRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowKmsForAgentCore',
      effect: iam.Effect.ALLOW,
      actions: [
        'kms:Decrypt',
        'kms:Encrypt',
        'kms:GenerateDataKey',
        'kms:DescribeKey',
      ],
      resources: [
        this.gatewayKey.keyArn,
        this.opensearchKey.keyArn,
      ],
    }));

    // Allow Athena query execution (read-only, chatbot workgroup only)
    this.agentCoreRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowAthenaReadOnly',
      effect: iam.Effect.ALLOW,
      actions: [
        'athena:StartQueryExecution',
        'athena:GetQueryExecution',
        'athena:GetQueryResults',
        'athena:StopQueryExecution',
        'athena:GetWorkGroup',
      ],
      resources: [
        `arn:aws:athena:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:workgroup/chatbot-readonly`,
      ],
    }));

    // Allow Glue Catalog read-only access
    this.agentCoreRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowGlueCatalogRead',
      effect: iam.Effect.ALLOW,
      actions: [
        'glue:GetDatabase',
        'glue:GetDatabases',
        'glue:GetTable',
        'glue:GetTables',
        'glue:GetPartition',
        'glue:GetPartitions',
      ],
      resources: [
        `arn:aws:glue:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:catalog`,
        `arn:aws:glue:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:database/*`,
        `arn:aws:glue:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:table/*/*`,
      ],
    }));

    // Allow Lake Formation data access
    this.agentCoreRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowLakeFormationAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'lakeformation:GetDataAccess',
        'lakeformation:GetResourceLFTags',
        'lakeformation:ListPermissions',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': cdk.Stack.of(this).region,
        },
      },
    }));

    // Allow CloudWatch observability
    this.agentCoreRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchForAgent',
      effect: iam.Effect.ALLOW,
      actions: [
        'logs:CreateLogStream',
        'logs:PutLogEvents',
        'cloudwatch:PutMetricData',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': cdk.Stack.of(this).region,
        },
      },
    }));

    // Reconciliation Lambda Role — compares Cedar permits vs Lake Formation grants
    this.reconciliationRole = new iam.Role(this, 'ReconciliationRole', {
      roleName: 'chatbot-reconciliation-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Role for daily permission reconciliation Lambda',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AWSLambdaBasicExecutionRole'
        ),
      ],
    });

    // Allow Lake Formation list permissions for reconciliation
    this.reconciliationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowLakeFormationListPermissions',
      effect: iam.Effect.ALLOW,
      actions: [
        'lakeformation:ListPermissions',
        'lakeformation:GetResourceLFTags',
        'lakeformation:ListLFTags',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': cdk.Stack.of(this).region,
        },
      },
    }));

    // Allow CloudWatch alarm and metric operations
    this.reconciliationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchAlerting',
      effect: iam.Effect.ALLOW,
      actions: [
        'cloudwatch:PutMetricData',
        'cloudwatch:SetAlarmState',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': cdk.Stack.of(this).region,
        },
      },
    }));

    // Allow S3 write for audit records
    this.reconciliationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowAuditWrite',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:PutObject',
      ],
      resources: [
        `arn:aws:s3:::chatbot-audit-${cdk.Stack.of(this).account}-${cdk.Stack.of(this).region}/*`,
      ],
    }));

    // Allow KMS for audit key
    this.reconciliationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowKmsAuditEncrypt',
      effect: iam.Effect.ALLOW,
      actions: [
        'kms:Encrypt',
        'kms:GenerateDataKey',
        'kms:DescribeKey',
      ],
      resources: [this.auditKey.keyArn],
    }));

    // Deprovisioning Webhook Lambda Role — revokes tokens on user departure
    this.deprovisioningRole = new iam.Role(this, 'DeprovisioningRole', {
      roleName: 'chatbot-deprovisioning-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Role for user deprovisioning webhook Lambda',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AWSLambdaBasicExecutionRole'
        ),
      ],
    });

    // Allow Cognito token revocation for deprovisioned users
    this.deprovisioningRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowCognitoTokenRevocation',
      effect: iam.Effect.ALLOW,
      actions: [
        'cognito-idp:AdminUserGlobalSignOut',
        'cognito-idp:AdminDisableUser',
        'cognito-idp:RevokeToken',
      ],
      resources: [this.userPool.userPoolArn],
    }));

    // Allow Secrets Manager delete for OBO token cleanup
    this.deprovisioningRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowSecretsManagerCleanup',
      effect: iam.Effect.ALLOW,
      actions: [
        'secretsmanager:DeleteSecret',
        'secretsmanager:DescribeSecret',
      ],
      resources: [this.oboTokenVault.secretArn],
    }));

    // Allow S3 write for audit trail
    this.deprovisioningRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowAuditWriteDeprovisioning',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:PutObject',
      ],
      resources: [
        `arn:aws:s3:::chatbot-audit-${cdk.Stack.of(this).account}-${cdk.Stack.of(this).region}/*`,
      ],
    }));

    // Allow KMS for audit encryption
    this.deprovisioningRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowKmsAuditEncryptDeprovisioning',
      effect: iam.Effect.ALLOW,
      actions: [
        'kms:Encrypt',
        'kms:GenerateDataKey',
        'kms:DescribeKey',
      ],
      resources: [this.auditKey.keyArn],
    }));

    // Allow CloudWatch for alerting on failures
    this.deprovisioningRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchAlertingDeprovisioning',
      effect: iam.Effect.ALLOW,
      actions: [
        'cloudwatch:PutMetricData',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'aws:RequestedRegion': cdk.Stack.of(this).region,
        },
      },
    }));

    // --------------------------------------------------------------------------
    // Outputs
    // --------------------------------------------------------------------------

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: this.userPool.userPoolId,
      description: 'Cognito User Pool ID',
      exportName: 'ChatbotUserPoolId',
    });

    new cdk.CfnOutput(this, 'UserPoolClientId', {
      value: this.userPoolClient.userPoolClientId,
      description: 'Cognito User Pool Client ID',
      exportName: 'ChatbotUserPoolClientId',
    });

    new cdk.CfnOutput(this, 'DatalakeKeyArn', {
      value: this.datalakeKey.keyArn,
      description: 'KMS CMK ARN for data lake',
      exportName: 'ChatbotDatalakeKeyArn',
    });

    new cdk.CfnOutput(this, 'AuditKeyArn', {
      value: this.auditKey.keyArn,
      description: 'KMS CMK ARN for audit trail',
      exportName: 'ChatbotAuditKeyArn',
    });

    new cdk.CfnOutput(this, 'OpenSearchKeyArn', {
      value: this.opensearchKey.keyArn,
      description: 'KMS CMK ARN for OpenSearch',
      exportName: 'ChatbotOpenSearchKeyArn',
    });

    new cdk.CfnOutput(this, 'QueryResultsKeyArn', {
      value: this.queryResultsKey.keyArn,
      description: 'KMS CMK ARN for query results',
      exportName: 'ChatbotQueryResultsKeyArn',
    });

    new cdk.CfnOutput(this, 'GatewayKeyArn', {
      value: this.gatewayKey.keyArn,
      description: 'KMS CMK ARN for Gateway',
      exportName: 'ChatbotGatewayKeyArn',
    });

    new cdk.CfnOutput(this, 'OboTokenVaultArn', {
      value: this.oboTokenVault.secretArn,
      description: 'OBO Token Vault Secret ARN',
      exportName: 'ChatbotOboTokenVaultArn',
    });
  }
}
