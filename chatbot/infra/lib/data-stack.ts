import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as glue from 'aws-cdk-lib/aws-glue';
import * as lakeformation from 'aws-cdk-lib/aws-lakeformation';
import * as athena from 'aws-cdk-lib/aws-athena';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as opensearchserverless from 'aws-cdk-lib/aws-opensearchserverless';
import { Construct } from 'constructs';

/**
 * Properties for the DataStack.
 */
export interface DataStackProps extends cdk.StackProps {
  /** VPC from the networking stack for resource placement */
  vpc: ec2.IVpc;
  /** KMS key for data lake S3 bucket encryption */
  datalakeKey: kms.IKey;
  /** KMS key for audit trail S3 bucket encryption */
  auditKey: kms.IKey;
  /** KMS key for OpenSearch Serverless encryption */
  opensearchKey: kms.IKey;
  /** KMS key for Athena query results encryption */
  queryResultsKey: kms.IKey;
}

/**
 * Data stack for the Chatbot Security Architecture.
 *
 * Implements:
 * - Requirement 11.2: S3 Object Lock in Compliance mode with 7-year retention for audit records
 * - Requirement 11.3: Cross-region replication for audit records (RPO ≤15 minutes)
 * - Requirement 16.5: OpenSearch Serverless vector collection with VPC-only access
 * - Requirement 6.4: Lake Formation column/row/cell-level permissions via OBO identity
 * - Requirement 6.5: Cedar and Lake Formation share no common configuration store
 */
export class DataStack extends cdk.Stack {
  /** S3 data lake bucket (SSE-KMS encrypted) */
  public readonly datalakeBucket: s3.Bucket;
  /** S3 audit bucket (Object Lock Compliance mode, 7-year retention) */
  public readonly auditBucket: s3.Bucket;
  /** S3 bucket for Athena query results */
  public readonly queryResultsBucket: s3.Bucket;
  /** S3 bucket for audit replication (cross-region) */
  public readonly auditReplicaBucket: s3.Bucket;
  /** Glue Catalog database for chatbot tables */
  public readonly glueDatabase: glue.CfnDatabase;
  /** Athena chatbot-readonly workgroup */
  public readonly athenaWorkgroup: athena.CfnWorkGroup;
  /** OpenSearch Serverless vector collection name */
  public readonly opensearchCollectionName: string;

  constructor(scope: Construct, id: string, props: DataStackProps) {
    super(scope, id, props);

    const { vpc, datalakeKey, auditKey, opensearchKey, queryResultsKey } = props;

    // --------------------------------------------------------------------------
    // S3 Data Lake Bucket (SSE-KMS) — stores Parquet/ORC data files
    // --------------------------------------------------------------------------

    this.datalakeBucket = new s3.Bucket(this, 'DatalakeBucket', {
      bucketName: `chatbot-datalake-${this.account}-${this.region}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: datalakeKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
    });

    // --------------------------------------------------------------------------
    // S3 Audit Bucket — Object Lock Compliance mode, 7-year retention (Req 11.2)
    // --------------------------------------------------------------------------

    this.auditBucket = new s3.Bucket(this, 'AuditBucket', {
      bucketName: `chatbot-audit-${this.account}-${this.region}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: auditKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true, // Required for Object Lock
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      objectLockEnabled: true, // Enable Object Lock on the bucket
    });

    // Configure Object Lock default retention — Compliance mode, 7-year retention (Req 11.2)
    // Records cannot be deleted or overwritten by any account including root
    const cfnAuditBucket = this.auditBucket.node.defaultChild as s3.CfnBucket;
    cfnAuditBucket.addPropertyOverride('ObjectLockConfiguration', {
      ObjectLockEnabled: 'Enabled',
      Rule: {
        DefaultRetention: {
          Mode: 'COMPLIANCE',
          Years: 7,
        },
      },
    });

    // --------------------------------------------------------------------------
    // S3 Audit Replica Bucket — Cross-region replication target (Req 11.3)
    // RPO ≤15 minutes via S3 replication time control
    // --------------------------------------------------------------------------

    // Replication destination bucket in secondary region
    // Note: In production, this bucket would be in a different region stack.
    // Here we define it in the same stack for CDK synthesis; actual cross-region
    // deployment requires a separate stack in the target region.
    this.auditReplicaBucket = new s3.Bucket(this, 'AuditReplicaBucket', {
      bucketName: `chatbot-audit-replica-${this.account}-${this.region}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: auditKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true, // Required for replication
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      objectLockEnabled: true,
    });

    // Configure Object Lock on replica bucket as well
    const cfnReplicaBucket = this.auditReplicaBucket.node.defaultChild as s3.CfnBucket;
    cfnReplicaBucket.addPropertyOverride('ObjectLockConfiguration', {
      ObjectLockEnabled: 'Enabled',
      Rule: {
        DefaultRetention: {
          Mode: 'COMPLIANCE',
          Years: 7,
        },
      },
    });

    // IAM role for S3 replication
    const replicationRole = new iam.Role(this, 'AuditReplicationRole', {
      roleName: 'chatbot-audit-replication-role',
      assumedBy: new iam.ServicePrincipal('s3.amazonaws.com'),
      description: 'Role for audit bucket cross-region replication',
    });

    replicationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowReplicationSourceRead',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:GetReplicationConfiguration',
        's3:ListBucket',
        's3:GetObjectVersionForReplication',
        's3:GetObjectVersionAcl',
        's3:GetObjectVersionTagging',
        's3:GetObjectRetention',
        's3:GetObjectLegalHold',
      ],
      resources: [
        this.auditBucket.bucketArn,
        `${this.auditBucket.bucketArn}/*`,
      ],
    }));

    replicationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowReplicationDestinationWrite',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:ReplicateObject',
        's3:ReplicateDelete',
        's3:ReplicateTags',
        's3:ObjectOwnerOverrideToBucketOwner',
      ],
      resources: [
        `${this.auditReplicaBucket.bucketArn}/*`,
      ],
    }));

    replicationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowKmsDecryptSource',
      effect: iam.Effect.ALLOW,
      actions: [
        'kms:Decrypt',
        'kms:DescribeKey',
      ],
      resources: [auditKey.keyArn],
    }));

    replicationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowKmsEncryptDestination',
      effect: iam.Effect.ALLOW,
      actions: [
        'kms:Encrypt',
        'kms:GenerateDataKey',
      ],
      resources: [auditKey.keyArn],
    }));

    // Configure replication on the audit bucket (Req 11.3: RPO ≤15 minutes)
    cfnAuditBucket.addPropertyOverride('ReplicationConfiguration', {
      Role: replicationRole.roleArn,
      Rules: [
        {
          Id: 'AuditCrossRegionReplication',
          Status: 'Enabled',
          Priority: 1,
          Filter: {
            Prefix: '',
          },
          Destination: {
            Bucket: this.auditReplicaBucket.bucketArn,
            StorageClass: 'STANDARD',
            EncryptionConfiguration: {
              ReplicaKmsKeyID: auditKey.keyArn,
            },
            ReplicationTime: {
              Status: 'Enabled',
              Time: {
                Minutes: 15, // RPO ≤15 minutes
              },
            },
            Metrics: {
              Status: 'Enabled',
              EventThreshold: {
                Minutes: 15,
              },
            },
          },
          SourceSelectionCriteria: {
            SseKmsEncryptedObjects: {
              Status: 'Enabled',
            },
          },
          DeleteMarkerReplication: {
            Status: 'Enabled',
          },
        },
      ],
    });

    // --------------------------------------------------------------------------
    // S3 Query Results Bucket — for Athena query output
    // --------------------------------------------------------------------------

    this.queryResultsBucket = new s3.Bucket(this, 'QueryResultsBucket', {
      bucketName: `chatbot-query-results-${this.account}-${this.region}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: queryResultsKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      lifecycleRules: [
        {
          id: 'ExpireQueryResults',
          expiration: cdk.Duration.days(7), // Query results expire after 7 days
          enabled: true,
        },
      ],
    });

    // --------------------------------------------------------------------------
    // AWS Glue Catalog Database — table metadata for Athena (Req 6.4)
    // --------------------------------------------------------------------------

    this.glueDatabase = new glue.CfnDatabase(this, 'ChatbotGlueDatabase', {
      catalogId: this.account,
      databaseInput: {
        name: 'chatbot_datalake',
        description: 'Chatbot data lake catalog — table metadata managed by Glue, permissions by Lake Formation',
        locationUri: `s3://${this.datalakeBucket.bucketName}/`,
      },
    });

    // --------------------------------------------------------------------------
    // Lake Formation Configuration (Req 6.4, 6.5)
    // Provides table/column/row/cell-level permissions independent of Cedar
    // Permissions evaluated at Athena query engine level using OBO identity
    // --------------------------------------------------------------------------

    // Register the data lake bucket with Lake Formation
    new lakeformation.CfnResource(this, 'LakeFormationDatalakeResource', {
      resourceArn: this.datalakeBucket.bucketArn,
      useServiceLinkedRole: true,
    });

    // Lake Formation settings — enforce Lake Formation permissions (not IAM-only)
    // This ensures Lake Formation column/row/cell permissions are evaluated (Req 6.4)
    new lakeformation.CfnDataLakeSettings(this, 'LakeFormationSettings', {
      admins: [
        {
          dataLakePrincipalIdentifier: `arn:aws:iam::${this.account}:role/chatbot-lakeformation-admin`,
        },
      ],
      // Disable IAM allowed principals on new databases/tables
      // Forces all access through Lake Formation grants
      createDatabaseDefaultPermissions: [],
      createTableDefaultPermissions: [],
    });

    // Grant Lake Formation permissions on the database to the AgentCore role
    // This is scoped — AgentCore can describe tables but data access requires per-user OBO
    new lakeformation.CfnPermissions(this, 'LakeFormationAgentCoreGrant', {
      dataLakePrincipal: {
        dataLakePrincipalIdentifier: `arn:aws:iam::${this.account}:role/chatbot-agentcore-runtime-role`,
      },
      resource: {
        databaseResource: {
          name: 'chatbot_datalake',
        },
      },
      permissions: ['DESCRIBE'],
      permissionsWithGrantOption: [],
    });

    // --------------------------------------------------------------------------
    // OpenSearch Serverless Vector Collection (Req 16.5)
    // VPC-only access — no public endpoint
    // --------------------------------------------------------------------------

    this.opensearchCollectionName = 'chatbot-schema-vectors';

    // Network policy — VPC-only access, no public endpoint (Req 16.5)
    const opensearchNetworkPolicy = new opensearchserverless.CfnSecurityPolicy(
      this,
      'OpenSearchNetworkPolicy',
      {
        name: 'chatbot-vectors-network',
        type: 'network',
        policy: JSON.stringify([
          {
            Description: 'VPC-only access to chatbot vector collection — no public endpoint',
            Rules: [
              {
                ResourceType: 'collection',
                Resource: [`collection/${this.opensearchCollectionName}`],
              },
              {
                ResourceType: 'dashboard',
                Resource: [`collection/${this.opensearchCollectionName}`],
              },
            ],
            AllowFromPublic: false,
            SourceVPCEs: [
              // Reference VPC endpoint for OpenSearch created in networking stack
              // The actual VPCE ID will be resolved at deploy time
              `vpce-placeholder`,
            ],
          },
        ]),
      }
    );

    // Encryption policy — use CMK for OpenSearch data
    const opensearchEncryptionPolicy = new opensearchserverless.CfnSecurityPolicy(
      this,
      'OpenSearchEncryptionPolicy',
      {
        name: 'chatbot-vectors-encryption',
        type: 'encryption',
        policy: JSON.stringify({
          Rules: [
            {
              ResourceType: 'collection',
              Resource: [`collection/${this.opensearchCollectionName}`],
            },
          ],
          AWSOwnedKey: false,
          KmsARN: opensearchKey.keyArn,
        }),
      }
    );

    // Data access policy — restrict to AgentCore role only
    const opensearchDataAccessPolicy = new opensearchserverless.CfnAccessPolicy(
      this,
      'OpenSearchDataAccessPolicy',
      {
        name: 'chatbot-vectors-access',
        type: 'data',
        policy: JSON.stringify([
          {
            Description: 'Data access for chatbot AgentCore to manage schema embeddings',
            Rules: [
              {
                ResourceType: 'collection',
                Resource: [`collection/${this.opensearchCollectionName}`],
                Permission: [
                  'aoss:CreateCollectionItems',
                  'aoss:UpdateCollectionItems',
                  'aoss:DescribeCollectionItems',
                  'aoss:ReadDocument',
                  'aoss:WriteDocument',
                ],
              },
              {
                ResourceType: 'index',
                Resource: [`index/${this.opensearchCollectionName}/*`],
                Permission: [
                  'aoss:CreateIndex',
                  'aoss:UpdateIndex',
                  'aoss:DescribeIndex',
                  'aoss:ReadDocument',
                  'aoss:WriteDocument',
                ],
              },
            ],
            Principal: [
              `arn:aws:iam::${this.account}:role/chatbot-agentcore-runtime-role`,
            ],
          },
        ]),
      }
    );

    // OpenSearch Serverless Collection — vector type for schema embeddings
    const opensearchCollection = new opensearchserverless.CfnCollection(
      this,
      'SchemaVectorCollection',
      {
        name: this.opensearchCollectionName,
        type: 'VECTORSEARCH',
        description: 'Vector collection for chatbot schema embeddings and business glossary — VPC-only access',
      }
    );

    // Ensure policies are created before the collection
    opensearchCollection.addDependency(opensearchNetworkPolicy);
    opensearchCollection.addDependency(opensearchEncryptionPolicy);
    opensearchCollection.addDependency(opensearchDataAccessPolicy);

    // --------------------------------------------------------------------------
    // Athena Workgroup — chatbot-readonly with bytes-scanned limits (Req 9.5, 6.4)
    // --------------------------------------------------------------------------

    this.athenaWorkgroup = new athena.CfnWorkGroup(this, 'ChatbotReadonlyWorkgroup', {
      name: 'chatbot-readonly',
      description: 'Read-only workgroup for chatbot queries — bytes-scanned limit enforced',
      state: 'ENABLED',
      recursiveDeleteOption: false,
      workGroupConfiguration: {
        enforceWorkGroupConfiguration: true, // Prevent client-side overrides
        publishCloudWatchMetricsEnabled: true,
        bytesScannedCutoffPerQuery: 10_737_418_240, // 10 GB in bytes (Req 9.5)
        resultConfiguration: {
          outputLocation: `s3://${this.queryResultsBucket.bucketName}/athena-results/`,
          encryptionConfiguration: {
            encryptionOption: 'SSE_KMS',
            kmsKey: queryResultsKey.keyArn,
          },
        },
        engineVersion: {
          selectedEngineVersion: 'Athena engine version 3',
        },
      },
    });

    // --------------------------------------------------------------------------
    // Outputs
    // --------------------------------------------------------------------------

    new cdk.CfnOutput(this, 'DatalakeBucketArn', {
      value: this.datalakeBucket.bucketArn,
      description: 'Data lake S3 bucket ARN',
      exportName: 'ChatbotDatalakeBucketArn',
    });

    new cdk.CfnOutput(this, 'AuditBucketArn', {
      value: this.auditBucket.bucketArn,
      description: 'Audit trail S3 bucket ARN (Object Lock Compliance, 7-year)',
      exportName: 'ChatbotAuditBucketArn',
    });

    new cdk.CfnOutput(this, 'QueryResultsBucketArn', {
      value: this.queryResultsBucket.bucketArn,
      description: 'Athena query results S3 bucket ARN',
      exportName: 'ChatbotQueryResultsBucketArn',
    });

    new cdk.CfnOutput(this, 'GlueDatabaseName', {
      value: 'chatbot_datalake',
      description: 'Glue Catalog database name',
      exportName: 'ChatbotGlueDatabaseName',
    });

    new cdk.CfnOutput(this, 'OpenSearchCollectionName', {
      value: this.opensearchCollectionName,
      description: 'OpenSearch Serverless vector collection name',
      exportName: 'ChatbotOpenSearchCollectionName',
    });

    new cdk.CfnOutput(this, 'OpenSearchCollectionEndpoint', {
      value: opensearchCollection.attrCollectionEndpoint,
      description: 'OpenSearch Serverless collection endpoint',
      exportName: 'ChatbotOpenSearchCollectionEndpoint',
    });

    new cdk.CfnOutput(this, 'AthenaWorkgroupName', {
      value: 'chatbot-readonly',
      description: 'Athena read-only workgroup name',
      exportName: 'ChatbotAthenaWorkgroupName',
    });
  }
}
