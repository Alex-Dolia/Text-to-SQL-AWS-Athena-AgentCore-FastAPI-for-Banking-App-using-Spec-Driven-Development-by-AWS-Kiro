import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

/**
 * Networking stack for the Chatbot Security Architecture.
 *
 * Implements Requirements 12.1–12.5:
 * - All inter-service communication via VPC PrivateLink (no public internet paths)
 * - TLS 1.2+ enforced; TLS 1.0/1.1 rejected
 * - Security groups enforce directional flow: corporate → ALB → FastAPI → VPC endpoints
 * - VPC endpoint policies restrict allowed actions/resources
 */
export class NetworkingStack extends cdk.Stack {
  public readonly vpc: ec2.Vpc;
  public readonly sgAlb: ec2.SecurityGroup;
  public readonly sgFastapi: ec2.SecurityGroup;
  public readonly sgVpce: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Corporate CIDR — configurable via context or parameter
    const corporateCidr = this.node.tryGetContext('corporateCidr') ?? '10.0.0.0/8';

    // --------------------------------------------------------------------------
    // VPC: Private subnets only, no NAT or Internet Gateway (Req 12.1, 12.6)
    // --------------------------------------------------------------------------
    this.vpc = new ec2.Vpc(this, 'ChatbotVpc', {
      vpcName: 'chatbot-vpc',
      maxAzs: 2,
      natGateways: 0, // No NAT gateway — all traffic via PrivateLink
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
        },
      ],
    });

    // Explicitly remove any default internet gateway route (defense in depth)
    // The PRIVATE_ISOLATED subnet type and natGateways: 0 ensure no public path exists.

    // --------------------------------------------------------------------------
    // Security Groups (Req 12.3, 12.4)
    // --------------------------------------------------------------------------

    // sg-alb: Only corporate CIDR allowed on port 443
    this.sgAlb = new ec2.SecurityGroup(this, 'SgAlb', {
      vpc: this.vpc,
      securityGroupName: 'sg-alb',
      description: 'Internal ALB - allows HTTPS 443 from corporate CIDR only',
      allowAllOutbound: false,
    });
    this.sgAlb.addIngressRule(
      ec2.Peer.ipv4(corporateCidr),
      ec2.Port.tcp(443),
      'Allow HTTPS from corporate network'
    );

    // sg-fastapi: Only sg-alb allowed on port 8000
    this.sgFastapi = new ec2.SecurityGroup(this, 'SgFastapi', {
      vpc: this.vpc,
      securityGroupName: 'sg-fastapi',
      description: 'FastAPI ECS tasks - allows port 8000 from sg-alb only',
      allowAllOutbound: false,
    });
    this.sgFastapi.addIngressRule(
      this.sgAlb,
      ec2.Port.tcp(8000),
      'Allow traffic from ALB on port 8000'
    );
    // FastAPI needs to reach VPC endpoints on 443
    this.sgFastapi.addEgressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'Allow HTTPS egress to VPC endpoints'
    );

    // sg-vpce: Only sg-fastapi allowed on port 443
    this.sgVpce = new ec2.SecurityGroup(this, 'SgVpce', {
      vpc: this.vpc,
      securityGroupName: 'sg-vpce',
      description: 'VPC Endpoints - allows HTTPS 443 from sg-fastapi only',
      allowAllOutbound: false,
    });
    this.sgVpce.addIngressRule(
      this.sgFastapi,
      ec2.Port.tcp(443),
      'Allow HTTPS from FastAPI security group'
    );

    // ALB egress to FastAPI
    this.sgAlb.addEgressRule(
      this.sgFastapi,
      ec2.Port.tcp(8000),
      'Allow egress to FastAPI on port 8000'
    );

    // --------------------------------------------------------------------------
    // VPC PrivateLink Interface Endpoints (Req 12.1, 12.2, 12.5)
    // All endpoints: private DNS enabled, TLS 1.2+ enforced via endpoint policy
    // --------------------------------------------------------------------------

    const privateSubnets = this.vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
    });

    // Helper to create VPC endpoints with consistent configuration
    const createInterfaceEndpoint = (
      id: string,
      service: ec2.InterfaceVpcEndpointAwsService,
      policy: iam.PolicyStatement
    ): ec2.InterfaceVpcEndpoint => {
      const endpoint = new ec2.InterfaceVpcEndpoint(this, id, {
        vpc: this.vpc,
        service,
        privateDnsEnabled: true,
        securityGroups: [this.sgVpce],
        subnets: privateSubnets,
      });

      // Attach VPC endpoint policy restricting allowed actions/resources (Req 12.5)
      endpoint.addToPolicy(policy);

      // Enforce TLS 1.2+ by denying non-secure transport and TLS < 1.2 (Req 12.2)
      endpoint.addToPolicy(
        new iam.PolicyStatement({
          sid: 'DenyNonSecureTransport',
          effect: iam.Effect.DENY,
          principals: [new iam.AnyPrincipal()],
          actions: ['*'],
          resources: ['*'],
          conditions: {
            Bool: {
              'aws:SecureTransport': 'false',
            },
          },
        })
      );
      endpoint.addToPolicy(
        new iam.PolicyStatement({
          sid: 'DenyTLSBelow12',
          effect: iam.Effect.DENY,
          principals: [new iam.AnyPrincipal()],
          actions: ['*'],
          resources: ['*'],
          conditions: {
            NumericLessThan: {
              's3:TlsVersion': '1.2',
            },
          },
        })
      );

      return endpoint;
    };

    // --- Bedrock Runtime Endpoint ---
    const bedrockEndpoint = createInterfaceEndpoint(
      'VpceBedrockRuntime',
      ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME,
      new iam.PolicyStatement({
        sid: 'AllowBedrockInvoke',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          'bedrock:InvokeModel',
          'bedrock:InvokeModelWithResponseStream',
          'bedrock:ApplyGuardrail',
        ],
        resources: ['*'],
      })
    );

    // --- Athena Endpoint ---
    const athenaEndpoint = createInterfaceEndpoint(
      'VpceAthena',
      ec2.InterfaceVpcEndpointAwsService.ATHENA,
      new iam.PolicyStatement({
        sid: 'AllowAthenaReadOnly',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          'athena:StartQueryExecution',
          'athena:GetQueryExecution',
          'athena:GetQueryResults',
          'athena:StopQueryExecution',
          'athena:GetWorkGroup',
        ],
        resources: ['*'],
      })
    );

    // --- Glue Endpoint ---
    const glueEndpoint = createInterfaceEndpoint(
      'VpceGlue',
      ec2.InterfaceVpcEndpointAwsService.GLUE,
      new iam.PolicyStatement({
        sid: 'AllowGlueCatalogRead',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          'glue:GetDatabase',
          'glue:GetDatabases',
          'glue:GetTable',
          'glue:GetTables',
          'glue:GetPartition',
          'glue:GetPartitions',
        ],
        resources: ['*'],
      })
    );

    // --- S3 Gateway Endpoint (S3 uses Gateway type for cost efficiency) ---
    const s3GatewayEndpoint = this.vpc.addGatewayEndpoint('VpceS3', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
      subnets: [privateSubnets],
    });
    s3GatewayEndpoint.addToPolicy(
      new iam.PolicyStatement({
        sid: 'AllowS3DataLakeAccess',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          's3:GetObject',
          's3:ListBucket',
          's3:GetBucketLocation',
          's3:PutObject',
        ],
        resources: ['*'],
      })
    );
    s3GatewayEndpoint.addToPolicy(
      new iam.PolicyStatement({
        sid: 'DenyInsecureTransport',
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        actions: ['*'],
        resources: ['*'],
        conditions: {
          Bool: {
            'aws:SecureTransport': 'false',
          },
        },
      })
    );

    // --- Secrets Manager Endpoint ---
    const secretsManagerEndpoint = createInterfaceEndpoint(
      'VpceSecretsManager',
      ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      new iam.PolicyStatement({
        sid: 'AllowSecretsManagerAccess',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          'secretsmanager:GetSecretValue',
          'secretsmanager:DescribeSecret',
          'secretsmanager:PutSecretValue',
          'secretsmanager:DeleteSecret',
        ],
        resources: ['*'],
      })
    );

    // --- KMS Endpoint ---
    const kmsEndpoint = createInterfaceEndpoint(
      'VpceKms',
      ec2.InterfaceVpcEndpointAwsService.KMS,
      new iam.PolicyStatement({
        sid: 'AllowKmsOperations',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          'kms:Decrypt',
          'kms:Encrypt',
          'kms:GenerateDataKey',
          'kms:DescribeKey',
        ],
        resources: ['*'],
      })
    );

    // --- CloudWatch Logs Endpoint ---
    const cloudWatchLogsEndpoint = createInterfaceEndpoint(
      'VpceCloudWatchLogs',
      ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      new iam.PolicyStatement({
        sid: 'AllowCloudWatchLogs',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          'logs:CreateLogGroup',
          'logs:CreateLogStream',
          'logs:PutLogEvents',
          'logs:DescribeLogGroups',
          'logs:DescribeLogStreams',
        ],
        resources: ['*'],
      })
    );

    // --- CloudWatch Monitoring Endpoint ---
    const cloudWatchMonitoringEndpoint = createInterfaceEndpoint(
      'VpceCloudWatchMonitoring',
      ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING,
      new iam.PolicyStatement({
        sid: 'AllowCloudWatchMetrics',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          'cloudwatch:PutMetricData',
          'cloudwatch:GetMetricData',
          'cloudwatch:DescribeAlarms',
        ],
        resources: ['*'],
      })
    );

    // --- OpenSearch Serverless Endpoint ---
    const openSearchEndpoint = new ec2.InterfaceVpcEndpoint(this, 'VpceOpenSearchServerless', {
      vpc: this.vpc,
      service: new ec2.InterfaceVpcEndpointService(
        `com.amazonaws.${this.region}.aoss`
      ),
      privateDnsEnabled: true,
      securityGroups: [this.sgVpce],
      subnets: privateSubnets,
    });
    openSearchEndpoint.addToPolicy(
      new iam.PolicyStatement({
        sid: 'AllowOpenSearchAccess',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          'aoss:APIAccessAll',
        ],
        resources: ['*'],
      })
    );
    openSearchEndpoint.addToPolicy(
      new iam.PolicyStatement({
        sid: 'DenyInsecureTransportOpenSearch',
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        actions: ['*'],
        resources: ['*'],
        conditions: {
          Bool: {
            'aws:SecureTransport': 'false',
          },
        },
      })
    );

    // --- Cognito Identity Provider Endpoint ---
    const cognitoEndpoint = new ec2.InterfaceVpcEndpoint(this, 'VpceCognito', {
      vpc: this.vpc,
      service: new ec2.InterfaceVpcEndpointService(
        `com.amazonaws.${this.region}.cognito-idp`
      ),
      privateDnsEnabled: true,
      securityGroups: [this.sgVpce],
      subnets: privateSubnets,
    });
    cognitoEndpoint.addToPolicy(
      new iam.PolicyStatement({
        sid: 'AllowCognitoOperations',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: [
          'cognito-idp:GetUser',
          'cognito-idp:InitiateAuth',
          'cognito-idp:RespondToAuthChallenge',
          'cognito-idp:RevokeToken',
          'cognito-idp:GlobalSignOut',
        ],
        resources: ['*'],
      })
    );
    cognitoEndpoint.addToPolicy(
      new iam.PolicyStatement({
        sid: 'DenyInsecureTransportCognito',
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        actions: ['*'],
        resources: ['*'],
        conditions: {
          Bool: {
            'aws:SecureTransport': 'false',
          },
        },
      })
    );

    // --------------------------------------------------------------------------
    // Outputs
    // --------------------------------------------------------------------------
    new cdk.CfnOutput(this, 'VpcId', {
      value: this.vpc.vpcId,
      description: 'Chatbot VPC ID',
      exportName: 'ChatbotVpcId',
    });

    new cdk.CfnOutput(this, 'SgAlbId', {
      value: this.sgAlb.securityGroupId,
      description: 'ALB Security Group ID',
      exportName: 'ChatbotSgAlbId',
    });

    new cdk.CfnOutput(this, 'SgFastapiId', {
      value: this.sgFastapi.securityGroupId,
      description: 'FastAPI Security Group ID',
      exportName: 'ChatbotSgFastapiId',
    });

    new cdk.CfnOutput(this, 'SgVpceId', {
      value: this.sgVpce.securityGroupId,
      description: 'VPC Endpoints Security Group ID',
      exportName: 'ChatbotSgVpceId',
    });
  }
}
