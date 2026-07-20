import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as events_targets from 'aws-cdk-lib/aws-events-targets';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import { Construct } from 'constructs';

/**
 * Properties for the ComputeStack.
 */
export interface ComputeStackProps extends cdk.StackProps {
  /** VPC from the networking stack */
  vpc: ec2.IVpc;
  /** ALB security group from networking stack */
  sgAlb: ec2.ISecurityGroup;
  /** FastAPI security group from networking stack */
  sgFastapi: ec2.ISecurityGroup;
  /** IAM role for FastAPI ECS tasks */
  fastapiTaskRole: iam.IRole;
  /** IAM role for AgentCore Runtime */
  agentCoreRole: iam.IRole;
  /** IAM role for reconciliation Lambda */
  reconciliationRole: iam.IRole;
  /** IAM role for deprovisioning webhook Lambda */
  deprovisioningRole: iam.IRole;
}

/**
 * Compute stack for the Chatbot Security Architecture.
 *
 * Implements:
 * - Requirement 18.4: ECS Fargate service with multi-AZ deployment
 * - Requirement 18.5: Auto-scaling (min 2, max 10) on response time and CPU
 * - Requirement 13.1: EventBridge daily reconciliation schedule
 * - Requirement 15.1: Lambda for user deprovisioning webhook
 *
 * Provides:
 * - Internal ALB (HTTPS 443, ACM cert) fronting FastAPI ECS Fargate service
 * - Auto-scaling: scale out on response time >1s or CPU >60%; scale in on response time <500ms and CPU <30%
 * - AgentCore Runtime task (1 vCPU, 2 GB memory)
 * - EventBridge rules: daily reconciliation + Glue Catalog change events
 * - Lambda for IdP deprovisioning webhook
 */
export class ComputeStack extends cdk.Stack {
  /** ECS Cluster for chatbot services */
  public readonly cluster: ecs.Cluster;
  /** Internal ALB for FastAPI service */
  public readonly alb: elbv2.ApplicationLoadBalancer;
  /** FastAPI ECS Fargate service */
  public readonly fastapiService: ecs.FargateService;
  /** AgentCore Runtime ECS Fargate service */
  public readonly agentCoreService: ecs.FargateService;
  /** Deprovisioning webhook Lambda function */
  public readonly deprovisioningLambda: lambda.Function;

  constructor(scope: Construct, id: string, props: ComputeStackProps) {
    super(scope, id, props);

    const { vpc, sgAlb, sgFastapi, fastapiTaskRole, agentCoreRole, reconciliationRole, deprovisioningRole } = props;

    // ACM certificate ARN — configurable via context for the internal ALB
    const acmCertArn = this.node.tryGetContext('acmCertificateArn')
      ?? `arn:aws:acm:${this.region}:${this.account}:certificate/placeholder-cert-id`;

    const certificate = acm.Certificate.fromCertificateArn(this, 'AlbCertificate', acmCertArn);

    // --------------------------------------------------------------------------
    // ECS Cluster — multi-AZ, private subnets only (Req 18.4)
    // --------------------------------------------------------------------------

    this.cluster = new ecs.Cluster(this, 'ChatbotCluster', {
      clusterName: 'chatbot-cluster',
      vpc,
      containerInsights: true, // Enhanced observability
    });

    // --------------------------------------------------------------------------
    // Internal ALB — HTTPS 443, ACM cert, no public access (Req 12.3, 18.4)
    // --------------------------------------------------------------------------

    this.alb = new elbv2.ApplicationLoadBalancer(this, 'InternalAlb', {
      loadBalancerName: 'chatbot-internal-alb',
      vpc,
      internetFacing: false, // Internal only
      securityGroup: sgAlb,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      },
    });

    // HTTPS listener on port 443 with ACM certificate
    const httpsListener = this.alb.addListener('HttpsListener', {
      port: 443,
      protocol: elbv2.ApplicationProtocol.HTTPS,
      certificates: [certificate],
      sslPolicy: elbv2.SslPolicy.TLS12, // Enforce TLS 1.2+ (Req 12.2)
      defaultAction: elbv2.ListenerAction.fixedResponse(404, {
        contentType: 'application/json',
        messageBody: '{"error": "not_found"}',
      }),
    });

    // --------------------------------------------------------------------------
    // FastAPI ECS Fargate Service — multi-AZ (Req 18.4)
    // --------------------------------------------------------------------------

    // Task execution role (for pulling images, logging)
    const fastapiExecutionRole = new iam.Role(this, 'FastapiExecutionRole', {
      roleName: 'chatbot-fastapi-execution-role',
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AmazonECSTaskExecutionRolePolicy'
        ),
      ],
    });

    const fastapiTaskDef = new ecs.FargateTaskDefinition(this, 'FastapiTaskDef', {
      family: 'chatbot-fastapi',
      cpu: 1024,        // 1 vCPU
      memoryLimitMiB: 2048, // 2 GB
      taskRole: fastapiTaskRole,
      executionRole: fastapiExecutionRole,
    });

    const fastapiContainer = fastapiTaskDef.addContainer('FastapiContainer', {
      containerName: 'fastapi',
      image: ecs.ContainerImage.fromAsset('../../api', {
        file: 'Dockerfile',
      }),
      portMappings: [
        { containerPort: 8000, protocol: ecs.Protocol.TCP },
      ],
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'fastapi',
        logGroup: new logs.LogGroup(this, 'FastapiTaskLogGroup', {
          logGroupName: '/chatbot/ecs/fastapi',
          retention: logs.RetentionDays.ONE_YEAR,
          removalPolicy: cdk.RemovalPolicy.RETAIN,
        }),
      }),
      environment: {
        SERVICE_NAME: 'chatbot-fastapi',
        LOG_LEVEL: 'INFO',
      },
      healthCheck: {
        command: ['CMD-SHELL', 'curl -f http://localhost:8000/health || exit 1'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        startPeriod: cdk.Duration.seconds(60),
      },
    });

    this.fastapiService = new ecs.FargateService(this, 'FastapiService', {
      serviceName: 'chatbot-fastapi',
      cluster: this.cluster,
      taskDefinition: fastapiTaskDef,
      desiredCount: 2, // Min 2 for multi-AZ availability
      securityGroups: [sgFastapi],
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      },
      assignPublicIp: false, // No public IP — private subnets only
      circuitBreaker: {
        rollback: true,
      },
      enableExecuteCommand: false, // No exec for security
    });

    // Register FastAPI service with ALB target group
    const fastapiTargetGroup = httpsListener.addTargets('FastapiTargets', {
      targetGroupName: 'chatbot-fastapi-tg',
      port: 8000,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targets: [this.fastapiService],
      healthCheck: {
        path: '/health',
        port: '8000',
        protocol: elbv2.Protocol.HTTP,
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
      },
      deregistrationDelay: cdk.Duration.seconds(30),
      conditions: [elbv2.ListenerCondition.pathPatterns(['/*'])],
      priority: 1,
    });

    // --------------------------------------------------------------------------
    // Auto-Scaling for FastAPI Service (Req 18.5)
    // Min 2, Max 10 tasks
    // Scale out: response time >1s or CPU >60%
    // Scale in: response time <500ms and CPU <30%
    // --------------------------------------------------------------------------

    const fastapiScaling = this.fastapiService.autoScaleTaskCount({
      minCapacity: 2,
      maxCapacity: 10,
    });

    // Scale on target response time
    fastapiScaling.scaleOnMetric('ScaleOnResponseTime', {
      metric: fastapiTargetGroup.metrics.targetResponseTime({
        period: cdk.Duration.minutes(1),
        statistic: 'Average',
      }),
      scalingSteps: [
        { upper: 0.5, change: -1 },   // Scale in when response time <500ms
        { lower: 1.0, change: +2 },   // Scale out when response time >1s
        { lower: 2.0, change: +3 },   // Aggressive scale out when response time >2s
      ],
      adjustmentType: cdk.aws_applicationautoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
      cooldown: cdk.Duration.seconds(120),
    });

    // Scale on CPU utilization
    fastapiScaling.scaleOnCpuUtilization('ScaleOnCpu', {
      targetUtilizationPercent: 60,   // Scale out above 60% CPU
      scaleInCooldown: cdk.Duration.seconds(180),
      scaleOutCooldown: cdk.Duration.seconds(60),
    });

    // Additional scale-in policy for low CPU (< 30%)
    fastapiScaling.scaleOnMetric('ScaleInOnLowCpu', {
      metric: this.fastapiService.metricCpuUtilization({
        period: cdk.Duration.minutes(5),
        statistic: 'Average',
      }),
      scalingSteps: [
        { upper: 30, change: -1 },  // Scale in when CPU <30%
      ],
      adjustmentType: cdk.aws_applicationautoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
      cooldown: cdk.Duration.seconds(300),
    });

    // --------------------------------------------------------------------------
    // AgentCore Runtime ECS Fargate Service (1 vCPU, 2 GB memory)
    // --------------------------------------------------------------------------

    const agentCoreExecutionRole = new iam.Role(this, 'AgentCoreExecutionRole', {
      roleName: 'chatbot-agentcore-execution-role',
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AmazonECSTaskExecutionRolePolicy'
        ),
      ],
    });

    const agentCoreTaskDef = new ecs.FargateTaskDefinition(this, 'AgentCoreTaskDef', {
      family: 'chatbot-agentcore',
      cpu: 1024,            // 1 vCPU (design spec)
      memoryLimitMiB: 2048, // 2 GB memory (design spec)
      taskRole: agentCoreRole,
      executionRole: agentCoreExecutionRole,
    });

    agentCoreTaskDef.addContainer('AgentCoreContainer', {
      containerName: 'agentcore',
      image: ecs.ContainerImage.fromAsset('../../agent', {
        file: 'Dockerfile',
      }),
      portMappings: [
        { containerPort: 8080, protocol: ecs.Protocol.TCP },
      ],
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'agentcore',
        logGroup: new logs.LogGroup(this, 'AgentCoreTaskLogGroup', {
          logGroupName: '/chatbot/ecs/agentcore',
          retention: logs.RetentionDays.ONE_YEAR,
          removalPolicy: cdk.RemovalPolicy.RETAIN,
        }),
      }),
      environment: {
        SERVICE_NAME: 'chatbot-agentcore',
        LOG_LEVEL: 'INFO',
        MAX_DISAMBIGUATION_ROUNDS: '3',
        MAX_SELF_CORRECTION_RETRIES: '2',
      },
      healthCheck: {
        command: ['CMD-SHELL', 'curl -f http://localhost:8080/health || exit 1'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        startPeriod: cdk.Duration.seconds(90),
      },
    });

    this.agentCoreService = new ecs.FargateService(this, 'AgentCoreService', {
      serviceName: 'chatbot-agentcore',
      cluster: this.cluster,
      taskDefinition: agentCoreTaskDef,
      desiredCount: 2, // Multi-AZ availability
      securityGroups: [sgFastapi], // Same SG rules — internal traffic only
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      },
      assignPublicIp: false,
      circuitBreaker: {
        rollback: true,
      },
      enableExecuteCommand: false,
    });

    // --------------------------------------------------------------------------
    // EventBridge Rule: Daily Reconciliation Schedule (Req 13.1)
    // Triggers reconciliation Lambda to compare Cedar permits vs Lake Formation grants
    // --------------------------------------------------------------------------

    const reconciliationLambda = new lambda.Function(this, 'ReconciliationLambda', {
      functionName: 'chatbot-reconciliation',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'reconciliation.handler',
      code: lambda.Code.fromAsset('../../scripts'),
      role: reconciliationRole,
      timeout: cdk.Duration.minutes(15), // Allow time for full comparison
      memorySize: 512,
      vpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      },
      environment: {
        SERVICE_NAME: 'chatbot-reconciliation',
        MAX_EXECUTION_MINUTES: '60',
      },
      logRetention: logs.RetentionDays.TWO_YEARS,
    });

    // Daily schedule — triggers at 02:00 UTC every day
    const dailyReconciliationRule = new events.Rule(this, 'DailyReconciliationRule', {
      ruleName: 'chatbot-daily-reconciliation',
      description: 'Triggers daily permission reconciliation — compares Cedar permits vs Lake Formation grants (Req 13.1)',
      schedule: events.Schedule.cron({
        minute: '0',
        hour: '2',
        day: '*',
        month: '*',
        year: '*',
      }),
    });
    dailyReconciliationRule.addTarget(
      new events_targets.LambdaFunction(reconciliationLambda, {
        retryAttempts: 2,
        maxEventAge: cdk.Duration.hours(1),
      })
    );

    // --------------------------------------------------------------------------
    // EventBridge Rule: Glue Catalog Change Events (Req 16.1, 16.2)
    // Triggers schema re-indexing when tables are created, modified, or deleted
    // --------------------------------------------------------------------------

    const glueCatalogChangeRule = new events.Rule(this, 'GlueCatalogChangeRule', {
      ruleName: 'chatbot-glue-catalog-changes',
      description: 'Triggers schema re-indexing on Glue Catalog table create/modify/delete events (Req 16.1, 16.2)',
      eventPattern: {
        source: ['aws.glue'],
        detailType: [
          'Glue Data Catalog Table State Change',
        ],
        detail: {
          typeOfChange: ['CreateTable', 'UpdateTable', 'DeleteTable'],
        },
      },
    });

    // Re-indexing Lambda triggered by Glue catalog changes
    const reindexLambda = new lambda.Function(this, 'ReindexLambda', {
      functionName: 'chatbot-schema-reindex',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'reindex_vectors.handler',
      code: lambda.Code.fromAsset('../../scripts'),
      role: agentCoreRole, // Reuses agentcore role for OpenSearch + Glue access
      timeout: cdk.Duration.minutes(5),
      memorySize: 256,
      vpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      },
      environment: {
        SERVICE_NAME: 'chatbot-schema-reindex',
        OPENSEARCH_COLLECTION: 'chatbot-schema-vectors',
      },
      logRetention: logs.RetentionDays.ONE_YEAR,
    });

    glueCatalogChangeRule.addTarget(
      new events_targets.LambdaFunction(reindexLambda, {
        retryAttempts: 2,
        maxEventAge: cdk.Duration.minutes(30),
      })
    );

    // --------------------------------------------------------------------------
    // Lambda: Deprovisioning Webhook (Req 15.1)
    // Receives IdP deprovisioning events and revokes all user access within 5 min
    // --------------------------------------------------------------------------

    this.deprovisioningLambda = new lambda.Function(this, 'DeprovisioningLambda', {
      functionName: 'chatbot-deprovisioning-webhook',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'deprovisioning.handler',
      code: lambda.Code.fromAsset('../../scripts'),
      role: deprovisioningRole,
      timeout: cdk.Duration.minutes(5), // Must complete within 5-minute SLA
      memorySize: 256,
      vpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      },
      environment: {
        SERVICE_NAME: 'chatbot-deprovisioning',
        SLA_SECONDS: '300', // 5-minute SLA
        MAX_RETRIES: '3',
      },
      logRetention: logs.RetentionDays.TWO_YEARS,
    });

    // Function URL for the deprovisioning webhook (authenticated via IAM)
    const deprovisioningFunctionUrl = this.deprovisioningLambda.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.AWS_IAM, // IAM auth — no public access
    });

    // --------------------------------------------------------------------------
    // Outputs
    // --------------------------------------------------------------------------

    new cdk.CfnOutput(this, 'ClusterArn', {
      value: this.cluster.clusterArn,
      description: 'ECS Cluster ARN',
      exportName: 'ChatbotClusterArn',
    });

    new cdk.CfnOutput(this, 'AlbDnsName', {
      value: this.alb.loadBalancerDnsName,
      description: 'Internal ALB DNS name',
      exportName: 'ChatbotAlbDnsName',
    });

    new cdk.CfnOutput(this, 'AlbArn', {
      value: this.alb.loadBalancerArn,
      description: 'Internal ALB ARN',
      exportName: 'ChatbotAlbArn',
    });

    new cdk.CfnOutput(this, 'FastapiServiceArn', {
      value: this.fastapiService.serviceArn,
      description: 'FastAPI ECS Service ARN',
      exportName: 'ChatbotFastapiServiceArn',
    });

    new cdk.CfnOutput(this, 'AgentCoreServiceArn', {
      value: this.agentCoreService.serviceArn,
      description: 'AgentCore Runtime ECS Service ARN',
      exportName: 'ChatbotAgentCoreServiceArn',
    });

    new cdk.CfnOutput(this, 'DeprovisioningLambdaArn', {
      value: this.deprovisioningLambda.functionArn,
      description: 'Deprovisioning webhook Lambda ARN',
      exportName: 'ChatbotDeprovisioningLambdaArn',
    });

    new cdk.CfnOutput(this, 'DeprovisioningWebhookUrl', {
      value: deprovisioningFunctionUrl.url,
      description: 'Deprovisioning webhook URL (IAM authenticated)',
      exportName: 'ChatbotDeprovisioningWebhookUrl',
    });

    new cdk.CfnOutput(this, 'ReconciliationLambdaArn', {
      value: reconciliationLambda.functionArn,
      description: 'Reconciliation Lambda ARN',
      exportName: 'ChatbotReconciliationLambdaArn',
    });
  }
}
