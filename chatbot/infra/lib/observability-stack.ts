import * as cdk from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatch_actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

/**
 * Properties for the ObservabilityStack.
 */
export interface ObservabilityStackProps extends cdk.StackProps {
  /** Optional SNS topic ARN for P1/P2 alerts. If not provided, topics are created. */
  snsAlertTopicArn?: string;
  /** Destination ARN for SIEM subscription filter (Splunk/QRadar endpoint) */
  siemDestinationArn?: string;
}

/**
 * Observability stack for the Chatbot Security Architecture.
 *
 * Implements:
 * - Requirement 12.6: P1 alert on network path to public internet detection
 * - Requirement 13.5: P0 escalation if assume-breach posture >4 hours
 * - Requirement 4.5: P2 alert on circuit breaker closed→open transition
 * - Requirement 2.5: Alert on auth failure spike (>5 failures/min from same IP)
 * - Requirement 18.1: CloudWatch dashboards for latency and performance monitoring
 *
 * Provides:
 * - CloudWatch dashboards for system health, security, and performance
 * - Alarms for circuit breaker, reconciliation, rate limiting, auth failures, network
 * - P0 escalation for prolonged assume-breach posture
 * - SIEM subscription filters exporting logs to Splunk/QRadar
 */
export class ObservabilityStack extends cdk.Stack {
  /** SNS topic for P1 security alerts */
  public readonly p1AlertTopic: sns.Topic;
  /** SNS topic for P2 operational alerts */
  public readonly p2AlertTopic: sns.Topic;
  /** SNS topic for P0 critical escalation alerts */
  public readonly p0AlertTopic: sns.Topic;
  /** CloudWatch dashboard for system overview */
  public readonly systemDashboard: cloudwatch.Dashboard;
  /** CloudWatch dashboard for security monitoring */
  public readonly securityDashboard: cloudwatch.Dashboard;

  constructor(scope: Construct, id: string, props: ObservabilityStackProps = {}) {
    super(scope, id, props);

    const siemDestinationArn = props.siemDestinationArn
      ?? this.node.tryGetContext('siemDestinationArn')
      ?? `arn:aws:logs:${this.region}:${this.account}:destination:bank-siem-destination`;

    // --------------------------------------------------------------------------
    // SNS Topics for Alert Routing
    // --------------------------------------------------------------------------

    this.p0AlertTopic = new sns.Topic(this, 'P0AlertTopic', {
      topicName: 'chatbot-p0-critical-alerts',
      displayName: 'Chatbot P0 Critical Alerts — On-Call Security Architect',
    });

    this.p1AlertTopic = new sns.Topic(this, 'P1AlertTopic', {
      topicName: 'chatbot-p1-security-alerts',
      displayName: 'Chatbot P1 Security Alerts — Security Operations Team',
    });

    this.p2AlertTopic = new sns.Topic(this, 'P2AlertTopic', {
      topicName: 'chatbot-p2-operational-alerts',
      displayName: 'Chatbot P2 Operational Alerts — Platform Engineering',
    });

    // --------------------------------------------------------------------------
    // Log Groups — centralized log groups for all chatbot components
    // --------------------------------------------------------------------------

    const fastapiLogGroup = new logs.LogGroup(this, 'FastApiLogGroup', {
      logGroupName: '/chatbot/api/fastapi',
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const agentLogGroup = new logs.LogGroup(this, 'AgentLogGroup', {
      logGroupName: '/chatbot/agent/langgraph',
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const securityEventsLogGroup = new logs.LogGroup(this, 'SecurityEventsLogGroup', {
      logGroupName: '/chatbot/security/events',
      retention: logs.RetentionDays.TWO_YEARS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const reconciliationLogGroup = new logs.LogGroup(this, 'ReconciliationLogGroup', {
      logGroupName: '/chatbot/security/reconciliation',
      retention: logs.RetentionDays.TWO_YEARS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // --------------------------------------------------------------------------
    // Custom Metrics Namespace
    // --------------------------------------------------------------------------

    const namespace = 'Chatbot/Security';
    const operationalNamespace = 'Chatbot/Operations';

    // --------------------------------------------------------------------------
    // Alarm: Circuit Breaker Open — P2 (Req 4.5)
    // Triggers when circuit breaker transitions closed→open
    // --------------------------------------------------------------------------

    const circuitBreakerOpenAlarm = new cloudwatch.Alarm(this, 'CircuitBreakerOpenAlarm', {
      alarmName: 'chatbot-circuit-breaker-open',
      alarmDescription: 'P2: Circuit breaker transitioned to OPEN state — AgentCore Runtime unavailable (Req 4.5)',
      metric: new cloudwatch.Metric({
        namespace: operationalNamespace,
        metricName: 'CircuitBreakerStateChange',
        dimensionsMap: { Service: 'AgentCoreRuntime', State: 'open' },
        statistic: 'Sum',
        period: cdk.Duration.minutes(1),
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    circuitBreakerOpenAlarm.addAlarmAction(new cloudwatch_actions.SnsAction(this.p2AlertTopic));
    circuitBreakerOpenAlarm.addOkAction(new cloudwatch_actions.SnsAction(this.p2AlertTopic));

    // --------------------------------------------------------------------------
    // Alarm: Reconciliation Failure — P1 (Req 13.3, 13.5)
    // Triggers when reconciliation job fails or detects divergence
    // --------------------------------------------------------------------------

    const reconciliationFailureAlarm = new cloudwatch.Alarm(this, 'ReconciliationFailureAlarm', {
      alarmName: 'chatbot-reconciliation-failure',
      alarmDescription: 'P1: Reconciliation job failed or divergence detected — assume-breach posture activated (Req 13.3)',
      metric: new cloudwatch.Metric({
        namespace,
        metricName: 'ReconciliationStatus',
        dimensionsMap: { Status: 'failure' },
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    reconciliationFailureAlarm.addAlarmAction(new cloudwatch_actions.SnsAction(this.p1AlertTopic));

    // --------------------------------------------------------------------------
    // Alarm: Sustained Rate Limiting — P2 (Req 3.3)
    // Triggers when a user has been rate-limited for >10 consecutive minutes
    // --------------------------------------------------------------------------

    const sustainedRateLimitAlarm = new cloudwatch.Alarm(this, 'SustainedRateLimitAlarm', {
      alarmName: 'chatbot-sustained-rate-limiting',
      alarmDescription: 'P2: User continuously rate-limited for >10 minutes — potential abuse investigation needed (Req 3.3)',
      metric: new cloudwatch.Metric({
        namespace: operationalNamespace,
        metricName: 'SustainedRateLimitTriggered',
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1,
      evaluationPeriods: 2, // 2 × 5 min = 10 min sustained
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    sustainedRateLimitAlarm.addAlarmAction(new cloudwatch_actions.SnsAction(this.p2AlertTopic));

    // --------------------------------------------------------------------------
    // Alarm: Auth Failure Spike — P1 (Req 2.5)
    // Triggers when auth failures exceed 5/min from same source
    // --------------------------------------------------------------------------

    const authFailureSpikeAlarm = new cloudwatch.Alarm(this, 'AuthFailureSpikeAlarm', {
      alarmName: 'chatbot-auth-failure-spike',
      alarmDescription: 'P1: Auth failures exceeded threshold — potential credential stuffing or brute force (Req 2.5)',
      metric: new cloudwatch.Metric({
        namespace,
        metricName: 'AuthFailureCount',
        statistic: 'Sum',
        period: cdk.Duration.minutes(1),
      }),
      threshold: 5,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    authFailureSpikeAlarm.addAlarmAction(new cloudwatch_actions.SnsAction(this.p1AlertTopic));

    // --------------------------------------------------------------------------
    // Alarm: Network Path Detection — P1 (Req 12.6)
    // Triggers if any public internet path (NAT/IGW/public IP) is detected
    // --------------------------------------------------------------------------

    const networkPathDetectionAlarm = new cloudwatch.Alarm(this, 'NetworkPathDetectionAlarm', {
      alarmName: 'chatbot-network-public-path-detected',
      alarmDescription: 'P1: Public internet path detected for chatbot components — network isolation breach (Req 12.6)',
      metric: new cloudwatch.Metric({
        namespace,
        metricName: 'PublicNetworkPathDetected',
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    networkPathDetectionAlarm.addAlarmAction(new cloudwatch_actions.SnsAction(this.p1AlertTopic));

    // --------------------------------------------------------------------------
    // Alarm: Assume-Breach Posture Escalation — P0 (Req 13.5)
    // Escalates to P0 if assume-breach posture persists >4 hours
    // --------------------------------------------------------------------------

    const assumeBreachEscalationAlarm = new cloudwatch.Alarm(this, 'AssumeBreachEscalationAlarm', {
      alarmName: 'chatbot-assume-breach-escalation-p0',
      alarmDescription: 'P0 CRITICAL: Assume-breach posture active >4 hours — escalating to on-call security architect (Req 13.5)',
      metric: new cloudwatch.Metric({
        namespace,
        metricName: 'AssumeBreachPostureActive',
        statistic: 'Maximum',
        period: cdk.Duration.minutes(15),
      }),
      // 4 hours = 16 × 15-minute periods
      threshold: 1,
      evaluationPeriods: 16,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    assumeBreachEscalationAlarm.addAlarmAction(new cloudwatch_actions.SnsAction(this.p0AlertTopic));

    // --------------------------------------------------------------------------
    // SIEM Subscription Filters — Export logs to bank SIEM (Splunk/QRadar)
    // via CloudWatch subscription filters (Req 12.6, 2.5)
    // --------------------------------------------------------------------------

    // IAM role for CloudWatch to deliver logs to the SIEM destination
    const siemDeliveryRole = new iam.Role(this, 'SiemDeliveryRole', {
      roleName: 'chatbot-siem-log-delivery-role',
      assumedBy: new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`),
      description: 'Role for CloudWatch Logs to deliver chatbot logs to bank SIEM destination',
    });

    siemDeliveryRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowLogDelivery',
      effect: iam.Effect.ALLOW,
      actions: [
        'logs:PutLogEvents',
        'logs:CreateLogStream',
      ],
      resources: [siemDestinationArn],
    }));

    // Security events subscription filter — all security events to SIEM
    new logs.SubscriptionFilter(this, 'SecurityEventsSiemFilter', {
      logGroup: securityEventsLogGroup,
      filterName: 'chatbot-security-events-to-siem',
      filterPattern: logs.FilterPattern.allEvents(),
      destination: new SiemLogDestination(siemDestinationArn, siemDeliveryRole),
    });

    // Auth failure events subscription filter
    new logs.SubscriptionFilter(this, 'AuthFailureSiemFilter', {
      logGroup: fastapiLogGroup,
      filterName: 'chatbot-auth-failures-to-siem',
      filterPattern: logs.FilterPattern.literal('{ $.event_type = "auth_failure" }'),
      destination: new SiemLogDestination(siemDestinationArn, siemDeliveryRole),
    });

    // Reconciliation events subscription filter
    new logs.SubscriptionFilter(this, 'ReconciliationSiemFilter', {
      logGroup: reconciliationLogGroup,
      filterName: 'chatbot-reconciliation-to-siem',
      filterPattern: logs.FilterPattern.allEvents(),
      destination: new SiemLogDestination(siemDestinationArn, siemDeliveryRole),
    });

    // Policy decision events subscription filter (permit/deny)
    new logs.SubscriptionFilter(this, 'PolicyDecisionSiemFilter', {
      logGroup: agentLogGroup,
      filterName: 'chatbot-policy-decisions-to-siem',
      filterPattern: logs.FilterPattern.literal('{ $.event_type = "policy_decision" }'),
      destination: new SiemLogDestination(siemDestinationArn, siemDeliveryRole),
    });

    // --------------------------------------------------------------------------
    // CloudWatch Dashboard: System Overview (Req 18.1)
    // --------------------------------------------------------------------------

    this.systemDashboard = new cloudwatch.Dashboard(this, 'SystemDashboard', {
      dashboardName: 'Chatbot-System-Overview',
    });

    this.systemDashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Chatbot System Overview\nEnd-to-end performance and availability metrics',
        width: 24,
        height: 1,
      }),
    );

    this.systemDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'API Request Latency (P95/P99)',
        left: [
          new cloudwatch.Metric({
            namespace: operationalNamespace,
            metricName: 'RequestLatency',
            statistic: 'p95',
            period: cdk.Duration.minutes(1),
            label: 'P95 Latency',
          }),
          new cloudwatch.Metric({
            namespace: operationalNamespace,
            metricName: 'RequestLatency',
            statistic: 'p99',
            period: cdk.Duration.minutes(1),
            label: 'P99 Latency',
          }),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Request Rate & Error Rate',
        left: [
          new cloudwatch.Metric({
            namespace: operationalNamespace,
            metricName: 'RequestCount',
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
            label: 'Total Requests',
          }),
        ],
        right: [
          new cloudwatch.Metric({
            namespace: operationalNamespace,
            metricName: 'ErrorCount',
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
            label: 'Errors',
          }),
        ],
        width: 12,
        height: 6,
      }),
    );

    this.systemDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Circuit Breaker State',
        left: [
          new cloudwatch.Metric({
            namespace: operationalNamespace,
            metricName: 'CircuitBreakerStateChange',
            dimensionsMap: { Service: 'AgentCoreRuntime', State: 'open' },
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
            label: 'Open Events',
          }),
          new cloudwatch.Metric({
            namespace: operationalNamespace,
            metricName: 'CircuitBreakerStateChange',
            dimensionsMap: { Service: 'AgentCoreRuntime', State: 'closed' },
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
            label: 'Closed Events',
          }),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Rate Limiting (HTTP 429)',
        left: [
          new cloudwatch.Metric({
            namespace: operationalNamespace,
            metricName: 'RateLimitedRequests',
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
            label: 'Rate Limited Requests',
          }),
        ],
        width: 12,
        height: 6,
      }),
    );

    // --------------------------------------------------------------------------
    // CloudWatch Dashboard: Security Monitoring
    // --------------------------------------------------------------------------

    this.securityDashboard = new cloudwatch.Dashboard(this, 'SecurityDashboard', {
      dashboardName: 'Chatbot-Security-Monitoring',
    });

    this.securityDashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Chatbot Security Monitoring\nAuthorization, reconciliation, and threat detection',
        width: 24,
        height: 1,
      }),
    );

    this.securityDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Auth Failures',
        left: [
          new cloudwatch.Metric({
            namespace,
            metricName: 'AuthFailureCount',
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
            label: 'Auth Failures',
          }),
        ],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Policy Decisions (Permit/Deny)',
        left: [
          new cloudwatch.Metric({
            namespace,
            metricName: 'PolicyDecision',
            dimensionsMap: { Decision: 'permit' },
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
            label: 'Permits',
          }),
          new cloudwatch.Metric({
            namespace,
            metricName: 'PolicyDecision',
            dimensionsMap: { Decision: 'deny' },
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
            label: 'Denials',
          }),
        ],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Reconciliation Status',
        left: [
          new cloudwatch.Metric({
            namespace,
            metricName: 'ReconciliationStatus',
            dimensionsMap: { Status: 'healthy' },
            statistic: 'Sum',
            period: cdk.Duration.hours(1),
            label: 'Healthy',
          }),
          new cloudwatch.Metric({
            namespace,
            metricName: 'ReconciliationStatus',
            dimensionsMap: { Status: 'failure' },
            statistic: 'Sum',
            period: cdk.Duration.hours(1),
            label: 'Failed/Divergent',
          }),
        ],
        width: 8,
        height: 6,
      }),
    );

    this.securityDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Guardrails Blocks',
        left: [
          new cloudwatch.Metric({
            namespace,
            metricName: 'GuardrailsBlockCount',
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
            label: 'Blocked Requests',
          }),
        ],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Assume-Breach Posture',
        left: [
          new cloudwatch.Metric({
            namespace,
            metricName: 'AssumeBreachPostureActive',
            statistic: 'Maximum',
            period: cdk.Duration.minutes(15),
            label: 'Breach Posture Active',
          }),
        ],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Network Security',
        left: [
          new cloudwatch.Metric({
            namespace,
            metricName: 'PublicNetworkPathDetected',
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
            label: 'Public Path Detections',
          }),
        ],
        width: 8,
        height: 6,
      }),
    );

    // --------------------------------------------------------------------------
    // Alarm: Reconciliation Divergence — P1 (Req 13.2)
    // Specific alarm for Cedar/LakeFormation divergence detection
    // --------------------------------------------------------------------------

    const reconciliationDivergenceAlarm = new cloudwatch.Alarm(this, 'ReconciliationDivergenceAlarm', {
      alarmName: 'chatbot-reconciliation-divergence',
      alarmDescription: 'P1: Cedar/Lake Formation authorization divergence detected — affected principals blocked (Req 13.2)',
      metric: new cloudwatch.Metric({
        namespace,
        metricName: 'ReconciliationDivergenceCount',
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    reconciliationDivergenceAlarm.addAlarmAction(new cloudwatch_actions.SnsAction(this.p1AlertTopic));

    // --------------------------------------------------------------------------
    // Outputs
    // --------------------------------------------------------------------------

    new cdk.CfnOutput(this, 'P0AlertTopicArn', {
      value: this.p0AlertTopic.topicArn,
      description: 'P0 Critical Alerts SNS Topic ARN',
      exportName: 'ChatbotP0AlertTopicArn',
    });

    new cdk.CfnOutput(this, 'P1AlertTopicArn', {
      value: this.p1AlertTopic.topicArn,
      description: 'P1 Security Alerts SNS Topic ARN',
      exportName: 'ChatbotP1AlertTopicArn',
    });

    new cdk.CfnOutput(this, 'P2AlertTopicArn', {
      value: this.p2AlertTopic.topicArn,
      description: 'P2 Operational Alerts SNS Topic ARN',
      exportName: 'ChatbotP2AlertTopicArn',
    });

    new cdk.CfnOutput(this, 'SystemDashboardName', {
      value: this.systemDashboard.dashboardName,
      description: 'System overview CloudWatch dashboard',
      exportName: 'ChatbotSystemDashboardName',
    });

    new cdk.CfnOutput(this, 'SecurityDashboardName', {
      value: this.securityDashboard.dashboardName,
      description: 'Security monitoring CloudWatch dashboard',
      exportName: 'ChatbotSecurityDashboardName',
    });
  }
}

/**
 * Custom ILogSubscriptionDestination implementation for cross-account SIEM delivery.
 * Wraps a destination ARN (Splunk/QRadar endpoint) for use with CloudWatch subscription filters.
 */
class SiemLogDestination implements logs.ILogSubscriptionDestination {
  private readonly destinationArn: string;
  private readonly role: iam.IRole;

  constructor(destinationArn: string, role: iam.IRole) {
    this.destinationArn = destinationArn;
    this.role = role;
  }

  bind(_scope: Construct, _sourceLogGroup: logs.ILogGroup): logs.LogSubscriptionDestinationConfig {
    return {
      arn: this.destinationArn,
      role: this.role,
    };
  }
}
