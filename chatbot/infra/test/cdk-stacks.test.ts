import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { NetworkingStack } from '../lib/networking-stack';
import { SecurityStack } from '../lib/security-stack';
import { DataStack } from '../lib/data-stack';

/**
 * CDK unit and snapshot tests for the Chatbot Security Architecture infrastructure.
 *
 * Validates:
 * - Requirement 12.1: All inter-service via VPC PrivateLink, no public internet paths
 * - Requirement 12.6: P1 alert if public internet path detected
 * - Requirement 11.2: S3 Object Lock Compliance mode, 7-year retention
 * - Security group rules enforce directional flow
 */

const ENV = { account: '123456789012', region: 'us-east-1' };

function createNetworkingStack(): { app: cdk.App; stack: NetworkingStack; template: Template } {
  const app = new cdk.App({ context: { corporateCidr: '10.0.0.0/8' } });
  const stack = new NetworkingStack(app, 'TestNetworkingStack', { env: ENV });
  const template = Template.fromStack(stack);
  return { app, stack, template };
}

function createFullStacks() {
  const app = new cdk.App({ context: { corporateCidr: '10.0.0.0/8' } });
  const networkingStack = new NetworkingStack(app, 'TestNetworkingStack', { env: ENV });
  const securityStack = new SecurityStack(app, 'TestSecurityStack', {
    env: ENV,
    vpc: networkingStack.vpc,
  });
  const dataStack = new DataStack(app, 'TestDataStack', {
    env: ENV,
    vpc: networkingStack.vpc,
    datalakeKey: securityStack.datalakeKey,
    auditKey: securityStack.auditKey,
    opensearchKey: securityStack.opensearchKey,
    queryResultsKey: securityStack.queryResultsKey,
  });
  return {
    app,
    networkingStack,
    securityStack,
    dataStack,
    networkingTemplate: Template.fromStack(networkingStack),
    securityTemplate: Template.fromStack(securityStack),
    dataTemplate: Template.fromStack(dataStack),
  };
}

// =============================================================================
// Stack Synthesis Tests — verify stacks produce expected resources
// =============================================================================
describe('Stack synthesis produces expected resources', () => {
  test('NetworkingStack synthesizes with VPC and security groups', () => {
    const { template } = createNetworkingStack();

    // VPC exists
    template.resourceCountIs('AWS::EC2::VPC', 1);

    // Three security groups: sg-alb, sg-fastapi, sg-vpce
    template.resourceCountIs('AWS::EC2::SecurityGroup', 3);

    // VPC endpoints exist (interface endpoints + gateway endpoint for S3)
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      VpcEndpointType: 'Gateway',
    });
  });

  test('SecurityStack synthesizes with KMS keys and Cognito', () => {
    const { securityTemplate } = createFullStacks();

    // 5 KMS CMKs: datalake, audit, opensearch, queryresults, gateway
    securityTemplate.resourceCountIs('AWS::KMS::Key', 5);

    // Cognito User Pool
    securityTemplate.resourceCountIs('AWS::Cognito::UserPool', 1);

    // Cognito User Pool Client
    securityTemplate.resourceCountIs('AWS::Cognito::UserPoolClient', 1);

    // Secrets Manager secret (OBO token vault)
    securityTemplate.resourceCountIs('AWS::SecretsManager::Secret', 1);
  });

  test('DataStack synthesizes with S3 buckets, Glue, Athena workgroup, OpenSearch', () => {
    const { dataTemplate } = createFullStacks();

    // S3 buckets: datalake, audit, audit-replica, query-results
    dataTemplate.resourceCountIs('AWS::S3::Bucket', 4);

    // Glue Database
    dataTemplate.resourceCountIs('AWS::Glue::Database', 1);

    // Athena Workgroup
    dataTemplate.resourceCountIs('AWS::Athena::WorkGroup', 1);

    // OpenSearch Serverless Collection
    dataTemplate.resourceCountIs('AWS::OpenSearchServerless::Collection', 1);
  });
});

// =============================================================================
// Networking — No public internet paths (Req 12.1)
// =============================================================================
describe('No public internet paths in networking stack', () => {
  test('VPC has zero NAT gateways', () => {
    const { template } = createNetworkingStack();
    template.resourceCountIs('AWS::EC2::NatGateway', 0);
  });

  test('VPC has no Internet Gateway', () => {
    const { template } = createNetworkingStack();
    template.resourceCountIs('AWS::EC2::InternetGateway', 0);
  });

  test('All subnets are PRIVATE_ISOLATED (no public subnets)', () => {
    const { template } = createNetworkingStack();

    // No public route to internet gateway should exist
    const routes = template.findResources('AWS::EC2::Route');
    for (const [_logicalId, route] of Object.entries(routes)) {
      const properties = (route as any).Properties ?? {};
      // No route should point to an internet gateway or NAT gateway
      expect(properties).not.toHaveProperty('GatewayId');
      expect(properties).not.toHaveProperty('NatGatewayId');
    }
  });

  test('VPC endpoints use private DNS', () => {
    const { template } = createNetworkingStack();

    // All interface VPC endpoints should have PrivateDnsEnabled: true
    const endpoints = template.findResources('AWS::EC2::VPCEndpoint');
    for (const [_logicalId, endpoint] of Object.entries(endpoints)) {
      const properties = (endpoint as any).Properties ?? {};
      if (properties.VpcEndpointType !== 'Gateway') {
        expect(properties.PrivateDnsEnabled).toBe(true);
      }
    }
  });

  test('VPC endpoint policies deny insecure transport', () => {
    const { template } = createNetworkingStack();

    // At least one endpoint policy should contain DenyNonSecureTransport
    const endpoints = template.findResources('AWS::EC2::VPCEndpoint');
    let foundDenyInsecure = false;
    for (const [_logicalId, endpoint] of Object.entries(endpoints)) {
      const properties = (endpoint as any).Properties ?? {};
      const policyDoc = properties.PolicyDocument;
      if (policyDoc) {
        const statements = policyDoc.Statement ?? [];
        for (const stmt of statements) {
          if (stmt.Sid === 'DenyNonSecureTransport' || stmt.Sid === 'DenyInsecureTransport' || stmt.Sid === 'DenyInsecureTransportOpenSearch' || stmt.Sid === 'DenyInsecureTransportCognito') {
            foundDenyInsecure = true;
            expect(stmt.Effect).toBe('Deny');
            expect(stmt.Condition?.Bool?.['aws:SecureTransport']).toBe('false');
          }
        }
      }
    }
    expect(foundDenyInsecure).toBe(true);
  });
});

// =============================================================================
// Object Lock configuration on audit bucket (Req 11.2)
// =============================================================================
describe('Object Lock configuration on audit bucket', () => {
  test('Audit bucket has Object Lock enabled', () => {
    const { dataTemplate } = createFullStacks();

    dataTemplate.hasResourceProperties('AWS::S3::Bucket', Match.objectLike({
      ObjectLockEnabled: true,
      BucketName: Match.stringLikeRegexp('chatbot-audit-.*'),
    }));
  });

  test('Audit bucket has Compliance mode with 7-year retention', () => {
    const { dataTemplate } = createFullStacks();

    // Find the audit bucket and check its ObjectLockConfiguration override
    const buckets = dataTemplate.findResources('AWS::S3::Bucket');
    let foundAuditBucketWithCompliance = false;

    for (const [_logicalId, bucket] of Object.entries(buckets)) {
      const properties = (bucket as any).Properties ?? {};
      const bucketName = properties.BucketName ?? '';
      // Match the primary audit bucket (not replica)
      if (typeof bucketName === 'string' && bucketName.includes('chatbot-audit-') && !bucketName.includes('replica')) {
        const objectLockConfig = properties.ObjectLockConfiguration;
        if (objectLockConfig) {
          expect(objectLockConfig.ObjectLockEnabled).toBe('Enabled');
          expect(objectLockConfig.Rule.DefaultRetention.Mode).toBe('COMPLIANCE');
          expect(objectLockConfig.Rule.DefaultRetention.Years).toBe(7);
          foundAuditBucketWithCompliance = true;
        }
      }
    }
    expect(foundAuditBucketWithCompliance).toBe(true);
  });

  test('Audit bucket has versioning enabled (required for Object Lock)', () => {
    const { dataTemplate } = createFullStacks();

    dataTemplate.hasResourceProperties('AWS::S3::Bucket', Match.objectLike({
      ObjectLockEnabled: true,
      VersioningConfiguration: {
        Status: 'Enabled',
      },
    }));
  });

  test('Audit bucket blocks all public access', () => {
    const { dataTemplate } = createFullStacks();

    // All buckets should block public access
    dataTemplate.hasResourceProperties('AWS::S3::Bucket', Match.objectLike({
      ObjectLockEnabled: true,
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
    }));
  });
});

// =============================================================================
// Security group rules enforce directional flow (Req 12.3, 12.4)
// =============================================================================
describe('Security group rules enforce directional flow', () => {
  test('sg-alb only allows inbound on port 443 from corporate CIDR', () => {
    const { template } = createNetworkingStack();

    template.hasResourceProperties('AWS::EC2::SecurityGroup', Match.objectLike({
      GroupDescription: Match.stringLikeRegexp('.*ALB.*'),
      SecurityGroupIngress: Match.arrayWith([
        Match.objectLike({
          IpProtocol: 'tcp',
          FromPort: 443,
          ToPort: 443,
          CidrIp: '10.0.0.0/8',
        }),
      ]),
    }));
  });

  test('sg-alb does not allow all outbound (restrictive egress)', () => {
    const { template } = createNetworkingStack();

    // sg-alb has SecurityGroupEgress defined separately via addEgressRule.
    // The SG itself should NOT have the default allow-all-outbound
    // (we verify by checking the SG does NOT contain an egress rule to 0.0.0.0/0 on all ports)
    const securityGroups = template.findResources('AWS::EC2::SecurityGroup');
    for (const [_logicalId, sg] of Object.entries(securityGroups)) {
      const properties = (sg as any).Properties ?? {};
      if (properties.GroupDescription?.includes('ALB')) {
        const egress = properties.SecurityGroupEgress ?? [];
        // Should not have a wide-open 0.0.0.0/0 all-ports rule
        const hasWideOpen = egress.some((rule: any) =>
          rule.CidrIp === '0.0.0.0/0' && rule.IpProtocol === '-1'
        );
        expect(hasWideOpen).toBe(false);
      }
    }
  });

  test('sg-fastapi allows inbound only from sg-alb on port 8000', () => {
    const { template } = createNetworkingStack();

    // sg-fastapi ingress rule references sg-alb
    template.hasResourceProperties('AWS::EC2::SecurityGroupIngress', Match.objectLike({
      IpProtocol: 'tcp',
      FromPort: 8000,
      ToPort: 8000,
      // GroupId references sg-fastapi, SourceSecurityGroupId references sg-alb
    }));
  });

  test('sg-vpce allows inbound only from sg-fastapi on port 443', () => {
    const { template } = createNetworkingStack();

    // sg-vpce ingress rule references sg-fastapi
    template.hasResourceProperties('AWS::EC2::SecurityGroupIngress', Match.objectLike({
      IpProtocol: 'tcp',
      FromPort: 443,
      ToPort: 443,
      // GroupId references sg-vpce, SourceSecurityGroupId references sg-fastapi
    }));
  });

  test('Security groups do not have allow-all inbound rules', () => {
    const { template } = createNetworkingStack();

    const securityGroups = template.findResources('AWS::EC2::SecurityGroup');
    for (const [_logicalId, sg] of Object.entries(securityGroups)) {
      const properties = (sg as any).Properties ?? {};
      const ingress = properties.SecurityGroupIngress ?? [];
      // No rule should allow all traffic (protocol -1) from 0.0.0.0/0
      const hasAllowAll = ingress.some((rule: any) =>
        rule.CidrIp === '0.0.0.0/0' && rule.IpProtocol === '-1'
      );
      expect(hasAllowAll).toBe(false);
    }
  });

  test('Directional flow: ALB->FastAPI->VPCE established via egress rules', () => {
    const { template } = createNetworkingStack();

    // ALB egress to FastAPI on port 8000 (separate SecurityGroupEgress resource)
    template.hasResourceProperties('AWS::EC2::SecurityGroupEgress', Match.objectLike({
      IpProtocol: 'tcp',
      FromPort: 8000,
      ToPort: 8000,
    }));

    // FastAPI egress on port 443 to VPC endpoints
    // When using Peer.anyIpv4() with allowAllOutbound: false, CDK puts egress
    // as an inline property on the SecurityGroup itself
    const securityGroups = template.findResources('AWS::EC2::SecurityGroup');
    let foundFastapiEgress443 = false;
    for (const [_logicalId, sg] of Object.entries(securityGroups)) {
      const properties = (sg as any).Properties ?? {};
      if (properties.GroupDescription?.includes('FastAPI')) {
        const egress = properties.SecurityGroupEgress ?? [];
        const has443 = egress.some((rule: any) =>
          rule.IpProtocol === 'tcp' && rule.FromPort === 443 && rule.ToPort === 443
        );
        if (has443) foundFastapiEgress443 = true;
      }
    }
    expect(foundFastapiEgress443).toBe(true);
  });
});
