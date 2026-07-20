#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { NetworkingStack } from '../lib/networking-stack';
import { SecurityStack } from '../lib/security-stack';
import { DataStack } from '../lib/data-stack';
import { ComputeStack } from '../lib/compute-stack';
import { ObservabilityStack } from '../lib/observability-stack';

const app = new cdk.App();

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
};

const networkingStack = new NetworkingStack(app, 'ChatbotNetworkingStack', {
  env,
  description: 'Chatbot Security Architecture - Networking (VPC, PrivateLink, Security Groups)',
});

const securityStack = new SecurityStack(app, 'ChatbotSecurityStack', {
  env,
  vpc: networkingStack.vpc,
  description: 'Chatbot Security Architecture - Security (KMS, Cognito, Secrets Manager, IAM)',
});
securityStack.addDependency(networkingStack);

const dataStack = new DataStack(app, 'ChatbotDataStack', {
  env,
  vpc: networkingStack.vpc,
  datalakeKey: securityStack.datalakeKey,
  auditKey: securityStack.auditKey,
  opensearchKey: securityStack.opensearchKey,
  queryResultsKey: securityStack.queryResultsKey,
  description: 'Chatbot Security Architecture - Data (S3, Glue, Lake Formation, OpenSearch, Athena)',
});
dataStack.addDependency(networkingStack);
dataStack.addDependency(securityStack);

const computeStack = new ComputeStack(app, 'ChatbotComputeStack', {
  env,
  vpc: networkingStack.vpc,
  sgAlb: networkingStack.sgAlb,
  sgFastapi: networkingStack.sgFastapi,
  fastapiTaskRole: securityStack.fastapiTaskRole,
  agentCoreRole: securityStack.agentCoreRole,
  reconciliationRole: securityStack.reconciliationRole,
  deprovisioningRole: securityStack.deprovisioningRole,
  description: 'Chatbot Security Architecture - Compute (ECS Fargate, ALB, Lambda, EventBridge)',
});
computeStack.addDependency(networkingStack);
computeStack.addDependency(securityStack);
computeStack.addDependency(dataStack);

const observabilityStack = new ObservabilityStack(app, 'ChatbotObservabilityStack', {
  env,
  description: 'Chatbot Security Architecture - Observability (Dashboards, Alarms, SIEM)',
});
observabilityStack.addDependency(networkingStack);
observabilityStack.addDependency(dataStack);
observabilityStack.addDependency(computeStack);

app.synth();
