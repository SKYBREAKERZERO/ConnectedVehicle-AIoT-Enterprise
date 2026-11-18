# Day40: Real AWS Staging Worker identity / configuration admission

**Status:** Source and offline negative tests. Not an AWS deployment, real
IAM policy permission test, verified Secret value, OTA runtime test, or
production release authorization.

## Scope and trust model

Two independent **read-only** observations run after the separately approved
Day37 saved-Plan deployment:

1. \`scripts.day39_worker_verify\`: observe exact deployed ECS service, running
   Fargate tasks, Task/Execution Role ARNs, tenant and manifest digest.
2. \`scripts.day40_worker_boundary\`: independently re-read AWS IAM trust
   policies, inline/attached policies, Secrets Manager metadata, SQS/DLQ,
   private ECS security group and Task Definition configuration. Both must
   succeed for Day37 Verify to pass. Neither authorizes OTA.

The expectation set comes from separately approved GitHub Staging environment
variables and image-digest evidence. It must **not** be reconstructed from
the untrusted running ECS task. Day40 binds the observation to the exact
checkout SHA, GitHub Run ID and Run Attempt. Evidence is uploaded only after
the entire verification step succeeds.

## Explicit authorized boundaries

| ECS Task | Task Role | Execution Role | DB Secret | Additional permitted use |
| --- | --- | --- | --- | --- |
| Outbox | \`cv-ota-staging-outbox\` | \`cv-ota-staging-outbox-exec\` | \`.../database/outbox\` | \`sqs:GetQueueUrl\`, \`sqs:SendMessage\` to exact command queue |
| Remote Command | \`cv-ota-staging-remote-command\` | \`cv-ota-staging-remote-command-exec\` | \`.../database/remote-command\` | SQS receive/delete/visibility, \`iot:Publish\` to pinned tenant topic |
| Campaign | \`cv-ota-staging-campaign\` | \`cv-ota-staging-campaign-exec\` | **currently shared \`.../database/application\`** | Version-pinned S3 reads for tenant firmware |

**Important release blocker:** Existing Campaign uses the API/application
PostgreSQL principal; it does not yet have a dedicated database role and Secret,
and a configured \`OTA_TRUSTED_KEYS_FILE\` path is not proof of a trust-root
file inside the image. Day40 therefore deliberately rejects enabling Campaign
in an enterprise **independent identity** acceptance run. Create a dedicated
Campaign DB principal/Secret and authenticated trust-root delivery with
unforgeable source/digest evidence before lifting this explicit fail-closed
guard. Do not bypass the guard or mark all three Workers fully isolated.

For enabled Outbox and Remote Command, Day40 verifies:

- Task Role and Execution Role are distinct and trust **only**
  \`ecs-tasks.amazonaws.com\` with \`sts:AssumeRole\`.
- Task Role has exactly \`minimum-staging-worker-access\` inline policy
  and **no** attached managed policy. No extra grants, wildcard resources,
  broad IoT topics, cross-tenant Secret or unauthorized SQS operations.
- Execution Role has only the standard ECS execution managed policy, with
  **only** Remote Command permitted a narrow Redis token-injection inline
  policy.
- All KMS decrypt grants are constrained to Secrets Manager and the exact
  \`kms:EncryptionContext:SecretARN\`.
- Secrets Manager ARN/name/customer-managed KMS, current Secret version,
  enabled schedule and recorded previous rotation (metadata **only**).
- SQS queue ARN, managed SSE, visibility, fixed DLQ and retry count.
- Running Task Definition references approved immutable image Digest,
  fixed module command, \`awsvpc\`, Fargate, non-root UID, read-only root
  filesystem, expected Secrets, exact configuration fields and tenant.
- Exactly one named, no-ingress private Worker Security Group; egress
  restricted to HTTPS 443, PostgreSQL 5432 and Remote Redis 6379.

## Required real AWS verify role read-only permissions

The \`aws-staging-verify\` environment must grant its existing trusted
\`cv-ota-staging-verify\` role **only** these read permissions with
resource/condition restrictions where supported:

\`sts:GetCallerIdentity\`,
\`ecs:DescribeServices\`,
\`ecs:DescribeTaskDefinition\`,
\`ecs:DescribeTasks\`, \`ecs:ListTasks\`,
\`iam:GetRole\`, \`iam:ListRolePolicies\`,
\`iam:ListAttachedRolePolicies\`, \`iam:GetRolePolicy\`,
\`secretsmanager:DescribeSecret\`,
\`sqs:GetQueueUrl\`, \`sqs:GetQueueAttributes\`,
\`ec2:DescribeSecurityGroups\`.

IAM role resources must be limited to the six fixed Worker Task/Execution
roles; Secrets Manager to the three database/Redis Secret ARNs; SQS to the
exact Staging command queue; ECS to the Staging cluster/resources. Where AWS
requires a wildcard on a Describe/List API, use account/region/role
conditions and a distinct read-only role rather than broader service
admin permissions. Do **not** add \`secretsmanager:GetSecretValue\`,
\`iam:PassRole\`, \`iam:PutRolePolicy\`, \`ecs:UpdateService\`,
\`ec2:AuthorizeSecurityGroupIngress\`, \`sqs:DeleteMessage\` or
\`iot:Publish\` to the verifier.

The account's reviewed verify-role Policy is pre-provisioned outside this
repository. No new IAM privileges are granted by creating the Day40 code;
a missing required read permission blocks the deployment.

## Job integration / admission

\`.github/workflows/day37-aws-staging.yml\` runs this as part of the existing
protected \`verify\` Job, after ECR/ALB validation and Day39 live Worker
identity verification. It only runs when \`DAY37_ENABLE_WORKERS == 'true'\`
and uses previously configured \`DAY37_...\` Staging environment variables.
A missing/empty prerequisite or extra IAM policy aborts the Verify Job.
The pair of JSON receipts is uploaded as
\`day39-verified-workers-<run-id>-<attempt>\`, never as a secret value.

Read-only comparison is **not** proof of successful RDS authentication,
actual Redis TLS AUTH, SQS idempotent delivery, IoT publish receipt, Campaign
ECU proof, IAM resource policy effects, or credentials rotation continuity.
These remain independent Real AWS Runtime Acceptance requirements.

## Release decision

- \`WORKER_IAM_CONFIG_OBSERVED\`: actual AWS metadata equals independently
  reviewed security/configuration contract for all **enabled** isolated
  Workers, and no unauthorized permissions or configuration are observed.
- \`DAY40 WORKER BLOCKED\`: any IAM mismatch, shared Campaign DB identity,
  configuration drift, missing metadata, missing authorization or absent
  source binding.
- \`STAGING_ACCEPTED\`: never produced by Day40; requires later OTA E2E,
  fault injection, RLS, credential cutover, SLO and independent evidence gates.

No AWS Apply, role changes, credentials publication or live AWS verification
is performed merely by committing this workflow.
