# Day41 — ECS Worker scale-in lifecycle and recovery contract

**Scope:** AWS Staging, Fargate Outbox / Remote Command / Campaign; read-only
and unit-test evidence until an independently approved real AWS deployment.
This file does not authorize AWS Apply or production rollout.

## State ownership and zero-replica scaling

Terraform `infra/terraform/environments/ota-staging/worker_base.tf` now keeps
`local.worker_active` based ONLY on the reviewed service-level enablement
flags. After `enable_service=true` and `enable_workers=true`, the three
service addresses remain present in State even at `worker_desired_counts`
`{outbox:0,remote_command:0,campaign:0}`. Changing a count from 1 to 0
updates `aws_ecs_service.worker["..."].desired_count`; it does **not**
delete the ECS Service, Task Definition, SG, IAM role or CloudWatch log group.
`prevent_destroy` remains a hard brake.

Never change `enable_workers=false` as the scale-in mechanism after services
exist: that is an explicit Terraform resource deletion attempt and should
be blocked. If any legacy State ownership was created with dynamic
`desired_count > 0` keys, review Plan/State manually. Do not run
`terraform state rm`, `-lock=false`, or an unreviewed Apply as a workaround.

Dormant Worker Task Definitions may exist while their runtime-only endpoints
are not ready. Those preconditions are enforced on a positive desired count.
Actual IAM/Secret/DB handoff and Campaign trust-root approval are separate
mandatory runtime gates.

## Batch lifecycle (all three Workers)

1. An AWS Staging worker must have `ECS_AGENT_URI` injected by ECS; the
   application validates it as a local/link-local HTTP agent URI and uses
   `PUT $ECS_AGENT_URI/task-protection/v1/state` with
   `{"ProtectionEnabled":true,"ExpiresInMinutes":10}`.
2. **Only after the agent confirms protection**, Outbox may claim PostgreSQL
   lease rows, Remote Command may begin SQS receive, or Campaign may dispatch.
   Agent failure/denial blocks all new intake; there is no unsafe fallback.
3. While work is in progress, refresh protection every 60 seconds. One
   Outbox or Remote Command operation has the existing bounded Worker
   operation deadline; Campaign has a 90-second dispatch deadline.
4. After durable processing, acknowledgement, or a handled operation failure,
   clear protection via the agent endpoint in a `finally` boundary.
   The ECS Fargate `stopTimeout=120` supports graceful SIGTERM shutdown.
5. If release fails, the task exits rather than accepting more work.
   Protection TTL is finite (10 min), preventing an indefinite protected
   orphan from permanently blocking a deployment. Operators must still
   reconcile DB/SQS and observe ECS deployment events.
6. Existing PostgreSQL Claim/lease, idempotency and SQS redelivery remain
   authoritative for crashes, lost ACK, health failures and forced stops.
   ECS protection does **not** provide exactly-once device execution or
   protect an ECU's entire download/install process.

AWS Task Role requires `ecs:GetTaskProtection` and
`ecs:UpdateTaskProtection`, constrained to the Staging ECS cluster/task
ARN resource. The app calls only the **self-agent** endpoint, not arbitrary
ECS service mutation APIs. A same-cluster task ARN IAM scope is not
cryptographic per-Task identity isolation; do not grant broad
`ecs:UpdateService` or `ecs:StopTask`.

## Controlled scale-in and rollback

- Stage 0: confirm real AWS Worker identity/tenant/Secret/SG and
  current RDS/SQS reconciliation, Checkov, Day35, Day37 and Day38 gates.
  Campaign is still BLOCKED for independent-identity acceptance until its
  shared application DB role and trust-root delivery are fixed.
- Stage 1: use the protected GitHub deployment path and a **saved,
  independently approved Terraform Plan**, checking that Worker Service
  actions are only `update` of `desired_count`; any `delete` or
  `replace`, IAM widening or SG widening must BLOCK.
- Stage 2: set a count to 0 *with* `enable_workers=true`. ECS protects
  in-flight Tasks and terminates idle Tasks. An active protected Task can
  delay the Plan Apply/wait-for-steady-state; do not bypass its guard.
- Stage 3: independently verify the service remains ACTIVE, desired and
  running count are zero, no RUNNING Task remains, Task Definitions and
  IAM roles persist, and PostgreSQL/SQS have no inconsistent Claims.
  `scripts.day39_worker_verify` now rejects a missing zero-count service
  instead of reporting an ungrounded disabled state.
- Stage 4: on `DEPLOYMENT_BLOCKED`, blocked Apply, stale protected Task,
  DB lease timeout, or unexpected DLQ growth, stop the release. Investigate
  ECS service events and `GetTaskProtection`. Wait for bounded work and
  protection release/expiry; do not force SIGKILL or clear protection on
  an unreviewed in-flight Task. Reconcile and approve recovery independently.

**Required AWS test evidence** (not performed by this code commit):
protected task during 1→0 scaling, 0→1 reactivation with pinned image,
SIGTERM during processing, force stop/crash and lease/visibility recovery,
SQS duplicate/ACK loss, failed agent protection, expired protection,
renewal failure, and campaign security blocking. Bind to source SHA,
Run/Attempt, Terraform Plan hash, cluster, Task ARN, ECR Digest and
resource/account ID. Missing evidence = BLOCKED, not STAGING_ACCEPTED.

References:
- https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-scale-in-protection.html
- https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service.html
