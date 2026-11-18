# Day39 — AWS Staging ECS Workers (fail closed; default OFF)

The Day39 files provision an **isolated Staging-only worker foundation** and
**optional** ECS services. They do not constitute an executed AWS Deployment.
All roles use GitHub-reviewed IAM trust or ECS task trust; PR CI has no AWS
deployment credentials. Neither `terraform plan` nor offline CI proves OTA
runtime acceptance.

## Entry points and separation

| ECS Service | Image command | Database Secret | AWS IAM |
| --- | --- | --- | --- |
| `cv-ota-staging-outbox` | `python -m apps.outbox_worker.main` | `/connected-vehicle/staging/database/outbox` | Read exact Secret; SQS GetQueueUrl/SendMessage |
| `cv-ota-staging-remote-command` | `python -m apps.remote_command_worker.main` | `/connected-vehicle/staging/database/remote-command` | Read exact Secret; SQS Receive/Delete/Visibility; IAM-scoped AWS IoT Publish |
| `cv-ota-staging-campaign` | `python -m apps.campaign` | **Currently shares application DB credentials** | Read application Secret, optional pinned S3 GetObjectVersion |

Each gets a separate Task Role, execution role, private SG, CloudWatch
log group, 512 CPU units / 1024 MiB, readonly root with bounded scratch,
SIGTERM handling, stop timeout 120s, and a bounded 0–2 desired count.
No public IP, inbound Worker listener, ECS Execute Command or Spot.

**Campaign is NOT approved for cloud activation yet:** it needs a real
immutable, signature-reviewed OTA trust root at the configured in-container
path, S3 object-version access matched to manifest prefixes, and
a separate least-privilege database principal instead of `app_user`.
The `campaign_trust_root_ready` bool is an administrative declaration,
not evidence of actual file access. Leave Campaign count 0 until the
independent runtime gate verifies those prerequisites.

## SQS and AWS IoT Core

The Terraform Bootstrap creates:
`cv-ota-staging-command` (SQS Standard, SSE-SQS, 120s visibility) and
`cv-ota-staging-command-dlq` (14d retention). Redrive after five receives
is not successful task completion; Claim/Lease and PostgreSQL business
idempotency must withstand redelivery.

Remote Command never uses local Mosquitto in AWS. It uses IAM-signed
AWS IoT Core Data Plane over HTTPS with QoS1/non-retained Publish to
`tenants/<approved-tenant>/vehicles/<vehicle-id>/commands`. The Task Role
policy limits `iot:Publish` to that tenant's topic pattern.
An independent operator must verify the endpoint with
`aws iot describe-endpoint --endpoint-type iot:Data-ATS` and verify the
vehicle subscription / identity policies in AWS IoT. Merely matching a
hostname regex is NOT authoritative endpoint ownership proof.

Redis connections in AWS now use `SSLConnection` with
`ssl_cert_reqs="required"`, including API and Remote Command runtime.
The Remote Command ECS **execution role**, not Task Role, may read the
dedicated Redis Secret and decrypt it only through Secrets Manager.
AWS Secrets injected at Task start are not refreshed live. Credential
rotation therefore requires controlled task replacement, Client/Redis
token reconciliation, and independent proof.

## Deployment sequence and stage controls

1. Day38 / Day35 / Day37 offline mandatory gates must pass on exact main SHA.
2. Independent Foundation / Credentials Bootstrap (see
   `docs/DAY39_FOUNDATION_CREDENTIALS_BOOTSTRAP.md`) must complete in real
   Staging. All three tenant-specific PostgreSQL roles and four Secrets
   require real login/rotation evidence.
3. Review the **separate** Day37 bootstrap saved Plan. Explicitly
   approve SQS + DLQ, Worker IAM, private SG rules and log groups.
   Never conflate these creations with deploy-phase ECS resource changes.
4. Configure protected GitHub Staging Environment variables:
   `DAY37_OUTBOX_DB_SECRET_ARN`, `DAY37_REMOTE_DB_SECRET_ARN`,
   `DAY37_IOT_DATA_ENDPOINT`, `DAY37_ENABLE_WORKERS`,
   `DAY37_WORKER_COUNTS_JSON`. Their names/ARNs must be exact, account-
   bound, and reviewed. Default is `false` / all-zero counts.
5. Apply the exact approved Bootstrap Plan, inspect SQS/DLQ and per-role
   IAM through **actual** AWS APIs and run cross-role negative permission
   tests. An SQS policy simulation alone is insufficient.
6. After API staging release and ECR manifest verification, approve a
   second saved ECS-only Plan. **Start with Outbox count 1**, Remote and
   Campaign 0. Confirm Outbox safely creates one SQS event per committed
   Outbox record and self-recovers on SIGTERM/crash.
7. Only after AWS IoT Data ATS endpoint, vehicle topic authorization,
   Redis TLS and SQS recovery are proven, review enabling Remote
   Command count 1. No local/Mosquitto fallback on cloud.
8. Keep Campaign count 0 until its own DB identity, immutable trust
   root, S3 access, and OTA Canaries are independently verified.
9. The Day37 Verify Role runs `scripts.day39_worker_verify` and requires
   exact Task Role/Execution Role/Image Digest/tenant/command/count.
   If any assertion fails, the existing recovery fence remains active.
   This verifier is **read-only** and does not prove end-to-end OTA.
10. An independent AWS Runtime Acceptance job must test real SQS
    redelivery, lost HTTP acknowledgment, PostgreSQL locks/RLS,
    Worker SIGTERM/restart, ECU replay/installation proof,
    Campaign pause/reconcile and DLQ operations. Approval requires
    evidence tied to Commit SHA, image Digest, Terraform Plan hash,
    account/region, GitHub Run/Attempt, service ARNs and result.

## Live command for independent observation

Only after a separately approved ECS Deploy and with an authorized
`cv-ota-staging-verify` identity, run:

```bash
python -m scripts.day39_worker_verify \
  --account-id "$DAY37_ACCOUNT_ID" \
  --cluster cv-ota-staging \
  --tenant "$DAY37_TENANT_ID" \
  --digest "$APPROVED_ECR_REGISTRY_DIGEST" \
  --counts-json '{"outbox":1,"remote_command":0,"campaign":0}' \
  --output evidence/day39-workers-observed.json
```

This outputs `WORKER_IDENTITY_VERIFIED` or **fails closed**.
It cannot claim `STAGING_ACCEPTED`: additional SQS/OTA acceptance
and independent evidence binding are mandatory.

## Remaining operational blockers

- No real AWS Plan/Apply, ECS Runtime, SQS/IoT publishing or cost evidence
  has been executed by this source-only PR.
- Task Scale-in Protection and ABS/AIMD are separate Runtime improvements;
  do not report those capabilities as enabled.
- SQS/DLQ alarm, pending-lease reconciliation, stopped-Task event alarm,
  signed firmware trust-root distribution and actual EFS/scratch ownership
  still require real integration validation.
- Verify-role permissions for `ecs:DescribeServices`, `ecs:ListTasks`,
  `ecs:DescribeTasks` and `ecs:DescribeTaskDefinition` are mandatory
  for real observation; neither permissions nor AWS success can be
  inferred from a Terraform static Plan.
