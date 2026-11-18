# Day39: independent Foundation and Credentials Bootstrap (AWS Staging)

**Status:** Code-level guards and negative tests only until executed by authorized
administrators against a real AWS Staging account. A green PR or Day38 offline gate
is **not** Foundation Apply, a database bootstrap, an actual credential rotation,
or release authorization. The new read-only handoff tool never mutates AWS.

## Fixed trust boundaries

| Stage | Identity / authority | Preconditions | Changes permitted |
| --- | --- | --- | --- |
| Day38 PR | GitHub read-only CI; no AWS OIDC | Immutable candidate | Source / IaC / unit / evidence only |
| Foundation | Independently provisioned `cv-ota-staging-foundation-admin` | Approved AWS account/region, private State, saved Plan, approved request | Dedicated `ota-staging-foundation` Terraform root only |
| PostgreSQL bootstrap and migrations | Independently authorized database bootstrap and migration identities | Live private RDS and empty/migration-approved DB | Role creation and separately reviewed Alembic migrations |
| Credentials | Independently provisioned `cv-ota-staging-credential-admin` plus DB bootstrap/migration identities | Exactly three precreated DB Secret containers, matching tenant and RLS, TLS Redis token | Scoped Secret publication and tested rotation only |
| Day37 application delivery | Separate environment-specific GitHub OIDC deploy roles | Fully bootstrapped Foundation + Secrets rotation | Approved immutable ECR/Task/Plan change only |
| Staging auditor | Read-only independent verification | Deployed resources and original receipts | Evidence verification, no state or credential writes |

The two administrator IAM roles above must be provisioned by a separate
reviewed AWS identity workflow with permission boundaries and **no GitHub PR
trust**. They do not exist merely because this Python check expects them.
Do not substitute Day37's deploy/bootstrap OIDC role or a root user.

## 1. Foundation (independent administrator; no automatic Apply)

- Use staging AWS account only, `ap-northeast-1`, verified STS identity,
  dedicated customer-managed KMS, private backend with versioning and locking.
- Use the existing **`infra/terraform/environments/ota-staging-foundation`**
  root with its own S3 State key. An authorized operator runs `terraform init`,
  `terraform plan -out=<secured-plan-file>`, `terraform show -json` and the
  approved plan policy check. Treat the binary Plan and its JSON as sensitive.
- Obtain independent approval binding source SHA, AWS account, State key, Plan
  SHA256, approver, change request and Run/Attempt. `terraform apply` must use
  the **exact saved approved Plan**, never a regenerated unreviewed Plan.
- Do not remove `-lock` / bypass State locking. Fail on any proposed destruction,
  replacement, role escalation or deletion of Secrets from legacy State.
- Confirm RDS PostgreSQL 17 private Multi-AZ, Valkey/Redis encrypted at rest and
  TLS in transit, VPC/network restrictions, encryption key and recovery controls.
- Important: the Foundation receives an ephemeral Redis AUTH token. Its value
  must come from the **same reviewed secure source** used in Credentials
  Bootstrap. Do not record it in tfvars, Terraform State, command arguments,
  GitHub Actions artifacts or operator notes.
- If Secrets from an older Foundation State would be destroyed, **STOP** and
  perform an explicitly reviewed state-ownership migration; never blindly Apply.

Once Foundation has *actually* been applied, a different read-only session
can collect the following **observation-only** receipt:

```bash
python -m scripts.day39_staging_handoff \
  --phase foundation \
  --account-id "$STAGING_ACCOUNT_ID" \
  --data-kms-key-arn "$DATA_KMS_KEY_ARN" \
  --vpc-id "$STAGING_VPC_ID" \
  --source-sha "$REVIEWED_SOURCE_SHA" \
  --output evidence/foundation-observation.json \
  --live
```

The tool checks caller identity, KMS, VPC, RDS and Redis via read-only AWS
APIs. It never creates or approves AWS resources. The operator must have the
separately reviewed `cv-ota-staging-foundation-admin` role.

## 2. Database Bootstrap and tenant-bound Secrets

Never reuse the RDS master secret for the API. Review and execute, under
**separate** database identities, the project's existing operations:

```bash
python -m database.bootstrap_cluster
python -m alembic upgrade head
python -m database.provision_runtime_credentials
```

The example above is **not** a script to run blindly. Prerequisites:

1. Run only from a restricted operator environment with private RDS network
   access, `APP_ENV=staging`, `CLOUD_RUNTIME=aws`, no LocalStack endpoint
   override, exact RDS DNS and tenant ID. RDS master limitations vs PostgreSQL
   local superuser must be verified before changing any role.
2. Set **separate** `BOOTSTRAP_DATABASE_USERNAME/PASSWORD` and
   `MIGRATION_DATABASE_USERNAME/PASSWORD` securely. Never copy secrets to
   source-controlled env files or command-line arguments. Pre-create the three
   metadata-only Secret containers using separately approved scoped AWS admin
   operations and the dedicated KMS key, at:
   `/connected-vehicle/staging/database/application`,
   `/connected-vehicle/staging/database/outbox`,
   `/connected-vehicle/staging/database/remote-command`.
3. Set each matching `APPLICATION_DATABASE_SECRET_ID`,
   `OUTBOX_DATABASE_SECRET_ID` and `REMOTE_COMMAND_DATABASE_SECRET_ID`
   explicitly. Ensure the approved `DATABASE_TENANT_ID` is pinned. Existing
   `database.provision_runtime_credentials` now uses the canonical
   tenant-specific database roles and binds GRANTs to this tenant. The old
   global fallback is not acceptable for Staging.
4. Supply three distinct high-entropy passwords from the authorized secret
   source to the controlled provisioning entry point, in an isolated admin
   process. Do not log, persist or output plaintext passwords. Runtimes must
   remain stopped until all three credentials are atomically reconciled with
   the bounded recovery journal. On failure, inspect and recover using the
   project's existing v2 journal and audit chain.
5. Existing PostgreSQL single-user password rotation uses a **maintenance
   window**, not zero-downtime dual-password semantics. Complete actual
   Lambda-based automatic rotation and maintenance/restart orchestration
   separately; `RotationEnabled` alone does not prove safe behavior.

Redis is deliberately **not** rotated by the PostgreSQL routine. The
separately authorized credential administrator must safely publish the
same token used by Foundation into
`/connected-vehicle/staging/redis/auth` with the reviewed KMS key, verify
actual TLS authentication, configure working Secrets Manager rotation and
reconcile the write-only ElastiCache `auth_token_wo` version source. Test
client replacement and old-token retirement before proceeding.

## 3. Independent Credentials observation

After the three database Secrets and Redis Secret have a real `AWSCURRENT`,
and each has completed one successful automatic rotation, collect a
read-only handoff receipt using the separate credential admin role:

```bash
python -m scripts.day39_staging_handoff \
  --phase credentials \
  --account-id "$STAGING_ACCOUNT_ID" \
  --data-kms-key-arn "$DATA_KMS_KEY_ARN" \
  --vpc-id "$STAGING_VPC_ID" \
  --source-sha "$REVIEWED_SOURCE_SHA" \
  --output evidence/credential-observation.json \
  --live
```

The reader checks the exact AWS account, RDS/Redis, KMS, `AWSCURRENT`,
no unresolved `AWSPENDING`, same-account Lambda, schedule and recorded
last rotation for **all four** Secrets. It does NOT call `GetSecretValue`
or prove database login/Redis token freshness. A separate real Runtime
acceptance must demonstrate actual DB tenant isolation, PostgreSQL login,
Redis TLS AUTH, credential cutover and revocation, audit and recovery.

Receipts carry `rotation_functionality_verified=false` and
`release_authorized=false` by design. They cannot replace the existing
Day37 live preflight or become a fake deployment approval.

## 4. Admission before Day37

- Require two independent administrator observations, secure Plan/Apply
  evidence, actual rotation proofs and RLS/Redis connectivity checks.
- Confirm the **same** Commit SHA, reviewed account, Region, VPC, KMS, image
  digest and intended tenant; reject stale Run/Attempt or an unexpected role.
- Only then invoke existing Day37 Plan/Bootstrap/Deploy with approved main,
  protected environments, approved saved Plan and independent AWS Runtime.
- Day38 remains strictly offline; this is a Staging prerequisite, not a
  production release authorization.

## Current implementation boundary

This change adds a read-only live handoff command, real failure-mode unit
tests, and tenant-bound provisioning fixes. It DOES NOT create administrator
roles, run Terraform Apply, create/publish live Secrets, install rotation
Lambdas, perform a real rotation or attest production readiness. Those steps
require the actual customer's AWS account, private connectivity, independently
approved administrator permissions and retained real Runtime evidence.
