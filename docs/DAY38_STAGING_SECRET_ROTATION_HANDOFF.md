# Day38 AWS Staging Secret Rotation Handoff (fail closed)

## Why this exists

The earlier `ota-staging-foundation` root defined two **metadata-only** `aws_secretsmanager_secret` resources for `application` and `redis_auth`, with no initial `AWSCURRENT` credential and no automatic rotation. Real Checkov 3.3.26 flagged both as `CKV2_AWS_57`. Attaching `aws_secretsmanager_secret_rotation` to those empty secrets would initiate an invalid rotation/test before application credentials exist. An inline skip or scanner exception is prohibited.

## Authorized deployment sequence

1. **Administrator only:** review the exact Terraform Plan for Foundation and enforce no destructive actions, unknown provider ownership, or cross-account resources. Foundation creates RDS PostgreSQL 17 and TLS Redis/Valkey; it **does not create application/Redis Secrets**. Do not apply Foundation from untrusted PR CI or as a GitHub deploy runtime identity.
2. **Bootstrap after RDS is ready:** create the tenant-scoped `app_user` database principal and least-privilege grants with an independent credential bootstrap. Maintain FORCE RLS, controlled state transitions, and separate migration credentials; verify the login as the application principal.
3. **Privileged credentials handoff:** an independent reviewed administrator provisions `/connected-vehicle/staging/database/application` and `/connected-vehicle/staging/redis/auth` in `ap-northeast-1`, the exact staging account and dedicated customer-managed data KMS key. Both must contain a legitimate `AWSCURRENT` version. Never pass plaintext through `terraform.tfvars`, Terraform State, CI artifacts, logs or PR comments.
4. **Real rotation implementation:** independently provision and test a narrowly scoped Secrets Manager rotation Lambda for EACH secret, with Secrets Manager invoke permission and rotation schedule. PostgreSQL rotation must preserve the actual `app_user`/RLS permission boundary and avoid lost credentials under concurrent sessions. Redis rotation must safely coordinate `AWSPENDING`, ElastiCache AUTH token transition (including `ROTATE`/`SET` as appropriate), application clients, and `AWSCURRENT`; explicitly reconcile externally rotated token state with Foundation's write-only `auth_token_wo` / `auth_token_wo_version` inputs before future infrastructure changes. A Lambda ARN or schedule alone is **not** rotation proof.
5. **Independent live review:** verify `DescribeSecret` reports the exact ARN/name/KMS, `RotationEnabled=true`, same-account/same-region Lambda ARN, rotation rules, a genuine `LastRotatedDate` and `AWSCURRENT`. Verify real DB authentication and Redis TLS AUTH after an actual rotation, concurrent Worker processing, a revoked old credential, audit trail and rollback/recovery. The Day37 read-only live preflight checks metadata without reading secret values. The separate application Terraform root additionally gates ECS enablement using data-only rotation metadata lookups. **No real AWS integration has been executed by this PR.**
6. **Release admission:** reject if the rotation test, application startup, RLS, Redis authentication, credentials reconciliation, CI Checkov or other mandatory gate is missing/failed. Do not treat a green offline IaC scan as AWS permission to release.

## Existing deployed Foundation state

Removing the legacy Terraform Secret resources is safe for an **unapplied** Foundation root. If a deployed Terraform State already owns either legacy resource, a normal Plan may propose **destroy**. Do **not** apply that Plan or delete the secret. Require a separate, independently approved state-ownership migration (retain the live secret, ensure reviewed new lifecycle ownership, re-run Plan and evidence admission). Never use unattended `terraform state rm` or `-lock=false` as a workaround.

## Invariants enforced in source

- No production/real AWS deploy credentials in PR CI; no new Checkov exceptions or inline skips.
- The pre-bootstrap Foundation owns no Secrets Manager metadata resources and never stores Secret values in State.
- The deploy-only (`enable_service=true`) application root requires named, encrypted Secrets and enabled, scheduled, same-account Lambda rotation.
- Day37 live preflight requires a current version and evidence of actual prior rotation. It remains read-only and cannot authorize Apply.
- Redis `auth_token_wo` drift and real rotation concurrency are **operational release blockers** until independently exercised in AWS; Terraform metadata cannot prove them alone.
