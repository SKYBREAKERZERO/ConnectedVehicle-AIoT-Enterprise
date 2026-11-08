# Day38 / Day37 enterprise acceptance convergence

## Scope and immutable safety boundary

This is a **read-only CI candidate** on Draft PR #18, stacked on Day37 PR #16. It is not an AWS deployment approval, not an ECS/ECR deploy, and not physical ECU evidence. PR jobs do not have AWS OIDC/`id-token: write`, and none of these changes applies Terraform to cloud resources.

Day37 `admission()` must reject every Plan/Bootstrap/Deploy unless the current protected-main SHA has latest completed successful Runtime, IaC, Day35, Day36 AND Day38 offline evidence. Day38 includes the latest run/attempt, candidate source, original GitHub artifact checksum and 22 stage proofs. An earlier green run cannot cover a newer failed or pending one.

## Risk ledger — do not declare unresolved controls passed

| ID | Scope | Evidence / disposition |
|---|---|---|
| 01 | Manual dispatch trust | Job only runs trusted read-only observer when dispatched from `refs/heads/main`; Python checks main SHA and current branch head. Non-main must be BLOCKED. |
| 02 | Mutable PR `offline_gate` | **OPEN**. A PR-controlled workflow does not constitute an independent, immutable validator. Implement org-level required workflow or trusted GitHub App status and enforce it in the Ruleset with reviews. |
| 03 | PostgreSQL RLS/GRANT | Actual PostgreSQL 16 sessions and runtime roles exercised by Runtime integration CI. **OPEN for AWS RDS 17:** separately attest PostgreSQL roles, RLS, grants, pooled sessions, tenant isolation, `force_ssl` and TLS rejection after approved AWS staging deployment. |
| 04 | ECU / signature / publisher key / Claim | Tests cover signed OTA/Claim and independent simulated-device boot. **OPEN for real ECU/device and actual key revocation** with independently captured runtime evidence. |
| 05 | Checkov | RDS `CKV2_AWS_69` static violation resolved through `rds.force_ssl=1` bound parameter group. **OPEN:** application and Redis auth secrets, `CKV2_AWS_57` twice. Never add waivers or fake rotation resources. |
| 06 | Latest-run override | `scripts.day38_readiness.selected_runs` selects latest matching upstream run/attempt; failed/pending result denies. Unit regression exists. |
| 07 | Negative fault evidence | Twelve independent probe JSON receipts + SHA-256 index retained in an artifact; trusted reviewer downloads and hashes each exact case, source, run, attempt, release-denial result. **Not hardware fault evidence.** |
| 08 | Duplicate Terraform/Checkov | **OPEN / P2**: do not deduplicate until a trusted validator independently proves exact source/run/attempt and native Runner jobs. Checkov failures remain intentional. |
| 09 | GitHub main Ruleset | Ruleset `24828733` currently requires `Runtime quality gate` and `IaC quality gate` only. **OPEN:** Day38 is not currently a required check. Requires explicit governance approval after Day38 is merged to protected main and independent gate installed; do not modify ruleset from this PR. |
| 10 | Evidence source binding | Manifest SHA, candidate SHA, run/attempt and aggregate hashes enforced. Full 22-stage independent artifact download/re-hash is the final source-level hardening; store only JSON/XML receipts, never secret or State. |
| 11 | Day37 deployment admission | `scripts.day37_gate.admission()` has fail-closed dependency on trusted Day38 offline same-SHA/run/attempt proof. **Not live AWS acceptance:** verify actual protected-main `workflow_dispatch` admission refusal in a controlled test. |

## Secret rotation exit criteria (must be genuine)

- **Application database credential:** real scoped database user, AWSCURRENT/AWSPENDING version control, `createSecret`/`setSecret`/`testSecret`/`finishSecret`, VPC/IAM/KMS least privilege, idempotent lock, rejected stale version, rollback, and live independent PostgreSQL session tests.
- **Redis authentication token:** real AWS ElastiCache rotation via supported ROTATE/SET overlap; clients can refresh credentials; AWSPENDING/AWSCURRENT move only after successful independent connection; bounded retries and rollback. Treat Terraform `auth_token_wo` and state as nonexportable.
- Only after each rotation actually works should `aws_secretsmanager_secret_rotation` be configured and `CKV2_AWS_57` re-run. Do **not** configure empty Lambda functions or skip the checks.

## Promotion order

1. Pass native Ruff, mypy, pytest, Terraform static tests and correctly BLOCK on current Checkov findings in Draft PR #18.
2. Merge prerequisites via reviewed PRs, establish independently trusted Day38 gate and branch protection; validate ruleset after applying approved configuration.
3. Implement and independently test both Secrets Manager rotations; repeat exact-source CI.
4. On approved main and verified environment, perform explicit AWS Staging Plan/Bootstrap/Deploy under Day37 workflow, record ECR image digest, ECS actual tasks, RDS TLS and zero-drift closure.
5. Execute independent ECU and live database least-privilege attestation. Physical ECU validation is a distinct gate, not implied by LocalStack.

Status labels: **CODE_READY** is not **CI_PASS**; **OFFLINE_AUDIT_PASS** is not **AWS_VERIFIED**; **READY_FOR_STAGING_REVIEW** is not deployment authority.
