# Day26 — Terraform state and saved-plan governance

Day26 delivers offline security contracts and an isolated LocalStack lock-protocol
test. It does not provision AWS resources, assume an AWS role, migrate state,
enable deployment credentials or authorize production Apply.

## GitHub approval controls

On 2026-10-27, repository ruleset `24828733` was updated and read back:

- Active on exactly `refs/heads/main`, without bypass actors.
- At least one approving review; new pushes dismiss previous approvals.
- Latest reviewable push requires approval by another person.
- Review conversations must be resolved; force pushes and deletion forbidden.
- Strict required checks remain `IaC quality gate` and `Runtime quality gate`,
  tied to the GitHub Actions integration ID 15368.

The existing `production` Environment still requires `SKYBREAKERZERO`, prevents
self review, disables administrator approval bypass and allows only branch `main`.
The owner cannot approve their own PR or their own deployment. An independently
authorized reviewer is needed for an owner-authored release. No successful
independent approval has been exercised. Administrators who can edit repository
settings can change controls; these settings do not eliminate that trust boundary.

The dry-run workflow rechecks the live main ruleset before and after Environment
approval, alongside the existing exact-SHA Runtime/IaC checks. It still has no
`id-token: write`, AWS credentials, credential action or Terraform Apply command.
Read failures or weakened rules fail closed. This workflow remains on PR #15;
GitHub dispatch availability requires a separately reviewed merge to main.

## Remote state design

The existing `bootstrap/state-backend` is LocalStack-only, with dummy credentials
and account `000000000000`. It remains unchanged. Do not reuse it for AWS.

`modules/terraform-state-store` is a new **unwired** production design module:

- A dedicated bucket, versioning, all four Public Access Block settings and
  BucketOwnerEnforced ownership. No force destroy, state expiration or historical
  version expiration; bucket and key have `prevent_destroy`.
- Dedicated rotating SSE-KMS key, 30-day key deletion window; bucket keys disabled
  so KMS context binds exact object ARNs.
- Explicit bucket-policy denials for HTTP, missing/wrong encryption headers,
  another KMS key and foreign/missing principal account.
- Dedicated pre-existing access-log destination, EventBridge notifications and
  SSE-KMS cross-region replication configuration. Inputs require a separate
  account-bound replication role and recovery bucket/key in us-west-2. No scanner
  exception or weakened security gate was added.
- Recovery bucket versioning, region, ownership, replication-role service trust,
  least-privilege source/destination grants, KMS policies, logging destination
  delivery policy, EventBridge consumers and actual delivery are **external
  prerequisites**, not proved by passing variable validation or mock contracts.
- Replication's state-key prefix also matches `.tflock`. Recovery must select a
  reviewed state version, never restore a replicated lock, and never use the
  recovery bucket concurrently as an active writer backend.

| Future identity | State object | `.tflock` object | KMS |
| --- | --- | --- | --- |
| Plan | Get; explicit deny Put/Delete/DeleteVersion | Get/Put/Delete | Exact key, S3 ViaService, account, exact state/lock context |
| Apply | Get/Put; explicit deny Delete/DeleteVersion | Get/Put/Delete | Same constrained key/context |
| Ordinary PR CI | No real AWS grant | No real AWS grant | No real AWS grant |

The exported policies are unattached fragments, not effective-access proof.
They provide no permission to deploy OTA resources. Future plan/apply roles need
separate trust, permission boundaries, resource-policy audit and real AWS denial
tests. Day25's preview identity remains unchanged and insufficient for deployment.

`environments/ota-aws/backend.tf.example` is an inert partial backend example:
`encrypt = true`, `use_lockfile = true`. The bucket, exact state key, account,
region and key ARN must come from a reviewed private backend configuration. It
is deliberately **not named `.tf`**: current CI refuses remote backends and AWS
roots without a read-only state-backed plan gate. Day26 preserves that restriction
instead of initializing an unreviewed cloud backend. No credentials belong in
backend configuration or saved plans.

## Saved-plan admission model

`scripts/iac/plan_admission.py` validates a closed manifest against separately
trusted expected release/state context. It binds:

- Full commit, originating Run ID **and attempt**, production environment, account.
- Distinct exact account-owned plan/apply role ARNs.
- Bucket/key, backend region/KMS key, current state lineage and serial.
- Terraform 1.14.7, provider lock SHA-256 and exact binary saved-plan SHA-256.
- UTC creation/expiration with maximum 30-minute lifetime.
- An independent reviewer receipt binding the SHA-256 of the **entire manifest**,
  approved after plan creation and before the current time.

Changing the plan, target, source, attempt, provider lock, identity or state version
requires a new plan and independent approval. Do not recompute a plan after review
and apply that new result. Future Apply must use the exact admitted binary under
the native backend lock and recheck state immediately before execution.

The receipt input is an **offline model**. Arbitrary JSON is not signed approval;
the validator neither authenticates a reviewer nor checks GitHub approval itself.
Production needs trusted GitHub deployment/review API evidence and attested source
and artifact provenance. A manifest digest alone proves neither authorization nor
the contents/meaning of a Terraform binary plan. Future admission must inspect a
trusted sanitized plan summary and the existing no-destroy policy too.

`reserve_offline_once` demonstrates atomic replay reservation with independent
SQLite connections and a primary-key insert inside `BEGIN IMMEDIATE`. It rejects
the same plan/state/account even after relabeling timestamps or Run ID. A crash
after reservation leaves it spent. **This is not the PostgreSQL Runtime test and
not a production cross-run replay ledger.** Future deployment needs a central,
authenticated, durable conditional-write store with recovery rules; deleting a
local SQLite file would defeat a local-only ledger. No Apply call exists here.

## Evidence and verification

Local validation:

```powershell
.venv/Scripts/python.exe -m pytest -c scripts/iac/pytest.ini tests/unit/iac -q --junitxml=.iac-reports/day25-security.xml
.venv/Scripts/python.exe -m scripts.iac.deploy_governance
.venv/Scripts/python.exe -m scripts.iac.day26_evidence
terraform -chdir=infra/terraform/modules/terraform-state-store init -backend=false -lockfile=readonly
terraform -chdir=infra/terraform/modules/terraform-state-store validate
terraform -chdir=infra/terraform/modules/terraform-state-store test
```

For a standalone module test, copy the committed environment lock into a disposable
module workspace first, as the IaC Gate already does. Do not update provider
versions or checksums to work around a failed init.

IaC CI runs the new unit/native contracts and Checkov plus existing regressions.
The gate's disposable LocalStack additionally tests **Terraform's real S3 backend
lock implementation**: contender times out, original lock stays unchanged, release
allows reacquisition, and a read-only plan leaves no state or lock. It never calls
AWS or Apply. The emulator fixture uses AES256; it does not validate real S3/KMS,
IAM policies, replication, failover or regional durability. The production module
separately requires SSE-KMS through offline contracts.

The mandatory `day26-state-plan-governance` artifact contains sanitized JSON and
full-suite JUnit, retained seven days. Test-time stamps bind SHA, Run/Attempt and
governance source digest; validation rejects failed/skipped tests, missing scenarios,
duplicate cases and relabeled provenance. The IaC summary carries actual lock-probe
outcome/timing. No `.tfplan`, state, private backend config or credentials are
uploaded. GitHub-artifact integrity does not provide independent cryptographic
attestation if the workflow itself is malicious; review remains mandatory.

Before real AWS: configure sandbox budget/cleanup; validate all external storage
prerequisites and effective IAM; test native lock competition on AWS; perform an
encrypted version restore drill; provision the authenticated replay/approval
control plane; then separately approve any deployment workflow change. These are
pending and must not be described as Day26 production acceptance.

References: [HashiCorp S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3),
[backend configuration and saved plans](https://developer.hashicorp.com/terraform/language/backend),
[GitHub ruleset controls](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).
