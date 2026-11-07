> Installation note (2026-10-20): This overlay was manually merged into newer commit 41a811b, preserving its OU ownership, retirement safeguards and provider schema contract. Local governance uses policy_types[].type (not the package's incorrect .name), retains manage_ou and retired_environments, and verifies OU subtree membership. Original contracts remain; package contracts are in day20_overlay.tftest.hcl. See DAY20_LOCAL_INSTALL_REPORT.md for actual execution results.

# Day20 — Acceptance & Execution Record

**Snapshot inspected:** GitHub repository `SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise`, WIP branch `wip/day20-infra-20261018`, commit `fc9033836285d84f5ff5be84d29711875d78e1f0` (2026-10-19). The baseline main commit for Day19 is `18c347d78a8fb492495dfcc1cd19cf93c862b60a`.

**Delivery strategy:** a safe-overwrite overlay ZIP, not a pushed GitHub commit, not a merged PR, not a self-contained source ZIP. Existing Python OTA business state machine, PostgreSQL migrations and GitHub workflows are NOT changed. The installer refuses unexpected local edits and expects the actual WIP commit in history.

## 8-hour checklist

| Hour | Work | Evidence delivered |
|---|---|---|
| 1 | Bootstrap and Terraform baseline review | existing `bootstrap/state-backend` verified in GitHub; retained as-is; contract tests added |
| 2 | Day17–19 source-to-runtime dependency audit | `DAY20_INFRA_COVERAGE.md` |
| 3 | OTA S3/IAM/KMS/Secret security boundaries | `DAY20_OTA_RUNTIME_ACCESS_MATRIX.md`, corrected artifact policy |
| 4 | API/Campaign/Outbox/Remote identity planning | Role boundary matrix and noted Campaign PostgreSQL identity gap |
| 5 | Terraform module and stage/scope interfaces | updated `ota-governance/*.tf`; safe-offline modes |
| 6 | Terraform contract testing coverage | native `.tftest.hcl` files in each new module |
| 7 | Regression validation | local Python sanity checks; **Terraform/Checkov/CI results pending** |
| 8 | Deliverable and traceability | overlay installer, artifact hashes, this acceptance record |

## Code-level changes included

- `ota-governance`: fixes provider `policy_types[].name`, stage separation, OU/account target mapping, topology-to-enforce OU ownership continuity, exact OU direct membership checks, partition match, firmware vs state object deletion, KMS key policy freeze; defaults offline/topology/OU.
- `ota-artifact-policy`: accepts real Day17 firmware path layout (`body/2.0.0/firmware.bin`) and prevents explicit wrong encryption while permitting requests that rely on default bucket SSE-KMS.
- `ota-secrets/versions.tf`: discovered by `scripts/iac/gate.py` (which scans only `versions.tf`); installer safely deletes the old duplicate `version.tf`.
- Native mock contract files: governance, bucket, artifact IAM, runtime IAM, Secrets and Bootstrap.
- `DAY20_INFRA_COVERAGE.md`, `DAY20_OTA_RUNTIME_ACCESS_MATRIX.md`, `verify_overlay.py`, tests and safe installer.

## Local validation status

- [x] Source file and dependency inspection against WIP branch.
- [x] Offline Python tests / structural sanity (refer to terminal execution result, when actually run).
- [ ] Terraform CLI 1.14.7 `fmt`, `init`, `validate`, `test` (not available in delivery container).
- [ ] Checkov (not available in delivery container).
- [ ] LocalStack/Docker apply and real S3/KMS negative tests (not executed).
- [ ] GitHub PR CI run on a pushed candidate commit (not initiated).
- [ ] Real Organizations SCP enforcement (explicitly out of scope through Day54).

## Apply on developer machine (PowerShell)

```powershell
# 1. Ensure you are on the WIP branch and preserved any local work.
cd D:\project\ConnectedVehicle-AIoT-Enterprise
git checkout wip/day20-infra-20261018

# 2. Extract archive to a separate directory. Preflight without touching worktree.
$pkg = 'D:\Downloads\ConnectedVehicle_Day20_Complete'
& "$pkg\INSTALL_DAY20.ps1" -ProjectRoot (Get-Location).Path -VerifyOnly

# 3. Only if preflight succeeds, install. Unknown modifications are refused.
& "$pkg\INSTALL_DAY20.ps1" -ProjectRoot (Get-Location).Path

# 4. Check and format ONLY the new/reviewed files.
python .\scripts\day20\verify_overlay.py
python -m pytest .\tests\unit\day20 -q
terraform fmt -recursive .\infra\terraform\modules\ota-governance
terraform fmt -recursive .\infra\terraform\modules\ota-artifact-policy
terraform fmt -recursive .\infra\terraform\modules\ota-artifact-bucket
terraform fmt -recursive .\infra\terraform\modules\ota-runtime-iam
terraform fmt -recursive .\infra\terraform\modules\ota-secrets
terraform fmt -recursive .\infra\terraform\bootstrap\state-backend
terraform fmt -check -recursive .\infra\terraform

# 5. Contracts, no real AWS keys or API calls. 'terraform test' uses mock AWS provider.
$modules = @(
  'infra/terraform/modules/ota-governance',
  'infra/terraform/modules/ota-artifact-bucket',
  'infra/terraform/modules/ota-artifact-policy',
  'infra/terraform/modules/ota-runtime-iam',
  'infra/terraform/modules/ota-secrets',
  'infra/terraform/bootstrap/state-backend'
)
foreach ($module in $modules) {
  Push-Location $module
  try {
    terraform init -backend=false
    if ($LASTEXITCODE -ne 0) { throw "init failed: $module" }
    terraform validate
    if ($LASTEXITCODE -ne 0) { throw "validate failed: $module" }
    terraform test
    if ($LASTEXITCODE -ne 0) { throw "test failed: $module" }
  } finally { Pop-Location }
}

# 6. Perform ordinary repository checks and IaC Gate, then inspect plan and PR diff.
python -m ruff check .
python -m ruff format --check .
python -m pytest tests/unit/iac -q
git diff --check
git status -sb
```

Existing full IaC Gate (`python -m scripts.iac.gate --baseline <checkout-of-main-base>`) additionally requires Docker, Terraform, Checkov and a separate clean baseline checkout. The runner creates disposable LocalStack resources itself. Do not point any of these commands at real AWS endpoints or inject real AWS credentials.

**Do not merge this overlay or claim enterprise acceptance until the Terraform contract checks and existing dual CI gates pass.** If the WIP branch has diverged or installer blocks modified files, review each mismatch rather than forcing overwrites.
