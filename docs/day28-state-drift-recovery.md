# Day28 — State disaster recovery, drift and release reconciliation

## Baseline and boundaries

Day27 commit `f9040c6487e38001a8a868ddf07828ab45e9ef05` passed both
[IaC 40496307466](https://github.com/SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise/actions/runs/40496307466)
and [Runtime 40496307034](https://github.com/SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise/actions/runs/40496307034).
Its offline release model, native lock/process-kill test and production limitations
remain in force. Day28 adds no second locking mechanism and enables no deployment.

All resource mutation below is confined to a new test-owned disposable LocalStack.
No real AWS credentials, production Apply, state push, force-unlock, active-backend
repair, GitHub approval or PR merge is performed. The production dry-run workflow,
OIDC boundary, main review rules, Environment controls and remote-backend example
remain unchanged. A successful evidence report never grants READY or Apply rights.

## State integrity and trustworthy version records

`scripts/iac/state_integrity.py` compares state bytes and the observed backend
context with a separately authenticated record containing:

| Field | Requirement |
| --- | --- |
| Account / environment / bucket / key | Exact reviewed backend scope |
| Object VersionId | Exact approved immutable version, not `null` or unspecified |
| SHA-256 | Exact state bytes, not ETag/MD5 |
| Lineage / serial | Exact trusted snapshot; rollback or unexpected advancement rejects |
| Commit / Run ID / Attempt | Exact recorded source and execution identity |
| State JSON | Version 4, integer serial, valid lineage, outputs/resources structure; no duplicate keys/nonfinite values |

Missing, empty, oversized or corrupt state blocks processing. Matching hashes do
not override invalid structure, a wrong version/scope or rejected/unavailable
record authority. Local `local:1` provenance is accepted only for dummy-account
LocalStack records; it cannot label production state as CI-verified.

The validators do not discover S3 ownership or authenticate a reviewer from arbitrary
JSON. `validate_record` checks syntax only. Actual authorization requires the
mandatory trust adapter, authenticated backend identity/record provenance and
trusted current release context. Tests use explicitly simulated adapters. No
production signed version registry, approval service or anti-replay ledger is
claimed. The exact-version rule is deliberately conservative: legitimate state
advancement also needs a new trusted record and review.

## Two drift checks, neither a remediation

`scripts/iac/drift_policy.py` classifies both native Terraform JSON plans:

```text
terraform plan -refresh-only -detailed-exitcode -no-color
terraform plan               -detailed-exitcode -no-color
```

- Refresh-only compares saved state/output observations with remote resources.
- Normal Plan separately compares the desired configuration with refreshed
  resources; a clear refresh-only result does not clear a normal Plan difference.
- Exit 0 is clean only when JSON contains no changes. Exit 2 requires review.
  Exit 1/unsupported codes, incomplete/deferred plans, malformed actions and
  contradictory exit-code/JSON results produce ERROR and block reconciliation.
- No `-refresh=false`, refresh command, refresh-only Apply or automatic repair is
  used by this drift/recovery probe. Provider refresh reads can affect proposed
  state in a saved plan; the test verifies they do not persist backend state.

The pinned fixture manages only the dedicated bucket-versioning resource. It avoids
overlapping bucket/versioning ownership: an independent bucket resource can retain
the pre-versioning observation from the initial Apply and report baseline drift.
That discovery was fixed in fixture design; the rejection policy was not weakened.

## Actual LocalStack fault and recovery rehearsal

`tests/integration/iac/test_state_disaster_recovery.py` fails if its fixture endpoint
or report configuration is missing. `state_dr_probe.py` performs this sequence:

1. Create uniquely named source-state, recovery-state and test-resource buckets
   in the gate-owned emulator. Enable versioning on both state buckets and use
   Terraform's native S3 `use_lockfile=true` backend with dummy credentials.
2. Apply only the single isolated fixture resource initially. Record the resulting
   source state bytes, SHA-256, VersionId, lineage/serial and current source/run.
3. Require clean refresh-only and normal baseline plans and verify neither changes
   the state bytes or object VersionId. Independently observe the actual resource.
4. Suspend the fixture bucket's versioning through the S3 API to inject out-of-band
   drift. Both plans must return 2; resource/state/release reconciliation rejects.
   The resource must remain suspended and source state unchanged after both plans.
5. Deliberately write corrupt state, then create a delete marker on the disposable
   source key to inject real object loss. Both cases must fail integrity checks.
   **DeleteObject here is fault injection, never a repair mechanism.** The original
   healthy historical VersionId remains readable and the damaged active source is
   never restored or un-deleted.
6. Read exactly the separately pinned version and validate bytes/record. A modeled
   independent approval binds source version/hash/run and the different disposable
   target backend. Missing, expired, revoked, self or changed approval is denied;
   a reported old lock blocks recovery admission without any unlock operation.
7. Copy only that version's state object to the different recovery bucket. Validate
   destination version metadata plus identical SHA, lineage and serial. Never copy
   a `.tflock` object. The copy is an automatic **isolated test exercise**, not an
   automatic repair of the active backend or real human approval.
8. Initialize a separate Terraform working directory against the recovery copy.
   Run both plans again, without Apply. Drift still exists, so review remains
   required and the interrupted/old release is rejected. New plan, policy review,
   trusted evidence and independent approval are required for any future request.

The fixture is protected by an explicit loopback-only endpoint and dummy-credential
guard. Each init uses the committed lock with `-lockfile=readonly`. The gate's
official download cache may be reused, but `.terraform/providers` is never manually
copied and no lockfile override/checksum bypass is enabled. Raw state and saved
plans remain inside the private disposable fixture directories. Only the gate's
own emulator container is destroyed during cleanup; other local projects are not
stopped or altered.

The state fixture uses AES256 in LocalStack, not real AWS SSE-KMS. Real AWS account
ownership, effective IAM, KMS/replication, network partitions, cross-region restore,
RPO/RTO, authenticated approval and central ledger reconciliation remain unverified.
The synthetic known-good version is from the same exercise run; production recovery
from historical runs requires a separately authenticated version/approval registry.
This is scoped managed-resource drift verification, not continuous fleet/account-wide
monitoring or proof about unmanaged attributes and resources outside the fixture.

## Release reconciliation

`reconciliation_errors` links a fresh VERIFIED release with current trusted context,
validated state identity/version/hash and independent resource identity/fingerprint.
Drift, error, changed State, a previous Run/Commit, a mismatched resource, unavailable
authority, READY reuse or INTERRUPTED status rejects. It does not reset the Day27
ledger, approve recovery or execute a deployment. Its inputs must come from actual
validated reads; an independently authenticated control plane is still future work.

Even after a byte-perfect restore, old approvals and a historical state snapshot
cannot prove the resources are correct. Preserve the original failure and version
evidence privately, reconcile owner/lock and resource outcomes, then request a new
reviewed plan. Never delete production state, force-unlock based on age alone, or
apply the first plan that happens to become executable.

## CI order and evidence

Existing IaC unit/native contracts, scanner, Day27 lock/fault checks and isolated
second-plan tests run first. Day28's real LocalStack DR test then runs in the same
test-owned emulator. After the gate, the Day27 proof is rechecked, followed by:

```powershell
python -m scripts.iac.day28_evidence --verify
```

There is no empty-report generator. Verification requires successful full unit
JUnit, all mandatory Day28 scenarios, successful real DR JUnit, matching test-time
Commit/Run/Attempt/source digest, both saved-plan hashes, source/destination state
records and safe outcome flags. Failed/skipped/duplicated/missing cases, changed
source/run, absent versions/hashes, active-backend restoration or a report claiming
AWS/human validation all fail closed. The Day27 fault proof is also revalidated.

The mandatory `day28-state-drift-recovery` artifact retains seven days:

- `day28-governance.json`: verified source/run, policy scenarios, state version/hash
  records, full-unit and DR XML/report hashes, explicit non-production boundaries.
- `day25-security.xml`: historical filename for the full current Days25–28 IaC
  suite; no duplicate selective run or empty PASS report replaces it.
- `day28-dr.xml`, `day28-dr.json`: actual emulator fault result, both plan exit
  codes/classifications and binary-plan SHA-256 summaries, without plan/state data.

Report bindings are not cryptographic attestation against a malicious workflow.
Reviewed source, GitHub controls and authenticated future production adapters remain
necessary. Runtime quality checks stay mandatory and unchanged.

Local policy checks:

```powershell
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m ruff format --check .
.venv/Scripts/python.exe -m mypy .
.venv/Scripts/python.exe -m pytest -c scripts/iac/pytest.ini tests/unit/iac -q --junitxml=.iac-reports/day25-security.xml
```

For the opt-in integration, supply only a disposable loopback LocalStack through
`DAY28_DR_ENDPOINT`, a private `DAY28_DR_REPORT` path and optionally the existing
official `DAY28_PROVIDER_CACHE`. CI provisions these automatically. Run evidence
verification only after the integration and Day27 fault proofs exist.

References: [HashiCorp S3 backend versioning](https://developer.hashicorp.com/terraform/language/backend/s3),
[Plan modes and detailed exit codes](https://developer.hashicorp.com/terraform/cli/commands/plan),
[refresh-only review](https://developer.hashicorp.com/terraform/tutorials/state/refresh).
