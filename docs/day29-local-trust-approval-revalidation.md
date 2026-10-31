# Day29 first 4h — Local registry, recovery approval and fresh verification

## First-session scope (historical)

This change adds three core modules and three unit suites. It does not change
Terraform modules, PostgreSQL Runtime schemas, workflow files or production
permissions. LocalStack faults, native Terraform joint plans and GitHub CI/Evidence
acceptance were deferred in the first session. Commit `d6d8244` was kept local
at that point. The resumed second-session implementation and its evidence are
documented in `day29-integrated-recovery-acceptance.md`; the limitations below
describe the original first-session delivery.

The implementation is a **single-host local governance service**, not a deployed
AWS/GitHub identity service. Bootstrap adapters in tests explicitly simulate
authentication. Real identity verification, real S3 object reads and signed
producer attestation are still required before production use.

## Trusted state registry

`scripts/iac/trusted_state_registry.py` reuses Day28 state byte/schema checks and
validates a record with exact account, environment, bucket/key, object VersionId,
SHA-256, lineage, integer serial, commit and originating Run/Attempt.

- Registration requires a fixed bootstrap registrar allowlist **and** successful
  authentication of the actor/action/record digest. Callers cannot pass a new
  trust callback into individual lookups.
- State bytes must match their record; raw state contents are not stored in SQLite.
- Each backend has an immutable version history and one active head. Serial must
  strictly increase under the same lineage. Same/lower serial, lineage reset and
  replacement of an existing VersionId reject.
- Verification accepts only the exact registered, active current record. Matching
  SHA with an unregistered VersionId, substituted fields or an old version fails.
- Revocation retains the head/high-water mark and never falls back to older data.
- Bootstrap scope/registrar policy is persisted and cannot silently change when
  reopening. Existing business databases and unmarked legacy data are rejected.

Registration authenticates the publisher first, then reuses `state_errors` for
byte/schema consistency of a not-yet-registered record. The local structural-check
callback at that point is not the source of trust. Later verification uses the
resident registry's current-head decision instead of a caller-supplied boolean.

The registry trusts its host/filesystem, bootstrap policy and identity adapter.
Digests detect inconsistent metadata; they do not resist an administrator rewriting
records, digests and metadata together. A constructor-created registry scope is
not proof of AWS account ownership. Day28's structural checks are reused, not
replaced with a complete Terraform resource-schema validator. Native validation
and actual version/owner observations are next-session work.

## Independent one-time recovery approval

`scripts/iac/recovery_approval.py` stores the following in the same dedicated IaC
SQLite file, independently of any vehicle business database:

| Record | Immutable binding / rule |
| --- | --- |
| Request | Source current registry record, exact allowed target, requester, original interrupted/rejected Day27 release and its binding/old Plan/Run |
| Approval | Request digest, approval ID, independent reviewer, approval/expiry times |
| Consumption | Exact approval and request, consumer and time, persistent unique receipt |

Targets are bootstrap-allowlisted exact backends in the same account/environment
and a different bucket. Requests expire after 30 minutes; approvals last at most
15 minutes and cannot outlive their request. A trusted UTC clock is configured at
startup, rather than supplied by a token holder on each operation.

Requesters/reviewers must be allowlisted and authenticated. Reviewer identity is
case-normalized; an authorized reviewer still cannot approve their own request.
Approvals cannot be replaced, reissued for the same request or consumed by another
requester. Field substitution, expiry, revocation, clock regression, changed source
head or unavailable authority denies consumption.

`BEGIN IMMEDIATE`, a unique consumption row and a conditional ACTIVE→CONSUMED
update commit together. Two independent local Python processes competing for one
approval produce one winner. Reopening the store cannot replay it. Revoking an
already consumed approval invalidates its receipt without resetting the spent
record. Consumption is **not recovery execution** and does not modify any backend.

## Release revalidation without Apply authorization

`scripts/iac/release_revalidation.py` reuses the Day27 `ReleaseStore`; it hardcodes
only REQUESTED→VERIFIED. It never advances APPROVED/READY or changes the old
INTERRUPTED/REJECTED request.

A new verification requires:

1. A real consumed local approval receipt that remains current, unrevoked and
   unexpired. A self-generated receipt hash is insufficient.
2. A current registered target snapshot with the approved source bytes/hash,
   lineage and serial and the approved target account/environment/backend.
3. A new request ID, different Plan SHA and different Run/Attempt from the original
   release. Commit and new registered State must match current trusted context.
4. Day26 exact manifest/plan-byte validation and Day27 current source/run evidence
   checks. An old plan, stale context, swapped state or prior evidence rejects.
5. Both drift plans classified by Day28 policy as CLEAR, without errors, incomplete
   plans or contradictory exit codes. REVIEW_REQUIRED never verifies a release.
6. Mandatory producer adapters authenticating the current evidence and a binding
   covering both plan-JSON digests, the binary Plan hash through its manifest,
   State record, expected context, source digest, release ID and receipt.

Receipt claims are persisted once. Registry, approval and Day27 tables must share
the same governance DB. The final registry/revocation/observation checks run inside
Day27's write transaction, preventing same-DB writers from changing them between
that check and the VERIFIED commit. A test revokes the target between initial
validation and the Day27 transaction and confirms REJECTED, not VERIFIED.

The returned status is a point-in-time **VERIFIED** with `apply_authorized=false`
and `new_release_approval_required=true`. It is not a durable production execution
permit. READY, Terraform state locks and actual execution remain separate controls.

Claim, Day27 request creation and the final local bookkeeping are separate durable
steps. A crash may leave a CLAIMED/spent entry or a VERIFIED Day27 row without final
bookkeeping; the API does not automatically reset or resume either. Full crash/
commit-response-loss reconciliation is explicitly deferred. Network identity
revocation cannot be made atomically consistent with SQLite by this implementation.
Future adapters must use bounded calls and authenticated live snapshots.

## Local checks and reports

Run the three suites first, then the full IaC regression:

```powershell
.venv/Scripts/python.exe -m ruff check scripts/iac tests/unit/iac
.venv/Scripts/python.exe -m ruff format --check scripts/iac tests/unit/iac
.venv/Scripts/python.exe -m mypy scripts/iac
.venv/Scripts/python.exe -m pytest -c scripts/iac/pytest.ini tests/unit/iac/test_trusted_state_registry.py tests/unit/iac/test_recovery_approval.py tests/unit/iac/test_release_revalidation.py -q --junitxml=.runtime-reports/day29/day29-unit.xml
.venv/Scripts/python.exe -m pytest -c scripts/iac/pytest.ini tests/unit/iac -q --junitxml=.runtime-reports/day29/iac-regression.xml
```

The local report is `.runtime-reports/day29/local-validation.json`, with per-file
source hashes, command results and JUnit digests/counts. It explicitly identifies
local-only scope and unperformed integration/CI acceptance. It is not a signed
Day29 CI Evidence artifact and cannot authorize a release. Successful governance
mutations have local audit entries; full failed-attempt/security audit collection
and tamper-resistant storage are not claimed.

The small two-process approval race is today's required unit-level SQLite check.
It does not complete tomorrow's broader process/crash and real Terraform scenarios.
Tests deliberately use synthetic state, synthetic plan bytes and simulated identity
adapters. Their success is not proof of a valid native Terraform plan or a live
GitHub review, AWS identity, S3 version or restored cloud infrastructure.

## Next-session acceptance checklist

- Read real LocalStack object versions/bytes and bind actual provider observations
  to registry registration; inject missing, wrong, old, corrupt and revoked versions.
- Exercise approval and registry races, process termination, commit success with
  lost response and stale/revoked consumption/revalidation receipts.
- Generate actual saved plans and refresh-only/normal JSON, bind them to the same
  commit, State snapshot and Run, then verify no drift or stale-plan bypass.
- Validate recovered target ownership/version and unresolved old lock behavior;
  do not automatically force-unlock, push state, overwrite the active backend or
  reset the Day27/29 ledger to repair failures.
- Implement authenticated producer/identity adapters; do not promote test
  `fake_identity` or `lambda True` callbacks into a deployment service.
- Add Day29 fail-closed CI/Evidence checks and verify Runtime/IaC on the same
  latest commit. Preserve real approval controls and dry-run-only deployment.
- Define separately reviewed reconciliation for ambiguous local claims and a
  central authenticated store before claiming coordination across GitHub runners.

No Terraform Module, PostgreSQL migration, real AWS credentials, production Apply,
state push, force-unlock or production deployment is part of today's delivery.
