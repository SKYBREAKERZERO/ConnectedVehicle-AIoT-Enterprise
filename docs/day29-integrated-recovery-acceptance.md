# Day29 second 4h: native recovery and fail-closed evidence

## Implementation

The single-host registry and approval ledger now have a LocalStack-only rehearsal
adapter. It checks signed, short-lived principal credentials, role allowlists,
actor sessions and signed producer observations. Its issuer is a local test
authority: it does not authenticate GitHub reviews, AWS OIDC or independent humans.
Private keys, raw State, binary Plans and ledger databases are never uploaded.

`day29_native_probe.py` reuses the Day28 isolated S3 recovery probe. Two independent
processes compete to register bytes fetched by exact S3 VersionId. Only one wins.
Approval binds the registered source, interrupted release and separate target
backend. A worker commits consumption and exits before responding; a read-only
lookup recovers the receipt without consuming it again. Only then does the fixture
copy the pinned object version to its isolated recovery bucket.

Native Terraform refresh-only and normal Plans initially detect the deliberately
introduced drift and revalidation rejects it. After the fixture operator explicitly
repairs its isolated resource, fresh native Plans must both return zero. Signed
observations bind their JSON hashes, binary Plan, State and current receipt.
Successful revalidation reaches **VERIFIED**, with `apply_authorized=false` and
`new_release_approval_required=true`. It never authorizes Apply or advances READY.

Default production admission remains strict. The explicit rehearsal mode accepts
only account `000000000000`, environment `local` and its fixed State key. Its
same-run exception allows CI's fixture to create a fresh request after consumption;
production still rejects reuse of the original Run. A Plan created before receipt
consumption and an old Plan hash are rejected in both modes.

## Process and failure coverage

- Real SQLite process races: one registry registration and one receipt revalidation
  succeed; the losing process is rejected.
- Commit success followed by process exit/lost response: durable consumption remains
  single-use; lookup rechecks authentication, scope, expiry and revocation.
- Exit after claiming or immediately after Day27 VERIFIED: ambiguous claims remain
  spent. Restart cannot silently reset, resume or create a replacement release.
- Revoked approvals/consumed receipts, unregistered versions, substituted State,
  credentials, old Plans and drift prevent acceptance.
- Evidence parser rejects missing, empty, failed, relabelled or unsafe reports,
  changed source/Run, duplicate consumption, READY and any production Apply claim.

The dedicated process-fault suite uses synthetic plans and identity fixtures; the
separate native suite uses actual Terraform, LocalStack S3 object versions and
native Plan JSON. These are distinct evidence scopes.

## CI and reproducible verification

The existing IaC gate runs Day28 recovery, Day29 native integration and the three
process-fault cases, in order. `python -m scripts.iac.day29_evidence --verify` then
requires prior Day28 evidence, the full unit JUnit, native JSON/JUnit and fault
JUnit. All must match the test-time Commit, Run/Attempt and current source digest.
It writes `day29-governance.json` only after successful verification.

The `day29-trusted-recovery` artifact contains that summary, the full unit JUnit
and native/fault reports, retained for seven days. Raw State, Plans, credential
bundles and SQLite files stay outside uploaded paths. Runtime and IaC results on
the same pushed commit must be checked separately; implementation is not proof
of a green remote run. Local and final downloaded CI acceptance records live in
`.runtime-reports/day29/`, which is ignored by Git.

```powershell
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m ruff format --check .
.venv/Scripts/python.exe -m mypy .
.venv/Scripts/python.exe -m pytest -c scripts/iac/pytest.ini tests/unit/iac -q
.venv/Scripts/python.exe -m pytest -c scripts/iac/pytest.ini tests/integration/iac/test_day29_process_faults.py -q
# Native suite needs a gate-owned loopback LocalStack and official provider cache.
# The gate supplies DAY29_ENDPOINT, DAY29_PROVIDER_CACHE and DAY29_NATIVE_REPORT.
```

## Remaining production boundaries

SQLite coordinates only processes sharing one durable local database. It is not
a central, authenticated cross-runner approval store or a tamper-proof audit log.
Ambiguous claims require separately reviewed reconciliation; there is no automatic
claim reset, production State restore, force-unlock or state push.

LocalStack AES256 and fixture credentials do not prove real AWS KMS, IAM, S3
durability, STS identity or GitHub approval enforcement. No production AWS Apply,
production credential acquisition, migration or Terraform module is added.
The existing GitHub independent-review and no-self-review restrictions remain in
place, so a repository owner cannot approve their own deployment.
