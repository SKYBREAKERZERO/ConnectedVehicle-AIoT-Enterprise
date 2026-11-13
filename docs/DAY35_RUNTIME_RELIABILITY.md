# Day35 OTA Runtime Reliability and CI Admission

## Scope and baseline

Day34 is present on the working branch at `e2e9cd274c022525ee79921e0bc79f5b7d9fc896`: `scripts/day34_evidence.py`, `runtime.yml` and standalone `day34.yml`. Baseline Runtime 41631497784, IaC 41631497740 and Day34 full acceptance 41631497854 completed successfully. Day34 deliberately reuses Day18/19/21 vertical tests; absence of a separate day34 test directory does not mean those tests are absent. PR #15 remains unmerged and requires independent non-author review; branch acceptance does not establish main installation.

## Two new cross-module faults

1. **Campaign/Wave → Job → audit atomicity**: a real PostgreSQL audit trigger raises an exception after the application requests a Wave tick. Verify no Job/audit or wave advancement commits, then replay the same operation through a fresh service twice. Exactly one dispatched target, one logical Wave, one Job and one creation audit persist; ECU anti-rollback floors remain unchanged. This extends the Day21 commit-response-loss/concurrent dispatch coverage with a failure inside the shared transaction.
2. **Durable ECU Bank → signed boot proof → PostgreSQL report/audit**: a separate local boot process checks staged bytes and creates a real Ed25519 proof. Activate the simulated Bank once, then inject a PostgreSQL audit failure during terminal report admission. Cloud Job remains installing, ECU inventory floor stays old, terminal report does not persist, and no terminal audit appears. Reopen the device store and fresh database engine; retry the durable report twice. Cloud terminal state, inventory firmware/security floor, persisted proof and audit agree, with one simulated installation and one logical terminal effect. Finish the single-target Campaign without another Job.

The second test starts from a **trusted verified-artifact fixture** (real signed manifest and known bytes); it does not repeat S3 delivery/pinning verification, covered by Day18. PostgreSQL transactions and application-role writes are real. SQLite is used only for the production simulator's local device Bank/outbox, never as a PostgreSQL substitute. Local simulated boot is not physical ECU boot; no downloaded firmware is executed.

## Evidence and workflow

- The existing `runtime-postgres.yml` PostgreSQL branch runs the two tests with `day35-runtime-faults.xml`; bootstrap uses an owned disposable PostgreSQL 16 container and a separate tenant runtime identity.
- JUnit binds the exact source fingerprint, Commit and Run/Attempt using the established Day34 envelope. Exactly both mandatory cases must execute without failures/errors/skips or duplicates.
- `scripts/day35_evidence.py` revalidates Day34's complete proof, binds actual XML/prior-acceptance bytes by SHA-256, checks GitHub Commit and Run/Attempt when in Actions, and emits `day35-acceptance.json`. Missing, stale, replayed or altered proof blocks admission. `--check-existing` recomputes the proof and detects changed report bytes or acceptance fields.
- Runtime Evidence performs Day35 admission after Day34 succeeds, uploads diagnostic Day35 XML/JSON, then seals the complete existing evidence bundle. The final required Runtime gate verifies the bundle and independently requires Day35 acceptance identity, closed authorization flags and matching report hashes. A missing Day35 JSON cannot pass via a generic manifest alone.
- Verifier/tests join the shared CI source fingerprint. Negative unit tests exercise corruption, missing/duplicate/skipped/failed cases, old Run/source, stale acceptance, prior-proof replacement, wrong Actions Attempt, malformed XML and the actual final workflow guard.
- Existing IaC scanning, provider locks, Plan policy, LocalStack Apply/second Plan remain intact. No Terraform resources or migrations are added. The active ruleset already requires `IaC quality gate` and `Runtime quality gate`; independent review remains required.

All evidence keeps `release_authorized=false`, `real_aws_verified=false`, `physical_boot_verified=false`, `simulated_installation=true`. Successful tests establish readiness for local review; protected merge additionally requires a qualified independent approval. No production AWS Apply, State Push/Restore/Force Unlock is enabled.

## Verification

```powershell
python -m ruff check .
python -m ruff format --check .
python -m mypy .
python -m pytest tests/unit tests/contract -q
python -m pytest -c scripts/iac/pytest.ini tests/unit/iac -q
$env:DAY16_EVIDENCE_RUN_ID = 'unique-local-drill:1'
python -m pytest tests/integration/day35 -q --junitxml=.runtime-reports/day35-runtime-faults.xml
```

Generating Day35 acceptance additionally requires a full fresh same-source Day34 Runtime evidence directory. A unit fixture or an isolated fault JUnit alone cannot authorize acceptance. CI is responsible for generating that complete directory. Local raw logs, current-run artifact audit and final pass/block decisions are retained under `.runtime-reports/day35/`; the report must state actual latest Commit/Run/Attempt rather than treating this document as a PASS receipt. Existing uncommitted user Workflow, Terraform, lock and root files are excluded from delivery.
