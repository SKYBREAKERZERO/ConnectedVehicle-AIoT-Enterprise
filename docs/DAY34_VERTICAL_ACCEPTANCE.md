# Day34 vertical acceptance

Baseline: `993aa2ca13dc6a2e9c8ef12b0249dcc45b613d3b` on
`wip/day20-infra-20261018` (the actual development branch, despite its older name).
No Day20–33 feature is presumed complete from its day number.

The existing Day18/19 suites already exercise signed version-pinned artifacts,
restricted tenant database identities, Campaign → Wave → Job dispatch, ECU
download/install processes, durable A/B banks, signed boot proofs, inventory and
audit consistency. Day21 exercises independent PostgreSQL connections, dispatch
leases, real deadlocks/lock timeouts, connection termination before commit,
process death after commit, lost HTTP responses and pause ordering. Some Day21
tests use administrator-created synthetic job states; those tests alone cannot
prove a trusted installation. Day34 requires the Day18/19 process evidence too.

Day34 adds whole-transaction retry to idempotent device claim/report calls,
an actual HTTP race between distinct claim operations, stable winning-token
replay, and actual PostgreSQL SERIALIZABLE update conflicts. The latter verifies
both recovery on a fresh transaction and exhaustion after three attempts.
No historical migration is edited; the single head remains `b16f238d45ac`.

## Reproduce locally (PowerShell, Python 3.12, Docker running)

Use a new evidence directory and a new run identifier for every run. Do not edit
the source during execution. The virtual environment must have the project's
runtime and development dependencies installed.

```powershell
$env:DAY16_EVIDENCE_RUN_ID = 'day34-' + [guid]::NewGuid().ToString('N')
$env:RUNTIME_EVIDENCE_DIR = '.runtime-reports/' + $env:DAY16_EVIDENCE_RUN_ID
New-Item -ItemType Directory $env:RUNTIME_EVIDENCE_DIR | Out-Null
.venv/Scripts/python -m pytest tests/integration/day18/test_ota_execution.py tests/integration/day19/test_campaign.py tests/integration/day21 -q --junitxml="$env:RUNTIME_EVIDENCE_DIR/day21-postgres.xml"
.venv/Scripts/python -m scripts.day34_evidence --quality
.venv/Scripts/python -m scripts.day34_evidence
```

The gate requires fresh Day18/19 runtime reports, all mandatory successful
PostgreSQL JUnit cases, and actual ruff/format/mypy/contracts/single-head/unit and
contract test command results. Commit, source content and run identity must
match. Quality output logs are hashed; evidence files and the gate output use
exclusive creation to prevent replacement within one run. An absent, failed,
skipped, stale or mixed-source proof yields `BLOCKED` with a nonzero exit code.
The local result is only `READY_FOR_LOCAL_REVIEW`, with `ci_verified=false`.

In GitHub Actions the existing transport verifies artifact hashes and native
run/attempt/source binding before Day34 evaluation. Day34 also requires all
mandatory upstream native job results to succeed. Its report and logs are
uploaded as `day34-vertical-acceptance`, and the acceptance JSON is included in
the sealed Runtime evidence consumed by the final Runtime gate.

These are real PostgreSQL/HTTP/process tests against disposable local services,
with simulated ECU installation. They do not prove physical ECU secure boot or
real AWS deployment. `release_authorized=false` is unconditional. No production
Apply, main update or merge is part of this procedure.
