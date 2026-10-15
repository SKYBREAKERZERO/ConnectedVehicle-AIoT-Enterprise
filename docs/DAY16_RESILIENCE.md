# Day16 — Fault injection and recovery acceptance

Scope: PostgreSQL 16 and free LocalStack only. AWS deployments and real AWS IAM
enforcement are outside this acceptance. Day15 working-tree changes are retained.

## Recovery behavior

Each API command issuance has one durable request identity:
`(tenant_id, vehicle_id, idempotency_key)`. PostgreSQL enforces its uniqueness.
Command parameters must match on replay, and the command and Outbox insert commit
in the same transaction. This existing identity is used as the operation ID;
there is no second independent commit-result table to drift out of sync.

`SQLAlchemyUnitOfWork.commit()` distinguishes a lost commit acknowledgement from
a confirmed rollback. `IssueRemoteCommandService` reconciles the original request
using a fresh session. If found, it validates the parameters and returns that
durable result. If absent or lookup fails, it raises `CommitOutcomeUnknown`:
absence alone is not proof that an earlier commit cannot still finish. The API
returns sanitized HTTP 503 and tells the client to retain the same idempotency key.
Do not generate another key to work around an unknown outcome. This path currently
requires client retry/operator reconciliation; it is not a background repair daemon.

Only confirmed SQLSTATE `55P03`, `40P01`, and `40001` failures retry the entire API
transaction, at most three attempts, with jittered exponential backoff. Validation,
permission, statement-timeout and ambiguous-commit failures are not blindly replayed.
Retry callbacks must use a fresh transaction and must not publish externally.

Runtime connections have configurable defaults:

| Setting | Default | Purpose |
| --- | --- | --- |
| `DATABASE_LOCK_TIMEOUT_SECONDS` | 2 | Bound each lock wait |
| `DATABASE_STATEMENT_TIMEOUT_SECONDS` | 10 | Bound SQL execution |
| `DATABASE_IDLE_TRANSACTION_TIMEOUT_SECONDS` | 30 | Terminate abandoned idle transactions |

Migration guards retain their explicit transaction-local migration deadlines.
Worker failures use interruptible exponential backoff with jitter, capped at 30s.
The worker remains running during an outage; shutdown interrupts waiting promptly.
Telemetry logging failures are isolated in the worker polling loop. This does not
claim that every exporter/instrumentation failure across the application is isolated.

## Crash and stale-operation behavior

Outbox uses at-least-once delivery. An abrupt exit before send leaves a reclaimable
lease. An exit after SQS send can cause duplicate delivery. The command dispatcher
checks durable state; device SQLite deduplicates repeated execution by command ID.
The test kills a real child process with `os._exit`, including after the Body ECU
SQLite commit but before SENT persistence. Restart and replay must leave one
execution row and the expected door state. This fixture calls the real simulator
execution store directly; the existing independent-process MQTT/CAN E2E tests
remain responsible for proving the transport chain.

Expired Outbox leases cannot mark publication/failure successful. Reclaimed leases
receive a new token; stale tokens cannot publish, fail or schedule retries. Token
fencing protects database writes; it cannot undo a message already sent to SQS or
an external physical action. Device deduplication remains necessary.

Credential recovery reuses Day15 management locks, ownership checks and Current /
Pending version checks. Actual concurrent SDK mutations bypass the management
lock in the test; external versions must survive without stale password overwrite.
Journal checkpoint failures must retain a recoverable state; archive corruption
must be rejected before credential writes. Audit hashes detect modification but
are not signatures or a guarantee of zero loss after physical storage failure.

## Reproduce and verify

Docker must be available. Tests create uniquely named PostgreSQL/LocalStack
containers on random loopback ports and remove them afterwards. Runtime actions
use separate tenant-bound roles; management credentials only seed/inspect fixtures.
No changes are made to an existing developer database.

```powershell
$day16Run = 'day16-' + [guid]::NewGuid().ToString('N')
$env:DAY16_EVIDENCE_RUN_ID = $day16Run
$env:RUNTIME_EVIDENCE_DIR = Join-Path '.runtime-reports' $day16Run
.\.venv\Scripts\python.exe -m pytest tests/integration/day16 -q
```

The final test requires all eleven scenario records and writes an exclusive
`day16-acceptance.json`. Keep test order for this suite; partial or shuffled runs
intentionally cannot produce complete acceptance. Records bind the run ID, Git
commit and current Python source digest, including uncommitted code. Missing
assertions, false values, a stale source/run or real-AWS claims fail the gate.
Evidence and manifests never overwrite an existing report; choose a fresh run
directory each time. Interrupted JSON files fail parsing and cannot pass.

The Runtime workflow includes this suite, so a failed assertion blocks the job.
It uploads sanitized Day16 records even on failure. A local pass does not establish
that remote CI has passed, that branch protection is configured, or that a PR merged.

## Fault matrix

| Fault | Required persistent assertion |
| --- | --- |
| Row lock exceeds deadline | Three attempts, `55P03`, both writes rolled back |
| Opposite row locks | Actual `40P01`, full transaction retry, exact final values |
| Backend terminated before COMMIT | Uncommitted write rolled back; fresh connection usable |
| COMMIT response cut on TCP | Durable request found, one command and one Outbox |
| Outbox child exits before/after SQS send | Lease reclaimed, duplicate handled |
| Worker exits after device commit | Restart leaves one SQLite execution |
| Duplicate / later command arrives first | No duplicate dispatch or state regression |
| Old worker after lease expiry/reclaim | Stale updates affect zero rows |
| Credential version takeover | External Current/Pending preserved |
| Audit checkpoint interruption | Recovery possible; tampered chains rejected |
| PostgreSQL / monitor unavailable | Worker backs off; later transaction succeeds |

This is deterministic local failure acceptance, not proof of arbitrary production
network partitions, disaster durability or physical exactly-once actuation.

## Local validation — 2026-10-15

The final unit/contract/Day16 run passed 907 tests, including all eleven evidence
scenarios. The existing 25 Day12/security/E2E cases also passed in the broader
regression. That earlier run had one workflow-guard failure because it prohibited
the always-upload evidence step; the corrected guard is covered by the final run
and continues to prohibit conditional quality checks.

Ruff check and format check (349 files), mypy (332 source files), module contracts,
Terraform recursive format check, and local/dev validation passed. Day16 evidence
includes the dirty working-tree Python digest rather than claiming that HEAD alone
identifies these changes. No Day16 commit, push, remote CI or real AWS acceptance
is claimed by this local result.
