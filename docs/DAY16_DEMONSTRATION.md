# Day16 recovery demonstration and completion contract

## Run a reviewable local exercise

Docker and the repository Python development environment are required. No AWS
account, production credentials, paid services or existing developer database is
used. The exercise creates its own PostgreSQL 16, free LocalStack and Prometheus
containers with random ports and tenant-bound Application / Outbox / Worker roles.

```powershell
.\.venv\Scripts\python.exe -m scripts.day16_demo
# Or inspect one fault independently:
.\.venv\Scripts\python.exe -m scripts.day16_demo --scenario lock
.\.venv\Scripts\python.exe -m scripts.day16_demo --scenario worker
```

Each execution prints a new evidence directory. `--output <new-directory>` is
optional; an existing path is refused before starting a process. Dependencies and
the temporary Prometheus instance are removed afterwards. The command has a 240s
deadline. On timeout/interruption it removes only containers labelled with this
invocation's generated owner ID. It never runs a global Docker prune.

Expected observations:

1. Hold the actual per-vehicle PostgreSQL advisory lock. The restricted API
   connection reaches `55P03`, emits FAULT_DETECTED / CLASSIFIED / RETRY, then the
   coordinator releases the blocker. A fresh transaction commits exactly one
   command and Outbox row. Repeating the same idempotency key returns that command.
2. Exit an actual Outbox child process immediately after SQS confirms send. After
   lease expiry, reclaim and republish: there are two deliveries of one event.
3. Exit an actual Worker child process after the simulator Body ECU SQLite commit
   but before SENT or SQS acknowledgement. Restart from the persistent records.
   The execution ledger remains one row and the door remains locked. Replaying
   the same ACK/result event IDs creates exactly two cloud report rows, in ACK
   then result order, and the command reaches `succeeded`.
4. Independently rotate real local credentials, create more than 128 audit events,
   interrupt checkpoint publication, and retry. The last confirmed checkpoint is
   unchanged on failure; historical segment bytes remain unchanged. The report
   embeds the sanitized checkpoint and actual segments so reviewers can check
   hashes, operation identity, sequence continuity and phase transitions offline.

The Worker exercise invokes the real simulator execution store and cloud report
service directly. It does not claim to exercise MQTT/HTTP/CAN transport in that
same scenario. CI separately requires the existing independent-process MQTT/CAN
E2E tests. SQS delivery is at least once; physical exactly-once execution is not
promised for arbitrary real vehicle actuators.

## Associate monitoring with persistent outcomes

Recovery events use the existing observability request/correlation/trace context
and add `operation_id`, `fault_id`, `component`, `attempt`, `state` and SQLSTATE.
Command operation IDs are hashes of the tenant / vehicle / idempotency identity;
raw idempotency keys, payloads and credentials are not emitted. Concurrent tasks
have isolated context. Missing commit results escalate without reporting recovery.

`vehicle_recovery_transitions_total{component,state}` uses only bounded labels.
Operation and trace identifiers are in the events, never Prometheus labels. The
API exposes this counter on its existing token-protected `/metrics` endpoint.
Worker processes retain their own counters and correlated logs; they are not
silently represented as API-process counters.

The exercise starts a real Prometheus instance using the same Prometheus image as
the existing local monitoring stack. It scrapes a temporary exporter and queries
the Prometheus API for FAULT_DETECTED, RETRY and RECOVERED observations. Merely
incrementing a Python counter cannot satisfy this check. The exporter binds a
temporary host port for Docker scraping and closes when the exercise finishes;
the Prometheus UI port is exposed on loopback only. The URL is printed while live.

Useful PromQL when adding the API target to the normal monitoring deployment:

```promql
sum by (component, state) (increase(vehicle_recovery_transitions_total[5m]))
```

Search the event JSON by the operation/fault ID in `day16-demo-proof.json`, then
compare its final DB/device state and Prometheus samples. Existing Day12 alert
FIRING → webhook → RESOLVED acceptance remains required; this exercise validates
recovery correlation, not a newly deployed production alert destination.

## Evidence and merge gate

| Completion requirement | Evidence |
| --- | --- |
| Critical injected faults pass | Eleven fault-matrix records plus recovery-demonstration record |
| No unbounded transaction retries / waits | Three-attempt SQL budget, server deadlines, bounded fault waits, command deadline |
| No unexpected repeated effects | One command/Outbox identity; one SQLite execution; two unique ACK/result reports |
| PostgreSQL / command state consistent | Requested after API lock recovery; succeeded after confirmed device result |
| Journal / audit do not regress | Actual public checkpoint/segments embedded; prior digests equal; chain verified |
| Fault / attempts / result associated | Same opaque IDs and request/trace context; actual Prometheus query results |
| CI evidence required and reviewable | Immutable manifest binds run/commit/source and proof hash; independent CI verification step |
| Failure blocks main | Trusted Runtime and IaC required checks, strict base freshness, administrator enforcement |

Full acceptance uses `pytest tests/integration/day16 -q`. The final test creates
`day16-acceptance.json` only after all twelve required scenario records and the
reviewable demonstration proof validate. CI then runs:

```powershell
.\.venv\Scripts\python.exe -m scripts.day16_evidence --check-existing
```

This verifies the existing manifest without overwriting it. A missing/stale proof,
changed audit segment, missing Prometheus observation, wrong operation/trace,
duplicate device effect or inconsistent command state blocks acceptance. A single
scenario demonstration is not full Day16 acceptance.

CI uploads `day16-*.json` even when tests fail. `day16-demo-diagnostics.json`
preserves the observed timeline and completed cases on assertion failure. These
files contain sanitized events and public audit data, not Secret values, database
backups, Terraform state or environment dumps. Existing manifests/reports are
never overwritten. These unsigned local artifacts detect corruption and drift;
they are not cryptographic attestation against someone rewriting all artifacts.

Verify current repository protection without merging:

```powershell
gh api repos/SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise/branches/main/protection
```

Required checks and administrator enforcement are distinct from mandatory human
review settings. A read-only protection check does not authorize a merge. CI
evidence must identify the latest PR commit; an earlier green commit is historical.

## LocalStack and real AWS boundaries

| Exercised locally | Still requires a separate real AWS acceptance |
| --- | --- |
| Real PostgreSQL transactions, disconnects and role/RLS checks | Managed database failover, production network and storage behavior |
| LocalStack SQS send/duplicate recovery | AWS redelivery timing, IAM authorization, quotas and account policy interactions |
| LocalStack Secret labels and concurrent SDK updates | AWS service consistency/timing and IAM/KMS authorization under actual assumed roles |
| Local KMS configuration and crypto probes | AWS KMS key-policy enforcement, CloudTrail evidence and service integration |
| Actual Prometheus scrapes in an isolated demo | Deployed long-running dashboards, remote retention and on-call delivery |
| SQLite process restart / durable replay | Physical disk damage, power-loss guarantees and arbitrary real ECU effects |

No real AWS call or cost is introduced. Reports retain `real_aws_verified=false`;
LocalStack success must never be relabelled as AWS IAM enforcement.

## Expanded local acceptance — 2026-10-15

The final unit/contract/Day16 run passed 924 tests. A separate invocation of the
documented `scripts.day16_demo` command also passed. The captured lock case had
one Outbox and a requested command; the Worker case reached succeeded with two
unique reports and one device execution. Prometheus returned the observed fault,
retry, verify and recovered states. Two actual audit segments were preserved and
the checkpoint sequence advanced from 147 to 148 after the injected failure/retry.

Ruff check/format, mypy, module contracts, Terraform format and local/dev validate
passed. These local observations do not substitute for CI on the next pushed commit.
