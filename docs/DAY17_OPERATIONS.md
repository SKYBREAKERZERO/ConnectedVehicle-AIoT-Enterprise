# Day17 — Local operational readiness

This profile proves a short local drill, not a production 30-day SLO. Only
PostgreSQL 16, free LocalStack and local processes are used. No deployment,
rollback, credential rotation or PR merge occurs implicitly in the release gate.

## SLO contract

The reviewed source is `config/operations/day17-slo.json`:

| Indicator | Local objective | Evidence |
| --- | --- | --- |
| `/health/ready` availability | >=99% across >=100 measured requests | Actual API socket requests reconciled with protected API counters |
| Readiness p95 | <=1 second | Nearest-rank p95 of observed client durations |
| Lock / Worker recovery | <=30 seconds each | Validated Day16 persistent outcomes and actual Prometheus proof |
| Evidence age | <=15 minutes | UTC observation time; future/stale windows are rejected |
| Integrity | Zero duplicate device effects / broken audit links | Mandatory Day16 invariants, not an expendable error budget |

The first 100-request canary deliberately includes five database connection
failures: 95% availability must abort. Restore the dedicated role's original
connection limit, then run a separate 100-request canary. Its result must satisfy
the objectives. The failed window is preserved; it is never erased or reclassified
as successful. Startup probes are outside both windows. This is a controlled
post-remediation re-evaluation, not permission to ignore a failed production canary.

The API is the actual `apps.api` process with a tenant-bound non-superuser identity.
Only bootstrap fixture credentials inject and restore the temporary connection
limit; the runtime never receives them. Dedicated test containers prevent changes
to the developer's existing database. No raw credentials or HTTP headers enter
the reports.

## Readiness budget burn

Alerts are generated from the same policy with `python -m scripts.day17_rules`.
Missing or changed policy/rule/runbook/workflow inputs invalidate readiness.
Never lower an objective to turn a failed canary green without a reviewed change.

1. Pause the release. Read the failed window and metrics reconciliation.
2. Check database reachability, runtime identity and lock/connection saturation.
3. Preserve the original request/operation IDs; do not issue replacement business
   commands while a commit or physical execution remains unknown.
4. Correct the dependency/configuration problem. In the isolated exercise the
   coordinator restores exactly the captured role connection limit.
5. Re-run a new canary and retain both the aborted and recovered windows.

## Recovery escalated

1. Hold release and identify the operation/fault/trace IDs in the correlated log.
2. Read PostgreSQL command state, device execution ledger and the immutable
   credential checkpoint/segments. MQTT/SQS publication alone is not execution.
3. Reconcile a commit using the original idempotency identity. Unknown outcomes
   stay quarantined; do not replay external effects merely because a client timed out.
4. For credential recovery, follow the existing maintenance-window protocol in
   `DAY15_CREDENTIAL_LIFECYCLE.md`; never modify the journal or adopt a foreign Pending.
5. If recovery cannot be verified, retain evidence and escalate for operator
   review. Do not force state to succeeded or destroy/recreate resources.

## Release and rollback protocol

The local gate requires the complete, same-run Day16 bundle, failed-canary abort,
healthy re-evaluation, recovery deadlines, restricted runtime identity and exact
code/policy digests. It emits `day17-readiness.json` with profile `local_drill`.
`--check-existing` verifies it without overwriting anything. This is not an AWS
production deployment approval.

An optional read-only GitHub gate requires the latest successful Runtime and IaC
workflows on the exact PR head, the correct merge-result evidence, and strict
trusted required checks enforced for administrators. A queued/failed rerun or
evidence from a previous head is rejected. The gate does not merge the PR.
It downloads both evidence artifacts through authenticated GitHub access, checks
their published ZIP SHA256 digests and run/head ownership, and compares every
required evidence file byte for byte. Relabelling locally produced JSON with a
successful run ID cannot satisfy this gate. Archives are inspected without extraction.

Rollback is an operator decision: hold new publication, preserve data and audit
history, identify the last compatible application artifact, verify its database
contract and credentials, then evaluate a fresh canary. Never automatically run
Alembic downgrade, reset secrets, truncate the Outbox or infer vehicle success.
Forward-only data/schema changes require an explicit compatible recovery plan.

## Limits

No production traffic volume, 30-day availability, load capacity, AWS IAM/KMS
authorization, managed failover or physical disk durability is claimed. The
existing LocalStack/AWS boundary in Day16 remains unchanged. Human review and a
real deployment environment remain separate release conditions.

## Repeat the exercise

```powershell
.\.venv\Scripts\python.exe -m scripts.day17_drill
```

This runs the complete Day16 fault matrix and Day17 canary/alert contracts under
one fresh run ID and evidence directory. Existing output directories are refused.
It then independently verifies the immutable readiness result. The canary stops
the temporary API process and restores the dedicated runtime role's connection
limit in `finally`. The coordinator has a 360s deadline, first requests graceful
interruption, and cleans only containers labelled with this invocation's owner ID.

Review `day17-canary.json`, `day17-readiness.json`, the retained aborted window,
and the Day16 public audit/Prometheus proof. To check an existing bundle:

```powershell
.\.venv\Scripts\python.exe -m scripts.day17_release --directory <evidence-directory> --check-existing
```

After downloading the matching CI artifacts into one directory, a repository
maintainer with authenticated read access can additionally run:

```powershell
.\.venv\Scripts\python.exe -m scripts.day17_release --directory <ci-evidence-directory> --require-remote <PR-number>
```

The remote gate rejects earlier heads, wrong workflow paths, failed/pending reruns,
untrusted required checks, an old merge result or a mismatched Runtime run attempt.
The evidence must still be fresh. A green historic workflow cannot renew an expired
canary; rerun the workflow for fresh evidence. The result is `ready_for_review`,
not permission to merge or deploy.

CI runs the same tests and verifies the Day17 manifest without overwriting it.
Sanitized operational evidence is uploaded even on failure. The SLO burn rule is
checked with real `promtool test rules`, including firing and resolution; existing
Day12 Prometheus/Alertmanager webhook acceptance continues to run with the new
rules mounted. A new production on-call destination is not claimed.
