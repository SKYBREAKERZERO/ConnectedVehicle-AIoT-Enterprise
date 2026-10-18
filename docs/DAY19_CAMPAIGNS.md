# Day19: tenant-bound OTA campaigns

## Baseline and scope

Day18 source is pinned to `d336c8a1be301ea08c79374c173ce0a4c8ef4f13`.
The forward migration is `f94d016b238a -> a05e127c349b`; published migrations
remain intact. The Day18 PR is still open, so this branch explicitly includes its
prerequisites. No deployment, migration stamping or automatic merge is implied.
Acceptance uses PostgreSQL 16, free LocalStack and local software ECU processes.
It does not prove AWS IAM/KMS, physical installation or hardware secure boot.

## Model and permissions

`ota_campaigns` stores an immutable release/manifest/signature and rollout policy.
`ota_campaign_targets` freezes the explicit ECU selection, vehicle, initial
firmware/security floor, reserved job UUID and wave. `ota_campaign_events` is the
atomic operation/audit ledger, including authenticated actor, reason, parameters
and durable result. All three tables use FORCE RLS and mandatory fixed-login tenant binding. Shared
base logins cannot read campaign rows by changing app.tenant_id; these tables
have no user-settable tenant-context fallback.
Application identities have SELECT plus exact migration-owned functions; no direct
campaign DML, schema ownership or DDL. Existing outbox/remote workers have no access.

The independent `apps.campaign` process uses the existing per-tenant application
identity and separate receipt authority file. It is within the application trust
boundary, not a fourth independently provisioned database/IAM role. It never uses
migration credentials. Splitting its identity/authority into a fourth production
security boundary requires separate provisioning and IAM lifecycle acceptance.

Commands require a short-lived domain-separated `cv-campaign/1` HMAC capability,
independent of database passwords. Startup checks function body/owner/settings and
effective privileges. A leaked application DB password cannot change snapshots,
disable a Canary gate or forge an execution result. Full application-authority or
ECU-private-key compromise remains a different threat.

## API

Operator routes require `ota:manage`; query routes require `ota:read`.

| Method | Path | Meaning |
| --- | --- | --- |
| POST | `/v2/ota/campaigns` | Create signed rollout intent with operation UUID |
| GET | `/v2/ota/campaigns` | Cursor-paginated tenant list |
| GET | `/v2/ota/campaigns/{id}` | State, full rollout policy, snapshot digest and durable job counts |
| GET | `/v2/ota/campaigns/{id}/targets` | Cursor-paginated frozen targets and job states |
| POST | `/v2/ota/campaigns/{id}/freeze` | Validate pinned bytes and freeze explicit ECU IDs |
| POST | `/v2/ota/campaigns/{id}/actions/{action}` | Start, pause, resume or cancel with reason |

Creation accepts name, release ID, manufacturer signature/key ID, target security
version, Canary size (1..100), wave size (1..100), failure budget (default zero),
observation interval (default 30 seconds), and wave timeout (default 900 seconds).
Freeze accepts 1..1000 unique ECU UUIDs and an operation UUID. It rejects missing,
foreign, incompatible, inactive, unbootstrapped or already-current targets. Sorted
ECU IDs determine the Canary and later waves; membership never silently expands.
Repeated operations return their durable original result. Reusing an operation
UUID with changed command, campaign, actor, reason or body conflicts.

## Rollout and recovery

State is `draft -> frozen -> running -> completed`, with explicit `paused` and
`cancelled`. A short database transaction serializes a campaign and creates one
wave of pending OTA intents plus audit and target markers atomically. Each target's
job UUID is reserved at freeze and is never regenerated on retry. Existing active
ECU uniqueness also protects competing campaigns. Artifact validation and Day18
verification happen outside that transaction with stable verification operation IDs.
A crash after job creation therefore resumes the same pending jobs.

Only after all released jobs are terminal and the observation interval has elapsed
can the dispatcher release another wave. A failed Canary exceeding the configured
cumulative campaign budget pauses immediately on reconciliation. Vehicle suspension, changed initial
floor, publisher expiry/revocation, wave timeout and dispatch/verification conflicts
also prevent later waves. Missing reports never count as success. A failed Canary
cannot be bypassed by resume. Repair policy problems before resuming; create a
separate reviewed campaign when changing targets, firmware or the failure policy.

Pause/cancel stop new claims. Already claimed jobs may finish reporting through
Day18's proof/vehicle/publisher checks; rollout control never pretends an in-flight
physical operation was undone. Cancellation withdraws unclaimed pending/verified
jobs with audit and leaves unreleased targets untouched. Permanently lost claimed
devices require the Day18 quarantine/observed-boot reconciliation procedure.

```powershell
python -m apps.campaign --campaign <UUID> --once
python -m apps.campaign --interval 10
```

Without an ID, the dispatcher rotates through bounded pages of running campaigns.
Each dispatch has a deadline; DB locks/statements and artifact IO are bounded.
Continuous dependency failures use bounded backoff and stop after three attempts,
with symbolic error output rather than SQL/capability dumps. SIGINT/SIGTERM (and
CTRL_BREAK on Windows) stop scheduling, let the bounded operation finish and close the pool.
The local-only `--crash-after-jobs` option exits after the durable transaction; it
must never be enabled in a production launch configuration.

## Acceptance and evidence

Real independent API, dispatcher and device processes exercise three-ECU Canary
success, a failed Canary, crash/restart, simultaneous dispatchers, competing
campaigns, audit rollback/retry, fixed-login RLS, vehicle suspension after claim,
publisher revocation with a stale registry, and cancellation. Assertions inspect
PostgreSQL inventory, report/audit rows and immutable target/job identities, beyond
HTTP status codes. Day18 still proves signed boot/A-B persistence separately.

The HTTP fault harness uses fresh connections: an intentionally unhandled audit
failure returns 500 and Uvicorn closes that connection. Reusing it can race the
close on Linux. Opening a new connection preserves the original rollback and
idempotency assertions without retrying writes or ignoring transport failures.

Runtime CI runs Day16/17/18 prerequisites and Day19 tests, then requires fresh
source/run-bound evidence and uploads `day19-local-campaign`. Missing, altered,
stale, mixed-run or falsely hardware/AWS-verified evidence fails the gate. The
optional remote verifier authenticates exact-head Runtime/IaC attempts, candidate
merge, enforced trusted checks and artifact ZIP digests. Terraform policy/security
checks remain the separate required IaC gate.

The timing tests inject elapsed timestamps under the test owner to avoid wall-clock
sleeps; they never synthesize device success. Frozen reservations also reject
one-off OTA intents and block raw inserted jobs from bypassing the rollout gate.
