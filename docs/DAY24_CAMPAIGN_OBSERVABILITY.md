# Day24 — Campaign runtime observability and release evidence

## Scope and metric semantics

The authenticated API `/metrics` endpoint collects the committed database state
for the API process's fixed `DATABASE_TENANT_ID`. Monitoring has no tenant query
parameter. The PostgreSQL login binding must equal that fixed tenant; shared or
mismatched identities fail collection. An unset fixed tenant explicitly disables
campaign metrics rather than exposing cross-tenant aggregates.

Each scrape uses a fresh repeatable-read, read-only transaction. SQL statement
timeout is 1500 ms, lock timeout 500 ms, database snapshot deadline 3 seconds and
the complete collection/lock acquisition deadline 4 seconds. The existing runtime
role receives no additional grants. Metrics do not change Campaign, Claim or Job
state. No migration or PostgreSQL role is introduced.

| Metric | Meaning |
| --- | --- |
| `vehicle_ota_enabled` | Fixed-tenant campaign collection configured |
| `vehicle_ota_collection_success` | Current scrape collected a valid database snapshot |
| `vehicle_ota_last_success_timestamp_seconds` | Last successful snapshot in this API process |
| `vehicle_ota_collection_duration_seconds` | Current collection duration, a gauge, not a latency percentile |
| `vehicle_ota_campaigns{state}` | Committed Campaign counts in six bounded states |
| `vehicle_ota_waves{state}` | Pending target waves, current running waves, overdue unfinished waves |
| `vehicle_ota_claims{state}` | Active or expired dispatcher leases on running Campaigns |
| `vehicle_ota_jobs{state}` | Created Campaign jobs in seven bounded states |
| `vehicle_ota_job_failures{state="recent"}` | Failed Campaign jobs updated in the last five minutes |

There are no tenant, Campaign, Wave number, Claim token, vehicle, ECU, Job or error
message labels. HTTP scrape authentication is checked before any collection.
On collection failure, the endpoint publishes health failure and omits business
gauges; it never republishes cached counts as current state. Concurrent scrapes
are serialized and bounded. Missing/dead API scrapes remain visible through `up`.
These are database state snapshots, not durable event counters or Dispatcher
process heartbeats. Multiple API replicas observe the same tenant state: do not
sum their counts to estimate fleet totals.

## Prometheus deployment

`infra/observability/prometheus.yml` loads `day24-campaign.yml` and scrapes the
existing Bearer-protected API endpoint. The existing local recovery collector is
unchanged. The opt-in `campaign` Compose profile runs a separate Prometheus target
against the API without replacing the existing Day12/17 recovery stack.

1. Run the API with its fixed tenant database login and a strong `METRICS_TOKEN`.
2. Write the same token to a private file, without committing it. Set
   `CAMPAIGN_METRICS_TOKEN_FILE` to that absolute path. Its default is the ignored
   `.runtime-reports/observability/metrics_token` path.
3. Start the reviewed Compose profile:

```powershell
docker compose -f infra/observability/compose.yml --profile campaign up -d campaign-prometheus alertmanager receiver
```

Prometheus is published on loopback port 19094. Its container must be able to reach
the protected API at `host.docker.internal:8000`; configure the API listener and
local firewall accordingly. Mount the token file read-only. Never put the token
inside labels, alert annotations, Git or evidence artifacts.

This change validates rule evaluation with real `promtool`; it does not claim
that a deployed Prometheus/Alertmanager notification reached an operator. A live
notification drill and production HTTPS/access controls remain deployment work.

## Alert runbooks

### Collector unavailable

`CampaignCollectorUnavailable` fires after one minute of failed/missing collection
on an enabled target, or a down API scrape. Check API health, scrape token, fixed
tenant binding and database availability/lock contention. Do not interpret omitted
business metrics as zero Campaigns. Restore collection and confirm resolution.

### Wave overdue

`CampaignWaveOverdue` fires after two minutes with an unfinished wave beyond that
Campaign's configured timeout. Completed jobs waiting for observation do not count
as unfinished. Inspect durable Job/audit records and Dispatcher progress. Reconcile
before using the existing authorized pause/resume workflow; do not edit SQL state.

### Claim expired

`CampaignClaimExpired` fires after one minute of expired Dispatcher ownership on a
running Campaign. Check worker availability and let the existing fenced claim
recovery acquire a new owner. Do not revive or reuse an old Claim token.

### Jobs failed

`CampaignJobsFailed` fires after one minute of failures in the five-minute window.
Inspect signed execution/report evidence and the existing Campaign failure budget.
Historical failures remain in state metrics but age out of this alert. A recovered
collector alone does not prove Job recovery or authorize automatic Campaign resume.

## Acceptance and limits

Eight dedicated integration scenarios use real PostgreSQL 16 and real promtool:
committed state counts, expired Claim/Wave detection and recovery, failure-window
aging, tenant mismatch rejection, bounded lock-timeout collection with stale-count
suppression, runtime write denial, authenticated scrape without identifier labels,
and alert pending/firing/resolution with stale-state suppression.

Runtime CI writes JUnit XML, produces `day24-acceptance.json`, then independently
checks it. Missing, failed, skipped or duplicate scenarios fail acceptance. Evidence
binds the full source digest, source commit, workflow run/attempt, alert rules,
scenario file and JUnit digest. Pytest stamps these identities inside JUnit at test
execution time; the validator checks them before accepting the report. Old cached
XML cannot be relabelled as a new source or run. Missing/duplicate attestation and
nonstandard XML hierarchy fail closed. Artifacts are mandatory; no failed check is removed
or converted into a skip. The existing IaC gate, native Terraform contracts,
provider integrity and zero-destroy checks remain required on the same PR head.

Day23's dedicated PostgreSQL identity and external IAM effective-access gaps remain
unchanged. Monitoring does not close those gaps or verify production AWS access,
physical vehicle installation, or live alert delivery. No AWS production apply or
GitHub merge is part of this work.
