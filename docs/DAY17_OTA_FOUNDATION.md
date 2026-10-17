# Day17 — OTA Foundation

Day17 has two deliverables: [Operational Readiness](DAY17_OPERATIONS.md) and this
OTA metadata/intent foundation. The combined readiness gate requires both bundles
from the same source and invocation. PostgreSQL 16 and free LocalStack are the
only exercise dependencies; no real AWS resources are created.

## Resources and API

| Resource | Write | Read |
| --- | --- | --- |
| ECU inventory | `PUT /vehicles/{vehicle_id}/ecus/{ecu_id}` | GET the same path, or `/vehicles/{vehicle_id}/ecus` |
| Firmware release | `POST /ota/firmware-releases` | `GET /ota/firmware-releases/{release_id}` and list |
| OTA job | `POST /vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs` | `GET /ota/jobs/{job_id}` and GET the creation path |
| Cancellation | `POST /ota/jobs/{job_id}/cancel` | Persisted job status and append-only audit |

Writes require `ota:manage`; reads require `ota:read`. Existing OIDC validation
supplies the signed tenant and operator identity. The existing `OTA_OPERATOR`
role also grants these capabilities. Tenant/actor fields are never accepted from
request JSON or caller-provided tenant headers. The single-tenant command service
token retains only its existing command permission. Devices cannot create OTA jobs.

Lists use `limit` (1–100, default 50) and optional UUID `after` cursors, ordered by
resource UUID. A cursor is the last returned ID, not a timestamp. Foreign or missing
individual resources and vehicle-scoped lists return 404; firmware lists contain
only the authenticated tenant's rows. Missing authentication returns 401 and
insufficient OTA permission returns 403.

ECU registration records `ecu_type`, `hardware_version`, `firmware_version` and
`serial_number`. Repeating the same vehicle/ECU and metadata returns `created:false`.
Changing that identity or metadata returns 409. These are operator-registered
inventory facts; registration is not device attestation. Installed firmware is
not overwritten when an OTA intent is created or cancelled.

Firmware registration example (JSON body):

```json
{
  "ecu_type": "body",
  "hardware_version": "hw-1",
  "version": "2.0.0",
  "artifact_bucket": "local-firmware",
  "artifact_key": "body/2.0.0/firmware.bin",
  "artifact_version": "immutable-object-version",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "size_bytes": 1024
}
```

The size must be a positive integer <=4 GiB; SHA256 is 64 lowercase hexadecimal
characters. An explicit object version is mandatory (`null` is rejected).
Metadata is immutable and returned as `verification_status:unverified`.
Registration validates the reference's shape; it does not fetch an S3 object or
prove bytes, signatures, authorization to a bucket, or anti-rollback eligibility.
The example digest is illustrative, not an executable firmware artifact.

Job creation takes `{"release_id":"<UUID>"}`. The vehicle must belong to the
tenant and be active; the ECU must belong to that vehicle; the release must be in
the same tenant with matching ECU type and hardware. A release matching the
recorded installed version is rejected. One outstanding job per ECU is allowed.
HTTP 202 means durable intent with `status:pending_verification`. No transition
to dispatching, installing or succeeded is exposed in this foundation.

Cancellation takes `{"reason":"maintenance requested"}` and changes only
`pending_verification -> cancelled`. Firmware metadata and ECU inventory stay
unchanged. A later operation can create a new pending job after cancellation.

## Transactions, idempotency and audit

Release creation, job creation and cancellation require `Idempotency-Key` (1–255
characters after trimming). Keys are scoped to a tenant and operation family.
An identical retry returns the persisted result; different parameters with the
same key return 409. A cancelled job is never recreated by retrying its creation
key. Concurrent duplicates serialize with PostgreSQL transaction advisory locks;
unique constraints are the final arbiter. Lock and statement waits are bounded.

ECU registration uses its resource ID as the natural operation identity. Each
successful mutation appends exactly one `ota_audit_events` record, containing
tenant, operator, resource, operation key, action, reason, UTC time and a canonical
request SHA256. Entity and audit writes share one transaction: an audit INSERT
failure rolls back both a new job and a cancellation. Retries preserve the first
operator/time record. On a timeout with unknown commit outcome, retry only with
the original operation key and original parameters to reconcile durable state.

## Database and migration boundary

Alembic revision `c61f98a742de` follows `b48f720da63e`. Apply it with the existing
independent, non-superuser `migration_owner` identity; cluster-role bootstrap is
unchanged. The migration adds `ecu_inventory`, `firmware_releases`, `ota_jobs`
and `ota_audit_events`, and a `(tenant_id,id)` unique constraint on `vehicles`.

Composite foreign keys enforce vehicle ownership and same-tenant ECU/release
hardware compatibility, including raw SQL inserts. All four tables have ENABLE
and FORCE RLS plus the existing restrictive tenant-binding contract. A dedicated
login cannot switch its database tenant by changing the session setting.

Application receives SELECT/INSERT on the four tables and column UPDATE on only
job status/time. Inventory, release metadata, job target and audit history cannot
be updated/deleted with runtime grants. Outbox/Remote Command workers get no OTA
table privileges. Startup checks verify policy semantics, FORCE RLS and the OTA
runtime privilege boundary. Existing dedicated tenant application logins receive
the new grants during migration; future provisioning uses the same grant contract.

This additive schema migration preserves the original five business tables' data.
The unique vehicle index requires a schema lock: use the existing migration lock
and timeout protocol, rehearse against the target-sized database, and schedule a
maintenance window when necessary. Destructive downgrade is refused; use reviewed
forward recovery. The historical Day11 restore/repeat-upgrade rehearsal now targets
this revision and explicitly accounts for the added vehicle ownership constraint.

## Acceptance and remaining execution phase

Run the combined exercise:

```powershell
.\.venv\Scripts\python.exe -m scripts.day17_drill
```

`day17-ota-foundation.json` must accompany the Day16/Day17 SLO evidence. The release
gate checks its exact assertions, source/run binding, freshness and file digest;
the optional remote gate also compares it with the authenticated GitHub artifact.
Reports are exclusive creations and never overwrite an earlier drill.

Real PostgreSQL/API acceptance covers authentication/permission denial, forged
tenants, immutable registrations, compatibility, concurrent idempotency, active
job uniqueness, cancellation, actual audit-trigger failures, fixed-login RLS,
worker/DDL denial, and operator/time audit records. Historical migration tests
cover a released Day11 backup -> current head -> repeat upgrade.

Next execution work must verify the actual object digest and signature, enforce a
trusted monotonic anti-rollback policy, authorize download, deliver to a device,
and record verified progress, installation, reboot and rollback results. A future
dispatcher must never treat `pending_verification` as an execution-ready state.
This foundation provides none of those physical execution guarantees.
