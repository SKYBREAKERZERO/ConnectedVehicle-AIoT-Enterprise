# Day18 — Signed OTA local execution

Day18 closes the local execution chain after the Day17 metadata foundation:
operator creates intent → verifies signed, pinned bytes → authenticated device
claims → device independently verifies/downloads → local bank activation → ordered
durable reports → cloud inventory and audit agree. Use PostgreSQL 16 and free
LocalStack. No real AWS calls, physical flashing or bootloader guarantees are
included in this acceptance.

## Eight-hour work plan

| Budget | Work | Acceptance |
| --- | --- | --- |
| 0.5h | Baseline and protocol design | Preserve existing work; version the execution protocol |
| 1.5h | Artifact trust | Fixed S3 version, size/SHA256, tenant-bound Ed25519 signature |
| 1.5h | Cloud state machine | Verified-only claims, device ownership, sequenced terminal reports |
| 2h | Device journal | Durable bank staging, atomic activation/report outbox, restart recovery |
| 1.5h | Fault injection | Real process exits, lost response, auth failure, audit rollback |
| 1h | Delivery | Quality checks, evidence gate, documentation and remote CI |

These are planning allocations, not a claim that each work package consumed the
entire allocation or that eight hours proves production readiness.

## Trust and bounded artifact access

`OTA_TRUSTED_KEYS_FILE` points to an operator-managed JSON public-key registry:

```json
{"tenant-a":{"manufacturer-1":"<base64-encoded 32-byte Ed25519 public key>"}}
```

Trust roots are never accepted in API bodies. Duplicate keys, missing tenant/key,
invalid signatures and oversized registries fail closed. Keep signing private keys
outside runtime processes, reports and Git. The offline helper accepts an existing
Ed25519 PEM key and a complete signed manifest JSON:

```powershell
.\.venv\Scripts\python.exe -m scripts.ota_sign_manifest --manifest manifest.json --private-key manufacturer.pem --output verification-request.json
```

Outputs are exclusive creations. The manifest is canonical UTF-8 JSON with sorted
keys, compact separators and ASCII escaping. It includes protocol `cv-ota/2`,
tenant/release IDs, ECU type, hardware/version, bucket/key/object version, size,
SHA256, security counter and key ID. This binds both bytes and deployment metadata.

The API verifies the signature before S3 access, then streams exactly the requested
object `VersionId`. ContentLength, returned VersionId, streamed byte count and SHA256
must match. The latest object is never a fallback. `OTA_MAX_ARTIFACT_BYTES` defaults
to 32 MiB for this local exercise (the Day17 registry can describe larger images).
Reads have SDK connect/read limits, a deadline checked between SDK reads and a
two-read concurrency limit. Cancellation retains capacity until the worker stops.
The artifact endpoint revalidates trust and bytes; it requires both a device JWT
and the persistent claim, and never returns an S3 URL or AWS credentials.

LocalStack fixtures create a private, versioned, AES256-encrypted bucket. These
checks prove local behavior, not AWS IAM enforcement. Before any real deployment,
provision the API's read-only S3 object/version permission for the intended tenant
prefix and encryption-key policy, and test actual AWS authorization separately.

## Versioned cloud protocol

Operator permissions remain `ota:read` / `ota:manage`. The new `ota:execute` scope is
available only to authenticated `principal_type=device` callers bound to the target
vehicle. Signed device scopes never confer operator management permissions.

| Endpoint | Meaning |
| --- | --- |
| `GET /v2/ota/jobs/{job_id}` | Tenant-scoped execution state |
| `GET /v2/vehicles/{vehicle_id}/ecus/{ecu_id}` | Operator reads installed firmware and monotonic security floor |
| `GET /v2/vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs/next` | Device discovers its ECU's verified or already-owned active job |
| `POST /v2/ota/jobs/{job_id}/verify` | Operator supplies operation UUID, trusted key ID, security counter and signature |
| `POST /v2/vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs/{job_id}/claim` | Device supplies a durable operation UUID; identical retry returns its same claim |
| `GET .../artifact` | Claimed device presents `X-OTA-Claim`; returns verified bytes |
| `POST .../reports` | Device reports sequence, stable event UUID and claim token |

States are `pending_verification → verified → downloading → installing → succeeded`
or `failed`. Day17 cancellation is allowed only before verification. One nonterminal
job per ECU is enforced across all active states. Verification does external IO
outside a DB transaction and rechecks job, vehicle and counter under locks before
promotion. A concurrent cancellation cannot be overwritten by verification.

Day17 request/response schemas remain unchanged. Calling the v2 verify endpoint
explicitly opts a job into the execution protocol. The old status endpoint and
creation-key replay return 409 with the v2 query path for an opted-in job; legacy
lists contain only legacy pending/cancelled jobs. Consumers must use v2 for opted-in
jobs. The new states are not silently returned through the old two-state contract.

Claims are persistent ownership/fencing identities, not automatically expiring
permission to repeat a physical effect. Another device or claim operation cannot
take over an installation of unknown outcome. Operator reconciliation is required
for permanently lost device state; there is intentionally no force-reclaim API.

An installing report precedes success. Reports must have consecutive sequence
numbers, valid state transitions and nonregressing event time. The same event and
body return the durable result; conflicting payloads and stale claims are rejected.
Success must report the verified digest. Job state, report ledger, ECU version /
monotonic security counter and audit append commit together. An audit failure rolls
them all back. All new tables use FORCE RLS and fixed-login tenant binding. Workers
get no execution-table access; only required application column updates are granted.
A migration-owned trigger independently rejects a decreasing counter or a firmware
change without a counter increase, including direct SQL by the application role.
Startup also verifies the trigger's exact body, enabled state and ownership.

Revision `d72fa60b319e` follows `c61f98a742de`. Use the existing independent migration
owner; bootstrap and runtime credentials stay separate. Destructive downgrade is
refused to preserve installed security counters and audit history.

## Device bank simulator and recovery

```powershell
.\.venv\Scripts\python.exe -m simulators.ota_device --base-url http://127.0.0.1:8000 --tenant tenant-a --vehicle <UUID> --ecu <UUID> --device-id tbox-1 --ecu-type body --hardware-version hw-1 --job <UUID> --state-dir <device-directory> --token-file <JWT-file> --trusted-keys <public-registry>
```

This entry point accepts only loopback HTTP, disables proxies/redirects, and reads
the bearer credential from a file. It persists tenant/vehicle/ECU/device binding,
claim operation, signed manifest, reports and the active bank in SQLite WAL with
FULL synchronization. An OS file lock excludes a second process. Existing state
cannot be rebound to a different device. Corrupt SQLite/active image is quarantined
by stopping; no automatic state reset is performed.
ECU type and hardware version come from trusted local configuration and are
persisted in the identity binding. A signed manifest for another hardware target
is rejected independently of the cloud's inventory checks.
Omit `--job` to first resume locally unfinished reports, then poll the next verified
job. Polling never transfers another device's claim. Each invocation is bounded;
an external local scheduler may invoke it again rather than running an infinite loop.

Image files are staged, hashed, fsynced and renamed into a content-addressed bank.
The device independently checks signature and monotonic security counter. It sends
and confirms the installing report before activating. The simulator's health check
is the `CVOTA1\n` image marker, with an explicit health-failure injection option.
Only a passing candidate becomes active. The SQLite active pointer/counter and
terminal report are committed together. Old image banks are retained; an unhealthy
candidate leaves the previous pointer and counter intact. The simulator never
executes image bytes or attempts hardware flashing.

Stable outbox events survive restart and 401/403. Authentication failure stops the
run without deleting reports. Transient HTTP operations have bounded retries;
rerun with repaired credentials and the same state directory to reconcile. A
committed terminal response lost before local acknowledgement is safely replayed.
Process-crash recovery is demonstrated; physical power-loss, disk destruction,
secure boot, Uptane/TUF, key revocation distribution and real ECU rollback remain
separate work. Retained banks need an explicit future capacity/retention policy.

## Repeatable acceptance and release gate

```powershell
.\.venv\Scripts\python.exe -m scripts.day18_drill
```

The command runs Day16/17 prerequisites plus the real Day18 API/S3/device-process
chain in fresh labelled containers. It deliberately exits the device after download,
activation and terminal acknowledgement, then restarts from persisted state.
It also injects untrusted signatures, wrong digests, stale/foreign claims, early
reports, regressed time, expired credentials, audit INSERT failure and unhealthy /
corrupt banks. PostgreSQL state, SQLite state, exact object bytes and audit counts
must agree. Reports never include signing keys, JWTs or database credentials.

`day18-ota-execution.json` and `day18-acceptance.json` are source/run-bound, exclusive
outputs. Python source binding includes API and device code; SQL, contract snapshots,
workflow and documentation also enter the readiness digest. Evidence must be fresh
within 15 minutes. An optional read-only remote check verifies exact-head trusted
Runtime/IaC gates and byte-identical authenticated GitHub artifacts:

```powershell
.\.venv\Scripts\python.exe -m scripts.day18_evidence --directory <CI-evidence-directory> --require-remote <PR>
```

The result is local review readiness, not deployment or merge authorization.
