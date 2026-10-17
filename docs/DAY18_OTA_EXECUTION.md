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
them all back. Public OTA tables use FORCE RLS and fixed-login tenant binding. Workers
get no execution-table access; only required application column updates are granted.
A migration-owned trigger independently rejects counter regression. The forward
security migration additionally removes application UPDATE access to both version
columns and INSERT access to the initial security counter. Only a short-lived,
independently authenticated installation receipt can advance an existing ECU.
Startup verifies both the trigger and the exact authority function bodies,
ownership, SECURITY DEFINER/search_path settings and runtime/public privileges.

The authoritative published lineage is `c61f98a742de` → `d72fa60b319e` →
`e83c904a127f`. The first two revisions remain unchanged; the forward migration
repairs existing base and tenant roles as well as freshly provisioned roles.
`d72a91b63ef0` is an alternate local proposal absent from this published Git
history, not a compatible predecessor or an alias. Its databases are refused by
Alembic. Never stamp them onto this line: preserve a backup and the original
revision source, compare schema/state/ACLs, then implement a reviewed explicit
conversion. There is no safe automatic merge without that source and data.
Single-head lineage and unknown-revision rejection are regression tested.
Use the independent non-superuser migration owner; bootstrap/runtime credentials
stay separate. Destructive downgrade is refused.

## Independent installation authority and ECU proof

`OTA_DEVICE_KEYS_FILE` is an operator-controlled public registry, independent of
JWT claims and application database rows:

```json
{"tenant-a":{"tbox-1":{"<ecu-uuid>":{"vehicle_id":"<vehicle-uuid>","install_allowed":true,"public_key":"<base64 raw Ed25519 public key>"}}}}
```

All four device routes (poll, claim, download, report) require proof using that
ECU's independent private key, in addition to the vehicle JWT. `X-ECU-Nonce`,
`X-ECU-Time` and `X-ECU-Signature` sign the method, exact path/body hash, tenant,
vehicle, ECU, principal, nonce and timestamp with domain `CV-ECU-PROOF/1`.
Proofs outside ±60 seconds, unauthorized/revoked mappings, altered requests and
reused nonces fail closed. Nonces persist in a private schema across API restarts;
each HTTP retry uses a fresh nonce while its business event/operation stays stable.
The simulator's private key is local and never returned by cloud endpoints.
This proves software key possession, not TPM-backed physical hardware identity.

`OTA_INSTALL_RECEIPT_KEYS_FILE` is a separate API authority secret, never derived
from or included in the application database Secret. It contains a random 32-byte
HMAC key per tenant, with an immutable key ID:

```json
{"tenant-a":{"key_id":"local-receipt-1","secret":"<base64 32 random bytes>"}}
```

Keep this file outside Git/reports, mounted read-only with restrictive OS access.
An operator explicitly registers the same key in the database using migration
credentials; runtime roles cannot read, replace, enable or register authority keys:

```powershell
.\.venv\Scripts\python.exe -m database.provision_ota_authority --tenant tenant-a --key-file <authority-secret.json>
```

The migration installs trusted PostgreSQL `pgcrypto` in private `ota_authority`.
An existing installation of that extension elsewhere requires reviewed migration
planning; it is not silently moved. No bootstrap/superuser credentials enter API
execution. Before minting a 60-second receipt the API rechecks the manufacturer
signature and the ECU proof, ordered success report and digest. The database
function verifies the HMAC and expiry, fixed-login tenant, exact job/release/ECU,
manifest/signature, device/claim, report sequence/body and audit digest. It inserts
an immutable private receipt and advances the version in the same transaction.
Job/report/audit failures roll back the entire transaction. A fabricated job,
report or SQL function call using only runtime database credentials cannot mint
this capability. The monotonic trigger remains a second guard.

Only the management owner can disable a compromised receipt key or provision a
new ID; old IDs cannot silently change material. Private receipts are retained.
Owner-only nonce housekeeping may delete entries older than 120 seconds, after
their proof validity window. Full API process/authority-key compromise remains a
different threat from leaked database credentials; production key custody and
hardware attestation are separate deployments.

## Device bank simulator and recovery

```powershell
.\.venv\Scripts\python.exe -m simulators.ota_device --base-url http://127.0.0.1:8000 --tenant tenant-a --vehicle <UUID> --ecu <UUID> --device-id tbox-1 --ecu-type body --hardware-version hw-1 --job <UUID> --state-dir <device-directory> --token-file <JWT-file> --trusted-keys <public-registry> --ecu-private-key <local-ECU-key.pem>
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
