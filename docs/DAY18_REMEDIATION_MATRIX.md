# Day18 OTA remediation and acceptance scope

This matrix describes the local PostgreSQL 16 / free LocalStack implementation.
It is not evidence of AWS authorization, physical flashing or hardware secure boot.

| Finding | Implementation / acceptance |
| --- | --- |
| Runtime SQL bypasses execution state | `f94d016b238a` removes Job/Claim UPDATE and execution/report/audit INSERT. New intent trigger permits only pending. Exact, migration-owned functions alone mutate execution state, validate short-lived independent HMAC capabilities and append audit atomically. Direct SQL and forged-capability negative cases must preserve state. |
| Untrusted initial counter | Registration's zero is explicitly untrusted (`bootstrap_confirmed=false`). Owner-only Bootstrap records observed firmware, counter and factory digest with operator/reason/operation. Execution requires that record; the device requires explicit factory-image Bootstrap and compares its bank to the cloud's recorded floor. |
| Migration split | One published line: Day17 `c61f98a742de` → `d72fa60b319e` → `e83c904a127f` → `f94d016b238a`. The unused, never-deployed `d72a91b63ef0` proposal is excluded. No stamp or invented conversion. Single Head, fresh/legacy upgrade and unknown-revision rejection are tested. |
| Manifest incompatibility | Only `cv-ota/2` canonical sorted, compact, ASCII-escaped UTF-8 JSON is accepted. Golden bytes/signature are frozen. Old manifests must be rebuilt and re-signed offline; no signature reinterpretation. Legacy public-key maps have a separate explicit, exclusive-output conversion tool. |
| Vehicle-only authorization | Independent ECU public-key mapping and installation grant, signed method/path/body/identity/time/nonce, durable replay protection; vehicle JWT alone is insufficient. |
| Claim revocation/recovery | Owner quarantines a task after stopping/fencing the old agent. API/download/state transitions reject quarantined claims. Fresh signed observation of the active bank permits audited abort of an unapplied task or adoption of a boot-confirmed candidate. No blind force-reclaim. Device closes its old queue only after authenticated authoritative reconciliation. |
| Vehicle disabled after claim | Download checks before and after object validation. Database transitions lock/check the vehicle; disabled vehicles cannot advance installation. Already committed duplicate reports return the durable result. A physical operation already in flight cannot be remotely undone by this simulator. |
| Bare installation assertion | Success requires a separate ECU-signed `cv-boot/1` measurement, fresh server challenge, exact target/claim/digest/counter and confirmed startup. `proof_source=local_process` is signed. This remains software evidence, not a TPM/secure-boot attestation. |
| A/B banks absent | Explicit A/B metadata, trusted initial A, candidate staging into inactive bank, separate boot-probe process, confirmed boot, atomic pointer + report commit, retained previous bank and failure rollback. Stage/boot/activation/ACK crashes are tested. |
| True HTTP response loss | Loopback fault proxy consumes upstream committed 200, drops the connection before any response byte reaches the device, and verifies retry preserves one activation and one terminal audit. |
| Publisher key lifecycle | Versioned registry with validity windows/revocation; owner-only DB registration/rotation/revocation and audit. DB denial remains authoritative even when the old public registry is stale. Revoked IDs cannot be rebound or revived. |
| Missing historical OTA contract baseline | Runtime CI checks a frozen snapshot against immutable Day17 commit `cf08e437c79aaa041d25aa49dd572cfb15075048` independently of the PR's main baseline. Missing Day17 OTA schema is a failure. |
| Missing IaC evidence binding | Digest includes both workflows, tracked IaC code, Checkov configuration/exceptions, pinned tool requirements and Terraform inputs/contracts. State/plans/provider caches are excluded. Mutation regression tests cover gate inputs. |
| Large images / resource use | Validated anonymous spool files and bounded streaming instead of full response buffering. Default 32 MiB; explicit quota up to 256 MiB; at most two server files/responses. Device uses 64 KiB chunks, two banks + one staging quota, free-space check and bounded transfer. Forty MiB spool, capacity exhaustion and slow-response cleanup are tested. |
| Last-read deadline gap | Deadline is checked immediately after every SDK read, including final data and EOF. Late completion is rejected and closed. This is not a claim that a blocking SDK read is preempted before its configured socket timeout. |
| Real AWS / physical ECU | **Not executed / not passed.** Local evidence requires `real_aws_verified=false`, `physical_boot_verified=false`, `simulated_installation=true`. Actual AssumeRole/S3 VersionId/KMS denial, hardware key custody, secure boot and controlled power-cut experiments remain a separately funded/provisioned acceptance phase. |

## Operator procedure

Use the existing independent non-superuser migration owner for schema and OTA
management; runtime identities never receive DDL or access to `ota_authority`.
Run `alembic upgrade head`, provision the independent receipt key as documented in
Day18, and register publisher records before attempting verification.

Every management command requires an explicit UUID operation ID, operator and
reason. Repeating the same operation is harmless; changing its parameters conflicts.

```powershell
python -m database.ota_operations publisher-register --tenant tenant-a --operation <UUID> --actor factory-operator --reason "approved publisher window" --body publisher-registry.json
python -m database.ota_operations bootstrap --tenant tenant-a --operation <UUID> --actor factory-operator --reason "observed factory bank" --body bootstrap.json
```

`bootstrap.json` contains `vehicle_id`, `ecu_id`, `firmware_version`, a nonnegative
integer `security_version` and observed image `sha256`. Zero is acceptable only
as this explicit attested baseline, not as evidence inferred from a column default.
Existing claimed jobs without a boot challenge must be quarantined and reviewed;
the migration does not invent installation evidence or reset a counter.

Run a new local device with the independently supplied ECU private key and factory
image metadata, in addition to the existing identity and public publisher roots:

```powershell
python -m simulators.ota_device <identity-and-endpoint-arguments> --ecu-private-key ecu.pem --bootstrap-image factory.bin --bootstrap-sha256 <SHA256> --bootstrap-version 1.0 --bootstrap-security-version 0
```

Bootstrap never overwrites an active bank. A local/cloud floor mismatch stops
execution. Raising `--max-artifact-bytes` / `OTA_MAX_ARTIFACT_BYTES` is an explicit
capacity decision; both sides must agree. Interrupted own staging files can be
retried; two referenced banks and queued evidence are preserved. Unreferenced
content-addressed image files are pruned before the next download. SQLite ledger
retention remains a separate operational policy.

For a lost or blocked claim, stop/fence the old agent first. Quarantine with a body
containing `job_id`:

```powershell
python -m database.ota_operations quarantine --tenant tenant-a --operation <UUID> --actor recovery-operator --reason "old agent stopped and fenced" --body quarantine.json
```

An unclaimed verified task can be withdrawn immediately. A claimed task remains
isolated until an independent observation, after quarantine, proves which bank is
actually active. `boot_probe --observed-active` takes the local process lock and
signs the observed bank using the existing claim/challenge. It must be run on the
device; never fabricate the observation at the API. Supply its proof in a body
`{"job_id":"...","proof":{...}}` within 120 seconds:

```powershell
python -m database.ota_operations reconcile --tenant tenant-a --operation <UUID> --actor recovery-operator --reason "verified observed boot" --body reconciliation.json
python -m simulators.ota_device <same-device-arguments> --job <UUID> --reconcile
```

Owner reconciliation refuses unknown banks, stale/cross-device proof, a regressing
counter, or adoption of an inactive/revoked candidate. It updates inventory, report
ledger, quarantine result and audit in one transaction. A failed audit rolls them
all back. The device retains original report payloads and records their quarantine
disposition instead of pretending they were delivered. Only then may a new task
be created; old task writes remain fenced.

## Publisher rotation and protocol migration

The public registry is `cv-ota-keys/1`, with `tenants[tenant][key_id]` records holding
`public_key` (raw 32-byte Ed25519, base64), `not_before`, `not_after` (aware ISO-8601)
and boolean `revoked`. Use a new key ID for rotation and an explicit overlap window.
Register the new record, distribute/activate the public registry on API and device,
and revoke the old ID after reconciling outstanding work. Revocation is a DB
transaction with audit and denies new execution even if the API file is stale.

```powershell
python -m database.ota_operations publisher-revoke --tenant tenant-a --operation <UUID> --actor key-operator --reason "retire publisher" --body revoke.json
```

`revoke.json` contains `key_id`. Revocation cannot be undone by re-registering the
same ID. A previously downloaded candidate or disconnected device cannot be made
to forget a key instantly; quarantine/fence such work before recovery. Production
revocation distribution and hardware enforcement are not proved here.

For an old plain public-key map, `python -m scripts.ota_key_registry --help`
describes explicit validity-window conversion into a new file and an exclusive
audit record. It neither activates trust nor re-signs artifacts. Build a complete
`cv-ota/2` manifest and use the existing offline signing helper; the old protocol's
signature is never treated as a v2 signature.

## External acceptance remains separate

Before a real rollout, use a dedicated AWS sandbox and restricted existing roles
to verify positive and negative versioned-object/Secret/KMS access; record account,
region, caller identity, resource ARNs and actual denial results without credentials.
On real ECU hardware, bind the key to the ECU secure element, verify the boot chain,
measure the running image/counter, and cut power during stage/switch/confirm with
independent recovery logs. These require actual resources and equipment. Current
tests deliberately do not manufacture those results or make paid AWS calls.
