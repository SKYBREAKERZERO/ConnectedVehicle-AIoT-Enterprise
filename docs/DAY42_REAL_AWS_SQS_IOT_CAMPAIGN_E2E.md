# Day42 — Real AWS Staging: SQS → IoT and Campaign → Virtual ECU E2E

**Status: code and offline negative tests. NOT REAL AWS PASS.**
No real AWS account, STS role, IoT device certificate, RDS audit login, approved
virtual test vehicle or private SSM tunnel was supplied to this code change.
PR CI runs only the offline contract matrix. Never mark Staging accepted from
ECS `RUNNING` or a self-supplied JSON receipt.

## Admission and strict isolation

A separate, manually approved, private staging runner (not a normal PR Runner)
must have a real STS assumed role containing `e2e` or `acceptance` in its name,
`DAY42_APPROVED_STAGING=true`, the exact source SHA checked out, account
`ap-northeast-1`, and a separately reviewed test fixture JSON:

```json
{
  "environment": "aws-staging",
  "account_id": "REPLACE_WITH_STAGING_ACCOUNT_ID",
  "tenant_id": "e2e-approval-01",
  "vehicle_id": "REPLACE_WITH_TEST_VEHICLE_UUID_V4",
  "test_only": true,
  "physical_vehicle": false
}
```

The target must be a **registered virtual-only vehicle**, with a unique
dedicated Staging tenant and no physical CAN, modem, fleet routing or customer
ECU assignment. Merely writing `test_only=true` is NOT an administrator
approval. Protect its source, reviewer identity, tenant/device registration
and expiry in the independent change record. No production account/tenant
or real vehicle may be used.

The auditor uses another role (containing `audit` or `acceptance`) and a
separately created PostgreSQL role
`cv_ota_staging_e2e_auditor`, with direct, SELECT-only grants and approved
tenant RLS policies. It MUST have `NOSUPERUSER NOBYPASSRLS NOCREATEDB
NOCREATEROLE NOINHERIT`; the DB connection must use a private RDS hostname
and PostgreSQL TLS `verify-full` with an independently reviewed CA bundle.
No PostgreSQL role, Secret, IoT certificate or policy is automatically
created or broadened by Day42.

## Remote Command: real Outbox → SQS → Worker → IoT Core

**Prerequisites:** actual RDS, SQS Standard queue and DLQ, Outbox and
Remote Command ECS Tasks with Day39/Day40 evidence, true OIDC operator role,
IoT Core ATS endpoint and an independently authorized virtual Thing with
an mTLS client certificate authorized ONLY to
`tenants/<test-tenant>/vehicles/<test-vehicle>/commands`.

Run `scripts.day42_aws_e2e --scenario remote --live` with these required
flags, supplied by the authorized staging run (values shown as shell variable
names; NEVER place tokens/cert private keys in command arguments):

```bash
export DAY42_APPROVED_STAGING=true
python -m scripts.day42_aws_e2e --scenario remote --live \
  --account-id "$STAGING_ACCOUNT_ID" --source-sha "$APPROVED_GIT_SHA" \
  --tenant "$E2E_TENANT" --vehicle "$E2E_VEHICLE_ID" \
  --approved-vehicle-file "$PROTECTED_VEHICLE_APPROVAL_JSON" \
  --operator-token-file "$PRIVATE_OIDC_TOKEN_FILE" \
  --api-url "$STAGING_HTTPS_API_ORIGIN" \
  --iot-endpoint "$REVIEWED_IOT_DATA_ATS_ENDPOINT" \
  --iot-cert "$PRIVATE_TEST_THING_CERT_FILE" \
  --iot-key "$PRIVATE_TEST_THING_KEY_FILE" \
  --iot-ca "$APPROVED_AWS_IOT_CA_FILE" \
  --output evidence/day42-remote-transport.json
```

This sequence:
1. Confirms real STS account/role/checkout and exact virtual test-only vehicle.
2. Reads the actual encrypted SQS queue ARN/RedrivePolicy and IoT ATS endpoint.
3. Establishes a **real MQTT mTLS subscription first** (QoS1) to the scoped IoT Topic.
4. Calls the real HTTPS API with an authorized operator OIDC token, expecting
   a **new** HTTP 202 `command_id`, not a reused idempotency result.
5. Waits for a matching IoT MQTT delivery with exact tenant, vehicle,
   command ID, command type and schema. Writes only metadata and payload SHA256.
6. Emits `REAL_AWS_TRANSPORT_OBSERVED_AUDIT_REQUIRED`, **not** E2E PASS.

Outbox now emits an application log marker
`outbox_sqs_published event_id=... message_id=...` only after it successfully
marks the outbox row published. The remote SQS processor emits
`remote_sqs_ack event_id=... message_id=... outcome=processed` after
idempotency completion and SQS DeleteMessage. These records are emitted
by real ECS Tasks to their configured CloudWatch log groups.

**Independent audit must match the *same* SQS MessageId across both groups**,
plus exact `remote_commands` state and `outbox_events.published_at` under
read-only tenant RLS. Neither queue depth nor ECS RUNNING is sufficient.

## Campaign: real Campaign → Job → Virtual ECU → durable report

**Hard prerequisite:** Day40 currently BLOCKS Campaign full independence
because it shares the API Application DB principal and lacks attested trusted
publisher key delivery. **Do not bypass Day40.** Campaign E2E can only
proceed once separate Campaign DB identity, the trusted key source,
signed firmware in version-pinned S3 and rollback/revocation contracts are
approved and verified in the actual Staging environment.

A separately authorized operator prepares, via the real HTTPS API, exactly
one isolated ECU target: a signed firmware release and registered trusted ECU,
a Campaign created/frozen with a non-empty `snapshot_sha256`, and a
reviewed `start` action. The Campaign Worker (not a local fake) must
dispatch its real `ota_jobs` Job. Obtain the immutable `job_id` from the
frozen target list. Do not bypass the Worker by writing an OTA Job directly.

The existing `simulators.ota_device` **deliberately rejects remote API URLs**.
Keep that boundary. The private runner must use a separately authenticated,
audited SSM/host-only port-forwarding session that binds
`http://127.0.0.1:<local-port>` to the real private HTTPS service with
certificate hostname validation at the upstream TLS hop. That tunnel setup
and source/destination approval are external to Day42 and must have
independent evidence. Do NOT change the simulator to permit arbitrary HTTP.

```bash
python -m scripts.day42_aws_e2e --scenario campaign --live \
  --account-id "$STAGING_ACCOUNT_ID" --source-sha "$APPROVED_GIT_SHA" \
  --tenant "$E2E_TENANT" --vehicle "$E2E_VEHICLE_ID" \
  --approved-vehicle-file "$PROTECTED_VEHICLE_APPROVAL_JSON" \
  --api-url "$STAGING_HTTPS_API_ORIGIN" \
  --operator-token-file "$PRIVATE_OIDC_TOKEN_FILE" \
  --local-api-tunnel "$VERIFIED_LOCAL_ONLY_API_TUNNEL" \
  --campaign-id "$APPROVED_SINGLE_ECU_CAMPAIGN_ID" \
  --ecu-id "$APPROVED_TEST_ECU_ID" \
  --expected-job-id "$FROZEN_TARGET_JOB_ID" \
  --device-id "$REGISTERED_TEST_DEVICE_ID" \
  --ecu-type "$TEST_ECU_TYPE" --hardware-version "$TEST_HW_VERSION" \
  --ecu-token-file "$PRIVATE_DEVICE_OIDC_TOKEN_FILE" \
  --ecu-private-key "$PRIVATE_TEST_ECU_KEY" \
  --trusted-keys "$REVIEWED_PUBLISHER_TRUST_FILE" \
  --state-dir "$ISOLATED_TEST_ECU_STATE_DIR" \
  --bootstrap-image "$TRUSTED_FACTORY_BANK_IMAGE" \
  --bootstrap-sha256 "$TRUSTED_FACTORY_SHA256" \
  --bootstrap-version "$FACTORY_FIRMWARE_VERSION" \
  --bootstrap-security-version 0 \
  --output evidence/day42-campaign-virtual-ecu.json
```

The runner verifies frozen target and preassigned Job ID, waits for the
**actual Campaign worker** to dispatch, runs the existing cryptographically
verified A/B Bank simulator with a registered ECU signing key, and checks
the **actual API** reports the job as `succeeded` and the single-ECU
Campaign counters reconcile. It does NOT generate firmware signing keys
or install a release from an untrusted arbitrary source. Receipt status is
`REAL_AWS_CAMPAIGN_ECU_OBSERVED_AUDIT_REQUIRED`.

## Independent RDS + CloudWatch audit (mandatory)

Use the **other** authorized AWS read-only auditor and its RDS read-only,
tenant-RLS role. The URI and credentials live only in a protected file
(`chmod 0600` on Linux); never upload the DSN. Verify-full TLS is required.

```bash
python -m scripts.day42_e2e_audit --live \
  --account-id "$STAGING_ACCOUNT_ID" --source-sha "$APPROVED_GIT_SHA" \
  --tenant "$E2E_TENANT" \
  --receipt evidence/day42-remote-transport.json \
  --audit-dsn-file "$PRIVATE_RDS_AUDITOR_DSN_FILE" \
  --output evidence/day42-remote-audit.json
```

Repeat with Campaign receipt. This audit requires:
- Exact real PostgreSQL `remote_commands`, `outbox_events` records and tenant
  association, committed publication and expected command status.
- Matching real CloudWatch Outbox SendMessage / Worker processed ACK with
  the **same SQS MessageId** and the exact event ID. No test may consume,
  acknowledge or purge the live SQS queue to fabricate this result.
- For Campaign: the actual immutable target/job association, succeeded
  `ota_jobs` state, durable `ota_execution_reports` with success status,
  and frozen `ota_campaigns` snapshot / exact target-job counts.
- The correct role, source SHA, account, tenant and recent receipt provenance.

Only this independent step may emit `REAL_AWS_E2E_AUDITED`. Its JSON does
not contain credentials, MQTT payloads, device private keys, raw database
records or Secret values.

## Enterprise release gate and failure handling

Required before any `STAGING_ACCEPTED`: all Day35–Day41 gates on the same
immutable source, approved and reconciled Plan/Apply, Day39/Day40 real IAM
verification, *both* Day42 real E2E audits, Campaign identity/keys remediation,
SLO/alarms, SQS redelivery/idempotency/ACK-loss faults, ECU revoked-key,
vehicle-disabled, signature and A/B rollback negative probes, independent
evidence integrity (versioned encrypted S3 + immutable retention/approver
attestation), and verified cleanup of isolated test resources.

Any test timeout, IAM denial, unreconciled CloudWatch MessageId, missing RDS
record, unexpected Campaign job, physical-device risk or missing evidence is
`STAGING_BLOCKED`. Do **not** downgrade to ECS RUNNING or replay actual
fleet commands. No `terraform apply`, AWS account mutation, IoT publish or
OTA installation was performed by committing these files.
