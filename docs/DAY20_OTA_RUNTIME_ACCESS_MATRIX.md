> Installation note (2026-10-20): This overlay was manually merged into newer commit 41a811b, preserving its OU ownership, retirement safeguards and provider schema contract. Local governance uses policy_types[].type (not the package's incorrect .name), retains manage_ou and retired_environments, and verifies OU subtree membership. Original contracts remain; package contracts are in day20_overlay.tftest.hcl. See DAY20_LOCAL_INSTALL_REPORT.md for actual execution results.

# Day20 — OTA Runtime Access Matrix (engineering contract)

| Caller | PostgreSQL | S3 artifact | KMS | OTA authority secret | ECUs/private keys | SQS/MQTT |
|---|---|---|---|---|---|---|
| Operator / offline firmware publisher | Metadata via operator-controlled business API; separate migration roles only for controlled key registry | upload explicitly approved object/version and sign manifest; publisher permission NOT shared with runtime | encrypt via S3; no arbitrary decrypt | must not access install authority | manufacturer private key stays offline | none for firmware release |
| OTA API | tenant-bound Application DB, SELECT/approved functions only | exact `GetObjectVersion` keys in approved bucket | `kms:Decrypt` via S3 for firmware and via Secrets Manager when required | API receipt authority needed for verified install transition | verify public registry + device proof, never receive ECU private key | no forced OTA per-wave SQS |
| OTA Campaign Dispatcher | currently same per-tenant Application DB identity (explicit known gap) | read pinned artifact when verifying a Campaign | scoped S3 decrypt | capability/receipt authority as required by current code | no ECU private key | no forced per-wave SQS |
| Outbox Dispatcher | outbox-specific runtime login/Secret | **DENY** | messaging-specific scoped key only | **DENY** | **DENY** | publish to assigned command queue |
| Remote Command Dispatcher | remote-command-specific runtime login/Secret | **DENY** | messaging-specific scoped key only | **DENY** | **DENY** | consume assigned queue and publish MQTT commands |
| Device/ECU simulator | **DENY** | no direct S3 access; stream via authenticated API | **DENY** | **DENY** | holds its own ECU signing private key locally | HTTP OTA poll/claim/reports; original command path separate |
| Migration/Bootstrap operator | owns migrations and reviewed GRANT changes, never runtime | only approved provisioning access | provisioning only | key registration (owner only) | no device private key | not runtime |

**Important:** This is the *intended* least-privilege contract, not proof of live AWS IAM authorization. LocalStack IAM emulation, Terraform mock tests and actual AWS service enforcement are separate evidence classes. The WIP `ota-runtime-iam` code uses one Campaign role with three distinct read policies. The Campaign PostgreSQL login is **not** independent yet and must not be reported otherwise.

## Security acceptance for later days

1. Negative tests: Outbox and Remote Command role can't read firmware or authority Secret.
2. Exact ObjectVersion: latest-version fallback, foreign tenant key, unsigned/altered image all rejected.
3. KMS: Runtime may decrypt only via correct service and encryption context (where supported).
4. No private signing key or secret values in Terraform State/Plan/CI logs.
5. Campaign crash/restart doesn't bypass frozen targets, canary results or audit.
6. Expiration/retirement: old pinned firmware versions remain until an approved campaign-safe retirement procedure.
