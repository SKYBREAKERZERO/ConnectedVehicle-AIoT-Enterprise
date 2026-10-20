> Installation note (2026-10-20): This overlay was manually merged into newer commit 41a811b, preserving its OU ownership, retirement safeguards and provider schema contract. Local governance uses policy_types[].type (not the package's incorrect .name), retains manage_ou and retired_environments, and verifies OU subtree membership. Original contracts remain; package contracts are in day20_overlay.tftest.hcl. See DAY20_LOCAL_INSTALL_REPORT.md for actual execution results.

# Day20 — OTA Infrastructure Coverage Matrix

Baseline: `SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise` at `wip/day20-infra-20261018`, commit `fc9033836285d84f5ff5be84d29711875d78e1f0`, checked 2026-10-20.

This document distinguishes source/configuration presence from executed Terraform, LocalStack, and real AWS proof. It **does not** claim a production AWS deployment or hardware OTA flashing. Day18/19 software ECU and PostgreSQL checks remain the business baseline.

## Runtime-to-infrastructure coverage

| Day / business component | Verified source path | Runtime identity and secrets | Infra dependency | IaC location at Day20 baseline | State before Day20 | Day20/next action |
|---|---|---|---|---|---|---|
| 17 OTA firmware release metadata / audit | `connected_vehicle/ota/service.py`, `database/migrations/` | tenant-bound Application DB login, independent schema migration owner | PostgreSQL, fixed-login RLS, immutable release metadata | database migrations & local compose, no RDS root | LOCAL_VERIFIED (previous tests) | document owner-vs-runtime rollout and grants; real AWS later |
| 18 signed firmware stream | `connected_vehicle/ota/artifacts.py` | OTA API; trusted public publisher key file | version-pinned S3 Object, SHA256/size, Ed25519, private Bucket | `modules/ota-artifact-bucket/`, `modules/ota-artifact-policy/` on WIP | IMPLEMENTED_UNVERIFIED | test resource versioning, Block Public Access, SSE-KMS and exact `GetObjectVersion`; ensure accepted object paths match Day17 |
| 18 OTA claim / report / authority | `connected_vehicle/ota/execution_service.py` | per-tenant Application DB identity; separate installation receipt authority | PostgreSQL, independent API authority material, JWT+ECU signature proof | `modules/ota-secrets/` on WIP + DB owner provisioning | PARTIAL_INFRA | confirm secret custody and no secret values in Terraform State; API secret delivery separate from DDL |
| 18 simulated ECU / signed boot proof | `simulators/ota_device/` | per-device private key stored only on device simulator | HTTP API, local SQLite journal, trusted public keys | non-Terraform local device simulator | LOCAL_VERIFIED (previous tests) | never upload ECU private keys or manufacturer private signing keys into Terraform |
| 19 OTA Campaign API | `apps/api/routers/ota_campaign.py` | operator `ota:read`/`ota:manage`, tenant Application DB | PostgreSQL, S3 versioned firmware, authorization materials | shared API role + `ota-artifact-policy`/`ota-secrets` WIP | PARTIAL_INFRA | review API scoped S3/KMS/Secret role permission and complete local composition |
| 19 Campaign Dispatcher | `apps/campaign/__main__.py`, `connected_vehicle/ota/campaign_service.py` | existing tenant Application DB identity; independent receipt/capability material | PostgreSQL, S3; no forced per-wave SQS | `modules/ota-runtime-iam/` on WIP | PARTIAL_INFRA | separate ECS IAM role exists as code; DB identity remains shared until independent GRANT/provision tested |
| Outbox Dispatcher | `apps/outbox/` | `outbox_worker` DB Secret | SQS send, KMS | `modules/messaging/` and existing local root | EXISTING | reuse; do not grant OTA execution table permissions |
| Remote Command Dispatcher | `apps/remote_command/` | `remote_command_worker` DB Secret | SQS receive/DLQ, MQTT, KMS | `modules/messaging/`, `modules/security/` | EXISTING | reuse; OTA claim/report does not run through command SQS |
| Terraform State bootstrap | `infra/terraform/bootstrap/state-backend/` | LocalStack dummy AWS key only | private versioned SSE-KMS S3, independent local bootstrap state | WIP Bootstrap files | IMPLEMENTED_UNVERIFIED | add native Mock contract tests; remote backend migration/lock is Day21–29, not completed now |
| Governance and SCP intent | `infra/terraform/modules/ota-governance/` | Organizations management identity, **not** OTA Runtime | OU, SCP, administrative S3/KMS protection | WIP Governance | PARTIAL_INFRA | offline JSON & tests; actual Organizations inheritance awaits real AWS |
| OTA observability | `infra/observability/`, `docs/DAY17_OPERATIONS.md` | protected metrics token and local observability identity | Prometheus/Alertmanager/OTel, later CloudWatch | existing observability config | PARTIAL_INFRA | add deployed campaign-specific metrics and runtime notifications in Day48–54 |
| OTA container deployment | `apps/api/`, `apps/campaign/` | per-process runtime identity | Docker image, ECS service, health checks | root `Dockerfile` is empty; no OTA runtime compose services | MISSING | build dedicated containers and deployment in subsequent days; no AWS now |
| AWS Dev root | `infra/terraform/environments/dev/` | GitHub OIDC/assumed Role (not available yet) | VPC/ECS/RDS/S3/KMS, state-backed AWS read-only Plan | `versions.tf` only on main | MISSING | Day55–59 only, after cost/identity approval |

Status legend: `EXISTING` code exists and was previously exercised within its documented bounds; `LOCAL_VERIFIED` local business behavior with prior evidence (not retested in this overlay); `IMPLEMENTED_UNVERIFIED` HCL present but this overlay has no Terraform execution proof; `PARTIAL_INFRA` only some of the required delivery chain is covered; `MISSING` no corresponding implementation; `NOT_SUPPORTED_LOCALSTACK` must be tested as Mock/contract or in explicitly approved AWS stage.

## Source-aware trust boundaries

1. **Firmware** is signed offline and registered by exact S3 `Bucket`, `Key`, `VersionId`, size, digest, tenant, release, hardware and ECU type. Reading latest object is not equivalent. S3 IAM grants exact versioned read permission; firmware publisher upload needs a distinct identity. No manufacturer private key in Terraform State.
2. **Runtime API** requires tenant-bound database login, signed publisher public-key registry, device public-key registry, and receipt authority material. ECU receives authenticated streamed bytes, not S3 credentials or unsigned URLs.
3. **Campaign** polls and serializes PostgreSQL transaction state; new SQS/Step Functions processing must not be claimed as existing or substituted casually. The Campaign ECS IAM role in WIP is separate from a dedicated PostgreSQL campaign login, which is NOT implemented.
4. **Outbox/Remote Command** identities and Secrets are already split. Do not give either worker OTA execution-table DML privileges or firmware publisher authority.
5. **Migration and Bootstrap** are operator roles and must never be mounted in API/Worker containers.
6. **Firmware vs State S3**: protect firmware object versions from deletion; protect State bucket configuration but do not freeze `.tflock` object deletion. State retention/lock/recovery are separate exercises.

## Terraform module inventory (WIP)

| Module | Inputs/outputs | Native Terraform test | Actual LocalStack Apply | Real AWS |
|---|---|---|---|---|
| `modules/ota-artifact-bucket` | present | added in Day20 overlay | not verified | not verified |
| `modules/ota-artifact-policy` | present; Day20 corrects default SSE header handling and Day17 key compatibility | added | not verified | not verified |
| `modules/ota-secrets` | present; Day20 normalizes `versions.tf` discovery | added | not verified | not verified |
| `modules/ota-runtime-iam` | present; Campaign IAM only | added | not verified | not verified |
| `modules/ota-governance` | revised for topology/enforce, OU/account | added | Organizations free LocalStack execution not verified | not verified |
| `bootstrap/state-backend` | existing WIP; self-bootstrap has local state | added | not verified | not verified |

## Day20 exit criteria

- [x] Current WIP branch and source dependencies audited.
- [x] Coverage Matrix constructed and gaps classified.
- [x] Governance default-off, stage, scope, membership checks and firmware/state protection corrected in deliverable source.
- [x] Terraform module native test files added in deliverable overlay.
- [x] Conservative no-real-AWS operations and permissions documented.
- [ ] Execute `terraform fmt -check -recursive`, `terraform init -backend=false`, `terraform validate`, `terraform test` for modules against the installed Terraform 1.14.7 / AWS 6.x toolchain.
- [ ] Execute repo full IaC Gate + Runtime Gate; check real CI on candidate SHA.
- [ ] Run actual LocalStack S3/IAM negative authorization tests with pinned firmware VersionId.

**Next work:** Day21 OTA firmware S3, Day22 IAM/Policy integration, Day23 Secret and Campaign runtime role integration, Day24–29 State/Drift/Import. No real AWS until Day55+.
