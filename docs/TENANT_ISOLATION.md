# Tenant isolation acceptance

| Priority | Control | Implementation and evidence |
| --- | --- | --- |
| P0 | JWT tenant context | Existing RS256 issuer/audience/expiry validation; signed tenant only. Forged signature / wrong algorithm tests retained. X-Tenant-ID cannot override identity; body tenant injection rejected. Database binding refuses a tenant differing from authenticated context. |
| P0 | API resource ownership | Command issue/status/report and telemetry ingest/query constrain tenant + vehicle. Cross-tenant resource returns 404; wrong device identity returns 403. Telemetry query now checks vehicle ownership before reading samples. |
| P0 | Repository constraints | Tenant-scoped reads retained; command locks include expected tenant/vehicle; command and vehicle saves constrain persisted tenant, plus command vehicle. Legacy unscoped helpers are privileged internal APIs, protected by runtime RLS; they are not HTTP tenant selectors. |
| P0 | Blocked report precision | Existing scoped T-Box replay: event UUID, operation UUID, actor/reason, one transaction, idempotent audit. No bulk replay. |
| P0 | Worker ownership | Entire RequestedPayload validated; persisted tenant, vehicle, command type, created/expiry times must match before state change or MQTT publication. Incomplete ID-only legacy events now fail validation and follow existing retry/DLQ flow. |
| P1 | PostgreSQL RLS | Migration e15c849a320b and provisioning install guards on vehicles, remote_commands, command_reports, telemetry_samples, outbox_events. Missing context denies runtime tenant rows. WITH CHECK restricts inserts. |
| P1 | Audit | Existing operator_actions and SQLite report_replays retain operation, actor, event/target, timestamp, action/reason. Actor strings from local tools remain declarations, not a deployed identity provider. |
| P1 | Device ledger binding | Existing ingress/restore tenant + vehicle binding; Store.accept now enforces persisted binding even immediately after reopen, before explicit rebind. Wrong restored identity or foreign command creates no command/report. |
| P2 | Regression | Signed API boundary tests, real PostgreSQL two-tenant raw SQL, Worker forged scope/type/timestamps, cache collision, SQLite restore/binding, and six-process LocalStack E2E. |

## Transaction and pool contract

`set_tenant_scope` uses parameterized `set_config('app.tenant_id', tenant, true)`.
It is transaction-local, applied in every API service transaction and both Worker
prepare/mark-sent transactions. Commit and rollback clear the value. Tests assert
no context remains while reusing the same PostgreSQL backend connection.

Runtime roles are non-owner, NOBYPASSRLS, and have no DDL permission. RLS combines a
permissive access policy and a restrictive tenant guard, so adding a permissive
policy does not remove the guard. Table owner/migration access is deliberately
preserved for migrations, backups and audited operations. Outbox Worker can scan
its one granted dispatch table across tenants; it cannot read vehicles or commands.
App outbox inserts require the database-generated tenant_id to match the bound context.
The stored generated column derives from event_body payload tenant_id, is indexed
with status, and cannot be supplied or changed independently. Generic platform
events without tenant ownership retain NULL for compatibility; API tenant writes
without ownership fail RLS. Malformed legacy JSON also derives NULL through an
immutable parsing function and retains its original bytes for failed-event
isolation; tenant API inserts of these events are rejected. ORM generated-default fetching is disabled so app_user
retains INSERT-only outbox privileges.

The application owns one shared database role across tenants. RLS guards against
omitted query filters, not compromised code or credentials that can deliberately
set arbitrary PostgreSQL session settings. JWT verification, service ownership
checks, Worker comparison with authoritative command data and least-privilege
GRANT remain required. RLS behavior follows the PostgreSQL documentation:
[PostgreSQL 16 row security policies](https://www.postgresql.org/docs/16/ddl-rowsecurity.html)

## Cache and rollout

Remote dispatch cache keys use `dispatch:v2`, event ID, and a canonical hash of
source/type/version/full payload. Changing tenant, vehicle or action cannot hit a
completed cache entry and skip validation. Trace metadata does not change the key.
Existing v1 completion entries are not reused; replay is resolved from persisted
command state and ECU deduplication, retaining the original command ID.

Deploy the updated API/Worker transaction binding code before enabling RLS on an
existing database, then run Alembic with the independent migration credentials.
The existing controlled runtime provisioning tool also installs the same RLS SQL
idempotently. On 2026-10-11 the existing local connected-vehicle database was
backed up, upgraded from a52bcd546e2d to f26d950b431c, and provisioned with three
independent runtime roles and LocalStack secrets. AWS was not changed. Privilege
and policy drift tests use a dedicated disposable PostgreSQL container. Legacy ID-only messages
need investigation/reconciliation, not bypassing tenant validation.

This is local acceptance. Remote CI, GitHub branch protection, real AWS IoT,
production identity-provider deployment and physical CAN remain unverified.

## Local validation result

699 tests passed without exclusions: the complete pytest suite, including unit, contract, independent-process E2E, device crash recovery, real PostgreSQL permissions/tenant tests, and real SQS/Redis deduplication. Ruff check, format check (296 files), mypy (286 source files), module contracts, Terraform fmt and local/dev validate, and git diff --check passed. Real AWS and remote CI were not run.


## Runtime startup and deployment evidence

Both API lifespan and worker database-pool composition verify the connected role
before serving traffic. A wrong account, SUPERUSER, BYPASSRLS, database/role creation,
replication, role memberships, schema creation or temporary table privileges cause
startup failure. All five protected tables must have RLS enabled with restrictive
tenant_guard policies and be owned by an independent account. The generated Outbox
tenant column must exist. Failure disposes the pool; there is no administrator fallback.

The local bootstrap/migration owner connected_vehicle remains an administrator for
migration and backup operations. Runtime connections read app_user, outbox_worker
and remote_command_worker from their corresponding Secrets Manager secrets; all
three have rolsuper=false and rolbypassrls=false. Never interpret the owner account's
flags as runtime acceptance evidence. This local administrator is not a deployed
production migration identity.

Actual local schema: vehicles, remote_commands, command_reports, telemetry_samples
and outbox_events all report relrowsecurity=true. Outbox tenant_id reports
is_generated=ALWAYS. Evidence is saved under .runtime-reports/local-database-security.json;
the pre-upgrade SQL backup is retained beside it and must be treated as sensitive data.
Local migration credentials were configured in the ignored .env, separately from
runtime secrets. Runtime passwords were generated and stored in LocalStack, not docs.

The Runtime quality gate now provisions PostgreSQL, Redis and LocalStack integration
services, applies Alembic with migration-only credentials, and runs real Redis and
SQS deduplication regression tests. These verify cached completion and a second SQS
delivery publishing nothing, in addition to the isolated least-privilege role tests
and independent runtime E2E. GitHub execution and branch protection are still external
acceptance items.

Local acceptance does not isolate administrator files from other programs running as the same operating-system user. Production runtime task environments and filesystem access must exclude migration credentials; the startup guard verifies database connection privileges.


## Closed gaps from the database inspection

| Reported gap | Verified outcome |
| --- | --- |
| Runtime SUPERUSER / BYPASSRLS | app_user, outbox_worker and remote_command_worker all false; startup rejects privilege drift. Administrator retained only for migration/backup tooling. |
| vehicles / remote_commands missing RLS | Actual local database now has RLS on both and three related tenant tables. |
| Outbox missing tenant column | Stored generated tenant_id and tenant/status index; legacy payload unchanged, malformed events remain quarantinable. |
| Runtime GRANT evidence missing | Real PostgreSQL positive operations and forbidden table/column/DDL tests passed for each independent role. |
| Transaction cleanup missing | Same-backend commit and rollback clear tenant scope; subsequent unscoped reads return zero rows. |
| SQS / Redis regression failure | Complete suite: 699 passed, no failures or skips; real SQS deduplication and Redis tests now part of Runtime CI. |
| Worker / repository / telemetry / cache negative cases | Forged tenant, vehicle, command type and timestamps reject without publishing; foreign updates return zero rows, telemetry returns 404, cache fingerprints differ. |
| SQLite replay / ACK / recovery acceptance | All 15 dedicated acceptance cases and real process crash-recovery E2E passed. |

The current three LocalStack Secrets were reconciled into Terraform state after
backing up the original state. The local apply passed the deletion gate and made
no destructive replacements. A second plan has zero changes and passes resolved
IAM/encryption policies. Actual IAM role attachments and policy documents were
checked: each runtime reads only its corresponding Secret, and all three use the
Terraform-managed Secrets KMS key. This inspects local policy configuration;
production IAM enforcement still requires AWS acceptance.

Additional evidence: .runtime-reports/local-runtime-iam-security.json,
.runtime-reports/local-security-terraform-apply.txt and
.runtime-reports/local-security-terraform-second-plan.txt. These files and local
backups are ignored by Git; no credential values were included in the reports.
