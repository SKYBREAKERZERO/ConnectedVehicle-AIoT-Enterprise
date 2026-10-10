# Database runtime credential isolation

| Runtime | PostgreSQL role | Secret suffix | Permissions in public schema |
| --- | --- | --- | --- |
| API/Application | app_user | database/application | SELECT vehicles and remote_commands; INSERT remote_commands and outbox_events |
| Outbox Dispatcher | outbox_worker | database/outbox | SELECT outbox_events; UPDATE status, attempts, available_at, claim_token, lease_expires_at, published_at, failed_at, failure_code, failure_reason |
| Remote Command Dispatcher | remote_command_worker | database/remote-command | SELECT remote_commands; UPDATE status, updated_at |

All roles receive only CONNECT and schema USAGE. UUID identifiers need no sequence grants.
Runtime roles cannot CREATE, CREATE TEMP, ALTER, DELETE, TRUNCATE, migrate, or access
alembic_version. SELECT FOR UPDATE works with the granted UPDATE columns. Dispatch
uses SQLAlchemy change tracking, so unchanged command attributes do not need UPDATE.
Application privileges reflect the current API, which reads vehicles but does not create
or modify them. Future APIs and migrations must add explicitly reviewed grants.
This isolates services, not tenants; tenant filtering remains an application concern.

## Setup and upgrade

1. Retain a separate database owner/admin for PostgreSQL and Alembic. Set
   MIGRATION_DATABASE_USERNAME and MIGRATION_DATABASE_PASSWORD explicitly. The
   database host, port and name remain DATABASE_HOST/PORT/NAME. Alembic refuses a
   runtime role or missing management credentials; it never reads a runtime secret.
2. Run `alembic upgrade head` with that migration identity.
3. Apply the local Terraform configuration to create three secret containers and the
   three existing task roles with isolated read policies. Terraform stores no passwords.
4. In a controlled provisioning process, securely set APP_USER_PASSWORD,
   OUTBOX_WORKER_PASSWORD and REMOTE_COMMAND_WORKER_PASSWORD to distinct values.
   Run `python -m database.provision_runtime_credentials` with migration credentials
   and AWS credentials authorized to PutSecretValue on all three secret containers.
   It applies database/runtime-grants.sql transactionally, assigns passwords, then
   writes the matching JSON secrets. The AWS bootstrap task role alone does not
   confer database admin access: the provisioning operator needs both capabilities.
5. Start/restart each runtime with its own task role and secret ID from Terraform's
   database_runtime_configuration output. Do not inject migration credentials or
   passwords for the other runtimes into those tasks. API lifespan loads app_user.
   Use `remote_command_worker_runtime(settings, publisher)` as an async context
   manager for the remote worker and `remote_command_outbox_runtime(settings,
   retry_policy)` for Outbox. The context managers own and dispose their isolated
   database pools. Lower-level factories accepting session factories are dependency
   injection seams for tests; production entry points should use the context managers.

Secrets use JSON fields engine, host, port, dbname, username and password. Runtime
loading validates the expected username and fails closed on missing, malformed or
inaccessible secrets. Explicit APPLICATION_DATABASE_SECRET_ID,
OUTBOX_DATABASE_SECRET_ID and REMOTE_COMMAND_DATABASE_SECRET_ID override the default
`/connected-vehicle/{APP_ENV}/database/...` paths. No admin credential fallback exists.

For LocalStack, use CLOUD_RUNTIME=localstack and an endpoint reachable from the
process. Secret host/port must likewise be reachable from the runtime (localhost and
the published port for host processes; postgres:5432 for containers). The PowerShell
bootstrap helper also supports -Runtime application/outbox/remote-command and reads
RUNTIME_DATABASE_PASSWORD; it only writes an already-provisioned credential.

For AWS, use CLOUD_RUNTIME=aws with the existing SDK credential chain and real secret
ARN overrides. The existing cloud factory omits LocalStack endpoints in AWS mode.
The dev Terraform root currently contains only provider version declarations, with
no ECS task definitions or AWS database deployment. The local root stays LocalStack
only. When wiring the AWS deployment, use the same per-role secret resource and KMS
conditions and the output mapping; do not deploy the local root against AWS.

## Operational behavior

Stop/drain runtimes before initial cutover or password changes. Database changes and
Secrets Manager writes cannot form one distributed transaction. If a secret write
fails, provisioning fails; keep runtimes stopped and rerun with the same passwords
until every secret is updated. Rerunning the grants clears old table/column grants
and role memberships. Existing runtime object ownership fails the transaction;
transfer it to the migration owner before retrying. No automatic ownership transfer
or shared-password rollback is performed.

Grants revoke PUBLIC privileges on the target database and public schema, so run this
only in the dedicated application database and review any other consumers first.
Default privileges apply to the executing migration owner. Future tables remain
inaccessible until reviewed grants are added. Apply runtime-grants.sql after relevant
migrations. This repository uses only the public schema; additional schemas, role
ownership, SECURITY DEFINER functions and grants from other owners require review
before extending the deployment.

## Verification

Run `ruff check .`, `ruff format --check .`, `mypy apps enterprise_platform connected_vehicle database`, and
`pytest tests/unit tests/contract tests/integration/security/test_database_runtime_permissions.py`.
The permission integration test starts a dedicated temporary PostgreSQL container,
exercises real API issue, outbox claim/retry/publish and remote dispatch, and verifies
cross-table, restricted-column, DELETE and DDL denials without changing the dev DB.
Run `terraform fmt -check -recursive` and validate both local and dev roots after init.
