# Independent runtimes and real E2E validation

## Run three independent processes

Install: `python -m pip install -e ".[dev]"` (Python 3.12).
The installed distribution now includes `connected_vehicle`; entry points work
outside the checkout as well.

| Process | Start command | Database role | Default Secret suffix | Owned connections |
|---|---|---|---|---|
| API | `python -m apps.api` / `vehicle-api` | app_user | /database/application | PostgreSQL |
| Outbox | `python -m apps.outbox` / `vehicle-outbox` | outbox_worker | /database/outbox | PostgreSQL, SQS |
| Remote Command | `python -m apps.remote_command` / `vehicle-remote-command` | remote_command_worker | /database/remote-command | PostgreSQL, SQS, Redis, MQTT |

Use Terraform's `database_runtime_configuration` output to inject each process's
own Secret ID and task role. Default names are
`/connected-vehicle/{APP_ENV}/database/{runtime}`. AWS mode uses the AWS credential
chain and ignores the LocalStack endpoint. LocalStack mode uses AWS_ENDPOINT_URL.
Never inject migration credentials into these runtimes. Run Alembic and the separate
provisioning tool with the migration owner as documented in
[credential isolation](../database/CREDENTIAL_ISOLATION.md).

Rerun runtime-grants.sql through the migration owner when deploying this change:
Outbox additionally needs UPDATE on the existing failed_at, failure_code and
failure_reason columns. No new table or DDL permission is required. Workers still
cannot modify payloads, delete records, or read unrelated tables.

## API identity and readiness

Existing trusted SecurityContext integrations remain supported. An optional
single-tenant service identity requires API_SERVICE_TOKEN (a random secret of at
least 32 characters) and API_SERVICE_TENANT_ID together. Send
`Authorization: Bearer <token>`. Tenant and VEHICLE_COMMAND permission are determined
by server configuration, never caller headers. No default token exists; missing
or invalid authentication returns 401. This is a service credential, not end-user
login: deploy HTTP behind TLS, provision and rotate the credential securely, and
use an identity provider for end users. E2E generates a token and does not bypass
authentication dependencies.

GET /health/live checks the process. GET /health/ready checks PostgreSQL using the
application role within DATABASE_HEALTH_TIMEOUT_SECONDS and returns a generic 503
on failure. HTTP 202 means command and Outbox acceptance committed together, not
that the vehicle executed the command.

## MQTT wire contract

The transport-independent MQTTRemoteCommandPublisher is composed with
MQTTBrokerTransport by MQTTBrokerPublisher in mqtt_runtime.py.

Topic: `tenants/{tenant_id}/vehicles/{vehicle_id}/commands`.
Tenant IDs must be one ASCII segment with letters, digits, underscores or hyphens
(1-128 characters). JSON contains schema_version="1.0", command_id, vehicle_id,
tenant_id, command_type, created_at and expires_at. QoS=1; retain=false. Only
DISPATCHING commands may publish. SENT means broker PUBACK, not device execution.
Devices must deduplicate command_id and reject expired commands.

Configure MQTT_HOST/PORT, MQTT_TIMEOUT_SECONDS and optional MQTT_USERNAME/PASSWORD.
AWS mode requires verified TLS: enable MQTT_TLS_ENABLED, optionally MQTT_CA_FILE,
and configure MQTT_CERT_FILE/MQTT_KEY_FILE together for mutual TLS such as AWS IoT
Core. Certificate and hostname verification remain enabled. Broker credentials are
separate from database credentials. A fresh bounded connection per publication
trades throughput for simple restart recovery; the next SQS delivery reconnects.
Windows runtime entry points select aiomqtt's required SelectorEventLoop.

## Failure and termination behavior

- Outbox publishes outside DB transactions and fences updates with claim tokens.
  Transient transport failures persist exponential backoff with jitter, 1s base
  and 30s cap. OUTBOX_MAX_ATTEMPTS defaults to 10. Exhaustion becomes FAILED with
  retry_exhausted; malformed/non-retryable items become FAILED with non_retryable.
  Only sanitized failure information is persisted. A poison item does not abort
  later valid items. Diagnose and replay deliberately with admin tooling: workers
  cannot rewrite payloads. Crashed claims recover after their lease expires.
- Remote workers poll one message per batch so serial processing does not consume
  later messages' visibility leases. Read timeout exceeds long polling; SDK retries
  are disabled in worker transports so application/SQS retry owns backoff. Failed
  work is never acknowledged. Redis active claims are released on handler failure
  and cancellation; already SENT commands are not republished. Completed duplicate
  events are acknowledged. Invalid SQS messages remain unacknowledged and eventually
  redrive to the configured DLQ. Set queue visibility longer than the complete
  processing deadline and configure a reviewed DLQ receive limit.
- A crash between PUBACK and the SENT commit can republish. Delivery is at least
  once, not exactly-once vehicle execution. Retries after command expiry use the
  existing EXPIRED transition. DLQ arrival does not automatically mark a command
  FAILED; operator reconciliation is still necessary. Device acknowledgement and
  execution are future stages beyond the broker-delivery E2E scope.
- SIGTERM/SIGINT (Ctrl+Break on Windows) stops polling, drains the current batch,
  then cancels at WORKER_SHUTDOWN_TIMEOUT_SECONDS without ACKing unfinished work.
  WORKER_OPERATION_TIMEOUT_SECONDS bounds batches, exceeds polling plus MQTT
  timeout, stays below Redis's 60s active lease, and stays shorter than
  OUTBOX_LEASE_SECONDS. DB pools, Redis, SQS clients and MQTT contexts close.
  In-flight synchronous SDK requests still finish within network timeouts after
  coroutine cancellation; set supervisor termination grace accordingly.

## Reproduce validation

```powershell
python -m pytest tests/unit tests/contract tests/e2e/test_independent_runtimes.py tests/integration/security/test_database_runtime_permissions.py -q
ruff check .
ruff format --check .
mypy apps enterprise_platform connected_vehicle database scripts/iac tests/e2e tests/unit/test_runtime_process.py tests/unit/connected_vehicle/test_mqtt_publisher.py tests/unit/api/test_service_auth.py
terraform -chdir=infra/terraform fmt -check -recursive
terraform -chdir=infra/terraform/environments/local validate
terraform -chdir=infra/terraform/environments/dev validate
```

The real E2E fixture starts uniquely named disposable PostgreSQL, Redis, LocalStack
and Mosquitto containers, localhost-only ports, real Alembic migrations, three real
Secrets and three real Python runtime processes. Admin credentials belong only to
migration/provisioning and fixture seeding; runtime processes inherit none. Tests
use actual HTTP, PostgreSQL, Redis, SQS and MQTT sockets, with no service mocks.
Assertions cover authentication/tenant isolation, durable acceptance, each runtime
role in PostgreSQL, broker outage/recovery, duplicate API requests/events, poison
SQS DLQ redrive, paused LocalStack and persisted Outbox retry/recovery, poison Outbox
FAILED, signal shutdown and zero remaining runtime DB connections. Cleanup touches
only fixture-owned containers/processes, never development volumes or data.
The separate Runtime quality gate workflow runs these checks on PRs/main/merge queue.

This validates real transports against LocalStack, not a deployment to actual AWS.
Account IAM enforcement, IoT policies, certificate paths and AWS network deployment
require an account-backed staging run. Whole-repository `mypy .` still reports
pre-existing errors in older test fixtures; production and new runtime tests use the
strict explicit scope above without weakening repository typing rules.
