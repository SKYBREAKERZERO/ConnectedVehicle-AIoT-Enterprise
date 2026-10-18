# Connected Vehicle AIoT Enterprise

Database credential isolation, provisioning, runtime entry points and upgrade steps:
[Database credential isolation](database/CREDENTIAL_ISOLATION.md).

Separate bootstrap/migration identities, recoverable credential publication and
opt-in AWS probes: [Database management](docs/DATABASE_MANAGEMENT.md).

Day14 Secret fail-closed and validated recovery: [Recovery hardening](docs/DAY14_CREDENTIAL_RECOVERY.md).

[IaC quality gates and main protection](docs/IAC_QUALITY_GATES.md).

Independent runtimes, MQTT contract and real-process validation: [Runtime and E2E](docs/RUNTIME_AND_E2E.md).

Database credential lifecycle and local fault acceptance: [Day15](docs/DAY15_CREDENTIAL_LIFECYCLE.md).

Transaction recovery, process crashes and mandatory evidence: [Day16](docs/DAY16_RESILIENCE.md).

Repeatable lock/crash exercise and monitored completion contract:
[Day16 demonstration](docs/DAY16_DEMONSTRATION.md).

SLOs, canary abort/recovery, runbooks and exact-head release readiness:
[Day17 operational readiness](docs/DAY17_OPERATIONS.md).

Tenant-scoped ECU inventory, immutable firmware metadata and durable OTA intent:
[Day17 OTA Foundation](docs/DAY17_OTA_FOUNDATION.md).

Signed, pinned firmware delivery and crash-recoverable local bank execution:
[Day18 OTA execution](docs/DAY18_OTA_EXECUTION.md).
