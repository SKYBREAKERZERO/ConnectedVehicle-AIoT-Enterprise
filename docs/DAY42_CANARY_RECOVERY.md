# Day42 OTA canary and recovery

The offline workflow evaluates the rollout definition and publishes a receipt
bound to the candidate, run, attempt, and JUnit digest. The Staging acceptance
workflow reports BLOCKED until a Day37-approved execution and native evidence
are available.

The Standard Step Functions template submits one wave, waits, and classifies
its observation before opening the next wave. An ECS incident requires a
verified service rollback. An OTA incident pauses the Campaign and reconciles
existing jobs and acknowledgements. Both recovery routes require reconciliation
before returning FAILED_RECOVERED.

The PostgreSQL integration exercise invokes the Campaign pause command with a
stable operation ID and checks tenant-scoped job reconciliation against native
rows. Outstanding jobs, mismatched target identities and jobs assigned to
undispatched targets block this check. This check covers Campaign and Job rows.
Outbox, device receipts and audit acceptance require additional observers.

The control Lambda version is a deployment-time placeholder. A live adapter
must verify the approval and signed release against a trusted store, use a
durable lock and operation IDs, and delegate Campaign progression and pause to
the existing PostgreSQL-backed service. The deterministic execution name is a
correlation key. Durable approval consumption is still required.

Before enabling a live start, install the scoped execution role and adapter,
approved wave and observation policy, CloudWatch and application probes, and
an EventBridge watchdog for timed-out or aborted executions. The watchdog
must inspect persisted state before initiating recovery. An independent
verifier must pull execution and reconciliation evidence from native sources.
Day37 remains the controlled AWS deployment entry point.
