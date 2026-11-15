# Cost-02 — Fleet-wide Redis Retry Budget (Outbox)

## Runtime scope

The Remote Command Outbox dispatcher creates one Redis-backed budget per logical
destination using a shared key prefixed by `outbox-retry-budget`. All replicas
with the same environment/key prefix and destination share the same bucket.
Separate destinations use separate keys. This is a retry budget, **not** a
request-rate limit for initial sends.

- **First attempts** (`claimed.attempts == 1`) do not consume retry permits.
- **Retries** (`claimed.attempts > 1`) reserve one Redis permit per event
  before SQS send. Attempted sends must not be refunded if their outcome is
  unknown; downstream consumer idempotency still applies.
- Redis Lua uses the Redis server clock and atomic token-bucket operations
  (`rate_per_second`, `burst`) with a bounded expiry.
- On budget denial (or an invalid/unavailable Redis decision), the worker
  must **not** send the denied retry. PostgreSQL `defer_unattempted` returns
  the claim to PENDING with a future `available_at`, clears the claim/lease,
  and refunds only the claim's just-added `attempts`.
- Deferral requires an unexpired lease and matching
  `(id, claim_token, status=processing)`. Stale workers cannot refund or
  modify another worker's claim.
- Cancellation before send releases unattempted claims via the same
  PostgreSQL fencing. A reserved Redis permit may be lost if a Worker exits
  before SQS send; this conservatively under-utilizes rather than over-sends.
- Redis/Circuit Breaker failure does not bypass the retry budget. If the
  existing Circuit Gate rejects a batch before Claim, PostgreSQL is untouched.

## Configuration

```text
OUTBOX_RETRY_BUDGET_ENABLED=true
OUTBOX_RETRY_BUDGET_RATE_PER_SECOND=20
OUTBOX_RETRY_BUDGET_BURST=40
OUTBOX_RETRY_BUDGET_DEFER_SECONDS=5
```

Tune for the downstream quota and worker fleet. All replicas must use the same
Redis endpoint and key prefix. Inconsistent keys produce independent budgets
and defeat fleet-wide limiting. Feature-flag rollback (`false`) removes
this limit and must not be treated as a safe failover during a downstream outage.

## Evidence and limitations

`.github/workflows/resilience-outbox-enterprise.yml` requires mandatory
unit cases, plus actual Redis/PostgreSQL 17/LocalStack tests for concurrent
Redis atomicity, SQS send count, persisted attempt refunds, retry delay, and
stale-token fencing. `scripts/ci/outbox_evidence.py` requires a `budget`
JUnit report and SHA-bound artifact. The candidate gate is **not** a protected
release attestation or proof of production AWS performance.

The current shared budget is destination-scoped, not tenant-fair. Separate
per-tenant budgets and a global limit for **first-attempt** SQS sends are
distinct future controls.
