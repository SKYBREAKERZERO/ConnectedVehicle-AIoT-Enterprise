# Cost-01: bounded Outbox claim batching

## Objective

Restore healthy (CLOSED) outbox claim throughput without weakening the
circuit breaker, Claim Token fencing, retry budgets or SQS at-least-once
delivery guarantees.

## Runtime contract

- CLOSED: one circuit permit allows up to `outbox_batch_size` events
  (bounded to at most 1,000 at the circuit/dispatcher boundary).
- HALF_OPEN: only one test message may be claimed and sent per probe.
- `min_interval_ms > 0`: one event per permit, so the configured
  rate limiter is not bypassed by batching.
- OPEN before the claim: zero database claims and zero consumed attempts.
- OPEN reached during a batch: finish accounting for the attempted event,
  then stop sending. Release *only* the unattempted remaining events
  with one atomic PostgreSQL UPDATE, provided their (id, claim_token)
  matches and their lease is still live. Restore exactly the attempts
  incremented by the unused claim; never refund an attempted send.
- Cancelled or failed batch: always attempt fenced release of the untouched
  remainder. An attempted send may have an unknown outcome and is **never**
  blindly reclassified as unsent.
- Stale tokens, expired leases, or completed events: refund must not update.
- Permit acquired for a CLOSED batch is bounded in-flight capacity;
  an OPEN transition in a different worker cannot unsend already authorized
  in-flight messages. A local failure that opens the circuit stops the
  remaining sends immediately.

## Illustrative transaction-count comparison

For 100 successfully delivered events, assuming `batch_size=10` and one
database transaction per `mark_published`:

| Mode | Claim transactions | Publish transactions | Total |
|---|---:|---:|---:|
| Prior protected path (batch forced to 1) | 100 | 100 | 200 |
| Cost-01 CLOSED with batch=10 | 10 | 100 | 110 |

This is a *deterministic transaction-count model*, **not** a measured
AWS-billing reduction or wall-clock throughput benchmark. The first-stage
optimization only reduces claim transactions and their associated Redis
permit acquisitions. Real CPU, I/O, SQS charges, lock contention, worker
latency and p95 must be measured under representative load.

## Required acceptance

- Unit: CLOSED batch=10, HALF_OPEN=1, per-event limiter=1, mid-batch
  OPEN releases four of five unattempted events.
- PostgreSQL 17: real ten-event claim and publication in one batch;
  OPEN refunds unused attempts and clears tokens; stale token cannot
  release a current claim.
- Existing LocalStack SQS outage and recovery suite remains passing.
- Both Quality/Contracts and PostgreSQL JUnit files contain required
  `test_cost01_*` cases; candidate evidence gate rejects missing cases.

## Remaining work

- Real throughput and per-1,000-event CPU, connection, WAL and SQS
  request benchmarks, under bounded 100-1,000 worker concurrency.
- Evaluate lease-expiry tail latency and constrain batch processing
  time against the worker operation timeout.
- Database-enforced business/destination claim authorization, and
  independent protected evidence acceptance (not implied by candidate CI).
