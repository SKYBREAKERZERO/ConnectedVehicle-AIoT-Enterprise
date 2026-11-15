# Cost-01B — Independent Outbox Batch Efficiency Benchmark

## Runtime and scope

The existing Outbox enterprise candidate workflow has a fourth independent
`cost_benchmark` job, with PostgreSQL 17, Redis 7 and the repository-pinned
LocalStack 3.8.1 SQS image. It measures the actual OutboxDispatcher,
RedisCircuitBreaker and SQLAlchemyOutboxStore in a single-worker, real-SQS
successful-delivery scenario. The CI input is **200 messages per configuration**
(800 successful messages total); the test also accepts 100–1000 events per
configuration when called with an explicit `OUTBOX_COST_EVENTS` value.

The four configurations are **Batch=1, 5, 10, 20**. Every configuration gets
new destination, Outbox events, Redis breaker key and LocalStack SQS queue.
Seeding, receipt verification and cleanup are **outside** the timed region.

## What is measured

- `claim_transactions`: successful OutboxStore claim UoW calls.
- `published_transactions`: successful per-event mark_published UoW calls.
- `redis_eval_calls`: RedisCircuitBreaker Lua EVAL calls through the
  instrumented implementation; not all Redis commands.
- `sqs_send_calls`: successful real LocalStack SQS SendMessage calls;
  queue receipt event IDs are checked against the seeded IDs.
- `elapsed_ms`: monotonic wall-clock dispatch duration.
- `process_cpu_ms`: Python benchmark-process CPU time; **excludes** CPU
  inside PostgreSQL/LocalStack/Redis containers.
- `throughput_events_per_sec`, SQS SendMessage mean and P95 latencies.

The output is `benchmark.json` plus `results.xml` and `manifest.json`.
The candidate evidence verifier requires all four batches, fixed integrity
invariants, a passing mandatory test identity and matching SHA256 evidence.
The protected default-branch verifier must also download the Cost artifact
once reviewed and deployed on `main`.

## Deterministic acceptance criteria

For a successful run of `N` messages per configuration:

- `claims = ceil(N / batch_size)`
- `published_transactions = N`
- `redis_eval_calls = claims + N`
- `sqs_send_calls = N`, all `N` unique messages observed in LocalStack
- Each PostgreSQL row has `PUBLISHED` state and `attempts = 1`
- Every timing and throughput metric must be finite and positive.

There are deliberately **no fixed speedup / CPU reduction thresholds** in
PR CI: GitHub-hosted runners vary in performance. Follow-up calibrated SLO
and cost gates should compare runs within equivalent environments and use
multiple warmups/samples before requiring a throughput uplift.

## Explicit limitations

The benchmark tests successful sequential delivery, **not** 100–1000
concurrent workers, fault-recovery latency, actual AWS billing, full container
CPU, WAL bytes, or a meaningful production SLO. Real cost attribution
requires an AWS deployment with CloudWatch/Cost Explorer or CUR alongside
RDS/ElastiCache/ECS usage, and repeated workload baselines.
