# Cost-01C — Real SQS SendMessageBatch and PostgreSQL batch acknowledgement

## Runtime

- Existing PostgreSQL Claim remains token/lease-fenced and destination scoped.
- Remote Command Worker uses SQS `SendMessageBatch` in **CLOSED** state.
- SQS API batches at most 10 entries and 1 MiB total payload. Outcomes are
  matched by response `Id`, never inferred from HTTP 200 or list position.
- For each confirmed success subbatch, a **single PostgreSQL transaction**
  updates all matching `(id, claim_token)` rows to `PUBLISHED`.
- Failed sender-fault entries are permanent; retryable failures consume a
  bounded retry budget. Unknown HTTP outcomes are not marked published.
- If the breaker opens, unattempted claims in subsequent subbatches are
  released by claim-token fencing; attempted subbatch outcomes are not refunded.
- HALF_OPEN or event-level rate limiting uses the existing single-message
  probe path. FIFO queues require explicit group and dedup IDs; this path
  fails closed for FIFO until the contract is implemented.
- Successful duplicates on unknown delivery outcome are handled by the
  downstream stable event-ID idempotency contract (at-least-once delivery).

## Cost model

For 20 successful small events and `outbox_batch_size=20`:

| Operation | Previous (Cost-01B) | Cost-01C |
|---|---:|---:|
| PostgreSQL Claim UoW | 1 | 1 |
| SQS send API requests | 20 | 2 |
| PostgreSQL `PUBLISHED` update UoWs | 20 | 2 |

This reduces **send API calls and successful-acknowledgement transactions** by
90% in this workload, not necessarily AWS billed requests by exactly 90%.
Other operations (polling, retries, queue receipts, Redis, and SQS payload
size billing) remain separate. SQS batch payloads are limited to 1 MiB.

## Acceptance and boundaries

Mandatory CI cases cover: HTTP 200 with per-entry partial failure, malformed
response IDs, lost response (no false published marks), Circuit HALF_OPEN,
fenced old token exclusion, 20 real SQS messages, and 2 real PostgreSQL batch
updates. JUnit tests are bound to the existing evidence gate and source SHA.

The Cost-01B batch-claim benchmark remains unchanged for an apples-to-apples
baseline. The Cost-01C real integration test reports exact send and update
counts, but does not establish an AWS invoice reduction or a production P95.
