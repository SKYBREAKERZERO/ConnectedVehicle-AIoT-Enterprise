# Day11 — HTTP report retry, jitter, and Retry-After

## Scope

T-Box SQLite report outbox (`acknowledged`, `succeeded`, `failed`). This is a
*device-to-cloud* HTTP retry policy. It does **not** retry a physical ECU action.

## Decision table

| Result | Decision |
|---|---|
| Verified HTTP 200 | `delivered`; retain original event until durable completion |
| All HTTP 3xx | `blocked` with `HTTP_REDIRECT_BLOCKED`; never follow |
| HTTP 408/429/500–599 | Retry with capped exponential backoff + equal jitter |
| Retryable + valid `Retry-After` | Earliest attempt `max(jittered_backoff, Retry-After)` |
| Retryable + malformed/past `Retry-After` | Fall back to local jitter |
| `Retry-After` > 86,400 seconds | `blocked` as `HTTP_RETRY_AFTER_TOO_LONG`; **never retry early** |
| Other 4xx | `blocked`; do not replay authorization/business conflicts |
| Token not provisioned | Wait 30–60 seconds with jitter, without an HTTP request |

The client must be configured with `follow_redirects=False` for credential-bearing
HTTP requests; `optional_review_only/mqtt_subscriber.py` shows the current
implementation. A 3xx response is not permission to change the report's URL.

## Algorithm

1. SQLite lease increments `attempts` durably; `attempt >= 1`.
2. `base = min(60, 2**min(max(attempt - 1, 0), 6))` seconds.
3. `jittered_backoff = ceil(base * (0.5 + 0.5 * random_unit))`,
   `random_unit` in `[0, 1)`; production randomness uses `SystemRandom`.
4. Parse `Retry-After` as non-negative decimal **delta-seconds** or an HTTP-date
   with timezone using `email.utils.parsedate_to_datetime`.
5. Use `wait = max(jittered_backoff, Retry-After)` for the retryable response.
6. Persist `next_attempt_at` in SQLite using a single write transaction.
7. Restarted T-Box only claims events when the recorded timestamp is due.

`Retry-After` is a lower bound, not an exact retry time. No jitter is applied
*in place of* the server deadline. Duration is rounded **up**, never down.
Date-based handling assumes a reasonably synchronized UTC clock. Ensure host
clock synchronization, including after T-Box suspend/restart. A backward clock
jump can delay recovery; a forward clock jump can cause an early retry. A
production-grade clock-change policy needs separate design and testing.

The maximum for an automated Retry-After is 24 hours **by policy**, not by the
HTTP standard. Longer values require operator reconciliation. The SQLite
`defer` bound is now 86,400 seconds instead of 3,600 seconds; the database
schema does not change.

## Reliability guardrails

* Do not change `event_id`, JSON body, or tenant/vehicle identity across retries.
* If ACK is not confirmed, `begin_execution()` must remain false.
* `Retry-After` is honored only for HTTP 408, 429 and 5xx responses.
* Infinite **total** retries on persistent 5xx are a separate lifecycle issue:
  this patch controls *timing* and does not introduce a retry-count limit.
* HTTP responses and device credentials are not logged as raw bodies.
* Existing `blocked` items require explicit, audited operator reconciliation.

## Validation

```powershell
python -m pytest tests/unit/simulators/test_result_reporter.py tests/unit/simulators/test_result_reporter_retry_policy.py -v -ra
python -m ruff check .
python -m ruff format --check .
python -m mypy .
```

Includes deterministic tests for HTTP 429/503, delta-seconds, HTTP-date,
invalid/past dates, 24-hour boundary, >24-hour block, redirect block, restart,
and identical event-id/body across retries.

Independent package validation: **44 passed** (Python 3.13). This is not the
user's Windows Python 3.12 or whole-repository CI validation.


## Current six-process runtime integration

The runnable `simulators.vehicle_device.runtime` uses `Store`, rather than the
separate `DeviceExecutionStore` / `DeviceResultReporter` component described above.
Both paths now preserve Retry-After up to 86,400 seconds and block longer deadlines.
The six-process runtime also honors 408, 429 and every 5xx, persists explicit
HTTP_RETRY_AFTER_TOO_LONG / HTTP_REDIRECT_BLOCKED / HTTP_INVALID_RECEIPT errors,
and verifies terminal receipts. Its local backoff starts at 0.2 seconds with
bounded multiplicative jitter (HTTP cap 30 seconds, T-Box CAN 10, Gateway CAN 5).
Jitter remains effective at the cap. Existing 401/403 retry behavior is retained
for external Token rotation; it differs from this component's other-4xx block
policy. Runtime execution may proceed after a durable local ACK is saved; it does
not require HTTP ACK delivery before CAN execution. Cloud reports remain ordered
ACK before result. The independent component is not wired into the CLI runtime.
