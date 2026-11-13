# Day41 — AWS Staging Rotation & Recovery Acceptance

**AWS Staging: BLOCKED. Production authorization: false.**

Day40 establishes a local test baseline. The Day41 offline workflow runs full
Python quality checks and separate recovery and admission tests. Its success
cannot grant AWS identity or certify a live rotation.

The manually dispatched Staging workflow checks out its exact protected-main
commit. It verifies the live Ruleset and latest same-commit Day38 and Day40 push
runs, including the Day39 attempt checks, native Day40 job inventory, original
artifact ZIP digests, sealed report digests and run/attempt/source provenance.
It validates the proposed `aws-staging-rotation` Environment settings but does
not request approval or OIDC. Its final decision is always BLOCKED until a
separately reviewed live executor and AWS evidence source exist.

## Checkpoints and incident handling

The SQLite journal models metadata-only observations. It binds each observation
to one account, region, staging secret and rotation version. It serializes
checkpoint writes and rejects conflicting observations, skipped steps and
simultaneous unresolved credential rotations in the same account and region.
It is a local test implementation; it is not a distributed AWS lock or an
authentication mechanism for receipts.

| Moment | Required observation before progress |
| --- | --- |
| PostgreSQL pending test | Fresh TLS login, existing RLS and GRANT unchanged |
| Redis target update | Both old and pending tokens authenticate with TLS |
| Promote pending | Observed AWSCURRENT matches the bound version |
| Refresh clients | All affected tasks replaced; API, tenant isolation, Outbox, Remote Command and OTA pass |
| Retire old Redis token | Client replacement already verified; fresh login accepts the new token and rejects the old one |
| Final | Continuity, CloudWatch and recovery exercise independently verified |

After a timeout or ambiguous result, inspect the version stages and target,
then reconcile with the exact operation identity and the stored observation.
Do not issue another RotateSecret, Redis SET, or ECS redeploy from a timeout
alone. A terminal BLOCKED checkpoint cannot be promoted by this journal.

## What still blocks live acceptance

- Only `production` is configured in GitHub. Create a separate Staging
  Environment with an independent reviewer, no self-review, no admin bypass
  and a main-only branch rule. Merge through the existing protected process.
- The current AWS identity can call STS, but the Day40 read-only audit reports
  access denied for both secrets, both Lambda lookups, RDS and ElastiCache.
  An administrator must verify the immutable Lambda versions, resource policy,
  KMS permissions and VPC connectivity using a dedicated read-only role.
- Install and review the live execution and evidence adapters with narrowly
  scoped OIDC, a durable shared journal, native service observation and an
  independent receipt verifier. The AWS workflow in this patch does not
  invoke Lambda, rotate a secret, replace ECS tasks or apply Terraform.
- Obtain independent Staging approval before any cloud mutation. Verify
  one credential at a time with real RDS, ElastiCache, ECS and business
  canaries. Archive only allowlisted metadata and digests.

Local commands: `python -m pytest -q tests/unit/test_day41_rotation.py
tests/unit/test_day41_admission.py` and `python -m mypy .`.
