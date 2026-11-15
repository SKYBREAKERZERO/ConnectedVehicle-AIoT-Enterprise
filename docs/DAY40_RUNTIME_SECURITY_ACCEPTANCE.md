# Day40 Runtime Security Acceptance

## Verification levels

| Level | Evidence |
| --- | --- |
| CODE_READY | Full repository Mypy and targeted regression tests. GitHub Runtime, Day34 and Day35 are tracked independently. |
| ROTATION_TESTED_LOCAL | PostgreSQL and LocalStack credential publication/recovery, plus Redis TLS and client replacement against an isolated Redis container. |
| AWS_ROTATION_VERIFIED | An approved AWS Staging run records both actual rotations, old credential rejection, and service continuity. |
| STAGING_SECURITY_ACCEPTED | Independently verified same-candidate runtime evidence and protected release gates. |
| BLOCKED | Missing identity, prerequisites, approvals or an observed rotation. |

## Local results and scope

- Repaired the Day39 strict Mypy regression using an explicit Day38 import
  and a standard-library Message for simulated HTTP headers.
- PostgreSQL and LocalStack ran the existing two real Day12 rotation/recovery
  cases. This uses the existing maintenance and journal flow.
- The Staging Redis client now consumes REDIS_TLS_ENABLED, requires
  authentication, and verifies the TLS certificate and hostname. The local
  Redis test checks old/new credential overlap, a newly constructed client with
  the new credential, and old credential rejection after retirement. Redis ACL
  changes model client behavior; they do not exercise ElastiCache APIs.
- The deployed Lambda handlers and ECS task replacements remain unverified.
  The application currently loads PostgreSQL credentials at process startup.
  ECS injects REDIS_PASSWORD at task startup. Plan an approved replacement of
  the affected API and worker tasks and verify health before retiring a Redis
  token. [AWS ECS secret injection](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html)

## Read-only prerequisite audit

```powershell
python -m scripts.day40_rotation_audit --account <reviewed-staging-account> --output .runtime-reports/day40/aws-prerequisites.json
```

The current AWS identity authenticated to STS. AWS denied metadata reads for
the two Secrets, both Lambda functions, RDS and ElastiCache. Access denial
does not determine whether a resource exists. GitHub listed only the production
Environment. AWS rotation, AWS Apply and release authorization were not performed.

The audit emits a blocked receipt by design. It reports metadata observations
only, keeps Secret values out of the evidence, and cannot certify an AWS
rotation. The receipt binds repository, checked-out SHA, account and region.
A local run has no GitHub Run ID or Attempt.

## Approved Staging acceptance

1. Verify the exact published versions and their execution policies, each
   Secret's invoke permission, KMS conditions, private networking, and the
   initial current credential. Ensure the database handler targets the
   tenant-pinned application identity and preserves its grants and RLS.
   Schedule registration can invoke testSecret even with immediate rotation
   disabled. [AWS RotateSecret](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_RotateSecret.html)
2. Exercise CreateSecret, SetSecret, TestSecret and FinishSecret for the same
   Version ID. Inject a failure before promotion, retry the same Version ID,
   and prove the new credential works over TLS, the old credential is rejected
   on a new connection, and the application role has no additional access.
3. For Redis, wait for the ElastiCache ROTATE operation to converge, prove
   overlap, replace clients and verify all tasks, then apply SET and verify old
   credential rejection. Observe API, outbox and remote-command health after
   replacement and test safe recovery from a partial rotation.
4. Bind repository, candidate SHA, Run ID, Attempt, account, region, exact
   Secret ARN, published Lambda version, observed rotation Version ID and
   redacted test result. Keep Secret values, raw configuration dumps and
   Terraform State out of evidence. A local receipt cannot authorize a release.
