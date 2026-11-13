# Day38 AWS Staging remediations

## PostgreSQL RDS TLS: corrected in Terraform

Foundation PostgreSQL 17 now declares rds.force_ssl=1 on its bound custom
aws_db_parameter_group. The Day38 IaC tests parse the HCL and reject disabled,
missing, or detached parameters. Day38 does NOT run AWS Plan or Apply.

After a separately approved Foundation Apply, verify the DB parameter group is
in-sync rather than pending-reboot, inspect rds.force_ssl in a live SQL session,
confirm pg_stat_ssl for a TLS session, and ensure sslmode=disable is rejected.
Existing RDS instances may need an approved reboot before the static change applies.

## Secrets Manager rotation

The Foundation root manages weekly schedules and grants invocation only to
Secrets Manager for the matching Secret in the reviewed account. Each schedule
uses a distinct published Lambda version. The Foundation administrator owns
the Lambda deployments, their database/cache reachability and their scoped
Secrets Manager, KMS and service permissions.

Before enabling schedules, the administrator must complete the reviewed initial
Foundation and credential bootstrap. The two Secrets need valid AWSCURRENT
credentials. Bootstrap of a new Foundation must be separately reviewed and
sequenced ahead of rotation activation. The full Foundation plan is required
once both handlers and credentials are ready.

- Application PostgreSQL must rotate the non-admin app_user. Use a reviewed
  four-step handler that tests the pending login over TLS and handles retries
  safely. Confirm running tasks can refresh credentials or coordinate their
  replacement during the rotation window.
- Redis uses a replication-group AUTH token. Use a reviewed handler that
  uses ROTATE to allow overlap, tests the pending token over TLS, and coordinates
  client refresh or task replacement before SET retires the old token. Prove
  rollback from a partially completed rotation. Keep bootstrap token values
  out of State and CI evidence.

Setting rotate_immediately to false waits for the schedule and still lets AWS
call testSecret on registration. The read-only Day37 release preflight requires
an enabled and correctly scoped schedule, a single current version, no separate
pending version, and a completed rotation timestamp within eight days for both
Secrets. AWS Staging acceptance still requires observing successful real
rotations and verifying client continuity. The CI scanner checks Terraform
configuration, and the unit tests exercise the preflight rejection paths.
