# Day38 AWS Staging remediations

## PostgreSQL RDS TLS: corrected in Terraform

Foundation PostgreSQL 17 now declares rds.force_ssl=1 on its bound custom
aws_db_parameter_group. The Day38 IaC tests parse the HCL and reject disabled,
missing, or detached parameters. Day38 does NOT run AWS Plan or Apply.

After a separately approved Foundation Apply, verify the DB parameter group is
in-sync rather than pending-reboot, inspect rds.force_ssl in a live SQL session,
confirm pg_stat_ssl for a TLS session, and ensure sslmode=disable is rejected.
Existing RDS instances may need an approved reboot before the static change applies.

## Two Secrets Manager rotation blockers remain intentionally enforced

The application database credential and Redis auth Secret resources are metadata-only.
The actual versions are administered separately. An empty Lambda, fake rotation schedule
or Checkov waiver would claim security without rotating credentials and is prohibited.

Application: bootstrap the least-privilege app_user role and AWSCURRENT credential; then
implement actual four-step Secrets Manager rotation using AWSPENDING, SQL password updates,
verify/test, idempotency, rollback, scoped IAM+KMS, and VPC network connectivity.

Redis: implement the documented ElastiCache ROTATE/SET overlap sequence, client token
refresh, AWSPENDING/AWSCURRENT stage movement, retries and rollback without exposing
the ephemeral Terraform auth_token_wo value or adding secrets to State/artifacts.

Only deploy aws_secretsmanager_secret_rotation after a working, reviewed, tested
rotation function and least-privilege permissions exist. CI must continue to fail
on both CKV2_AWS_57 findings until that work is completed.

Day38 remains an offline read-only candidate, not AWS deployment approval.
