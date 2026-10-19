# OTA governance

This module adds deny-only SCP guardrails to an existing Organization. Defaults are offline and create no Organizations resources. `environments/governance-local` is an integrated offline example; it never claims real SCP enforcement.

## Provider contract

The installed AWS providers 6.67.0 and 6.69.1 expose `roots[].policy_types[].type` and `.status`, not `.name`. The IaC gate reads `terraform providers schema -json` and verifies that contract before running the committed native tests. An unexpected schema fails closed. The document limit of 5120 characters is this project's conservative portability cap, not the current AWS service quota.

## Establish OU inheritance

1. Bootstrap an Organization and enable ALL features separately. This module never creates accounts or changes an Organization's feature set.
2. Use `governance_stage = "topology"`, `enable_organizations_management = true` and `manage_ou = true` on the mapped existing member account. This only creates an empty OU. It does not attach an SCP or claim inheritance.
3. Review the current account parent, source and destination OU, baseline inherited Allow policies and a rollback destination. An authorized organization operator moves the existing account in a separate change. Record the operation ID, actor, reason, before/after parent and timestamp. This repository does not automatically move accounts or execute AWS changes.
4. Keep `manage_ou = true`, fill `existing_ou_id` with the created OU's actual ID, and select `governance_stage = "enforce"`. Keeping the ownership flag preserves the Terraform resource address across stages; do not drop it and accidentally request deletion of the owned OU. Preexisting externally managed OUs use `manage_ou = false`.
5. With the default `attachment_scope = "ou"`, every mapped account must be ACTIVE, belong to this Organization, and be the only account in the selected OU subtree. Extra accounts are rejected to avoid unreviewed policy impact. The SCP is attached to that OU, not silently to the account. Explicit `attachment_scope = "account"` is a separate opt-in with different semantics.
6. Inspect the plan, apply under a reviewed organization change, and test positive/negative requests using a restricted member-account role. Preserve existing inherited Allow policies: SCPs do not grant permissions. Do not remove FullAWSAccess without an independently designed replacement.

## Protection contract

Enforcement requires nonempty firmware bucket and KMS key lists. Firmware buckets must be included in `protected_bucket_arns`; state buckets must be disjoint from firmware buckets. The firmware object deny applies only to `firmware/*` in explicitly named firmware buckets and covers DeleteObject and DeleteObjectVersion. State PutObject and lock DeleteObject remain available subject to IAM and bucket policy. KMS protection includes PutKeyPolicy, DisableKey, DisableKeyRotation and ScheduleKeyDeletion.

The bucket administration freeze blocks normal configuration changes too. Establish the bucket encryption, versioning, ownership, access block and safe lifecycle baseline before attaching governance. Existing lifecycle expiration rules must be removed or reconciled before enforcement; an SCP does not undo historical deletions or prove service-internal expiration safety. The baseline lifecycle only aborts incomplete multipart uploads and never expires completed versions.

SCPs constrain member principals, not the management account or service-linked roles. Region protection covers the enumerated regional OTA services; S3 location and cross-region effects require separate controls. This is not an Object Lock, immutable backup, Secure Boot or real AWS acceptance claim.

## Controlled retirement

See [retirement procedure](../../../../docs/ota-governance-retirement.md). Simply disabling management, deleting an environment mapping, or switching ownership is intentionally blocked by prevent_destroy while resources are managed. The normal CI deletion gate remains strict. Retirement is a separate reviewed maintenance operation, never a CI bypass or terraform state rm shortcut.

## Local verification

`terraform test` runs committed mocked contracts. The root example is independently planned in CI; its plan must contain no managed resource changes. The gate records `aws_organizations_enforcement_verified = false`. The free LocalStack fixture validates OTA storage deployment and repeat-plan idempotency, not Organizations authorization enforcement.
