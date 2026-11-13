# OTA governance retirement

This is a maintenance runbook, not an automatic destroy workflow. Runtime deployment must never disable governance by deleting mappings. The ordinary IaC gate continues to reject every delete, replacement and state-forget action.

## Preconditions

Obtain an approved change with operation ID, actor, reason, rollback owner and destination. Preserve a private State backup and checksum. Record the source commit and current Organizations policy IDs, attachment target IDs and OU parent IDs. Verify an alternative inherited SCP baseline remains attached. Do not detach the last SCP, use terraform state rm, remove all resource blocks, or turn force_destroy on.

## Phase 1: detach exact attachments

Keep `enable_organizations_management`, `governance_stage`, environment account mappings, managed OU ownership and protection lists unchanged. Set `retired_environments` to the explicit environment names and `retirement_operation_id` to a unique 32-hex ID. The normal source still refuses destruction.

On a dedicated reviewed maintenance branch, change only the attachment resource's literal `prevent_destroy` to false. Terraform does not permit a variable here; do not replace the default with a generally available unsafe switch. Commit the reviewed maintenance source. Generate a saved plan in the deployment root. Its only managed changes must be deletion of the named attachments; all unrelated resources must be no-op. Do not use auto-approve.

Prepare the manifest shown below from real pre-change State and the reviewed commit. Store it privately in `.runtime-reports/` and replace every placeholder. Run the read-only validator from the repository root:

```powershell
python -m scripts.iac.governance_retirement `
  --root <management-root> `
  --plan <absolute-saved-plan.tfplan> `
  --manifest .runtime-reports/retirement-manifest.json `
  --output .runtime-reports/retirement-unique-evidence.json
```

The validator requires a clean committed worktree, obtains JSON directly from the saved binary plan, checks exact resource identities and source commit, and records plan/manifest SHA256, actor, reason, phase and UTC time. Existing evidence is never overwritten. It never applies, detaches a policy, moves an account, deletes an OU or changes State. A human change approver must inspect the report and recheck the binary plan digest before manually applying that same saved plan. Immediately restore the default protection in source; retain retirement IDs/mappings until the handoff is complete.

```json
{
  "version": 1,
  "operation_id": "11111111111111111111111111111111",
  "actor": "REPLACE_OPERATOR",
  "reason": "REPLACE_APPROVED_CHANGE_REASON",
  "source_commit": "REPLACE_REVIEWED_40_HEX_COMMIT",
  "phase": "detach",
  "resources": [{
    "address": "module.governance.aws_organizations_policy_attachment.environment["dev"]",
    "id": "REPLACE_ACTUAL_ATTACHMENT_STATE_ID",
    "policy_id": "REPLACE_ACTUAL_POLICY_ID",
    "target_id": "REPLACE_ACTUAL_OU_OR_ACCOUNT_ID"
  }]
}
```

## Phase 2: delete an unattached policy

Only after all attachments are detached and current Organizations reads confirm no remaining targets, select topology stage while retaining account/OU mappings. The policy source protection must be changed in a separately reviewed maintenance commit. Use phase `delete-policy`, with resource entries containing only address and the exact policy id. The plan may delete only that policy. AWS must reject deleting a policy that is still attached. Restore all source protections afterward.

## Phase 3: retire owned OUs

Move member accounts through the separately approved organization procedure, record before/after parents, and verify the OU contains no accounts or child OUs. Only OUs actually owned by this module are eligible. Keep their environment names in retired_environments so stale membership is not treated as active enforcement evidence. Set manage_ou=false while retaining the recorded existing_ou_id, rather than deleting the last environment mapping too early. Transfer their ownership in a reviewed maintenance commit that changes only the OU protection. Use phase `delete-empty-ous` and exact address, id and parent_id entries. The saved plan may delete only these OUs. AWS also refuses deleting nonempty OUs; this runbook and mocked tests do not substitute for that live preflight. Externally managed OUs are never deleted here.

Every phase has its own commit, manifest, saved plan and non-overwriting evidence. The tool is not wired into the standard no-destroy gate and cannot grant merge or deployment authorization. No retirement operation or real AWS account movement was executed during local implementation.

References: [Terraform lifecycle](https://developer.hashicorp.com/terraform/language/meta-arguments/lifecycle), [AWS SCP inheritance](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html).

## Phase 4: finish local metadata

After all cloud resources have been removed or handed off and their State bindings reconciled, disable management. If the saved plan only deletes `module.governance.terraform_data.management_guard[0]`, review it with phase `finish-local-guard` and the exact local resource id. This does not permit any AWS resource deletion. Then remove obsolete mappings and retirement metadata together. Preserve every prior evidence report; retiring accounts do not need to remain active or stay in the old OU, but their old attachment identities still must match the reviewed plan allowlist.
