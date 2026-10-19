mock_provider "aws" {
  override_during = plan
  mock_data "aws_caller_identity" {
    defaults = { account_id = "000000000000", arn = "arn:aws:iam::000000000000:root", user_id = "local-management" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_organizations_organization" {
    defaults = {
      master_account_id = "000000000000"
      feature_set       = "ALL"
      roots             = [{ id = "r-abcd", arn = "arn:aws:organizations::000000000000:root/o-localorg/r-abcd", name = "Root", policy_types = [{ type = "SERVICE_CONTROL_POLICY", status = "ENABLED" }] }]
      accounts = [
        { id = "111111111111", state = "ACTIVE", status = "ACTIVE", arn = "arn:aws:organizations::000000000000:account/o-localorg/111111111111", name = "dev", email = "dev@example.invalid", joined_method = "CREATED", joined_timestamp = "2026-01-01T00:00:00Z" },
        { id = "222222222222", state = "ACTIVE", status = "ACTIVE", arn = "arn:aws:organizations::000000000000:account/o-localorg/222222222222", name = "prod", email = "prod@example.invalid", joined_method = "CREATED", joined_timestamp = "2026-01-01T00:00:00Z" }
      ]
    }
  }
  mock_data "aws_organizations_organizational_unit_descendant_accounts" {
    defaults = {
      accounts = [{ id = "111111111111", state = "ACTIVE", status = "ACTIVE", arn = "arn:aws:organizations::000000000000:account/o-localorg/111111111111", name = "dev", email = "dev@example.invalid", joined_method = "CREATED", joined_timestamp = "2026-01-01T00:00:00Z" }]
    }
  }
}
variables {
  deployment_mode                 = "localstack"
  enable_organizations_management = true
  organization_root_id            = "r-abcd"
  environment_accounts = {
    dev = { account_id = "111111111111", existing_ou_id = "ou-abcd-abcdefgh" }
  }
  protected_bucket_arns          = ["arn:aws:s3:::cv-local-state", "arn:aws:s3:::cv-local-firmware"]
  protected_state_bucket_arns    = ["arn:aws:s3:::cv-local-state"]
  protected_firmware_bucket_arns = ["arn:aws:s3:::cv-local-firmware"]
  protected_kms_key_arns         = ["arn:aws:kms:ap-northeast-1:111111111111:key/11111111-1111-1111-1111-111111111111"]
}
run "offline_has_no_organizations_writes" {
  command = plan
  variables {
    deployment_mode                 = "offline"
    enable_organizations_management = false
  }
  assert {
    condition     = output.scp_policy_id == null && length(output.scp_attachment_targets) == 0 && length(output.managed_ou_ids) == 0
    error_message = "Offline mode must not manage Organizations resources."
  }
}
run "verified_ou_inheritance" {
  command = plan
  assert {
    condition     = aws_organizations_policy_attachment.environment["dev"].target_id == "ou-abcd-abcdefgh" && length(aws_organizations_organizational_unit.environment) == 0 && output.attachment_scope == "ou"
    error_message = "Enforcement must attach to the verified OU, not silently to the account."
  }
}
run "topology_precedes_account_movement" {
  command = plan
  variables {
    governance_stage     = "topology"
    environment_accounts = { dev = { account_id = "111111111111" } }
  }
  assert {
    condition     = length(aws_organizations_organizational_unit.environment) == 1 && length(aws_organizations_policy.ota) == 0 && length(output.scp_attachment_targets) == 0
    error_message = "Creating empty topology must not claim inheritance or attach enforcement policies."
  }
}
run "explicit_account_scope" {
  command = plan
  variables { attachment_scope = "account" }
  assert {
    condition     = output.scp_attachment_targets.dev == "111111111111"
    error_message = "Direct account attachment requires an explicit scope choice."
  }
}
run "firmware_history_and_key_policy_protected" {
  command = plan
  assert {
    condition     = anytrue([for statement in jsondecode(output.scp_document_json).Statement : statement.Sid == "PreventFirmwareVersionDeletion" && contains(try(statement.Action, []), "s3:DeleteObjectVersion") && try(statement.Resource, []) == ["arn:aws:s3:::cv-local-firmware/firmware/*"]]) && anytrue([for statement in jsondecode(output.scp_document_json).Statement : contains(try(statement.Action, []), "kms:PutKeyPolicy")])
    error_message = "Firmware object versions and KMS key policies must be protected."
  }
  assert {
    condition     = alltrue([for statement in jsondecode(output.scp_document_json).Statement : !contains(try(statement.Action, []), "s3:DeleteObjectVersion") || !contains(try(statement.Resource, []), "arn:aws:s3:::cv-local-state/*")])
    error_message = "Firmware retention must not break state lock deletion."
  }
}
run "reject_empty_firmware_protection" {
  command = plan
  variables { protected_firmware_bucket_arns = [] }
  expect_failures = [var.protected_firmware_bucket_arns]
}
run "reject_empty_key_protection" {
  command = plan
  variables { protected_kms_key_arns = [] }
  expect_failures = [var.protected_kms_key_arns]
}
run "reject_overlapping_state_and_firmware" {
  command = plan
  variables { protected_state_bucket_arns = ["arn:aws:s3:::cv-local-firmware"] }
  expect_failures = [var.protected_state_bucket_arns]
}
run "reject_unestablished_ou" {
  command = plan
  variables { environment_accounts = { dev = { account_id = "111111111111" } } }
  expect_failures = [var.attachment_scope]
}

run "wrong_caller_rejected" {
  command = plan
  variables {
    deployment_mode                 = "localstack"
    enable_organizations_management = true
    organization_root_id            = "r-abcd"
    environment_accounts            = { dev = { account_id = "111111111111", existing_ou_id = "ou-abcd-abcdefgh" } }
  }
  override_data {
    target = data.aws_caller_identity.management[0]
    values = { account_id = "999999999999" }
  }
  expect_failures = [terraform_data.management_guard]
}

run "scp_not_enabled_rejected" {
  command = plan
  variables {
    deployment_mode                 = "localstack"
    enable_organizations_management = true
    organization_root_id            = "r-abcd"
    environment_accounts            = { dev = { account_id = "111111111111", existing_ou_id = "ou-abcd-abcdefgh" } }
  }
  override_data {
    target = data.aws_organizations_organization.current[0]
    values = {
      master_account_id = "000000000000"
      feature_set       = "ALL"
      roots             = [{ id = "r-abcd", arn = "arn:aws:organizations::000000000000:root/o-localorg/r-abcd", name = "Root", policy_types = [] }]
      accounts          = [{ id = "111111111111", state = "ACTIVE", status = "ACTIVE", arn = "arn:aws:organizations::000000000000:account/o-localorg/111111111111", name = "dev", email = "dev@example.invalid", joined_method = "CREATED", joined_timestamp = "2026-01-01T00:00:00Z" }]
    }
  }
  expect_failures = [terraform_data.management_guard]
}

run "foreign_member_rejected" {
  command = plan
  variables {
    deployment_mode                 = "localstack"
    enable_organizations_management = true
    organization_root_id            = "r-abcd"
    environment_accounts            = { dev = { account_id = "333333333333", existing_ou_id = "ou-abcd-abcdefgh" } }
  }
  expect_failures = [terraform_data.management_guard]
}

run "ou_membership_mismatch_rejected" {
  command = plan
  variables {
    deployment_mode                 = "localstack"
    enable_organizations_management = true
    organization_root_id            = "r-abcd"
    environment_accounts            = { prod = { account_id = "222222222222", existing_ou_id = "ou-abcd-abcdefgh" } }
  }
  expect_failures = [terraform_data.management_guard]
}

run "owned_topology_keeps_resource_address_during_enforcement" {
  command = plan
  variables {
    environment_accounts = { dev = { account_id = "111111111111", existing_ou_id = "ou-abcd-abcdefgh", manage_ou = true } }
  }
  override_resource {
    override_during = plan
    target          = aws_organizations_organizational_unit.environment["dev"]
    values          = { id = "ou-abcd-abcdefgh" }
  }
  assert {
    condition     = length(aws_organizations_organizational_unit.environment) == 1 && aws_organizations_organizational_unit.environment["dev"].id == "ou-abcd-abcdefgh"
    error_message = "Owned OUs must stay at the same Terraform address during the topology-to-enforcement transition."
  }
}
run "retirement_requires_operation_id" {
  command = plan
  variables { retired_environments = ["dev"] }
  expect_failures = [var.retired_environments]
}

run "retired_account_is_not_active_inheritance_evidence" {
  command = plan
  variables {
    retired_environments    = ["dev"]
    retirement_operation_id = "11111111111111111111111111111111"
  }
  assert {
    condition     = length(output.scp_attachment_targets) == 0 && length(data.aws_organizations_organizational_unit_descendant_accounts.existing) == 0
    error_message = "Retired accounts must not require stale OU membership or be reported as attached."
  }
}
run "owned_ou_must_match_recorded_id" {
  command = plan
  variables {
    environment_accounts = { dev = { account_id = "111111111111", existing_ou_id = "ou-abcd-abcdefgh", manage_ou = true } }
  }
  override_resource {
    override_during = plan
    target          = aws_organizations_organizational_unit.environment["dev"]
    values          = { id = "ou-abcd-ijklmnop" }
  }
  expect_failures = [aws_organizations_organizational_unit.environment["dev"]]
}
