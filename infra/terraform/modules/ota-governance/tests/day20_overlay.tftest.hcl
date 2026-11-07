mock_provider "aws" {}

run "offline_by_default_no_organizations_resources" {
  command = plan

  assert {
    condition     = !output.organizations_management_enabled && !output.enforcement_enabled
    error_message = "Default execution must be completely offline."
  }
  assert {
    condition     = length(aws_organizations_organizational_unit.environment) == 0 && length(aws_organizations_policy.ota) == 0 && length(aws_organizations_policy_attachment.environment) == 0
    error_message = "Offline mode must not create OUs, SCPs or attachments."
  }
  assert {
    condition     = output.governance_stage == "topology" && output.attachment_scope == "ou"
    error_message = "Default stage/scope must be topology/OU."
  }
}

run "offline_scp_is_deny_only" {
  command = plan

  assert {
    condition     = alltrue([for statement in jsondecode(output.scp_document_json).Statement : statement.Effect == "Deny"])
    error_message = "Offline governance SCP must not grant permissions."
  }
  assert {
    condition     = contains(jsondecode(output.scp_document_json).Statement[0].Condition.StringNotEquals["aws:RequestedRegion"], "ap-northeast-1")
    error_message = "Only the approved default regional workload region may be used."
  }
}

run "stage_enforce_alone_cannot_activate_writes" {
  command = plan
  variables {
    governance_stage = "enforce"
  }

  assert {
    condition     = !output.organizations_management_enabled && !output.enforcement_enabled && length(aws_organizations_policy.ota) == 0
    error_message = "Changing the stage alone must never opt into AWS Organizations writes."
  }
}

run "firmware_objects_are_protected_but_state_objects_are_not" {
  command = plan
  variables {
    protected_bucket_arns = [
      "arn:aws:s3:::cv-firmware-lab-123",
      "arn:aws:s3:::cv-state-lab-123"
    ]
    protected_firmware_bucket_arns = ["arn:aws:s3:::cv-firmware-lab-123"]
    protected_state_bucket_arns    = ["arn:aws:s3:::cv-state-lab-123"]
    protected_kms_key_arns         = ["arn:aws:kms:ap-northeast-1:111111111111:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]
  }

  assert {
    condition = (
      contains(output.protected_resources.firmware_object_arns, "arn:aws:s3:::cv-firmware-lab-123/*") &&
      !contains(output.protected_resources.firmware_object_arns, "arn:aws:s3:::cv-state-lab-123/*")
    )
    error_message = "S3 object deletion Deny must cover firmware versions, not state or lock objects."
  }
  assert {
    condition = (
      strcontains(output.scp_document_json, "s3:DeleteObjectVersion") &&
      strcontains(output.scp_document_json, "kms:PutKeyPolicy")
    )
    error_message = "SCP must protect pinned firmware versions and key policy."
  }
}

run "reject_organizations_writes_offline" {
  command = plan
  variables {
    enable_organizations_management = true
  }
  expect_failures = [var.enable_organizations_management]
}

run "reject_fake_management_account_in_aws" {
  command = plan
  variables {
    deployment_mode = "aws"
  }
  expect_failures = [var.management_account_id]
}

run "reject_duplicate_member_account_ids" {
  command = plan
  variables {
    environment_accounts = {
      dev  = { account_id = "111111111111" }
      prod = { account_id = "111111111111" }
    }
  }
  expect_failures = [var.environment_accounts]
}

run "reject_management_as_member" {
  command = plan
  variables {
    environment_accounts = {
      dev = { account_id = "000000000000" }
    }
  }
  expect_failures = [var.environment_accounts]
}

run "reject_unapproved_region_format" {
  command = plan
  variables {
    allowed_regions = ["not-a-region"]
  }
  expect_failures = [var.allowed_regions]
}

run "reject_object_arn_as_bucket" {
  command = plan
  variables {
    protected_bucket_arns = ["arn:aws:s3:::cv-firmware-lab-123/firmware.bin"]
  }
  expect_failures = [var.protected_bucket_arns]
}

run "reject_firmware_bucket_not_administratively_protected" {
  command = plan
  variables {
    protected_firmware_bucket_arns = ["arn:aws:s3:::cv-firmware-lab-123"]
  }
  expect_failures = [var.protected_firmware_bucket_arns]
}

run "reject_state_and_firmware_overlap" {
  command = plan
  variables {
    protected_bucket_arns          = ["arn:aws:s3:::cv-firmware-lab-123"]
    protected_firmware_bucket_arns = ["arn:aws:s3:::cv-firmware-lab-123"]
    protected_state_bucket_arns    = ["arn:aws:s3:::cv-firmware-lab-123"]
  }
  expect_failures = [var.protected_state_bucket_arns]
}

run "reject_kms_alias_in_protection" {
  command = plan
  variables {
    protected_kms_key_arns = ["arn:aws:kms:ap-northeast-1:111111111111:alias/ota"]
  }
  expect_failures = [var.protected_kms_key_arns]
}

run "reject_invalid_governance_stage" {
  command = plan
  variables {
    governance_stage = "deploy"
  }
  expect_failures = [var.governance_stage]
}

run "reject_invalid_attachment_scope" {
  command = plan
  variables {
    attachment_scope = "root"
  }
  expect_failures = [var.attachment_scope]
}
