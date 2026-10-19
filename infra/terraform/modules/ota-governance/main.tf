data "aws_caller_identity" "management" {
  count = local.organizations_enabled ? 1 : 0
}

data "aws_partition" "current" {
  count = local.organizations_enabled ? 1 : 0
}

data "aws_organizations_organization" "current" {
  count = local.organizations_enabled ? 1 : 0
}

data "aws_organizations_organizational_unit_descendant_accounts" "existing" {
  for_each = local.organizations_enabled ? local.existing_ou_configs : {}

  parent_id = each.value.existing_ou_id
}

resource "terraform_data" "management_guard" {
  count = local.organizations_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition = (
        data.aws_caller_identity.management[0].account_id == var.management_account_id &&
        data.aws_organizations_organization.current[0].master_account_id == var.management_account_id
      )

      error_message = "Use the configured organization management account identity."
    }

    precondition {
      condition = (
        var.deployment_mode != "localstack" ||
        var.management_account_id == "000000000000"
      )

      error_message = "LocalStack mode requires the configured local management account 000000000000."
    }

    precondition {
      condition = (
        data.aws_organizations_organization.current[0].feature_set == "ALL" &&
        length(data.aws_organizations_organization.current[0].roots) > 0 &&
        alltrue([
          for root in data.aws_organizations_organization.current[0].roots :
          anytrue([
            for policy_type in root.policy_types :
            policy_type.type == "SERVICE_CONTROL_POLICY" &&
            policy_type.status == "ENABLED"
          ])
        ])
      )

      error_message = "The existing organization must have ALL features and SCPs enabled on its roots."
    }

    precondition {
      condition = (
        var.organization_root_id == null ||
        contains(
          [
            for root in data.aws_organizations_organization.current[0].roots :
            root.id
          ],
          var.organization_root_id
        )
      )

      error_message = "organization_root_id must belong to the current organization."
    }

    precondition {
      condition = alltrue([
        for account_id in values(local.scp_target_accounts) :
        contains(
          [
            for account in data.aws_organizations_organization.current[0].accounts :
            account.id if account.state == "ACTIVE"
          ],
          account_id
        ) &&
        account_id != var.management_account_id
      ])

      error_message = "Every SCP target must be an active member account of the current organization."
    }

    precondition {
      condition = alltrue([
        for environment, config in local.existing_ou_configs :
        contains(
          [
            for account in data.aws_organizations_organizational_unit_descendant_accounts.existing[environment].accounts :
            account.id if account.state == "ACTIVE"
          ],
          config.account_id
        )
      ])

      error_message = "Each configured existing OU must contain its mapped active environment account."
    }

    precondition {
      condition = alltrue([
        for arn in concat(
          local.protected_bucket_arns,
          local.protected_kms_key_arns
        ) :
        split(":", arn)[1] == data.aws_partition.current[0].partition
      ])

      error_message = "Protected resource ARNs must use the current provider partition."
    }

    precondition {
      condition     = length(local.scp_json) <= 5120
      error_message = "The compact SCP document exceeds this module's 5120-character portability cap."
    }
  }
}

resource "aws_organizations_organizational_unit" "environment" {
  for_each = local.managed_ou_configs

  name      = each.value.ou_name
  parent_id = var.organization_root_id
  tags      = each.value.tags

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    terraform_data.management_guard,
  ]
}

resource "aws_organizations_policy" "ota" {
  count = local.organizations_enabled ? 1 : 0

  name        = "${local.name_prefix}-guardrails"
  description = "OTA regional service and protected resource guardrails."
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.scp_json
  tags        = local.common_tags

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    terraform_data.management_guard,
  ]
}

resource "aws_organizations_policy_attachment" "environment" {
  for_each = local.scp_target_accounts

  policy_id = aws_organizations_policy.ota[0].id
  target_id = each.value

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    terraform_data.management_guard,
  ]
}