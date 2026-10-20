locals {
  name_prefix = "${var.project_name}-ota-governance"

  organizations_enabled = (
    var.enable_organizations_management &&
    contains(["localstack", "aws"], var.deployment_mode)
  )

  enforcement_enabled = local.organizations_enabled && var.governance_stage == "enforce"

  # Module-owned tags take precedence over caller-supplied tags.
  common_tags = merge(var.tags, {
    Project        = var.project_name
    Service        = "ota-governance"
    ManagedBy      = "terraform"
    GovernanceMode = var.deployment_mode
  })

  environment_configs = {
    for environment, config in var.environment_accounts :
    environment => {
      account_id     = config.account_id
      existing_ou_id = config.existing_ou_id
      manage_ou      = config.manage_ou
      ou_name        = "${var.project_name}-ota-${environment}"

      tags = merge(local.common_tags, {
        Environment = environment
      })
    }
  }

  # These maps describe configured intent, not verified account membership.
  existing_ou_configs = {
    for environment, config in local.environment_configs :
    environment => config
    if config.existing_ou_id != null
  }

  verified_ou_configs = {
    for environment, config in local.existing_ou_configs : environment => config
    if !contains(var.retired_environments, environment)
  }

  managed_ou_configs = {
    for environment, config in local.environment_configs :
    environment => config
    if local.organizations_enabled && (config.manage_ou || (var.governance_stage == "topology" && config.existing_ou_id == null))
  }

  # Member account expectations are separate from the actual attachment scope.
  # The organization root is never a policy target here.
  scp_target_accounts = {
    for environment, config in local.environment_configs :
    environment => config.account_id
    if local.enforcement_enabled
  }

  scp_targets = {
    for environment, config in local.environment_configs :
    environment => (var.attachment_scope == "ou" ? coalesce(config.existing_ou_id, "ou-unconfigured-unconfigured") : config.account_id)
    if local.enforcement_enabled && !contains(var.retired_environments, environment)
  }

  protected_firmware_bucket_arns = sort(tolist(var.protected_firmware_bucket_arns))
  protected_firmware_object_arns = [for arn in local.protected_firmware_bucket_arns : "${arn}/*"]
  firmware_object_arns           = local.protected_firmware_object_arns

  allowed_regions        = sort(tolist(var.allowed_regions))
  protected_bucket_arns  = sort(tolist(var.protected_bucket_arns))
  protected_kms_key_arns = sort(tolist(var.protected_kms_key_arns))

  protection_configured = {
    buckets  = length(local.protected_bucket_arns) > 0
    kms_keys = length(local.protected_kms_key_arns) > 0
  }
}

locals {
  # Scope the region guard to OTA regional services. Global IAM, STS,
  # Organizations, Route 53, and CloudFront are outside this statement.
  # S3 location and cross-region effects require separate controls.
  scp_document = {
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "DenyOtaRegionalServicesOutsideApprovedRegions"
          Effect = "Deny"
          Action = [
            "cloudwatch:*",
            "ec2:*",
            "ecr:*",
            "ecs:*",
            "elasticloadbalancing:*",
            "kms:*",
            "logs:*",
            "rds:*",
            "secretsmanager:*",
            "sns:*",
            "sqs:*",
          ]
          Resource = "*"
          Condition = {
            StringNotEquals = {
              "aws:RequestedRegion" = local.allowed_regions
            }
          }
        }
      ],
      length(local.protected_bucket_arns) > 0 ? [
        {
          Sid    = "FreezeProtectedBucketAdministration"
          Effect = "Deny"
          Action = [
            "s3:DeleteBucket",
            "s3:DeleteBucketPolicy",
            "s3:PutBucketPolicy",
            "s3:PutBucketPublicAccessBlock",
            "s3:PutBucketOwnershipControls",
            "s3:PutBucketVersioning",
            "s3:PutEncryptionConfiguration",
            "s3:PutLifecycleConfiguration",
          ]
          Resource = local.protected_bucket_arns
        }
      ] : [],
      length(local.firmware_object_arns) > 0 ? [
        {
          Sid      = "PreventFirmwareVersionDeletion"
          Effect   = "Deny"
          Action   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
          Resource = local.firmware_object_arns
        }
      ] : [],
      length(local.protected_kms_key_arns) > 0 ? [
        {
          Sid    = "PreventProtectedKeyRetirement"
          Effect = "Deny"
          Action = [
            "kms:PutKeyPolicy",
            "kms:DisableKey",
            "kms:DisableKeyRotation",
            "kms:ScheduleKeyDeletion",
          ]
          Resource = local.protected_kms_key_arns
        }
      ] : [],
    )
  }

  scp_json = jsonencode(local.scp_document)
}
