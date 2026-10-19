module "artifact_kms" {
  source = "../../modules/security/kms-key"

  alias_name              = "alias/${local.name_prefix}/artifacts"
  description             = "Tenant OTA firmware encryption key."
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

module "authority_kms" {
  source = "../../modules/security/kms-key"

  alias_name              = "alias/${local.name_prefix}/authority"
  description             = "Tenant OTA runtime authority encryption key."
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

module "artifact_bucket" {
  source = "../../modules/ota-artifact-bucket"

  bucket_name = local.artifact_bucket_name
  kms_key_arn = module.artifact_kms.key_arn
  tags        = local.common_tags
}

module "artifact_policy" {
  source = "../../modules/ota-artifact-policy"

  bucket_name   = module.artifact_bucket.bucket_name
  kms_key_arn   = module.artifact_kms.key_arn
  artifact_keys = var.artifact_keys
  environment   = var.environment

  # 本地 LocalStack 使用 HTTP；仍保留加密和公共访问阻断。
  enforce_tls = false
  tags        = local.common_tags
}

module "ota_authority" {
  source = "../../modules/ota-secrets"

  project_name            = var.project_name
  environment             = var.environment
  tenant_id               = var.tenant_id
  kms_key_arn             = module.authority_kms.key_arn
  recovery_window_in_days = 30
  tags                    = local.common_tags
}

module "database_read_policy" {
  source = "../../modules/security/iam-policy"

  policy_name = "${local.name_prefix}-database-read"
  description = "Read the existing tenant application database secret."
  tags        = local.common_tags

  policy_json = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ReadTenantDatabaseSecret"
        Effect = "Allow"

        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]

        Resource = var.application_database_secret_arn
      },
      {
        Sid      = "DecryptTenantDatabaseSecret"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.application_database_kms_key_arn

        Condition = {
          StringEquals = {
            "kms:ViaService"                  = "secretsmanager.${var.aws_region}.amazonaws.com"
            "kms:EncryptionContext:SecretARN" = var.application_database_secret_arn
          }
        }
      },
    ]
  })
}

module "campaign_runtime" {
  source = "../../modules/ota-runtime-iam"

  role_name                    = local.campaign_role_name
  database_read_policy_arn     = module.database_read_policy.policy_arn
  authority_read_policy_arn    = module.ota_authority.read_policy_arn
  artifact_read_policy_arn     = module.artifact_policy.read_policy_arn
  max_session_duration_seconds = 3600
  tags                         = local.common_tags
}

resource "aws_iam_role_policy_attachment" "api_read" {
  for_each = {
    database  = module.database_read_policy.policy_arn
    authority = module.ota_authority.read_policy_arn
    artifact  = module.artifact_policy.read_policy_arn
  }

  role       = var.api_runtime_role_name
  policy_arn = each.value

  lifecycle {
    precondition {
      condition     = var.api_runtime_role_name != local.campaign_role_name
      error_message = "API and Campaign must use separate runtime roles."
    }
  }
}