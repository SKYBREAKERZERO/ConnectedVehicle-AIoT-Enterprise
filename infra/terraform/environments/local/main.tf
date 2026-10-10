module "secret_bootstrap_role" {
  source = "../../modules/security/iam-role"

  role_name = local.secret_bootstrap_role_name

  description = (
    "Controlled identity for bootstrapping application secret values."
  )

  assume_role_policy_json = (
    local.secret_bootstrap_assume_role_policy
  )

  max_session_duration_seconds = 3600

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-role"
      RoleType       = "secret-bootstrap"
    }
  )
}

module "secret_bootstrap_policy" {
  source = "../../modules/security/iam-policy"

  policy_name = "${local.name_prefix}-secret-bootstrap"

  description = (
    "Least-privilege access for bootstrapping the application database secret value."
  )

  policy_json = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "BootstrapDatabaseApplicationSecret"
        Effect = "Allow"

        Action = [
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret"
        ]

        Resource = [for secret in module.platform_secret : secret.secret_arn]
      },
      {
        Sid    = "UseSecretsKeyViaSecretsManager"
        Effect = "Allow"

        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]

        Resource = module.platform_kms["secrets"].key_arn

        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-policy"
      PolicyType     = "secret-bootstrap"
    }
  )
}

resource "aws_iam_role_policy_attachment" "secret_bootstrap" {
  role       = module.secret_bootstrap_role.role_name
  policy_arn = module.secret_bootstrap_policy.policy_arn
}

module "remote_command_dispatcher_secret_read_policy" {
  source = "../../modules/security/iam-policy"

  policy_name = "${local.name_prefix}-remote-cmd-dispatcher-secret-read"

  description = (
    "Least-privilege access for the remote command dispatcher to read the remote command database secret."
  )

  policy_json = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ReadDatabaseApplicationSecret"
        Effect = "Allow"

        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]

        Resource = module.platform_secret["database_remote_command"].secret_arn
      },
      {
        Sid    = "DecryptDatabaseSecretViaSecretsManager"
        Effect = "Allow"

        Action = [
          "kms:Decrypt"
        ]

        Resource = module.platform_kms["secrets"].key_arn

        Condition = {
          StringLike = {
            "kms:EncryptionContext:SecretARN" = module.platform_secret["database_remote_command"].secret_arn
          }
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-policy"
      PolicyType     = "remote-command-dispatcher-secret-read"
    }
  )
}

resource "aws_iam_role_policy_attachment" "remote_command_dispatcher_secret_read" {
  role       = module.remote_command_dispatcher_role.role_name
  policy_arn = module.remote_command_dispatcher_secret_read_policy.policy_arn
}

module "remote_command_dispatcher_messaging_policy" {
  source = "../../modules/security/iam-policy"

  policy_name = "${local.name_prefix}-remote-cmd-dispatcher-messaging"

  description = (
    "Least-privilege SQS consumer and KMS access for the remote command dispatcher."
  )

  policy_json = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ConsumeRemoteCommandsFromQueue"
        Effect = "Allow"

        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:ChangeMessageVisibility",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl"
        ]

        Resource = module.remote_command_messaging.queue_arn
      },
      {
        Sid    = "DecryptMessagingKeyViaSqs"
        Effect = "Allow"

        Action = [
          "kms:Decrypt"
        ]

        Resource = module.platform_kms["messaging"].key_arn

        Condition = {
          StringEquals = {
            "kms:ViaService" = "sqs.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-policy"
      PolicyType     = "remote-command-dispatcher-messaging"
    }
  )
}

resource "aws_iam_role_policy_attachment" "remote_command_dispatcher_messaging" {
  role       = module.remote_command_dispatcher_role.role_name
  policy_arn = module.remote_command_dispatcher_messaging_policy.policy_arn
}

module "remote_command_dispatcher_role" {
  source = "../../modules/security/iam-role"

  role_name = local.remote_command_dispatcher_role_name

  description = (
    "Runtime identity for the Connected Vehicle remote command dispatcher."
  )

  assume_role_policy_json = (
    local.remote_command_dispatcher_assume_role_policy
  )

  max_session_duration_seconds = 3600

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-role"
      RoleType       = "remote-command-dispatcher"
    }
  )
}

module "remote_command_messaging" {
  source = "../../modules/messaging"

  queue_name             = var.remote_command_queue_name
  dead_letter_queue_name = var.remote_command_dead_letter_queue_name

  message_retention_seconds = (
    var.remote_command_message_retention_seconds
  )

  dead_letter_message_retention_seconds = (
    var.remote_command_dead_letter_message_retention_seconds
  )

  visibility_timeout_seconds = (
    var.remote_command_visibility_timeout_seconds
  )

  receive_wait_time_seconds = (
    var.remote_command_receive_wait_time_seconds
  )

  delay_seconds = var.remote_command_delay_seconds

  max_message_size_bytes = (
    var.remote_command_max_message_size_bytes
  )

  max_receive_count = (
    var.remote_command_max_receive_count
  )

  encryption_mode = (
    var.remote_command_encryption_mode
  )

  kms_master_key_id = (
    var.remote_command_encryption_mode == "kms"
    ? module.platform_kms["messaging"].key_arn
    : null
  )

  kms_data_key_reuse_period_seconds = (
    var.remote_command_kms_data_key_reuse_period_seconds
  )

  enable_dead_letter_redrive_allow_policy = (
    var.remote_command_enable_redrive_allow_policy
  )

  tags = local.common_tags
}

module "platform_kms" {
  for_each = local.platform_kms_keys

  source = "../../modules/security/kms-key"

  alias_name = (
    "alias/${var.project_name}/${var.environment}/${each.key}"
  )

  description = each.value.description

  enable_key_rotation = (
    var.platform_kms_enable_key_rotation
  )

  deletion_window_in_days = (
    var.platform_kms_deletion_window_in_days
  )

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = each.key
      ResourceType   = "kms-key"
    }
  )
}

module "platform_secret" {
  for_each = local.platform_secrets

  source = "../../modules/security/secret"

  secret_name = each.value.name
  description = each.value.description

  kms_key_arn = module.platform_kms["secrets"].key_arn

  recovery_window_in_days = (
    var.platform_secret_recovery_window_in_days
  )

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "secrets"
      SecretDomain   = each.value.domain
      ResourceType   = "secret"
    }
  )
}

module "application_runtime_role" {
  source = "../../modules/security/iam-role"

  role_name = local.application_runtime_role_name

  description = (
    "Runtime identity for Connected Vehicle application workloads."
  )

  assume_role_policy_json = (
    local.application_runtime_assume_role_policy
  )

  max_session_duration_seconds = 3600

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-role"
      RoleType       = "application-runtime"
    }
  )
}

module "application_secret_read_policy" {
  source = "../../modules/security/iam-policy"

  policy_name = "${local.name_prefix}-application-secret-read"

  description = (
    "Least-privilege access for application workloads to read the database secret."
  )

  policy_json = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ReadDatabaseApplicationSecret"
        Effect = "Allow"

        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]

        Resource = (
          module.platform_secret["database_application"].secret_arn
        )
      },
      {
        Sid    = "DecryptDatabaseSecretViaSecretsManager"
        Effect = "Allow"

        Action = [
          "kms:Decrypt"
        ]

        Resource = (
          module.platform_kms["secrets"].key_arn
        )

        Condition = {
          StringLike = {
            "kms:EncryptionContext:SecretARN" = module.platform_secret["database_application"].secret_arn
          }
          StringEquals = {
            "kms:ViaService" = (
              "secretsmanager.${var.aws_region}.amazonaws.com"
            )
          }
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-policy"
      PolicyType     = "secret-read"
    }
  )
}

resource "aws_iam_role_policy_attachment" "application_secret_read" {
  role       = module.application_runtime_role.role_name
  policy_arn = module.application_secret_read_policy.policy_arn
}

module "outbox_dispatcher_role" {
  source = "../../modules/security/iam-role"

  role_name = local.outbox_dispatcher_role_name

  description = (
    "Runtime identity for the Connected Vehicle transactional outbox dispatcher."
  )

  assume_role_policy_json = (
    local.outbox_dispatcher_assume_role_policy
  )

  max_session_duration_seconds = 3600

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-role"
      RoleType       = "outbox-dispatcher"
    }
  )
}

module "outbox_dispatcher_messaging_policy" {
  source = "../../modules/security/iam-policy"

  policy_name = "${local.name_prefix}-outbox-dispatcher-messaging"

  description = (
    "Least-privilege SQS and KMS access for the transactional outbox dispatcher."
  )

  policy_json = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "PublishRemoteCommandsToQueue"
        Effect = "Allow"

        Action = [
          "sqs:SendMessage",
          "sqs:GetQueueUrl",
          "sqs:GetQueueAttributes"
        ]

        Resource = module.remote_command_messaging.queue_arn
      },
      {
        Sid    = "UseMessagingKeyViaSqs"
        Effect = "Allow"

        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]

        Resource = module.platform_kms["messaging"].key_arn

        Condition = {
          StringEquals = {
            "kms:ViaService" = "sqs.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-policy"
      PolicyType     = "outbox-dispatcher-messaging"
    }
  )
}

resource "aws_iam_role_policy_attachment" "outbox_dispatcher_messaging" {
  role       = module.outbox_dispatcher_role.role_name
  policy_arn = module.outbox_dispatcher_messaging_policy.policy_arn
}

module "outbox_dispatcher_secret_read_policy" {
  source = "../../modules/security/iam-policy"

  policy_name = "${local.name_prefix}-outbox-dispatcher-secret-read"

  description = (
    "Least-privilege access for the transactional outbox dispatcher to read the outbox database secret."
  )

  policy_json = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ReadDatabaseApplicationSecret"
        Effect = "Allow"

        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]

        Resource = module.platform_secret["database_outbox"].secret_arn
      },
      {
        Sid    = "DecryptDatabaseSecretViaSecretsManager"
        Effect = "Allow"

        Action = [
          "kms:Decrypt"
        ]

        Resource = module.platform_kms["secrets"].key_arn

        Condition = {
          StringLike = {
            "kms:EncryptionContext:SecretARN" = module.platform_secret["database_outbox"].secret_arn
          }
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      SecurityDomain = "identity"
      ResourceType   = "iam-policy"
      PolicyType     = "outbox-dispatcher-secret-read"
    }
  )
}

resource "aws_iam_role_policy_attachment" "outbox_dispatcher_secret_read" {
  role       = module.outbox_dispatcher_role.role_name
  policy_arn = module.outbox_dispatcher_secret_read_policy.policy_arn
}