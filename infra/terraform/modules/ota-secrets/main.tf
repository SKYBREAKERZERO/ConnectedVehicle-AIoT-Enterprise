resource "aws_secretsmanager_secret" "this" {
  name        = local.secret_name
  description = "Tenant-bound OTA installation and campaign authority."

  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days

  tags = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_policy" "read" {
  name        = local.policy_name
  description = "Read the tenant OTA authority secret with context-bound KMS decryption."

  tags = var.tags

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ReadTenantOtaAuthority"
        Effect = "Allow"

        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]

        Resource = aws_secretsmanager_secret.this.arn
      },
      {
        Sid    = "DecryptAuthorityViaSecretsManager"
        Effect = "Allow"

        Action = [
          "kms:Decrypt"
        ]

        Resource = var.kms_key_arn

        Condition = {
          StringEquals = {
            "kms:ViaService"                  = local.kms_via_service
            "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.this.arn
          }
        }
      }
    ]
  })

  lifecycle {
    ignore_changes = [description]
  }
}