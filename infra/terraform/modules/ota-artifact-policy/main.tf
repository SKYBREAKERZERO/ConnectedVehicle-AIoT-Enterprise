resource "aws_iam_policy" "this" {
  name        = local.policy_name
  description = "Read approved pinned firmware versions and decrypt only via S3."
  tags        = var.tags

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ReadPinnedFirmwareVersions"
        Effect = "Allow"

        Action = [
          "s3:GetObjectVersion"
        ]

        Resource = local.object_arns
      },
      {
        Sid    = "DecryptApprovedFirmwareViaS3"
        Effect = "Allow"

        Action = [
          "kms:Decrypt"
        ]

        Resource = var.kms_key_arn

        Condition = {
          StringEquals = {
            "kms:ViaService"                   = local.kms_via_service
            "kms:EncryptionContext:aws:s3:arn" = local.object_arns
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "this" {
  bucket = var.bucket_name

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = concat(
      [
        {
          Sid       = "DenyUploadsWithoutSseKms"
          Effect    = "Deny"
          Principal = "*"

          Action = [
            "s3:PutObject"
          ]

          Resource = [
            "${local.bucket_arn}/*"
          ]

          Condition = {
            StringNotEquals = {
              "s3:x-amz-server-side-encryption" = "aws:kms"
            }
          }
        },
        {
          Sid       = "DenyUploadsWithoutApprovedKey"
          Effect    = "Deny"
          Principal = "*"

          Action = [
            "s3:PutObject"
          ]

          Resource = [
            "${local.bucket_arn}/*"
          ]

          Condition = {
            ArnNotEqualsIfExists = {
              "s3:x-amz-server-side-encryption-aws-kms-key-id" = var.kms_key_arn
            }
          }
        }
      ],
      var.enforce_tls ? [
        {
          Sid       = "DenyInsecureTransport"
          Effect    = "Deny"
          Principal = "*"

          Action = [
            "s3:*"
          ]

          Resource = [
            local.bucket_arn,
            "${local.bucket_arn}/*"
          ]

          Condition = {
            Bool = {
              "aws:SecureTransport"       = "false"
              "aws:PrincipalIsAWSService" = "false"
            }
          }
        }
      ] : []
    )
  })
}