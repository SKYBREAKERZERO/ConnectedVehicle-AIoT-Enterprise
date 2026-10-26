locals {
  # Repository and environment are reviewed constants, not caller-controlled scope.
  subject = "repo:SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise:environment:production"
  preview_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadExactArtifactProtectionMetadata"
      Effect = "Allow"
      Action = [
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
      ]
      Resource  = sort(tolist(var.artifact_bucket_arns))
      Condition = { StringEquals = { "aws:ResourceAccount" = var.aws_account_id } }
    }]
  })
}

resource "aws_iam_policy" "boundary" {
  name        = "${var.role_name}-boundary"
  description = "Day25 preview boundary: exact bucket metadata reads only; no deployment writes."
  policy      = local.preview_policy
  tags        = var.tags
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "this" {
  name                 = var.role_name
  description          = "GitHub production OIDC preview identity; not authorized for Terraform Apply."
  max_session_duration = 3600
  permissions_boundary = aws_iam_policy.boundary.arn
  tags                 = var.tags
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com" }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = local.subject
        }
      }
    }]
  })
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "preview" {
  name   = "ota-production-metadata-preview"
  role   = aws_iam_role.this.id
  policy = local.preview_policy
}
