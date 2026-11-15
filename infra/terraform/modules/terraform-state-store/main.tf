# Unwired design module: no credentials, provider endpoints, or deployment root.
locals {
  bucket_arn = "arn:aws:s3:::${var.state_bucket_name}"
  state_arn  = "${local.bucket_arn}/${var.state_key}"
  lock_arn   = "${local.state_arn}.tflock"
  kms_context = {
    StringEquals = {
      "kms:ViaService"                   = "s3.${var.aws_region}.amazonaws.com"
      "kms:CallerAccount"                = var.aws_account_id
      "kms:EncryptionContext:aws:s3:arn" = [local.state_arn, local.lock_arn]
    }
  }
  # Plan also writes/removes the lock object; it cannot write or delete state.
  reader_statements = [
    {
      Effect    = "Allow", Action = ["s3:ListBucket"], Resource = local.bucket_arn
      Condition = { StringEquals = { "s3:prefix" = [var.state_key, "${var.state_key}.tflock"] } }
    },
    { Effect = "Allow", Action = ["s3:GetObject"], Resource = local.state_arn },
    { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = local.lock_arn },
    { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.state.arn, Condition = local.kms_context },
    { Effect = "Deny", Action = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"], Resource = local.state_arn },
  ]
}

resource "aws_kms_key" "state" {
  description                        = "Production Terraform state and lock encryption; design only"
  enable_key_rotation                = true
  deletion_window_in_days            = 30
  bypass_policy_lockout_safety_check = false
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountDelegation", Effect = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
      Action    = "kms:*", Resource = "*"
    }]
  })
  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket" "state" {
  bucket        = var.state_bucket_name
  force_destroy = false
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id
  rule { object_ownership = "BucketOwnerEnforced" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    # Object ARN encryption contexts keep the state/lock KMS grants distinct.
    bucket_key_enabled = false
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
  }
}
resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyUnencryptedWrites", Effect = "Deny", Principal = "*", Action = "s3:PutObject"
        Resource  = "${local.bucket_arn}/*"
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } }
      },
      {
        Sid       = "DenyOtherKeys", Effect = "Deny", Principal = "*", Action = "s3:PutObject"
        Resource  = "${local.bucket_arn}/*"
        Condition = { ArnNotEquals = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.state.arn } }
      },
      {
        Sid       = "DenyForeignAccount", Effect = "Deny", Principal = "*", Action = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = { StringNotEquals = { "aws:PrincipalAccount" = var.aws_account_id } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.state]
}
resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter { prefix = "" }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

resource "aws_s3_bucket_logging" "state" {
  bucket        = aws_s3_bucket.state.id
  target_bucket = var.access_log_bucket_name
  target_prefix = "terraform-state/"
}

resource "aws_s3_bucket_notification" "state" {
  bucket      = aws_s3_bucket.state.id
  eventbridge = true
}

resource "aws_s3_bucket_replication_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  role   = var.replication_role_arn
  rule {
    id     = "encrypted-production-state-recovery"
    status = "Enabled"
    # Prefix also includes .tflock; recovery MUST restore only a reviewed state
    # version to the active backend and must never restore a replicated lock.
    filter { prefix = var.state_key }
    delete_marker_replication { status = "Disabled" }
    source_selection_criteria {
      sse_kms_encrypted_objects { status = "Enabled" }
    }
    destination {
      bucket        = var.recovery_bucket_arn
      storage_class = "STANDARD"
      encryption_configuration { replica_kms_key_id = var.recovery_kms_key_arn }
    }
  }
  depends_on = [aws_s3_bucket_versioning.state]
}
