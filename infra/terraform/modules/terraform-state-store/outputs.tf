output "backend_contract" {
  value = {
    bucket              = var.state_bucket_name
    key                 = var.state_key
    region              = var.aws_region
    encrypt             = true
    kms_key_id          = aws_kms_key.state.arn
    use_lockfile        = true
    allowed_account_ids = [var.aws_account_id]
  }
}
output "plan_state_policy_json" {
  description = "Future plan identity: read state, exclusive lock write; attach to no role today."
  value       = jsonencode({ Version = "2012-10-17", Statement = local.reader_statements })
}
output "apply_state_policy_json" {
  description = "Future separate apply identity: exact state write and lock operations, no state deletion."
  value = jsonencode({
    Version = "2012-10-17"
    Statement = concat(slice(local.reader_statements, 0, 4), [
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = local.state_arn },
      { Effect = "Deny", Action = ["s3:DeleteObject", "s3:DeleteObjectVersion"], Resource = local.state_arn },
    ])
  })
}
