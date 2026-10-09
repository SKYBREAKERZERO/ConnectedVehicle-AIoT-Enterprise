resource "aws_secretsmanager_secret" "this" {
  name        = var.secret_name
  description = var.description

  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days

  tags = var.tags
}

resource "aws_secretsmanager_secret_policy" "this" {
  count = var.resource_policy_json == null ? 0 : 1

  secret_arn          = aws_secretsmanager_secret.this.arn
  policy              = var.resource_policy_json
  block_public_policy = true
}