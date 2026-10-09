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