output "deployment_context" {
  description = "Resolved non-sensitive Terraform deployment context."

  value = {
    project_name = var.project_name
    service_name = var.service_name
    environment  = var.environment
    aws_region   = var.aws_region
    name_prefix  = local.name_prefix
    target       = "localstack"
  }
}

output "remote_command_messaging" {
  description = "Resolved non-sensitive infrastructure details for remote command messaging."

  value = {
    queue_name = module.remote_command_messaging.queue_name
    queue_arn  = module.remote_command_messaging.queue_arn
    queue_url  = module.remote_command_messaging.queue_url

    dead_letter_queue_name = (
      module.remote_command_messaging.dead_letter_queue_name
    )

    dead_letter_queue_arn = (
      module.remote_command_messaging.dead_letter_queue_arn
    )

    dead_letter_queue_url = (
      module.remote_command_messaging.dead_letter_queue_url
    )

    encryption_mode = (
      module.remote_command_messaging.encryption_mode
    )

    max_receive_count = (
      module.remote_command_messaging.redrive_max_receive_count
    )
  }
}

output "platform_kms" {
  description = "Non-sensitive metadata for platform-managed KMS security domains."

  value = {
    for purpose, kms in module.platform_kms :
    purpose => {
      key_id                  = kms.key_id
      key_arn                 = kms.key_arn
      alias_name              = kms.alias_name
      alias_arn               = kms.alias_arn
      enable_key_rotation     = kms.enable_key_rotation
      deletion_window_in_days = kms.deletion_window_in_days
    }
  }
}

output "platform_secrets" {
  description = "Non-sensitive metadata for platform-managed Secrets Manager resources."

  value = {
    for name, secret in module.platform_secret :
    name => {
      secret_id               = secret.secret_id
      secret_arn              = secret.secret_arn
      secret_name             = secret.secret_name
      kms_key_arn             = secret.kms_key_arn
      recovery_window_in_days = secret.recovery_window_in_days
    }
  }
}