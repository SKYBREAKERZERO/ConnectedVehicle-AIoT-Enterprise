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

output "application_runtime_security" {
  description = "Security resources attached to the application runtime identity."

  value = {
    role_name              = module.application_runtime_role.role_name
    role_arn               = module.application_runtime_role.role_arn
    secret_read_policy_arn = module.application_secret_read_policy.policy_arn
  }
}

output "outbox_dispatcher_identity" {
  description = "Security resources used by the transactional outbox dispatcher."

  value = {
    role_name              = module.outbox_dispatcher_role.role_name
    role_arn               = module.outbox_dispatcher_role.role_arn
    messaging_policy_arn   = module.outbox_dispatcher_messaging_policy.policy_arn
    secret_read_policy_arn = module.outbox_dispatcher_secret_read_policy.policy_arn
  }
}

output "remote_command_dispatcher_identity" {
  description = "Security resources used by the remote command dispatcher."

  value = {
    role_name              = module.remote_command_dispatcher_role.role_name
    role_arn               = module.remote_command_dispatcher_role.role_arn
    messaging_policy_arn   = module.remote_command_dispatcher_messaging_policy.policy_arn
    secret_read_policy_arn = module.remote_command_dispatcher_secret_read_policy.policy_arn
  }
}

output "secret_bootstrap_identity" {
  description = "Security resources used to bootstrap application secret values."

  value = {
    role_name  = module.secret_bootstrap_role.role_name
    role_arn   = module.secret_bootstrap_role.role_arn
    policy_arn = module.secret_bootstrap_policy.policy_arn
  }
}
output "database_runtime_configuration" {
  description = "Per-task role and database secret environment configuration; no secret values."
  value = {
    application = {
      task_role_arn = module.application_runtime_role.role_arn
      environment   = { APPLICATION_DATABASE_SECRET_ID = module.platform_secret["database_application"].secret_arn }
    }
    outbox = {
      task_role_arn = module.outbox_dispatcher_role.role_arn
      environment   = { OUTBOX_DATABASE_SECRET_ID = module.platform_secret["database_outbox"].secret_arn }
    }
    remote_command = {
      task_role_arn = module.remote_command_dispatcher_role.role_arn
      environment   = { REMOTE_COMMAND_DATABASE_SECRET_ID = module.platform_secret["database_remote_command"].secret_arn }
    }
  }
}
