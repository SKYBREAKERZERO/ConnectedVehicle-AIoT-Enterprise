mock_provider "aws" {
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::000000000000:policy/contract-policy" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:ap-northeast-1:000000000000:key/12345678-1234-1234-1234-123456789abc" }
  }
}
variables {
  remote_command_queue_name                            = "contract-command"
  remote_command_dead_letter_queue_name                = "contract-command-dlq"
  remote_command_message_retention_seconds             = 345600
  remote_command_dead_letter_message_retention_seconds = 1209600
  remote_command_visibility_timeout_seconds            = 60
  remote_command_receive_wait_time_seconds             = 20
  remote_command_delay_seconds                         = 0
  remote_command_max_message_size_bytes                = 262144
  remote_command_max_receive_count                     = 5
  remote_command_encryption_mode                       = "kms"
  remote_command_kms_data_key_reuse_period_seconds     = 300
  remote_command_enable_redrive_allow_policy           = true
}
run "runtime_secret_isolation" {
  command = apply
  assert {
    condition     = length(output.platform_secrets) == 3 && output.platform_secrets.database_application.secret_name != output.platform_secrets.database_outbox.secret_name && output.platform_secrets.database_outbox.secret_name != output.platform_secrets.database_remote_command.secret_name
    error_message = "Three separate runtime secrets must exist."
  }
  assert {
    condition     = jsondecode(module.outbox_dispatcher_secret_read_policy.policy_json).Statement[0].Resource == module.platform_secret["database_outbox"].secret_arn && jsondecode(module.remote_command_dispatcher_secret_read_policy.policy_json).Statement[0].Resource == module.platform_secret["database_remote_command"].secret_arn
    error_message = "Workers must each read only their own secret."
  }
  assert {
    condition     = jsondecode(module.outbox_dispatcher_secret_read_policy.policy_json).Statement[1].Condition.StringLike["kms:EncryptionContext:SecretARN"] == module.platform_secret["database_outbox"].secret_arn && jsondecode(module.remote_command_dispatcher_secret_read_policy.policy_json).Statement[1].Condition.StringLike["kms:EncryptionContext:SecretARN"] == module.platform_secret["database_remote_command"].secret_arn
    error_message = "Worker KMS decrypt must be bound to the same secret."
  }
  assert {
    condition     = jsondecode(module.application_secret_read_policy.policy_json).Statement[0].Resource == module.platform_secret["database_application"].secret_arn
    error_message = "Application must read only its own secret."
  }
}
