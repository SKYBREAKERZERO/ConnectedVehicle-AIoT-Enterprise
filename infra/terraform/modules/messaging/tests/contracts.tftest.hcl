mock_provider "aws" {}
variables {
  queue_name                            = "contract-command"
  dead_letter_queue_name                = "contract-command-dlq"
  message_retention_seconds             = 345600
  dead_letter_message_retention_seconds = 1209600
  visibility_timeout_seconds            = 60
  receive_wait_time_seconds             = 20
  delay_seconds                         = 0
  max_message_size_bytes                = 262144
  max_receive_count                     = 5
  encryption_mode                       = "sqs-managed"
}
run "sqs_managed_encryption_and_redrive" {
  command = apply
  assert {
    condition     = aws_sqs_queue.main.sqs_managed_sse_enabled && aws_sqs_queue.dead_letter.sqs_managed_sse_enabled
    error_message = "Primary and DLQ must both use encryption."
  }
  assert {
    condition     = jsondecode(aws_sqs_queue_redrive_policy.main.redrive_policy).deadLetterTargetArn == aws_sqs_queue.dead_letter.arn && jsondecode(aws_sqs_queue_redrive_policy.main.redrive_policy).maxReceiveCount == 5
    error_message = "Redrive must target the DLQ with the configured retry bound."
  }
  assert {
    condition     = jsondecode(aws_sqs_queue_redrive_allow_policy.dead_letter[0].redrive_allow_policy).redrivePermission == "byQueue"
    error_message = "DLQ must not permit arbitrary source queues."
  }
}
run "kms_encrypts_both_queues" {
  command = plan
  variables {
    encryption_mode   = "kms"
    kms_master_key_id = "arn:aws:kms:ap-northeast-1:000000000000:key/12345678-1234-1234-1234-123456789abc"
  }
  assert {
    condition     = aws_sqs_queue.main.kms_master_key_id == var.kms_master_key_id && aws_sqs_queue.dead_letter.kms_master_key_id == var.kms_master_key_id
    error_message = "Both queues must use the configured KMS key."
  }
}
run "reject_plaintext_mode" {
  command = plan
  variables { encryption_mode = "none" }
  expect_failures = [var.encryption_mode]
}
run "reject_same_queue_and_dlq" {
  command = plan
  variables { dead_letter_queue_name = "contract-command" }
  expect_failures = [aws_sqs_queue.dead_letter]
}
run "reject_short_dlq_retention" {
  command = plan
  variables { dead_letter_message_retention_seconds = 60 }
  expect_failures = [aws_sqs_queue.dead_letter]
}
