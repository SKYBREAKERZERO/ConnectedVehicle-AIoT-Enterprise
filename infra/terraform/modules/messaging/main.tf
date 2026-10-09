locals {
  use_kms = var.encryption_mode == "kms"
}

resource "aws_sqs_queue" "dead_letter" {
  name                      = var.dead_letter_queue_name
  message_retention_seconds = var.dead_letter_message_retention_seconds
  max_message_size          = var.max_message_size_bytes

  sqs_managed_sse_enabled = local.use_kms ? null : true
  kms_master_key_id       = local.use_kms ? var.kms_master_key_id : null

  kms_data_key_reuse_period_seconds = (
    local.use_kms
    ? var.kms_data_key_reuse_period_seconds
    : null
  )

  tags = merge(
    var.tags,
    {
      Name      = var.dead_letter_queue_name
      QueueRole = "dead-letter"
    }
  )

  lifecycle {
    precondition {
      condition = (
        var.dead_letter_queue_name != var.queue_name
      )

      error_message = "dead_letter_queue_name must be different from queue_name."
    }

    precondition {
      condition = (
        var.dead_letter_message_retention_seconds >=
        var.message_retention_seconds
      )

      error_message = "The dead-letter queue retention period must be greater than or equal to the primary queue retention period."
    }
  }
}

resource "aws_sqs_queue" "main" {
  name                       = var.queue_name
  delay_seconds              = var.delay_seconds
  max_message_size           = var.max_message_size_bytes
  message_retention_seconds  = var.message_retention_seconds
  visibility_timeout_seconds = var.visibility_timeout_seconds
  receive_wait_time_seconds  = var.receive_wait_time_seconds

  sqs_managed_sse_enabled = local.use_kms ? null : true
  kms_master_key_id       = local.use_kms ? var.kms_master_key_id : null

  kms_data_key_reuse_period_seconds = (
    local.use_kms
    ? var.kms_data_key_reuse_period_seconds
    : null
  )

  tags = merge(
    var.tags,
    {
      Name      = var.queue_name
      QueueRole = "primary"
    }
  )
}

resource "aws_sqs_queue_redrive_policy" "main" {
  queue_url = aws_sqs_queue.main.id

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
    maxReceiveCount     = var.max_receive_count
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "dead_letter" {
  count = var.enable_dead_letter_redrive_allow_policy ? 1 : 0

  queue_url = aws_sqs_queue.dead_letter.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.main.arn]
  })
}