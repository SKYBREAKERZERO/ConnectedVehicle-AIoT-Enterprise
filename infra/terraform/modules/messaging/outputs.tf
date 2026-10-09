output "queue_id" {
  description = "Provider resource ID of the primary SQS queue."
  value       = aws_sqs_queue.main.id
}

output "queue_name" {
  description = "Name of the primary SQS queue."
  value       = aws_sqs_queue.main.name
}

output "queue_arn" {
  description = "ARN of the primary SQS queue."
  value       = aws_sqs_queue.main.arn
}

output "queue_url" {
  description = "URL of the primary SQS queue."
  value       = aws_sqs_queue.main.url
}

output "dead_letter_queue_id" {
  description = "Provider resource ID of the dead-letter SQS queue."
  value       = aws_sqs_queue.dead_letter.id
}

output "dead_letter_queue_name" {
  description = "Name of the dead-letter SQS queue."
  value       = aws_sqs_queue.dead_letter.name
}

output "dead_letter_queue_arn" {
  description = "ARN of the dead-letter SQS queue."
  value       = aws_sqs_queue.dead_letter.arn
}

output "dead_letter_queue_url" {
  description = "URL of the dead-letter SQS queue."
  value       = aws_sqs_queue.dead_letter.url
}

output "encryption_mode" {
  description = "Configured encryption mode for the messaging queues."
  value       = var.encryption_mode
}

output "redrive_max_receive_count" {
  description = "Maximum receive attempts before messages are moved to the dead-letter queue."
  value       = var.max_receive_count
}