output "read_policy_arn" {
  description = "IAM policy ARN to attach to the OTA API runtime role."
  value       = aws_iam_policy.this.arn
}

output "read_policy_json" {
  description = "IAM policy JSON to attach to the OTA API runtime role."
  value       = aws_iam_policy.this.policy
}

output "bucket_policy_json" {
  description = "S3 bucket policy JSON to attach to the OTA firmware bucket."
  value       = aws_s3_bucket_policy.this.policy
}