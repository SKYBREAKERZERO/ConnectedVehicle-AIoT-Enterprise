variable "aws_account_id" {
  description = "Future AWS deployment account. No account/provider is created by this module."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id)) && var.aws_account_id != "000000000000"
    error_message = "An explicit non-LocalStack 12-digit AWS account is required."
  }
}

variable "role_name" {
  description = "Dedicated production preview role, separate from application/runtime roles."
  type        = string
  default     = "connected-vehicle-ota-production-deploy-preview"
  nullable    = false
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.role_name))
    error_message = "Provide an exact IAM role name without wildcards."
  }
}

variable "artifact_bucket_arns" {
  description = "Exact account-owned buckets whose encryption/protection metadata may be inspected."
  type        = set(string)
  nullable    = false
  validation {
    condition = length(var.artifact_bucket_arns) > 0 && length(var.artifact_bucket_arns) <= 10 && alltrue([
      for arn in var.artifact_bucket_arns : can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", arn))
    ])
    error_message = "Provide 1-10 exact bucket ARNs; wildcard or object paths are prohibited."
  }
}

variable "tags" {
  description = "Governance tags for the future preview identity."
  type        = map(string)
  default     = {}
}
