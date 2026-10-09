variable "project_name" {
  description = "Logical project name used for resource naming."
  type        = string
  default     = "connected-vehicle-enterprise"
  nullable    = false

  validation {
    condition = (
      length(var.project_name) >= 3 &&
      length(var.project_name) <= 40 &&
      can(regex("^[a-z0-9-]+$", var.project_name))
    )

    error_message = "project_name must be 3-40 characters using lowercase letters, numbers, and hyphens only."
  }
}

variable "service_name" {
  description = "Logical service name used for resource naming and tagging."
  type        = string
  default     = "connected-vehicle"
  nullable    = false

  validation {
    condition = (
      length(var.service_name) >= 3 &&
      length(var.service_name) <= 40 &&
      can(regex("^[a-z0-9-]+$", var.service_name))
    )

    error_message = "service_name must be 3-40 characters using lowercase letters, numbers, and hyphens only."
  }
}

variable "environment" {
  description = "Deployment environment represented by this Terraform root."
  type        = string
  default     = "local"
  nullable    = false

  validation {
    condition     = var.environment == "local"
    error_message = "The local Terraform root requires environment = local."
  }
}

variable "owner" {
  description = "Logical infrastructure owner used for resource tagging."
  type        = string
  default     = "connected-vehicle-platform"
  nullable    = false

  validation {
    condition = (
      length(trimspace(var.owner)) >= 1 &&
      length(var.owner) <= 256
    )

    error_message = "owner must contain 1-256 characters."
  }
}

variable "aws_region" {
  description = "AWS-compatible region used by LocalStack."
  type        = string
  default     = "ap-northeast-1"
  nullable    = false

  validation {
    condition     = length(trimspace(var.aws_region)) > 0
    error_message = "aws_region must not be empty."
  }
}

variable "aws_endpoint_url" {
  description = "LocalStack edge endpoint used by the AWS provider."
  type        = string
  default     = "http://localhost:14566"
  nullable    = false

  validation {
    condition = can(
      regex(
        "^https?://[^[:space:]]+$",
        var.aws_endpoint_url
      )
    )

    error_message = "aws_endpoint_url must be a valid HTTP or HTTPS URL."
  }
}

variable "remote_command_queue_name" {
  description = "Name of the LocalStack SQS queue used to dispatch remote commands."
  type        = string
  nullable    = false
}

variable "remote_command_dead_letter_queue_name" {
  description = "Name of the LocalStack dead-letter queue for failed remote command messages."
  type        = string
  nullable    = false
}

variable "remote_command_message_retention_seconds" {
  description = "Message retention period for the remote command queue."
  type        = number
  nullable    = false
}

variable "remote_command_dead_letter_message_retention_seconds" {
  description = "Message retention period for the remote command dead-letter queue."
  type        = number
  nullable    = false
}

variable "remote_command_visibility_timeout_seconds" {
  description = "Visibility timeout for messages consumed from the remote command queue."
  type        = number
  nullable    = false
}

variable "remote_command_receive_wait_time_seconds" {
  description = "Long-polling wait time for the remote command queue."
  type        = number
  nullable    = false
}

variable "remote_command_delay_seconds" {
  description = "Default delivery delay for remote command messages."
  type        = number
  nullable    = false
}

variable "remote_command_max_message_size_bytes" {
  description = "Maximum message size accepted by the remote command queue."
  type        = number
  nullable    = false
}

variable "remote_command_max_receive_count" {
  description = "Maximum receive attempts before a remote command message is moved to the DLQ."
  type        = number
  nullable    = false
}

variable "remote_command_encryption_mode" {
  description = "Encryption mode used by the remote command SQS queues."
  type        = string
  nullable    = false
}

variable "remote_command_kms_data_key_reuse_period_seconds" {
  description = "KMS data-key reuse period for the remote command SQS queues."
  type        = number
  nullable    = false
}

variable "remote_command_enable_redrive_allow_policy" {
  description = "Whether the DLQ restricts redrive sources to the remote command queue."
  type        = bool
  nullable    = false
}

variable "platform_kms_enable_key_rotation" {
  description = "Whether automatic rotation is enabled for platform-managed KMS keys in the local environment."
  type        = bool
  default     = false
  nullable    = false
}

variable "platform_kms_deletion_window_in_days" {
  description = "Deletion waiting period for platform-managed KMS keys in the local environment."
  type        = number
  default     = 7
  nullable    = false

  validation {
    condition = (
      floor(var.platform_kms_deletion_window_in_days) ==
      var.platform_kms_deletion_window_in_days &&
      var.platform_kms_deletion_window_in_days >= 7 &&
      var.platform_kms_deletion_window_in_days <= 30
    )

    error_message = "platform_kms_deletion_window_in_days must be an integer between 7 and 30."
  }
}

variable "platform_secret_recovery_window_in_days" {
  description = "Recovery window for platform-managed Secrets Manager resources in the local environment."
  type        = number
  default     = 7
  nullable    = false

  validation {
    condition = (
      floor(var.platform_secret_recovery_window_in_days) ==
      var.platform_secret_recovery_window_in_days &&
      var.platform_secret_recovery_window_in_days >= 7 &&
      var.platform_secret_recovery_window_in_days <= 30
    )

    error_message = "platform_secret_recovery_window_in_days must be an integer between 7 and 30."
  }
}