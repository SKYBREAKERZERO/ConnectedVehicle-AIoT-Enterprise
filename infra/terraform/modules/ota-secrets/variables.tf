variable "project_name" {
  description = "Project identifier used in secret paths and policy names."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex("^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$", var.project_name)
    )

    error_message = "project_name must contain 3-40 lowercase letters, numbers, or hyphens."
  }
}

variable "environment" {
  description = "Environment owning the OTA authority secret."
  type        = string
  nullable    = false

  validation {
    condition = contains(
      ["local", "dev", "staging", "prod"],
      var.environment
    )

    error_message = "environment must be local, dev, staging, or prod."
  }
}

variable "tenant_id" {
  description = "Exact tenant identity; used to derive a tenant-specific secret path."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(var.tenant_id) >= 1 &&
      length(var.tenant_id) <= 255 &&
      var.tenant_id == trimspace(var.tenant_id)
    )

    error_message = "tenant_id must contain 1-255 characters without surrounding whitespace."
  }
}

variable "kms_key_arn" {
  description = "Customer-managed symmetric KMS key ARN used to encrypt the secret."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex(
        "^arn:(aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$",
        var.kms_key_arn
      )
    )

    error_message = "Provide an explicit KMS key ARN, not an alias or wildcard."
  }
}

variable "recovery_window_in_days" {
  description = "Recovery period before a scheduled secret deletion becomes permanent."
  type        = number
  default     = 30
  nullable    = false

  validation {
    condition = (
      floor(var.recovery_window_in_days) == var.recovery_window_in_days &&
      var.recovery_window_in_days >= 7 &&
      var.recovery_window_in_days <= 30
    )

    error_message = "recovery_window_in_days must be an integer between 7 and 30."
  }
}

variable "tags" {
  description = "Governance tags applied to the secret and IAM policy."
  type        = map(string)
  default     = {}
  nullable    = false

  validation {
    condition = (
      length(var.tags) <= 50 &&
      alltrue([
        for key, value in var.tags :
        length(trimspace(key)) > 0 &&
        length(key) <= 128 &&
        length(value) <= 256 &&
        !startswith(lower(key), "aws:")
      ])
    )

    error_message = "Use at most 50 tags with valid lengths and no reserved aws: prefix."
  }
}