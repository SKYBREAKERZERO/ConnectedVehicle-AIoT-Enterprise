variable "secret_name" {
  description = "Hierarchical name of the platform-managed Secrets Manager secret resource."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(var.secret_name) >= 2 &&
      length(var.secret_name) <= 512 &&
      startswith(var.secret_name, "/") &&
      !endswith(var.secret_name, "/") &&
      !strcontains(var.secret_name, "//") &&
      can(regex("^/[A-Za-z0-9/_+=.@-]+$", var.secret_name))
    )

    error_message = "secret_name must be a hierarchical path beginning with '/', must not end with '/', must not contain '//', must be 2-512 characters, and may contain only letters, numbers, and /_+=.@-."
  }
}

variable "description" {
  description = "Human-readable description of the secret resource and its intended workload."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(trimspace(var.description)) >= 1 &&
      length(var.description) <= 2048
    )

    error_message = "description must contain between 1 and 2048 characters."
  }
}

variable "kms_key_arn" {
  description = "ARN of the platform-managed customer KMS key used by Secrets Manager to encrypt secret values."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(trimspace(var.kms_key_arn)) > 0 &&
      can(regex(
        "^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/.+$",
        var.kms_key_arn
      ))
    )

    error_message = "kms_key_arn must be a valid customer-managed KMS key ARN."
  }
}

variable "recovery_window_in_days" {
  description = "Number of days Secrets Manager waits before permanently deleting the secret."
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

variable "resource_policy_json" {
  description = "Optional Secrets Manager resource policy JSON attached to the secret."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.resource_policy_json == null ||
      try(
        jsondecode(var.resource_policy_json).Statement != null,
        false
      )
    )

    error_message = "resource_policy_json must be null or a valid policy JSON document containing Statement."
  }
}

variable "tags" {
  description = "Governance tags applied to the Secrets Manager secret resource."
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

    error_message = "tags must contain at most 50 entries; keys must be non-empty, at most 128 characters, must not use the reserved aws: prefix, and values must be at most 256 characters."
  }
}