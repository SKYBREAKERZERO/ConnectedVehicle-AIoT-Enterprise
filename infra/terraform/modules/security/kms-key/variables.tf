variable "alias_name" {
  description = "KMS alias used to provide a stable platform-facing identifier for the key."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(var.alias_name) >= 7 &&
      length(var.alias_name) <= 256 &&
      startswith(var.alias_name, "alias/") &&
      !startswith(var.alias_name, "alias/aws/") &&
      can(regex("^alias/[A-Za-z0-9/_-]+$", var.alias_name))
    )

    error_message = "alias_name must start with \"alias/\", must not use the reserved \"alias/aws/\" prefix, must be 7-256 characters, and may contain only letters, numbers, slashes, underscores, and hyphens."
  }
}

variable "description" {
  description = "Human-readable description of the platform encryption key and its intended security domain."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(trimspace(var.description)) >= 1 &&
      length(var.description) <= 8192
    )

    error_message = "description must contain between 1 and 8192 characters."
  }
}

variable "enable_key_rotation" {
  description = "Whether automatic KMS key rotation is enabled."
  type        = bool
  default     = true
  nullable    = false
}

variable "deletion_window_in_days" {
  description = "Waiting period before a scheduled KMS key deletion becomes effective."
  type        = number
  default     = 30
  nullable    = false

  validation {
    condition = (
      floor(var.deletion_window_in_days) == var.deletion_window_in_days &&
      var.deletion_window_in_days >= 7 &&
      var.deletion_window_in_days <= 30
    )

    error_message = "deletion_window_in_days must be an integer between 7 and 30."
  }
}

variable "key_policy_json" {
  description = "Optional explicit KMS key policy JSON. Null allows the provider/AWS default key policy behavior."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.key_policy_json == null ||
      try(jsondecode(var.key_policy_json) != null, false)
    )

    error_message = "key_policy_json must be null or valid JSON."
  }
}

variable "tags" {
  description = "Common governance tags applied to the KMS key."
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