variable "bucket_name" {
  description = "Name of the private, versioned OTA firmware bucket."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name)
    )

    error_message = "bucket_name must contain 3-63 lowercase letters, numbers, or hyphens, and start and end with a letter or number."
  }
}

variable "kms_key_arn" {
  description = "ARN of the customer-managed symmetric KMS key used to encrypt OTA firmware."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex(
        "^arn:[^:]+:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$",
        var.kms_key_arn
      )
    )

    error_message = "kms_key_arn must be a KMS key ARN, not an alias, key ID, or wildcard."
  }
}

variable "tags" {
  description = "Governance tags applied to the OTA firmware bucket."
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

    error_message = "tags must contain at most 50 entries with non-empty keys up to 128 characters, values up to 256 characters, and no reserved aws: prefix."
  }
}