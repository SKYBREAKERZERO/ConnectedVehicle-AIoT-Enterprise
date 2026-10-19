variable "bucket_name" {
  description = "Existing OTA firmware bucket name."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name)
    )

    error_message = "Use a 3-63 character lowercase bucket name without dots."
  }
}

variable "kms_key_arn" {
  description = "Symmetric KMS key ARN used by the firmware bucket."
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

variable "artifact_keys" {
  description = "Exact approved firmware object keys; no wildcard access."
  type        = set(string)
  nullable    = false

  validation {
    condition = (
      length(var.artifact_keys) > 0 &&
      alltrue([
        for key in var.artifact_keys :
        length(key) <= 1024 &&
        can(regex("^firmware/[A-Za-z0-9._/-]+$", key)) &&
        !strcontains(key, "..") &&
        !endswith(key, "/")
      ])
    )

    error_message = "Provide exact firmware/ object keys without wildcards or traversal."
  }
}

variable "environment" {
  description = "Deployment environment; only local may disable HTTPS enforcement."
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

variable "enforce_tls" {
  description = "Require HTTPS. Set false only for local HTTP LocalStack."
  type        = bool
  default     = true
  nullable    = false

  validation {
    condition = (
      var.enforce_tls ||
      var.environment == "local"
    )

    error_message = "HTTPS enforcement may only be disabled in local."
  }
}

variable "tags" {
  description = "Tags applied to the managed IAM policy."
  type        = map(string)
  default     = {}
  nullable    = false
}