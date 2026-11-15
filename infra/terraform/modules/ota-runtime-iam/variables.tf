variable "role_name" {
  description = "Name of the dedicated Campaign Dispatcher runtime role."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(var.role_name) >= 1 &&
      length(var.role_name) <= 64 &&
      can(regex("^[A-Za-z0-9+=,.@_-]+$", var.role_name))
    )

    error_message = "role_name must contain 1-64 IAM-supported characters."
  }
}

variable "database_read_policy_arn" {
  description = "Account-owned policy allowing access to the intended database secret."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex(
        "^arn:(aws|aws-cn|aws-us-gov):iam::[0-9]{12}:policy/[A-Za-z0-9+=,.@_/-]+$",
        var.database_read_policy_arn
      )
    )

    error_message = "Provide an account-owned database read policy ARN without wildcards."
  }
}

variable "authority_read_policy_arn" {
  description = "Account-owned policy allowing access to the tenant OTA authority secret."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex(
        "^arn:(aws|aws-cn|aws-us-gov):iam::[0-9]{12}:policy/[A-Za-z0-9+=,.@_/-]+$",
        var.authority_read_policy_arn
      )
    )

    error_message = "Provide an account-owned OTA authority read policy ARN without wildcards."
  }
}

variable "artifact_read_policy_arn" {
  description = "Account-owned policy allowing approved firmware version reads and scoped decryption."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex(
        "^arn:(aws|aws-cn|aws-us-gov):iam::[0-9]{12}:policy/[A-Za-z0-9+=,.@_/-]+$",
        var.artifact_read_policy_arn
      )
    )

    error_message = "Provide an account-owned artifact read policy ARN without wildcards."
  }
}

variable "max_session_duration_seconds" {
  description = "Maximum role session duration in seconds."
  type        = number
  default     = 3600
  nullable    = false

  validation {
    condition = (
      floor(var.max_session_duration_seconds) == var.max_session_duration_seconds &&
      var.max_session_duration_seconds >= 3600 &&
      var.max_session_duration_seconds <= 43200
    )

    error_message = "Session duration must be an integer between 3600 and 43200 seconds."
  }
}

variable "tags" {
  description = "Governance tags applied to the Campaign Dispatcher role."
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

    error_message = "Use at most 50 valid tags without the reserved aws: prefix."
  }
}