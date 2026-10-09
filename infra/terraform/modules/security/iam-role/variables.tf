variable "role_name" {
  description = "Name of the platform-managed IAM role."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(trimspace(var.role_name)) >= 1 &&
      length(var.role_name) <= 64 &&
      can(regex("^[A-Za-z0-9+=,.@_-]+$", var.role_name))
    )

    error_message = "role_name must contain 1-64 characters using IAM-supported role name characters."
  }
}

variable "description" {
  description = "Human-readable description of the IAM role and its security responsibility."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(trimspace(var.description)) >= 1 &&
      length(var.description) <= 1000
    )

    error_message = "description must contain between 1 and 1000 characters."
  }
}

variable "assume_role_policy_json" {
  description = "IAM trust policy defining which principals may assume the role."
  type        = string
  nullable    = false

  validation {
    condition = try(
      jsondecode(var.assume_role_policy_json).Statement != null,
      false
    )

    error_message = "assume_role_policy_json must be a valid IAM policy JSON document containing Statement."
  }
}

variable "max_session_duration_seconds" {
  description = "Maximum IAM role session duration in seconds."
  type        = number
  default     = 3600
  nullable    = false

  validation {
    condition = (
      floor(var.max_session_duration_seconds) == var.max_session_duration_seconds &&
      var.max_session_duration_seconds >= 3600 &&
      var.max_session_duration_seconds <= 43200
    )

    error_message = "max_session_duration_seconds must be an integer between 3600 and 43200."
  }
}

variable "permissions_boundary_arn" {
  description = "Optional IAM permissions boundary ARN applied to the role."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.permissions_boundary_arn == null ||
      can(regex(
        "^arn:[^:]+:iam::[0-9]{12}:policy/.+$",
        var.permissions_boundary_arn
      ))
    )

    error_message = "permissions_boundary_arn must be null or a valid IAM managed policy ARN."
  }
}

variable "tags" {
  description = "Governance tags applied to the IAM role."
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