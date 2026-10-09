variable "policy_name" {
  description = "Name of the platform-managed IAM policy."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(trimspace(var.policy_name)) >= 1 &&
      length(var.policy_name) <= 128 &&
      can(regex("^[A-Za-z0-9+=,.@_-]+$", var.policy_name))
    )

    error_message = "policy_name must contain 1-128 characters using IAM-supported managed policy name characters."
  }
}

variable "description" {
  description = "Human-readable description of the IAM policy and its security purpose."
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

variable "policy_json" {
  description = "IAM permissions policy JSON document."
  type        = string
  nullable    = false

  validation {
    condition = try(
      jsondecode(var.policy_json).Statement != null,
      false
    )

    error_message = "policy_json must be a valid IAM policy JSON document containing Statement."
  }
}

variable "path" {
  description = "IAM path for the managed policy."
  type        = string
  default     = "/"
  nullable    = false

  validation {
    condition = (
      startswith(var.path, "/") &&
      endswith(var.path, "/") &&
      length(var.path) >= 1 &&
      length(var.path) <= 512
    )

    error_message = "path must begin and end with '/' and contain at most 512 characters."
  }
}

variable "tags" {
  description = "Governance tags applied to the IAM managed policy."
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