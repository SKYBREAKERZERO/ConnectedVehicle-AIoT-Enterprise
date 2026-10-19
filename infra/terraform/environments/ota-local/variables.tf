variable "project_name" {
  description = "Short project identifier used in OTA resource names."
  type        = string
  default     = "connected-vehicle"
  nullable    = false

  validation {
    condition = can(
      regex("^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$", var.project_name)
    )

    error_message = "project_name must contain 3-24 lowercase letters, numbers, or hyphens."
  }
}

variable "environment" {
  description = "This root is restricted to the local environment."
  type        = string
  default     = "local"
  nullable    = false

  validation {
    condition     = var.environment == "local"
    error_message = "ota-local only supports environment = local."
  }
}

variable "tenant_id" {
  description = "Exact tenant identity used by the OTA API and Campaign Dispatcher."
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

variable "aws_region" {
  description = "AWS-compatible region used by LocalStack."
  type        = string
  default     = "ap-northeast-1"
  nullable    = false

  validation {
    condition = can(
      regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.aws_region)
    )

    error_message = "Provide a valid AWS-style region name."
  }
}

variable "aws_endpoint_url" {
  description = "Explicit local endpoint used by every AWS service in this root."
  type        = string
  default     = "http://127.0.0.1:4566"
  nullable    = false

  validation {
    condition = can(
      regex(
        "^https?://(localhost|127[.]0[.]0[.]1|localstack):[0-9]{1,5}/?$",
        var.aws_endpoint_url
      )
    )

    error_message = "Use a localhost, 127.0.0.1, or localstack endpoint with an explicit port."
  }
}

variable "api_runtime_role_name" {
  description = "Existing tenant API runtime role receiving OTA read permissions."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(var.api_runtime_role_name) >= 1 &&
      length(var.api_runtime_role_name) <= 64 &&
      can(regex("^[A-Za-z0-9+=,.@_-]+$", var.api_runtime_role_name))
    )

    error_message = "Provide an existing IAM role name, not a role ARN."
  }
}

variable "application_database_secret_arn" {
  description = "Existing tenant-bound application database secret ARN in LocalStack."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex(
        "^arn:aws:secretsmanager:${var.aws_region}:000000000000:secret:[A-Za-z0-9/_+=.@-]+$",
        var.application_database_secret_arn
      )
    )

    error_message = "Provide a LocalStack database secret ARN in the configured region and account 000000000000."
  }
}

variable "application_database_kms_key_arn" {
  description = "Existing KMS key ARN encrypting the application database secret."
  type        = string
  nullable    = false

  validation {
    condition = can(
      regex(
        "^arn:aws:kms:${var.aws_region}:000000000000:key/[A-Za-z0-9-]+$",
        var.application_database_kms_key_arn
      )
    )

    error_message = "Provide the database secret's LocalStack KMS key ARN in the configured region."
  }
}

variable "artifact_keys" {
  description = "Exact firmware object keys approved for this tenant."
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

variable "owner" {
  description = "Team responsible for the local OTA infrastructure."
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