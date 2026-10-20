variable "bucket_name" {
  description = "Existing OTA firmware Bucket name."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "Use a 3-63 character lowercase Bucket name without dots."
  }
}

variable "kms_key_arn" {
  description = "Customer-managed symmetric KMS Key ARN, not alias or wildcard."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:(aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$", var.kms_key_arn))
    error_message = "Provide an explicit KMS key ARN."
  }
}

variable "artifact_keys" {
  description = "EXACT OTA firmware object keys. Day17 key layout such as body/2.0.0/firmware.bin is supported."
  type        = set(string)
  nullable    = false

  validation {
    condition = length(var.artifact_keys) > 0 && alltrue([
      for key in var.artifact_keys :
      length(key) <= 1024 &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]+$", key)) &&
      strcontains(key, "/") &&
      !strcontains(key, "..") &&
      !strcontains(key, "//") &&
      !endswith(key, "/")
    ])
    error_message = "Specify exact slash-separated firmware object keys, no wildcards, empty segments, traversal or trailing slash."
  }
}

variable "environment" {
  description = "Deployment environment; only local may disable TLS for HTTP LocalStack."
  type        = string
  nullable    = false

  validation {
    condition     = contains(["local", "dev", "staging", "prod"], var.environment)
    error_message = "environment must be local, dev, staging or prod."
  }
}

variable "enforce_tls" {
  description = "Require HTTPS in AWS; may disable only in local HTTP emulator tests."
  type        = bool
  default     = true
  nullable    = false

  validation {
    condition     = var.enforce_tls || var.environment == "local"
    error_message = "TLS enforcement may only be disabled in local."
  }
}

variable "tags" {
  description = "Governance tags applied to the read policy."
  type        = map(string)
  default     = {}
  nullable    = false
}
