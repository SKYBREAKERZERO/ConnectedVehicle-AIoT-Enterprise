variable "queue_name" {
  description = "Name of the primary standard SQS queue."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(var.queue_name) >= 1 &&
      length(var.queue_name) <= 80 &&
      can(regex("^[A-Za-z0-9_-]+$", var.queue_name))
    )

    error_message = "queue_name must be 1-80 characters and contain only letters, numbers, hyphens, and underscores."
  }
}

variable "dead_letter_queue_name" {
  description = "Name of the dead-letter SQS queue associated with the primary queue."
  type        = string
  nullable    = false

  validation {
    condition = (
      length(var.dead_letter_queue_name) >= 1 &&
      length(var.dead_letter_queue_name) <= 80 &&
      can(regex("^[A-Za-z0-9_-]+$", var.dead_letter_queue_name))
    )

    error_message = "dead_letter_queue_name must be 1-80 characters and contain only letters, numbers, hyphens, and underscores."
  }
}

variable "message_retention_seconds" {
  description = "Number of seconds that messages are retained in the primary queue."
  type        = number
  nullable    = false

  validation {
    condition = (
      floor(var.message_retention_seconds) == var.message_retention_seconds &&
      var.message_retention_seconds >= 60 &&
      var.message_retention_seconds <= 1209600
    )

    error_message = "message_retention_seconds must be an integer between 60 and 1209600 seconds."
  }
}

variable "dead_letter_message_retention_seconds" {
  description = "Number of seconds that failed messages are retained in the dead-letter queue."
  type        = number
  nullable    = false

  validation {
    condition = (
      floor(var.dead_letter_message_retention_seconds) == var.dead_letter_message_retention_seconds &&
      var.dead_letter_message_retention_seconds >= 60 &&
      var.dead_letter_message_retention_seconds <= 1209600
    )

    error_message = "dead_letter_message_retention_seconds must be an integer between 60 and 1209600 seconds."
  }
}

variable "visibility_timeout_seconds" {
  description = "Number of seconds a received message remains invisible to other consumers."
  type        = number
  nullable    = false

  validation {
    condition = (
      floor(var.visibility_timeout_seconds) == var.visibility_timeout_seconds &&
      var.visibility_timeout_seconds >= 0 &&
      var.visibility_timeout_seconds <= 43200
    )

    error_message = "visibility_timeout_seconds must be an integer between 0 and 43200 seconds."
  }
}

variable "receive_wait_time_seconds" {
  description = "Long-polling duration used by ReceiveMessage calls."
  type        = number
  nullable    = false

  validation {
    condition = (
      floor(var.receive_wait_time_seconds) == var.receive_wait_time_seconds &&
      var.receive_wait_time_seconds >= 0 &&
      var.receive_wait_time_seconds <= 20
    )

    error_message = "receive_wait_time_seconds must be an integer between 0 and 20 seconds."
  }
}

variable "delay_seconds" {
  description = "Default delivery delay applied to messages sent to the primary queue."
  type        = number
  default     = 0
  nullable    = false

  validation {
    condition = (
      floor(var.delay_seconds) == var.delay_seconds &&
      var.delay_seconds >= 0 &&
      var.delay_seconds <= 900
    )

    error_message = "delay_seconds must be an integer between 0 and 900 seconds."
  }
}

variable "max_message_size_bytes" {
  description = "Maximum size of a message in bytes for the primary queue."
  type        = number
  default     = 262144
  nullable    = false

  validation {
    condition = (
      floor(var.max_message_size_bytes) == var.max_message_size_bytes &&
      var.max_message_size_bytes >= 1024 &&
      var.max_message_size_bytes <= 1048576
    )

    error_message = "max_message_size_bytes must be an integer between 1024 and 1048576 bytes."
  }
}

variable "max_receive_count" {
  description = "Number of failed receive attempts before a message is moved to the dead-letter queue."
  type        = number
  nullable    = false

  validation {
    condition = (
      floor(var.max_receive_count) == var.max_receive_count &&
      var.max_receive_count >= 1
    )

    error_message = "max_receive_count must be an integer greater than or equal to 1."
  }
}

variable "encryption_mode" {
  description = "Encryption mode for SQS resources. Supported values are sqs-managed and kms."
  type        = string
  default     = "sqs-managed"
  nullable    = false

  validation {
    condition = contains(
      [
        "sqs-managed",
        "kms",
      ],
      var.encryption_mode
    )

    error_message = "encryption_mode must be either \"sqs-managed\" or \"kms\"."
  }
}

variable "kms_master_key_id" {
  description = "Customer-managed KMS key ID or ARN required when encryption_mode is kms. Must be null when using SQS-managed encryption."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      (
        var.encryption_mode == "kms" &&
        try(length(trimspace(var.kms_master_key_id)) > 0, false)
      ) ||
      (
        var.encryption_mode == "sqs-managed" &&
        var.kms_master_key_id == null
      )
    )

    error_message = "kms_master_key_id must be provided when encryption_mode is \"kms\" and must be null when encryption_mode is \"sqs-managed\"."
  }
}

variable "kms_data_key_reuse_period_seconds" {
  description = "Number of seconds SQS may reuse a KMS data key before requesting a new one."
  type        = number
  default     = 300
  nullable    = false

  validation {
    condition = (
      floor(var.kms_data_key_reuse_period_seconds) == var.kms_data_key_reuse_period_seconds &&
      var.kms_data_key_reuse_period_seconds >= 60 &&
      var.kms_data_key_reuse_period_seconds <= 86400
    )

    error_message = "kms_data_key_reuse_period_seconds must be an integer between 60 and 86400 seconds."
  }
}

variable "enable_dead_letter_redrive_allow_policy" {
  description = "Whether the DLQ explicitly restricts redrive sources to the primary queue."
  type        = bool
  default     = true
  nullable    = false
}

variable "tags" {
  description = "Common governance tags applied to all messaging resources."
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