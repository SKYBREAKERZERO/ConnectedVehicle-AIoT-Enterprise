
variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "local"

  validation {
    condition = contains(
      ["local", "dev", "staging", "prod"],
      var.environment
    )
    error_message = "Invalid environment."
  }
}

variable "expected_environment" {
  description = "Expected target environment"
  type        = string
  default     = "local"
}

variable "rds_publicly_accessible" {
  description = "Whether the existing RDS is public"
  type        = bool
  default     = false
}

variable "rds_storage_encrypted" {
  description = "Whether existing RDS storage is encrypted"
  type        = bool
  default     = true
}

variable "database_ingress_cidrs" {
  description = "Existing database ingress CIDR ranges"
  type        = list(string)
  default     = []
}

variable "enable_deletion_protection" {
  description = "Existing RDS deletion protection"
  type        = bool
  default     = true
}
