variable "aws_account_id" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id)) && var.aws_account_id != "000000000000"
    error_message = "A reviewed non-LocalStack AWS account ID is required."
  }
}

variable "state_bucket_name" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.state_bucket_name)) && !startswith(var.state_bucket_name, "xn--") && !startswith(var.state_bucket_name, "amzn-s3-demo-") && !endswith(var.state_bucket_name, "-s3alias")
    error_message = "Provide a dedicated valid S3 state bucket name."
  }
}

variable "state_key" {
  type     = string
  default  = "ota/production/terraform.tfstate"
  nullable = false
  validation {
    condition     = var.state_key == "ota/production/terraform.tfstate"
    error_message = "This contract permits only the reviewed production state key."
  }
}

variable "aws_region" {
  type     = string
  default  = "ap-northeast-1"
  nullable = false
  validation {
    condition     = var.aws_region == "ap-northeast-1"
    error_message = "The production state contract is scoped to ap-northeast-1."
  }
}

variable "access_log_bucket_name" {
  description = "Pre-provisioned same-account/region private S3 log destination; validate its delivery policy before deployment."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.access_log_bucket_name)) && var.access_log_bucket_name != var.state_bucket_name
    error_message = "Access logs require a distinct dedicated bucket."
  }
}

variable "recovery_bucket_arn" {
  description = "Pre-provisioned same-account versioned cross-region recovery bucket."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.recovery_bucket_arn)) && var.recovery_bucket_arn != "arn:aws:s3:::${var.state_bucket_name}"
    error_message = "Recovery must use a separate exact bucket ARN."
  }
}

variable "replication_role_arn" {
  description = "Separate reviewed S3 service replication role; never a CI or deployment role."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^arn:aws:iam::${var.aws_account_id}:role/[A-Za-z0-9+=,.@_/-]+$", var.replication_role_arn))
    error_message = "Replication role must belong to the reviewed account."
  }
}

variable "recovery_kms_key_arn" {
  description = "Existing KMS key in the reviewed recovery region, account-bound."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^arn:aws:kms:us-west-2:${var.aws_account_id}:key/[0-9a-f-]{36}$", var.recovery_kms_key_arn))
    error_message = "Recovery requires an exact account-owned us-west-2 KMS key."
  }
}
