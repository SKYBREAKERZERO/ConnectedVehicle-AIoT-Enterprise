variable "project_name" {
  description = "Project identifier used in resource names and tags."
  type        = string
  default     = "connected-vehicle"
  nullable    = false

  validation {
    condition = can(
      regex(
        "^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$",
        var.project_name
      )
    )
    error_message = "project_name must contain 3-24 lowercase letters,numbers,or hyphens."
  }
}

variable "environment" {
  description = "Environment owning this LocalStack state backend."
  type        = string
  default     = "local"
  nullable    = false

  validation {
    condition     = var.environment == "local"
    error_message = "This bootstrap only supports environment = local"
  }
}

variable "aws_region" {
  description = "AWS-compatible region used by LocalStack."
  type        = string
  default     = "ap-northeast-1"
  nullable    = false

  validation {
    condition = can(
      regex(
        "^[a-z]{2}(-[a-z]+)+-[0-9]+$",
        var.aws_region
      )
    )

    error_message = "Provide a valid AWS-style region name."
  }
}

variable "aws_endpoint_url" {
  description = "LocalStack endpoint used by the bootstrap provider."
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

    error_message = "Use localhost, 127.0.0.1, or localstack with an explicit port."
  }
}

variable "state_bucket_name" {
  description = "Dedicated S3 bucket for Terraform state; never reuse the firmware bucket."
  type        = string
  nullable    = false

  validation {
    condition = (
      can(
        regex(
          "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$",
          var.state_bucket_name
        )
      ) &&
      !startswith(var.state_bucket_name, "xn--") &&
      !startswith(var.state_bucket_name, "sthree-") &&
      !startswith(var.state_bucket_name, "amzn-s3-demo-") &&
      !endswith(var.state_bucket_name, "-s3alias") &&
      !endswith(var.state_bucket_name, "--ol-s3") &&
      !endswith(var.state_bucket_name, "--x-s3") &&
      !endswith(var.state_bucket_name, "--table-s3")
    )

    error_message = "Use a valid 3-63 character bucket name containing lowercase letters, numbers, or hyphens without reserved S3 prefixes or suffixes."
  }
}

variable "owner" {
  description = "Team responsible for the Terraform state backend."
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