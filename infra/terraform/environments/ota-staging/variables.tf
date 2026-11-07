variable "aws_account_id" {
  type        = string
  description = "Exact authorized AWS staging account. Not a production account."
  nullable    = false
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "A 12-digit account ID is mandatory."
  }
}

variable "aws_region" {
  type        = string
  description = "Exact AWS staging region."
  default     = "ap-northeast-1"
  nullable    = false
  validation {
    condition     = var.aws_region == "ap-northeast-1"
    error_message = "Day37 scope is limited to ap-northeast-1."
  }
}

variable "name_prefix" {
  type     = string
  default  = "cv-ota-staging"
  nullable = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.name_prefix)) && endswith(var.name_prefix, "-staging")
    error_message = "Use a short lowercase name ending in -staging."
  }
}

variable "vpc_id" {
  type        = string
  nullable    = false
  description = "Existing dedicated staging VPC ID."
  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "Exact staging VPC ID required."
  }
}

variable "private_subnet_ids" {
  type        = list(string)
  nullable    = false
  description = "At least two private subnets in different AZs with ECR/Logs/Secrets/STS and JWKS egress."
  validation {
    condition     = length(var.private_subnet_ids) >= 2 && length(distinct(var.private_subnet_ids)) == length(var.private_subnet_ids) && alltrue([for s in var.private_subnet_ids : can(regex("^subnet-[0-9a-f]{8,17}$", s))])
    error_message = "Two or more distinct private subnet IDs required."
  }
}

variable "alb_security_group_id" {
  type        = string
  nullable    = false
  description = "Existing staging ALB security group; only it can reach the API on 8000."
  validation {
    condition     = can(regex("^sg-[0-9a-f]{8,17}$", var.alb_security_group_id))
    error_message = "Valid ALB security group required."
  }
}

variable "database_security_group_id" {
  type        = string
  nullable    = false
  description = "Existing RDS/PostgreSQL security group; its ingress must separately permit task SG."
  validation {
    condition     = can(regex("^sg-[0-9a-f]{8,17}$", var.database_security_group_id))
    error_message = "Valid database security group required."
  }
}

variable "redis_security_group_id" {
  type        = string
  nullable    = false
  description = "Existing Redis security group; its ingress must separately permit task SG."
  validation {
    condition     = can(regex("^sg-[0-9a-f]{8,17}$", var.redis_security_group_id))
    error_message = "Valid Redis security group required."
  }
}

variable "alb_target_group_arn" {
  type        = string
  default     = null
  description = "Existing staging ALB target group ARN; required only when enabling service. Must be target_type ip."
  validation {
    condition     = var.alb_target_group_arn == null || can(regex("^arn:aws:elasticloadbalancing:ap-northeast-1:[0-9]{12}:targetgroup/", var.alb_target_group_arn))
    error_message = "Target group must be an ap-northeast-1 ARN."
  }
}

variable "application_database_secret_arn" {
  type        = string
  nullable    = false
  description = "Provisioned tenant-bound app_user database secret, no bootstrap/migration credentials."
  validation {
    condition     = can(regex("^arn:aws:secretsmanager:ap-northeast-1:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.application_database_secret_arn))
    error_message = "Exact Secrets Manager ARN is required."
  }
}

variable "database_kms_key_arn" {
  type        = string
  default     = null
  description = "Customer-managed KMS key of the database secret, if used."
}

variable "tenant_id" {
  type        = string
  nullable    = false
  description = "Exact tenant ID matching database Secret and PostgreSQL RLS bootstrap."
  validation {
    condition     = length(trimspace(var.tenant_id)) > 0 && length(var.tenant_id) <= 128
    error_message = "Nonblank tenant_id required."
  }
}

variable "oidc_issuer" {
  type     = string
  nullable = false
  validation {
    condition     = startswith(var.oidc_issuer, "https://")
    error_message = "External OIDC issuer must use HTTPS."
  }
}
variable "oidc_jwks_url" {
  type     = string
  nullable = false
  validation {
    condition     = startswith(var.oidc_jwks_url, "https://")
    error_message = "External JWKS URL must use HTTPS."
  }
}
variable "oidc_audience" {
  type     = string
  nullable = false
  validation {
    condition     = length(trimspace(var.oidc_audience)) > 0
    error_message = "OIDC audience required."
  }
}

variable "image_digest" {
  type        = string
  default     = null
  description = "Registry MANIFEST sha256 digest issued by signed Day37 ECR supply chain, NEVER Docker Image ID."
  validation {
    condition     = var.image_digest == null || can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "Only sha256:64-hex manifest digests are allowed."
  }
}

variable "enable_service" {
  type        = bool
  default     = false
  description = "OFF by default. Requires protected staging approval, signed source and ECR digest."
}

variable "desired_count" {
  type    = number
  default = 0
  validation {
    condition     = var.desired_count >= 0 && var.desired_count <= 4 && floor(var.desired_count) == var.desired_count
    error_message = "Bounded staging desired_count 0-4."
  }
}

variable "cpu" {
  type    = number
  default = 512
  validation {
    condition     = contains([256, 512, 1024, 2048], var.cpu)
    error_message = "Supported Fargate CPU shape only."
  }
}
variable "memory" {
  type    = number
  default = 1024
  validation {
    condition     = var.memory == 1024
    error_message = "Day37 initially fixes memory to 1024 MiB; review scaling separately."
  }
}

variable "redis_host" {
  type        = string
  description = "Existing private Redis DNS name; provisioned and secured outside this Terraform root."
  nullable    = false
  validation {
    condition     = length(trimspace(var.redis_host)) > 4 && !startswith(var.redis_host, "http")
    error_message = "Expected a private Redis host, not a URL."
  }
}

variable "redis_auth_secret_arn" {
  type        = string
  nullable    = false
  description = "External Secrets Manager current Redis auth token; execution role injects into container as REDIS_PASSWORD."
  validation {
    condition     = can(regex("^arn:aws:secretsmanager:ap-northeast-1:[0-9]{12}:secret:", var.redis_auth_secret_arn))
    error_message = "Require an exact same-region AWS Redis auth secret ARN."
  }
}

# Separately provisioned CMK for ECR and application log encryption.
# Key policies must grant ECR and logs service principals required usage.
variable "data_kms_key_arn" {
  type        = string
  nullable    = false
  description = "Exact customer-managed Staging data encryption KMS key, not Terraform State key."
  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-1:[0-9]{12}:key/[A-Za-z0-9-]+$", var.data_kms_key_arn)) && split(":", var.data_kms_key_arn)[4] == var.aws_account_id
    error_message = "Real same-account Tokyo CMK ARN required for ECR and CloudWatch Logs."
  }
}
