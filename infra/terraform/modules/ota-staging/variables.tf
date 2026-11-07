variable "aws_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "Explicit target AWS account required."
  }
}
variable "aws_region" {
  type    = string
  default = "ap-northeast-1"
  validation {
    condition     = var.aws_region == "ap-northeast-1"
    error_message = "This reviewed staging root is restricted to ap-northeast-1."
  }
}
variable "registry_digest" {
  type = string
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.registry_digest))
    error_message = "An independently verified ECR manifest digest is required, never a tag or local Image ID."
  }
}
variable "vpc_id" { type = string }
variable "private_subnet_ids" {
  type = set(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "At least two reviewed private subnets are required."
  }
}
variable "ingress_cidrs" {
  type = set(string)
  validation {
    condition     = length(var.ingress_cidrs) > 0 && alltrue([for cidr in var.ingress_cidrs : can(cidrnetmask(cidr)) && !contains(["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"], cidr)])
    error_message = "Explicit internal client networks required; public ingress is forbidden."
  }
}
variable "certificate_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:acm:${var.aws_region}:${var.aws_account_id}:certificate/[0-9a-f-]+$", var.certificate_arn))
    error_message = "TLS certificate must belong to the staging account/region."
  }
}
variable "database_security_group_id" { type = string }
variable "redis_security_group_id" { type = string }
variable "aws_endpoints_security_group_id" { type = string }
variable "oidc_proxy_security_group_id" { type = string }
variable "s3_prefix_list_id" { type = string }
variable "application_database_secret_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:.+", var.application_database_secret_arn))
    error_message = "Application-only Secret must belong to the exact staging account and region."
  }
}
variable "application_database_kms_key_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/[0-9a-f-]+$", var.application_database_kms_key_arn))
    error_message = "Exact regional/account database KMS key required."
  }
}
variable "logs_kms_key_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/[0-9a-f-]+$", var.logs_kms_key_arn))
    error_message = "Logs KMS key must belong to the staging account/region."
  }
}
variable "tenant_id" {
  type = string
  validation {
    condition     = length(trimspace(var.tenant_id)) > 0
    error_message = "Pin the application DB runtime tenant."
  }
}
variable "redis_host" { type = string }
variable "oidc_issuer" {
  type = string
  validation {
    condition     = startswith(var.oidc_issuer, "https://")
    error_message = "Trusted HTTPS issuer required."
  }
}
variable "oidc_audience" { type = string }
variable "oidc_jwks_url" {
  type = string
  validation {
    condition     = startswith(var.oidc_jwks_url, "https://")
    error_message = "Trusted HTTPS JWKS endpoint required; private egress must be provisioned."
  }
}

variable "registry_kms_key_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/[0-9a-f-]+$", var.registry_kms_key_arn))
    error_message = "Registry KMS key must be in the staging account/region."
  }
}
variable "access_logs_bucket" { type = string }
