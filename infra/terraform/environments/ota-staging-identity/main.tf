# Run with a separately approved identity-provisioning administrator.
# Never execute from PR CI or an AWS Staging workload/deployment role.
# This root creates IAM roles but does not grant broad permissions to them.
provider "aws" {
  region              = "ap-northeast-1"
  allowed_account_ids = [var.account_id]
}

locals {
  modes = toset(["plan", "bootstrap", "publish", "deploy", "verify", "recovery"])
}

variable "account_id" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id)) && var.account_id != "000000000000"
    error_message = "Reviewed non-placeholder Staging AWS account ID required."
  }
}

variable "github_oidc_provider_arn" {
  type     = string
  nullable = false
  validation {
    condition     = var.github_oidc_provider_arn == "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com"
    error_message = "Only the exact account-owned GitHub Actions OIDC provider is accepted."
  }
}

variable "permissions_boundary_arn" {
  type     = string
  nullable = false
  validation {
    condition     = var.permissions_boundary_arn == "arn:aws:iam::${var.account_id}:policy/cv-ota-staging-boundary"
    error_message = "A separately reviewed Staging permissions boundary must exist."
  }
}

variable "reviewed_policy_arns" {
  type        = map(string)
  nullable    = false
  description = "Six separately reviewed, narrow IAM policies. Different policy per job."
  validation {
    condition = (
      length(var.reviewed_policy_arns) == 6 &&
      toset(keys(var.reviewed_policy_arns)) == toset(["plan", "bootstrap", "publish", "deploy", "verify", "recovery"]) &&
      length(distinct(values(var.reviewed_policy_arns))) == 6 &&
      alltrue([for mode, arn in var.reviewed_policy_arns : arn == "arn:aws:iam::${var.account_id}:policy/cv-ota-staging/${mode}"])
    )
    error_message = "Exactly six distinct reviewed policy ARNs, each scoped to its mode, required."
  }
}

data "aws_iam_openid_connect_provider" "github" {
  arn = var.github_oidc_provider_arn
}

resource "aws_iam_role" "staging" {
  for_each             = local.modes
  name                 = "cv-ota-staging-${each.key}"
  path                 = "/"
  permissions_boundary = var.permissions_boundary_arn
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise:environment:aws-staging-${each.key}"
        }
      }
    }]
  })
  lifecycle {
    prevent_destroy = true
  }
  tags = {
    Project = "ConnectedVehicle-AIoT-Enterprise"
    Environment = "staging"
    Day37Role = each.key
  }
}

resource "aws_iam_role_policy_attachment" "staging" {
  for_each   = local.modes
  role       = aws_iam_role.staging[each.key].name
  policy_arn = var.reviewed_policy_arns[each.key]
}

output "role_arns" {
  value = {for mode, role in aws_iam_role.staging: mode => role.arn}
}
