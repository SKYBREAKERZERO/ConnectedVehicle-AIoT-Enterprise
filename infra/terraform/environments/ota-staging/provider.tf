provider "aws" {
  region               = var.aws_region
  allowed_account_ids  = [var.aws_account_id]

  default_tags {
    tags = {
      Project     = "ConnectedVehicle-AIoT-Enterprise"
      Environment = "staging"
      ManagedBy   = "Terraform"
      Scope       = "day37-aws-staging"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_vpc" "existing" {
  id = var.vpc_id
}

data "aws_subnet" "private" {
  for_each = toset(var.private_subnet_ids)
  id       = each.value
}

data "aws_lb_target_group" "existing" {
  count = var.enable_service ? 1 : 0
  arn   = var.alb_target_group_arn
}
