provider "aws" {
  region = var.aws_region

  # LocalStack only.
  # Never use real AWS credentials in this environment root.
  access_key = "test"
  secret_key = "test"

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true

  endpoints {
    sqs            = var.aws_endpoint_url
    sns            = var.aws_endpoint_url
    events         = var.aws_endpoint_url
    kms            = var.aws_endpoint_url
    secretsmanager = var.aws_endpoint_url
    iam            = var.aws_endpoint_url
  }

  default_tags {
    tags = local.common_tags
  }
}