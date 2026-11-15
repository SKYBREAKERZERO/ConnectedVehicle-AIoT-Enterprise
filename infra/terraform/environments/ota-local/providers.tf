provider "aws" {
  region = var.aws_region

  # LocalStack dummy credentials only.
  access_key = "test"
  secret_key = "test"

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true

  s3_use_path_style = true

  endpoints {
    s3             = var.aws_endpoint_url
    iam            = var.aws_endpoint_url
    kms            = var.aws_endpoint_url
    secretsmanager = var.aws_endpoint_url
    sts            = var.aws_endpoint_url
  }

  default_tags {
    tags = local.common_tags
  }
}