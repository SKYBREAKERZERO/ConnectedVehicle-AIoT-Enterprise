provider "aws" {
  region                      = "ap-northeast-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    organizations = "http://127.0.0.1:4566"
    iam           = "http://127.0.0.1:4566"
    sts           = "http://127.0.0.1:4566"
  }
}
