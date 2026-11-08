terraform {
  required_version = ">= 1.14.7, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }

  # Supply a separate, reviewed backend.hcl outside Git. Never use production state.
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}
