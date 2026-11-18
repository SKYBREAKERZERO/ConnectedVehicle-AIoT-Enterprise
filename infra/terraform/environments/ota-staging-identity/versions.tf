terraform {
  required_version = ">= 1.14.7, < 1.17.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
  # Separate protected backend supplied and reviewed before running init/apply.
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}
