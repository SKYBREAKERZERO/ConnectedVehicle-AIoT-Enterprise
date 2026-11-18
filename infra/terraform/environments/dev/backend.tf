terraform {
  # A real, secured and versioned S3 state bucket must be provisioned first.
  # Pass bucket/key/region/use_lockfile through -backend-config.
  backend "s3" {}
}
