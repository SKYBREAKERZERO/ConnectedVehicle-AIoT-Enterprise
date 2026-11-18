mock_provider "aws" {}

variables {
  bucket_name   = "cv-ota-firmware-contract-123"
  kms_key_arn   = "arn:aws:kms:ap-northeast-1:111111111111:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  artifact_keys = ["body/2.0.0/firmware.bin", "firmware/tenant-a/gateway/1.0/firmware.bin"]
  environment   = "local"
  enforce_tls   = false
}

run "read_permissions_are_version_pinned_and_exact" {
  command = plan

  assert {
    condition = (
      contains(jsondecode(aws_iam_policy.this.policy).Statement[0].Action, "s3:GetObjectVersion") &&
      !contains(jsondecode(aws_iam_policy.this.policy).Statement[0].Action, "s3:GetObject") &&
      length(jsondecode(aws_iam_policy.this.policy).Statement[0].Resource) == 2
    )
    error_message = "Artifact reader must only access approved pinned object versions."
  }
  assert {
    condition     = jsondecode(aws_iam_policy.this.policy).Statement[1].Condition.StringEquals["kms:ViaService"] == "s3.ap-northeast-1.amazonaws.com"
    error_message = "KMS Decrypt must be bound to S3 in the intended region."
  }
}

run "bucket_policy_allows_missing_sse_headers_for_default_sse_kms" {
  command = plan

  assert {
    condition = (
      jsondecode(aws_s3_bucket_policy.this.policy).Statement[0].Condition.Null["s3:x-amz-server-side-encryption"] == "false" &&
      jsondecode(aws_s3_bucket_policy.this.policy).Statement[1].Condition.Null["s3:x-amz-server-side-encryption-aws-kms-key-id"] == "false"
    )
    error_message = "Explicit invalid SSE headers must be denied without blocking safe bucket-default encryption."
  }
}

run "aws_requires_tls" {
  command = plan
  variables {
    environment = "prod"
    enforce_tls = true
  }
  assert {
    condition     = length(jsondecode(aws_s3_bucket_policy.this.policy).Statement) == 3
    error_message = "AWS deployment must append a TLS Deny statement."
  }
}

run "reject_tls_disabled_in_prod" {
  command = plan
  variables { environment = "prod" }
  expect_failures = [var.enforce_tls]
}

run "reject_wildcard_firmware_keys" {
  command = plan
  variables { artifact_keys = ["firmware/*"] }
  expect_failures = [var.artifact_keys]
}

run "reject_traversal_firmware_key" {
  command = plan
  variables { artifact_keys = ["body/../other.bin"] }
  expect_failures = [var.artifact_keys]
}
