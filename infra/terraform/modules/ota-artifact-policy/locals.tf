locals {
  kms_arn_parts = split(":", var.kms_key_arn)
  partition     = try(local.kms_arn_parts[1], "aws")
  kms_region    = try(local.kms_arn_parts[3], "invalid")
  dns_suffix    = local.partition == "aws-cn" ? "amazonaws.com.cn" : "amazonaws.com"

  bucket_arn = "arn:${local.partition}:s3:::${var.bucket_name}"
  object_arns = [
    for key in sort(tolist(var.artifact_keys)) : "${local.bucket_arn}/${key}"
  ]

  kms_via_service = "s3.${local.kms_region}.${local.dns_suffix}"
  policy_name     = "${var.bucket_name}-ota-read"
}
