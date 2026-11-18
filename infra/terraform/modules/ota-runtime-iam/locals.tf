locals {
  read_policy_arns = {
    database  = var.database_read_policy_arn
    authority = var.authority_read_policy_arn
    artifact  = var.artifact_read_policy_arn
  }
}
