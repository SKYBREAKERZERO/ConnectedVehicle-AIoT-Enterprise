module "governance" {
  source                          = "../../modules/ota-governance"
  deployment_mode                 = "offline"
  enable_organizations_management = false
  environment_accounts = {
    dev  = { account_id = "111111111111", existing_ou_id = "ou-demo-dev000001" }
    prod = { account_id = "222222222222", existing_ou_id = "ou-demo-prod00001" }
  }
  protected_bucket_arns          = ["arn:aws:s3:::cv-example-state", "arn:aws:s3:::cv-example-firmware"]
  protected_state_bucket_arns    = ["arn:aws:s3:::cv-example-state"]
  protected_firmware_bucket_arns = ["arn:aws:s3:::cv-example-firmware"]
  protected_kms_key_arns         = ["arn:aws:kms:ap-northeast-1:111111111111:key/11111111-1111-1111-1111-111111111111"]
}
output "policy_document" { value = module.governance.scp_document_json }
output "attachment_targets" { value = module.governance.scp_attachment_targets }
