mock_provider "aws" {}
run "integrated_root_remains_offline" {
  command = plan
  assert {
    condition     = length(output.attachment_targets) == 0 && length(jsondecode(output.policy_document).Statement) == 4
    error_message = "The local governance root must export complete policy contracts without managing cloud resources."
  }
}
