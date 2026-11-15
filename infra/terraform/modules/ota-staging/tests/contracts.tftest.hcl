mock_provider "aws" { override_during = plan }
variables {
  registry_kms_key_arn             = "arn:aws:kms:ap-northeast-1:111122223333:key/33333333-3333-3333-3333-333333333333"
  access_logs_bucket               = "offline-staging-access-logs"
  aws_account_id                   = "111122223333"
  registry_digest                  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  vpc_id                           = "vpc-0123456789abcdef0"
  private_subnet_ids               = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  ingress_cidrs                    = ["10.50.0.0/24"]
  certificate_arn                  = "arn:aws:acm:ap-northeast-1:111122223333:certificate/11111111-1111-1111-1111-111111111111"
  database_security_group_id       = "sg-0123456789abcdef0"
  redis_security_group_id          = "sg-0123456789abcdef1"
  aws_endpoints_security_group_id  = "sg-0123456789abcdef2"
  oidc_proxy_security_group_id     = "sg-0123456789abcdef3"
  s3_prefix_list_id                = "pl-0123456789abcdef0"
  application_database_secret_arn  = "arn:aws:secretsmanager:ap-northeast-1:111122223333:secret:staging/application-abcdef"
  application_database_kms_key_arn = "arn:aws:kms:ap-northeast-1:111122223333:key/11111111-1111-1111-1111-111111111111"
  logs_kms_key_arn                 = "arn:aws:kms:ap-northeast-1:111122223333:key/22222222-2222-2222-2222-222222222222"
  tenant_id                        = "offline-staging-contract"
  redis_host                       = "redis.staging.internal"
  oidc_issuer                      = "https://identity.staging.invalid"
  oidc_audience                    = "ota-staging"
  oidc_jwks_url                    = "https://identity.staging.invalid/.well-known/jwks.json"
}
override_resource {
  override_during = plan
  target          = aws_iam_role.application
  values          = { arn = "arn:aws:iam::111122223333:role/connected-vehicle-ota-staging-application" }
}
override_resource {
  override_during = plan
  target          = aws_iam_role.execution
  values          = { arn = "arn:aws:iam::111122223333:role/connected-vehicle-ota-staging-execution" }
}
run "staging_release_boundaries" {
  command = plan
  assert {
    condition     = aws_ecr_repository.api.image_tag_mutability == "IMMUTABLE" && !aws_ecr_repository.api.force_delete && aws_ecr_repository.api.image_scanning_configuration[0].scan_on_push
    error_message = "Registry must be immutable, scanned and protected from destructive cleanup."
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.api.container_definitions)[0].image == "111122223333.dkr.ecr.ap-northeast-1.amazonaws.com/connected-vehicle-ota-staging@${var.registry_digest}"
    error_message = "Task requires the exact registry manifest reference."
  }
  assert {
    condition     = aws_ecs_task_definition.api.task_role_arn != aws_ecs_task_definition.api.execution_role_arn && jsondecode(aws_ecs_task_definition.api.container_definitions)[0].readonlyRootFilesystem && jsondecode(aws_ecs_task_definition.api.container_definitions)[0].user == "10001:10001"
    error_message = "Execution and application identities must stay separate and non-root."
  }
  assert {
    condition     = alltrue([for entry in jsondecode(aws_ecs_task_definition.api.container_definitions)[0].environment : !can(regex("PASSWORD|BOOTSTRAP|MIGRATION|ACCESS_KEY", entry.name))])
    error_message = "No DB management or AWS long-lived credentials in task environment."
  }
  assert {
    condition     = aws_ecs_service.api.deployment_circuit_breaker[0].enable && aws_ecs_service.api.deployment_circuit_breaker[0].rollback && !aws_ecs_service.api.network_configuration[0].assign_public_ip && aws_lb.api.internal
    error_message = "Private staging and bounded service rollback are mandatory."
  }
  assert {
    condition     = jsondecode(aws_iam_role.github_staging.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise:environment:aws-staging" && jsondecode(aws_iam_role.github_staging.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "Staging OIDC must be exact and independent of production."
  }
  assert {
    condition     = !strcontains(aws_iam_role_policy.github_staging.policy, "UpdateService") && !strcontains(aws_iam_role_policy.github_staging.policy, "PutImage") && !strcontains(aws_iam_role_policy.github_staging.policy, "GetSecretValue")
    error_message = "Initial staging identity cannot publish, deploy or read database secrets."
  }
}
run "deny_mutable_tag" {
  command = plan
  variables { registry_digest = "api:latest" }
  expect_failures = [var.registry_digest]
}
run "deny_foreign_account_secret" {
  command = plan
  variables { application_database_secret_arn = "arn:aws:secretsmanager:ap-northeast-1:999988887777:secret:staging/application-abcdef" }
  expect_failures = [var.application_database_secret_arn]
}
run "deny_other_region" {
  command = plan
  variables { aws_region = "us-east-1" }
  expect_failures = [var.aws_region]
}
run "deny_public_ingress" {
  command = plan
  variables { ingress_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.ingress_cidrs]
}

run "deny_secret_other_region" {
  command = plan
  variables { application_database_secret_arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/application-abcdef" }
  expect_failures = [var.application_database_secret_arn]
}
