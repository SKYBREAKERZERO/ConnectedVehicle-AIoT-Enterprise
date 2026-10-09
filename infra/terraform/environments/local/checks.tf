check "local_environment_only" {
  assert {
    condition     = var.environment == "local"
    error_message = "The environments/local root module can only deploy environment = local."
  }
}

check "localstack_endpoint_required" {
  assert {
    condition = can(
      regex(
        "^https?://(localhost|127[.]0[.]0[.]1|localstack)(:[0-9]+)?(/.*)?$",
        var.aws_endpoint_url
      )
    )

    error_message = "The local Terraform root must use a LocalStack endpoint."
  }
}