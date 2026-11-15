
locals {
  environment_matches = (
    var.environment == var.expected_environment
  )

  database_network_safe = alltrue([
    for cidr in var.database_ingress_cidrs :
    !contains(["0.0.0.0/0", "::/0"], cidr)
  ])

  production_rds_protected = (
    var.environment != "prod" ||
    var.enable_deletion_protection
  )
}

resource "terraform_data" "day21_security_gate" {
  input = {
    environment = var.environment
  }

  lifecycle {
    precondition {
      condition     = local.environment_matches
      error_message = "Environment mismatch."
    }

    precondition {
      condition     = !var.rds_publicly_accessible
      error_message = "RDS must not be publicly accessible."
    }

    precondition {
      condition     = var.rds_storage_encrypted
      error_message = "RDS storage encryption must be enabled."
    }

    precondition {
      condition     = local.database_network_safe
      error_message = "Database ingress contains public CIDR."
    }

    precondition {
      condition     = local.production_rds_protected
      error_message = "Production RDS requires deletion protection."
    }
  }
}
