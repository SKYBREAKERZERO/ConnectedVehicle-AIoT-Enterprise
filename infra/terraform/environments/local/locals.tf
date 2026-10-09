locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = {
    Project     = var.project_name
    Service     = var.service_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = var.owner
    Repository  = "ConnectedVehicle-AIoT-Enterprise"
  }

  platform_kms_keys = {
    messaging = {
      description = "Platform-managed KMS key for messaging infrastructure."
    }

    secrets = {
      description = "Platform-managed KMS key for Secrets Manager infrastructure."
    }
  }

  platform_secrets = {
    database_application = {
      name        = "/connected-vehicle/${var.environment}/database/application"
      description = "Application database credentials for the Connected Vehicle platform."
      domain      = "database"
    }
  }

}

