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
    database_outbox = {
      name        = "/connected-vehicle/${var.environment}/database/outbox"
      description = "Outbox worker database credentials."
      domain      = "database"
    }
    database_remote_command = {
      name        = "/connected-vehicle/${var.environment}/database/remote-command"
      description = "Remote command worker database credentials."
      domain      = "database"
    }
    database_application = {
      name        = "/connected-vehicle/${var.environment}/database/application"
      description = "Application database credentials for the Connected Vehicle platform."
      domain      = "database"
    }
  }

  application_runtime_role_name = "${local.name_prefix}-application-runtime"

  application_runtime_assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AllowEcsTasksToAssumeRole"
        Effect = "Allow"

        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  outbox_dispatcher_role_name = "${local.name_prefix}-outbox-dispatcher"

  outbox_dispatcher_assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AllowEcsTasksToAssumeRole"
        Effect = "Allow"

        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  remote_command_dispatcher_role_name = "${local.name_prefix}-remote-cmd-dispatcher"

  remote_command_dispatcher_assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AllowEcsTasksToAssumeRole"
        Effect = "Allow"

        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  secret_bootstrap_role_name = "${local.name_prefix}-secret-bootstrap"

  secret_bootstrap_assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AllowLocalAccountToAssumeBootstrapRole"
        Effect = "Allow"

        Principal = {
          AWS = "arn:aws:iam::000000000000:root"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

}