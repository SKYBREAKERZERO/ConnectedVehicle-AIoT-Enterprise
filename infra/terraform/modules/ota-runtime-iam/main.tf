resource "aws_iam_role" "this" {
  name                  = var.role_name
  description           = "Dedicated runtime role for the OTA Campaign Dispatcher."
  path                  = "/"
  max_session_duration  = var.max_session_duration_seconds
  force_detach_policies = false

  assume_role_policy = jsonencode({
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

  tags = var.tags

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = (
        length(toset(values(local.read_policy_arns))) == 3
      )

      error_message = "Database, authority, and artifact read policies must be distinct."
    }
  }
}

resource "aws_iam_role_policy_attachment" "read" {
  for_each = local.read_policy_arns

  role       = aws_iam_role.this.name
  policy_arn = each.value
}