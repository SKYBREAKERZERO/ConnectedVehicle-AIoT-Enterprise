locals {
  name_prefix = "${var.project_name}-${var.environment}-state"

  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    Service     = "terraform-state"
    ManagedBy   = "terraform"
    Owner       = var.owner
    Repository  = "ConnectedVehicle-AIoT-Enterprise"
  }
}
