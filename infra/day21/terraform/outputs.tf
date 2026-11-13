
output "day21_security_checks" {
  description = "Evaluated security checks"

  value = {
    environment_matches = local.environment_matches

    rds_private = !var.rds_publicly_accessible

    rds_encrypted = var.rds_storage_encrypted

    database_network_safe = local.database_network_safe

    production_protected = local.production_rds_protected
  }
}
