# Distinct Foundation root. A reviewed infra administrator runs this with a separate
# remote state. Neither GitHub publish/deploy roles nor this Day37 workflow apply it.
# Requires a valid ACM certificate and separately bootstrapped Application DB role.
terraform {
  required_version = ">= 1.14.7, < 2.0.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0, < 7.0" }
  }
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region              = "ap-northeast-1"
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = { Project = "ConnectedVehicle-AIoT-Enterprise", Environment = "staging", ManagedBy = "Terraform", Scope = "day37-foundation" }
  }
}

variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id)) && var.account_id != "000000000000"
    error_message = "Reviewed non-placeholder staging AWS account is required."
  }
}
variable "availability_zones" {
  type = list(string)
  validation {
    condition     = length(var.availability_zones) == 2 && length(distinct(var.availability_zones)) == 2 && alltrue([for z in var.availability_zones : startswith(z, "ap-northeast-1")])
    error_message = "Exactly two distinct Tokyo AZs required."
  }
}
variable "allowed_ingress_cidrs" {
  type = list(string)
  validation {
    condition     = length(var.allowed_ingress_cidrs) > 0 && alltrue([for c in var.allowed_ingress_cidrs : can(cidrhost(c, 0)) && c != "0.0.0.0/0"])
    error_message = "Explicit private ingress CIDR allowlist required; 0.0.0.0/0 prohibited."
  }
}
variable "alb_certificate_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:acm:ap-northeast-1:[0-9]{12}:certificate/", var.alb_certificate_arn))
    error_message = "Reviewed Tokyo ACM certificate ARN required."
  }
}
variable "postgres_engine_version" {
  type        = string
  description = "Use a currently supported region-specific PostgreSQL 17 minor version."
  validation {
    condition     = can(regex("^17\\.[0-9]+$", var.postgres_engine_version))
    error_message = "Choose an available PostgreSQL 17.x RDS engine version."
  }
}
variable "redis_auth_token" {
  type      = string
  ephemeral = true
  sensitive = true
  validation {
    condition     = length(var.redis_auth_token) >= 16 && length(var.redis_auth_token) <= 128
    error_message = "ElastiCache requires a distinct strong auth token (provided outside State)."
  }
}
variable "redis_token_version" {
  type    = number
  default = 1
}

# Every foundation data key must be provisioned and permission-scoped by the
# independent infrastructure administrator; never share the Terraform State key.
variable "data_kms_key_arn" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-1:[0-9]{12}:key/[A-Za-z0-9-]+$", var.data_kms_key_arn)) && split(":", var.data_kms_key_arn)[4] == var.account_id
    error_message = "Dedicated customer-managed staging data KMS key from the reviewed account required."
  }
}
variable "vpc_flow_log_bucket_arn" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{3,62}$", var.vpc_flow_log_bucket_arn))
    error_message = "An independently provisioned private S3 VPC Flow Logs destination is required."
  }
}
variable "alb_access_log_bucket_name" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{3,62}$", var.alb_access_log_bucket_name))
    error_message = "An independently provisioned private ALB access-log bucket is required."
  }
}
variable "rds_monitoring_role_arn" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", var.rds_monitoring_role_arn)) && split(":", var.rds_monitoring_role_arn)[4] == var.account_id
    error_message = "Reviewed least-privilege RDS Enhanced Monitoring role is required."
  }
}

locals {
  prefix  = "cv-ota-staging"
  public  = { for i, az in var.availability_zones : az => cidrsubnet("10.77.0.0/16", 8, i) }
  private = { for i, az in var.availability_zones : az => cidrsubnet("10.77.0.0/16", 8, i + 10) }
}
resource "aws_vpc" "this" {
  cidr_block           = "10.77.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  lifecycle { prevent_destroy = true }
  tags = { Name = "${local.prefix}-vpc" }
}
# The default VPC Security Group is intentionally empty in both directions.
resource "aws_default_security_group" "deny_all" {
  vpc_id = aws_vpc.this.id
}
# Destination bucket must already permit vpc-flow-logs delivery and use
# administrator-reviewed retention, encryption, and access controls.
resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = var.vpc_flow_log_bucket_arn
}
resource "aws_internet_gateway" "this" { vpc_id = aws_vpc.this.id }
resource "aws_subnet" "public" {
  for_each                = local.public
  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.prefix}-public-${each.key}" }
}
resource "aws_subnet" "private" {
  for_each                = local.private
  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.prefix}-private-${each.key}" }
}
resource "aws_route_table" "public" { vpc_id = aws_vpc.this.id }
resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}
resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}
resource "aws_eip" "nat" {
  for_each = aws_subnet.public
  domain   = "vpc"
}
resource "aws_nat_gateway" "nat" {
  for_each      = aws_subnet.public
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = each.value.id
  depends_on    = [aws_internet_gateway.this]
}
resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.this.id
}
resource "aws_route" "private_nat" {
  for_each               = aws_route_table.private
  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat[each.key].id
}
resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}
resource "aws_security_group" "alb" {
  name        = "${local.prefix}-alb"
  vpc_id      = aws_vpc.this.id
  description = "Internal HTTPS staging ingress"
}
resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each          = toset(var.allowed_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "Approved private HTTPS clients only"
}
resource "aws_vpc_security_group_egress_rule" "alb_to_service" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = aws_vpc.this.cidr_block
  ip_protocol       = "tcp"
  from_port         = 8000
  to_port           = 8000
  description       = "Internal ALB to private OTA API port only"
}
resource "aws_security_group" "postgres" {
  name        = "${local.prefix}-postgres"
  vpc_id      = aws_vpc.this.id
  description = "RDS PostgreSQL; ingress added only from Day37 task SG"
}
resource "aws_security_group" "redis" {
  name        = "${local.prefix}-redis"
  vpc_id      = aws_vpc.this.id
  description = "TLS ElastiCache; ingress added only from Day37 task SG"
}
resource "aws_lb" "internal" {
  name                       = "${local.prefix}-alb"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = [for s in aws_subnet.private : s.id]
  enable_deletion_protection = true
  drop_invalid_header_fields = true
  access_logs {
    bucket  = var.alb_access_log_bucket_name
    prefix  = "cv-ota-staging/alb"
    enabled = true
  }
  lifecycle { prevent_destroy = true }
}
resource "aws_lb_target_group" "api" {
  name                 = "${local.prefix}-api"
  port                 = 8000
  protocol             = "HTTP"
  vpc_id               = aws_vpc.this.id
  target_type          = "ip"
  deregistration_delay = 30
  health_check {
    path                = "/health/ready"
    protocol            = "HTTP"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
  lifecycle { prevent_destroy = true }
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.internal.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.alb_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
resource "aws_db_subnet_group" "postgres" {
  name       = "${local.prefix}-postgres"
  subnet_ids = [for s in aws_subnet.private : s.id]
}
# Staging stores limited-duration SQL evidence; separate KMS-protected RDS
# CloudWatch exports and access policies are required before Foundation Apply.
resource "aws_db_parameter_group" "postgres" {
  name   = "cv-ota-staging-postgres-logging"
  family = "postgres17"
  parameter {
    name  = "log_statement"
    value = "ddl"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}
resource "aws_db_instance" "postgres" {
  identifier                  = "${local.prefix}-postgres"
  engine                      = "postgres"
  engine_version              = var.postgres_engine_version
  instance_class              = "db.t4g.small"
  allocated_storage           = 50
  max_allocated_storage       = 150
  storage_type                = "gp3"
  storage_encrypted           = true
  kms_key_id                  = var.data_kms_key_arn
  parameter_group_name        = aws_db_parameter_group.postgres.name
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  monitoring_interval         = 60
  monitoring_role_arn         = var.rds_monitoring_role_arn
  iam_database_authentication_enabled = true
  performance_insights_enabled = true
  performance_insights_kms_key_id = var.data_kms_key_arn
  db_name                     = "connected_vehicle"
  username                    = "staging_rds_admin"
  manage_master_user_password = true
  publicly_accessible         = false
  db_subnet_group_name        = aws_db_subnet_group.postgres.name
  vpc_security_group_ids      = [aws_security_group.postgres.id]
  multi_az                    = true
  backup_retention_period     = 7
  deletion_protection         = true
  skip_final_snapshot         = false
  copy_tags_to_snapshot       = true
  auto_minor_version_upgrade  = true
  lifecycle { prevent_destroy = true }
}
resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.prefix}-redis"
  subnet_ids = [for s in aws_subnet.private : s.id]
}
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${local.prefix}-redis"
  description                = "TLS Staging Redis/Valkey cache"
  engine                     = "valkey"
  engine_version             = "8.0"
  node_type                  = "cache.t4g.small"
  port                       = 6379
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = var.data_kms_key_arn
  auth_token_wo              = var.redis_auth_token
  auth_token_wo_version      = var.redis_token_version
  subnet_group_name          = aws_elasticache_subnet_group.redis.name
  security_group_ids         = [aws_security_group.redis.id]
  snapshot_retention_limit   = 7
  lifecycle { prevent_destroy = true }
}
# Secret metadata only: write no application database credentials to Terraform state.
resource "aws_secretsmanager_secret" "application" {
  kms_key_id              = var.data_kms_key_arn
  name                    = "/connected-vehicle/staging/database/application"
  description             = "Empty metadata until separately approved app_user RLS bootstrap creates secret VERSION"
  recovery_window_in_days = 30
  lifecycle { prevent_destroy = true }
}
output "vpc_id" { value = aws_vpc.this.id }
output "private_subnet_ids" { value = [for s in aws_subnet.private : s.id] }
output "alb_security_group_id" { value = aws_security_group.alb.id }
output "database_security_group_id" { value = aws_security_group.postgres.id }
output "redis_security_group_id" { value = aws_security_group.redis.id }
output "alb_target_group_arn" { value = aws_lb_target_group.api.arn }
output "application_database_secret_arn" { value = aws_secretsmanager_secret.application.arn }
output "postgres_endpoint" { value = aws_db_instance.postgres.address }
output "rds_managed_admin_secret_arn" { value = aws_db_instance.postgres.master_user_secret[0].secret_arn }
output "redis_host" { value = aws_elasticache_replication_group.redis.primary_endpoint_address }
output "redis_tls_auth_required" { value = true }
output "alb_internal" { value = aws_lb.internal.internal }
output "oidc_application_provisioned" { value = false }
output "foundation_release_authorized" { value = false }

# Admin must populate AWSCURRENT with EXACT redis_auth_token source independently.
resource "aws_secretsmanager_secret" "redis_auth" {
  kms_key_id              = var.data_kms_key_arn
  name                    = "/connected-vehicle/staging/redis/auth"
  description             = "Metadata only: actual Redis token version is added by privileged administrator"
  recovery_window_in_days = 30
  lifecycle { prevent_destroy = true }
}
output "redis_auth_secret_arn" { value = aws_secretsmanager_secret.redis_auth.arn }
