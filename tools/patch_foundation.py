"""Fail-closed IaC patch for the observed Day37 Foundation Checkov failures.

Adds an actual rotation RESOURCE bound to independently provisioned, reviewed
Lambda functions, NOT a Checkov skip. Will not conjure rotation Lambdas, secrets,
or AWS permissions. Review and validate the preexisting rotation protocols first.
"""
from __future__ import annotations
import argparse
from pathlib import Path

ROTATION = '''

# CKV2_AWS_57: these two secrets are only metadata until external administrator
# provisions AWSCURRENT, Lambda rotation protocols, and downstream credentials.
# These ARNs intentionally have NO DEFAULT. Never replace them with placeholders.
variable "application_rotation_lambda_arn" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^arn:aws:lambda:ap-northeast-1:[0-9]{12}:function:[A-Za-z0-9_-]+(:[A-Za-z0-9_-]+)?$", var.application_rotation_lambda_arn)) && split(":", var.application_rotation_lambda_arn)[4] == var.account_id
    error_message = "Independent, reviewed same-account Application DB rotation Lambda ARN required."
  }
}
variable "redis_rotation_lambda_arn" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^arn:aws:lambda:ap-northeast-1:[0-9]{12}:function:[A-Za-z0-9_-]+(:[A-Za-z0-9_-]+)?$", var.redis_rotation_lambda_arn)) && split(":", var.redis_rotation_lambda_arn)[4] == var.account_id
    error_message = "Independent, reviewed same-account Redis multi-stage rotation Lambda ARN required."
  }
}
resource "aws_secretsmanager_secret_rotation" "application" {
  secret_id           = aws_secretsmanager_secret.application.id
  rotation_lambda_arn = var.application_rotation_lambda_arn
  rotate_immediately  = false
  rotation_rules {
    automatically_after_days = 30
  }
  lifecycle { prevent_destroy = true }
}
resource "aws_secretsmanager_secret_rotation" "redis_auth" {
  secret_id           = aws_secretsmanager_secret.redis_auth.id
  rotation_lambda_arn = var.redis_rotation_lambda_arn
  rotate_immediately  = false
  rotation_rules {
    automatically_after_days = 30
  }
  lifecycle { prevent_destroy = true }
}
'''

def patch(text: str) -> str:
    require = ('resource "aws_db_parameter_group" "postgres" {',
               'resource "aws_secretsmanager_secret" "application" {',
               'resource "aws_secretsmanager_secret" "redis_auth" {',
               'parameter {\n    name  = "log_statement"')
    for item in require:
        if text.count(item)!=1:raise ValueError("BLOCKED: source Foundation contract changed: "+item)
    if 'aws_secretsmanager_secret_rotation' in text or 'rds.force_ssl' in text:
        raise ValueError('BLOCKED: controls may already be present; manually review rather than double-insert')
    text=text.replace('parameter {\n    name  = "log_statement"',
        'parameter {\n    name  = "rds.force_ssl"\n    value = "1"\n  }\n  parameter {\n    name  = "log_statement"',1)
    return text + ROTATION

if __name__=='__main__':
    a=argparse.ArgumentParser()
    a.add_argument('--repo',type=Path,required=True)
    a.add_argument('--apply',action='store_true')
    a.add_argument('--output',type=Path,default=Path('day37-foundation-patched.tf'))
    args=a.parse_args()
    path=args.repo/'infra/terraform/environments/ota-staging-foundation/main.tf'
    if not path.is_file():raise SystemExit('BLOCKED: exact existing Foundation root required')
    out=patch(path.read_text())
    destination=path if args.apply else args.output
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(out)
    print('UPDATED' if args.apply else 'PREVIEW', destination)
