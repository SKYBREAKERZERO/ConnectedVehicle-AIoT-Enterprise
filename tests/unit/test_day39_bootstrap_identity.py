"""Bootstrap IAM roles must never inherit GitHub deploy identity trust."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "infra/terraform/environments/ota-staging-identity/main.tf"


def test_independent_bootstrap_role_trust_is_not_github_oidc() -> None:
    source = TF.read_text(encoding="utf-8")
    assert 'resource "aws_iam_role" "bootstrap_admin"' in source
    block = source.split('resource "aws_iam_role" "bootstrap_admin"', 1)[1]
    block = block.split('resource "aws_iam_role_policy_attachment" "bootstrap_admin"', 1)[0]
    assert 'Principal = { AWS = each.value }' in block
    assert 'Action    = "sts:AssumeRole"' in block
    assert "sts:AssumeRoleWithWebIdentity" not in block
    assert "token.actions.githubusercontent.com" not in block
    assert "permissions_boundary = var.permissions_boundary_arn" in block
    assert "prevent_destroy = true" in block


def test_bootstrap_roles_have_distinct_reviewed_operator_and_policy_sources() -> None:
    source = TF.read_text(encoding="utf-8")
    assert '"cv-ota-staging-foundation-admin"' in source
    assert '"cv-ota-staging-credential-admin"' in source
    assert '"bootstrap_operator_role_arns"' in source
    assert '"bootstrap_policy_arns"' in source
    assert 'policy_arn = each.value' in source
    assert 'role       = aws_iam_role.bootstrap_admin[each.key].name' in source
    assert "cv-ota-staging-operator-foundation" in source
    assert "cv-ota-staging-operator-credentials" in source
    assert "cv-ota-staging-admin/foundation" in source
    assert "cv-ota-staging-admin/credentials" in source
    assert 'output "bootstrap_admin_role_arns"' in source
