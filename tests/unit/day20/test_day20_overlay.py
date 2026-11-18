"""Sanity assertions for a delivered Day20 overlay (not a Terraform replacement)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.day20.verify_overlay import block_balance_hcl, verify

ROOT = Path(__file__).resolve().parents[3]


def test_delivered_day20_file_inventory() -> None:
    result = verify(ROOT)
    assert len(result) >= 17


@pytest.mark.parametrize("bad", ["resource {", 'variable "broken" {', "resource (}", "a = [1,2]]"])
def test_sanity_checker_rejects_structurally_invalid_hcl(bad: str) -> None:
    with pytest.raises(AssertionError):
        block_balance_hcl(bad)


def test_sanity_checker_allows_hcl_string_interpolation_and_comments() -> None:
    block_balance_hcl(
        'resource "terraform_data" "ok" {\n  input = "${var.env}-{not an HCL block}" # }\n}\n'
    )


def test_gov_scopes_are_distinct_and_default_safe() -> None:
    base = ROOT / "infra/terraform/modules/ota-governance"
    variables = (base / "variables.tf").read_text()
    locals_hcl = (base / "locals.tf").read_text()
    assert 'default     = "topology"' in variables
    assert 'default     = "offline"' in variables
    assert "local.protected_firmware_bucket_arns" in locals_hcl
    assert '"s3:DeleteObjectVersion"' in locals_hcl
    firmware_scope = locals_hcl.split("protected_firmware_object_arns =", 1)[1].split("}", 1)[0]
    assert "local.protected_state_bucket_arns" not in firmware_scope


def test_existing_state_bootstrap_is_preserved() -> None:
    assert (ROOT / "infra/terraform/bootstrap/state-backend/main.tf").exists()
    assert (ROOT / "infra/terraform/bootstrap/state-backend/tests/contracts.tftest.hcl").exists()


def test_artifact_policy_allows_versioned_existing_key_layout() -> None:
    data = (ROOT / "infra/terraform/modules/ota-artifact-policy/variables.tf").read_text()
    assert "Exact" in data or "EXACT" in data
    assert '"^[A-Za-z0-9][A-Za-z0-9._/-]+$"' in data
