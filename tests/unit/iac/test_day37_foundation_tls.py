"""PostgreSQL 17 explicit TLS enforcement: real parsed Terraform contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

ROOT = (
    Path(__file__).resolve().parents[3]
    / "infra/terraform/environments/ota-staging-foundation/main.tf"
)


def _single(value: Any) -> Any:
    if isinstance(value, list):
        assert len(value) == 1, "ambiguous Terraform attribute"
        return value[0]
    return value


def _resource(parsed: dict[str, Any], kind: str, name: str) -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    for resource in parsed.get("resource", []):
        for group in resource.get(kind, []):
            if name in group:
                value = _single(group[name])
                assert isinstance(value, dict)
                found.append(value)
    assert len(found) == 1, f"resource {kind}.{name} missing or ambiguous"
    return found[0]


def _verify(src: str) -> None:
    hcl2 = pytest.importorskip("hcl2", reason="Pinned HCL parser runs in IaC CI")
    parsed = hcl2.loads(src)
    assert isinstance(parsed, dict)
    group = _resource(parsed, "aws_db_parameter_group", "postgres")
    db = _resource(parsed, "aws_db_instance", "postgres")
    assert _single(group.get("family")) == "postgres17"
    assert _single(db.get("parameter_group_name")) == "${aws_db_parameter_group.postgres.name}"
    params = group.get("parameter")
    assert isinstance(params, list)
    forced = [
        item
        for item in params
        if isinstance(item, dict) and _single(item.get("name")) == "rds.force_ssl"
    ]
    assert len(forced) == 1, "rds.force_ssl must be unique"
    assert _single(forced[0].get("value")) == "1", "RDS plaintext must be rejected"
    assert _single(forced[0].get("apply_method")) == "pending-reboot"


def test_foundation_rds_tls_enforced_by_bound_postgres17_group() -> None:
    _verify(ROOT.read_text(encoding="utf-8"))


@pytest.mark.parametrize("mutation", ("missing", "disabled", "detached"))
def test_foundation_rds_tls_rejects_mutations(mutation: str) -> None:
    src = ROOT.read_text(encoding="utf-8")
    if mutation == "missing":
        src = src.replace('    name         = "rds.force_ssl"', '    name         = "other.ssl"')
    elif mutation == "disabled":
        src = src.replace('    value        = "1"', '    value        = "0"', 1)
    else:
        src = src.replace(
            "parameter_group_name                = aws_db_parameter_group.postgres.name",
            "parameter_group_name                = aws_db_parameter_group.other.name",
        )
    with pytest.raises(AssertionError):
        _verify(src)
