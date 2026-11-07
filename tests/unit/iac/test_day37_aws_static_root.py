"""Day37 AWS roots cannot be initialized with live state or planned in PR CI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scripts.iac import gate


@pytest.mark.parametrize(
    ("root_name", "variable"),
    [
        ("ota-staging", "aws_account_id"),
        ("ota-staging-foundation", "account_id"),
        ("ota-staging-identity", "account_id"),
    ],
)
def test_static_aws_root_never_uses_backend_or_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    root_name: str,
    variable: str,
) -> None:
    # The runtime toolchain excludes the IaC-only HCL parser; IaC CI
    # installs it and runs this same test against the real parser.
    pytest.importorskip("hcl2", reason="Requires pinned IaC HCL parser; exercised in IaC CI")
    root = tmp_path / "environments" / root_name
    root.mkdir(parents=True)
    (root / ".terraform.lock.hcl").write_text("# committed lock\n")
    (root / "main.tf").write_text(
        "terraform {\n"
        '  backend "s3" {\n'
        "    encrypt = true\n"
        "    use_lockfile = true\n"
        "  }\n"
        "}\n"
        'provider "aws" {\n'
        f"  allowed_account_ids = [var.{variable}]\n"
        "}\n"
    )
    calls: list[tuple[str, ...]] = []

    def guarded_terraform(_root: Path, *args: str, **_kw: Any) -> None:
        calls.append(args)
        assert "plan" not in args
        assert "apply" not in args
        assert "-backend=false" in args or args[0] == "validate"

    monkeypatch.setattr(gate, "terraform", guarded_terraform)
    gate.initialize_aws_staging_static(root, env={"AWS_EC2_METADATA_DISABLED": "true"})
    assert len(calls) == 2
    assert calls[0][0] == "init" and calls[1][0] == "validate"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-lock",
        "unencrypted",
        "unlocked",
        "local-backend",
        "foreign-account-var",
        "unlisted-root",
    ],
)
def test_static_aws_root_rejects_trust_boundary_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    # Missing-lock and path-isolation checks don't need the HCL parser.
    if mutation not in {"missing-lock", "unlisted-root"}:
        pytest.importorskip("hcl2", reason="Requires pinned IaC HCL parser; exercised in IaC CI")
    root = tmp_path / "environments" / ("foreign" if mutation == "unlisted-root" else "ota-staging")
    root.mkdir(parents=True)
    if mutation != "missing-lock":
        (root / ".terraform.lock.hcl").write_text("# committed lock\n")
    backend = "local" if mutation == "local-backend" else "s3"
    encrypt = "false" if mutation == "unencrypted" else "true"
    locked = "false" if mutation == "unlocked" else "true"
    account = "account_id" if mutation == "foreign-account-var" else "aws_account_id"
    (root / "main.tf").write_text(
        "terraform {\n"
        f'  backend "{backend}" {{\n'
        f"    encrypt = {encrypt}\n"
        f"    use_lockfile = {locked}\n"
        "  }\n"
        "}\n"
        'provider "aws" {\n'
        f"  allowed_account_ids = [var.{account}]\n"
        "}\n"
    )
    monkeypatch.setattr(
        gate,
        "terraform",
        lambda *_args, **_kwargs: pytest.fail("untrusted AWS root reached terraform"),
    )
    with pytest.raises(ValueError):
        gate.initialize_aws_staging_static(root, env={})


def test_aws_only_root_matching_excludes_identically_named_module(tmp_path: Path) -> None:
    candidate = tmp_path / "terraform"
    assert "environments/ota-staging" in gate.AWS_STAGING_STATIC_PATHS
    assert "modules/ota-staging" not in gate.AWS_STAGING_STATIC_PATHS
    module = candidate / "modules" / "ota-staging"
    with pytest.raises(ValueError, match="isolated environment"):
        gate.initialize_aws_staging_static(module, env={})
