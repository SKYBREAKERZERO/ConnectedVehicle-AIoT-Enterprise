from __future__ import annotations

from pathlib import Path

import pytest

from scripts.iac.gate import copy_infra, sandbox_environment


def test_gate_copy_never_reads_development_state_or_credentials(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    infra = source / "infra/terraform"
    infra.mkdir(parents=True)
    for name in [
        "main.tf",
        ".terraform.lock.hcl",
        "terraform.tfstate",
        "terraform.tfstate.backup",
        "terraform.tfvars",
        "local.auto.tfvars.json",
        "plan.tfplan",
        ".env",
        "credential.key",
    ]:
        (infra / name).write_text("test", encoding="utf-8")
    cache = infra / ".terraform"
    cache.mkdir()
    (cache / "terraform.tfstate").write_text("sensitive", encoding="utf-8")
    target = tmp_path / "sandbox"
    copy_infra(source, target)
    assert {p.name for p in target.iterdir()} == {"main.tf", ".terraform.lock.hcl"}
    assert (infra / "terraform.tfstate").read_text() == "test"


def test_gate_subprocesses_cannot_inherit_real_cloud_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for key in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "TF_VAR_password",
        "TF_TOKEN_app_terraform_io",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "CHECKOV_SKIP_CHECK",
        "CKV_SKIP_CHECK",
    ]:
        monkeypatch.setenv(key, "real-sensitive-value")
    env = sandbox_environment(tmp_path)
    assert env["AWS_ACCESS_KEY_ID"] == env["AWS_SECRET_ACCESS_KEY"] == "test"
    assert "real-sensitive-value" not in env.values()
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert Path(env["TF_CLI_CONFIG_FILE"]).is_relative_to(tmp_path)
    assert not Path(env["AWS_SHARED_CREDENTIALS_FILE"]).exists()
