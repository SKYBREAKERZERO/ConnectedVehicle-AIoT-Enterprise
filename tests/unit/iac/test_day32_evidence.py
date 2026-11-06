"""Day32 cannot convert partial deployment proof into production authority."""

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.day31_evidence import provenance
from scripts.iac.day32_evidence import evidence, main
from scripts.iac.deployment_probe import CHECKS, queue_url, require_endpoint
from scripts.iac.module_contracts import GROUPS, merge_reports
from tests.unit.iac.test_module_contracts import reports


def prepared(folder: Path) -> None:
    documents: dict[str, Any] = {
        "summary.json": {
            "status": "passed",
            "phase": "assembled-dag",
            "contract_runs": 18,
            "module_contract_groups": list(GROUPS),
            "destroy_actions": 0,
            "second_plan_exit_code": 0,
            "ota_local_apply_second_plan": True,
            "security_scan": "passed",
        },
        "contracts.json": merge_reports(reports()),
        "security.json": {
            "status": "passed",
            "phase": "security",
            "security_scan": "passed",
            "scanned_sources": 2,
        },
        "day31-governance.json": {
            "provenance": provenance(),
            "apply_authorized": False,
            "cross_workflow_binding_completed": False,
        },
        "day32-deployment.json": {
            "version": 1,
            "scope": "localstack_only",
            "provenance": provenance(),
            "checks": {k: True for k in CHECKS},
            "observed_counts": {"sqs_messages": 1, "kms_keys": 2, "secrets": 3, "iam_roles": 1},
            "deployed_roots": ["environments/local", "environments/ota-local"],
            "terraform_outputs_sha256": "a" * 64,
            "real_aws_verified": False,
            "production_apply_enabled": False,
        },
    }
    for name, document in documents.items():
        (folder / name).write_text(json.dumps(document), encoding="utf-8")


def test_day32_pass_never_authorizes_production(tmp_path: Path) -> None:
    prepared(tmp_path)
    result = evidence(tmp_path)
    assert result["status"] == "passed" and result["scope"] == "localstack_iac_acceptance"
    assert not any(
        result[k]
        for k in (
            "production_apply_enabled",
            "release_authorized",
            "independent_approval_verified",
            "trusted_main_promotion_verified",
        )
    )


@pytest.mark.parametrize(
    "attack",
    [
        "wrong-attempt",
        "wrong-scope",
        "missing-check",
        "numeric-check",
        "empty-counts",
        "aws-claim",
        "changed-plan",
        "destroy",
        "missing-module",
        "prior-identity",
    ],
)
def test_incomplete_or_replayed_deployment_is_denied(tmp_path: Path, attack: str) -> None:
    prepared(tmp_path)
    name = "day32-deployment.json"
    if attack in {"changed-plan", "destroy"}:
        name = "summary.json"
    elif attack == "missing-module":
        name = "contracts.json"
    elif attack == "prior-identity":
        name = "day31-governance.json"
    path = tmp_path / name
    data = json.loads(path.read_text())
    if attack == "wrong-attempt":
        data["provenance"]["day31_run_id"] = "1:999"
    elif attack == "wrong-scope":
        data["scope"] = "production"
    elif attack == "missing-check":
        del data["checks"]["sqs_roundtrip"]
    elif attack == "numeric-check":
        data["checks"]["sqs_roundtrip"] = 1
    elif attack == "empty-counts":
        data["observed_counts"]["kms_keys"] = 0
    elif attack == "aws-claim":
        data["real_aws_verified"] = True
    elif attack == "changed-plan":
        data["second_plan_exit_code"] = 2
    elif attack == "destroy":
        data["destroy_actions"] = 1
    elif attack == "missing-module":
        del data["contract_groups"]["ota"]
    else:
        data["provenance"]["day31_commit"] = "0" * 40
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        evidence(tmp_path)


def test_final_verifier_recomputes_bytes_after_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared(tmp_path)
    monkeypatch.setattr("sys.argv", ["day32_evidence", "--directory", str(tmp_path)])
    main()
    monkeypatch.setattr("sys.argv", ["day32_evidence", "--directory", str(tmp_path), "--verify"])
    main()
    path = tmp_path / "day32-acceptance.json"
    data = json.loads(path.read_text())
    data["release_authorized"] = True
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="changed or replayed"):
        main()


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://sqs.amazonaws.com",
        "http://localhost:4566",
        "http://127.0.0.1:0",
        "http://127.0.0.1:70000",
        "http://127.0.0.1:4566/path",
    ],
)
def test_probe_cannot_contact_real_aws_or_unowned_endpoint(endpoint: str) -> None:
    with pytest.raises(ValueError):
        require_endpoint(endpoint)


def test_queue_address_is_rebound_only_to_owned_emulator() -> None:
    assert (
        queue_url(
            "http://127.0.0.1:12345",
            "http://sqs.ap-northeast-1.localhost.localstack.cloud:4566/000000000000/test",
        )
        == "http://127.0.0.1:12345/000000000000/test"
    )
    with pytest.raises(ValueError):
        queue_url(
            "http://127.0.0.1:12345",
            "https://sqs.ap-northeast-1.amazonaws.com/123456789012/production",
        )
