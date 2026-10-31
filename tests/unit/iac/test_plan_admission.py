"""Offline Day26 admission and atomic replay tests, never real AWS authorization."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.deploy_governance import ROOT, run_identity
from scripts.iac.plan_admission import (
    BOUND,
    admission_errors,
    canonical_digest,
    reserve_offline_once,
    ruleset_errors,
)

NOW = datetime(2026, 10, 27, 9, 0, tzinfo=UTC)
PLAN = b"synthetic binary saved plan -- no credentials"


@pytest.fixture(scope="module", autouse=True)
def stamp_day26(record_testsuite_property: Callable[[str, object], None]) -> None:
    from scripts.iac.day26_evidence import source_digest

    for name, value in {
        "day26_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "day26_run_id": run_identity(),
        "day26_source_sha256": source_digest(),
    }.items():
        record_testsuite_property(name, value)


def manifest() -> dict[str, Any]:
    return {
        "commit": "a" * 40,
        "run_id": "12345:1",
        "environment": "production",
        "account": "123456789012",
        "plan_role": "arn:aws:iam::123456789012:role/ota-plan",
        "apply_role": "arn:aws:iam::123456789012:role/ota-apply",
        "state_bucket": "cv-production-state",
        "state_key": "ota/production/terraform.tfstate",
        "state_region": "ap-northeast-1",
        "state_kms_key_arn": (
            "arn:aws:kms:ap-northeast-1:123456789012:key/11111111-1111-1111-1111-111111111111"
        ),
        "state_lineage": "11111111-2222-3333-4444-555555555555",
        "state_serial": 3,
        "lockfile_sha256": "c" * 64,
        "terraform_version": "1.14.7",
        "plan_sha256": hashlib.sha256(PLAN).hexdigest(),
        "created_at": (NOW - timedelta(minutes=2)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
    }


def check(
    value: dict[str, Any], *, plan: bytes = PLAN, approval: dict[str, Any] | None = None
) -> list[str]:
    return admission_errors(
        value,
        plan=plan,
        expected={k: manifest()[k] for k in BOUND},
        approval=approval
        if approval is not None
        else {
            "manifest_sha256": canonical_digest(value),
            "reviewer": "independent-reviewer",
            "approved_at": (NOW - timedelta(minutes=1)).isoformat(),
        },
        actor="release-author",
        now=NOW,
    )


def test_bound_saved_plan_contract_passes() -> None:
    assert check(manifest()) == []


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("commit", "b" * 40),
        ("run_id", "12345:2"),
        ("environment", "staging"),
        ("account", "999999999999"),
        ("plan_role", "arn:aws:iam::123456789012:role/other"),
        ("apply_role", "arn:aws:iam::123456789012:role/other"),
        ("state_bucket", "other-state"),
        ("state_key", "other.tfstate"),
        ("state_region", "us-east-1"),
        (
            "state_kms_key_arn",
            "arn:aws:kms:ap-northeast-1:123456789012:key/22222222-2222-2222-2222-222222222222",
        ),
        ("state_lineage", "00000000-0000-0000-0000-000000000000"),
        ("state_serial", 4),
        ("state_serial", True),
        ("lockfile_sha256", "d" * 64),
        ("terraform_version", "1.14.8"),
        ("plan_sha256", "f" * 64),
        ("created_at", (NOW + timedelta(minutes=1)).isoformat()),
        ("expires_at", NOW.isoformat()),
        ("expires_at", (NOW + timedelta(hours=2)).isoformat()),
        ("created_at", "2026-10-27T08:59:00"),
    ],
)
def test_wrong_or_expired_plan_rejected(key: str, value: Any) -> None:
    data = manifest()
    data[key] = value
    assert check(data)


@pytest.mark.parametrize("plan", [b"", PLAN + b"modified"])
def test_saved_plan_bytes_cannot_change(plan: bytes) -> None:
    assert check(manifest(), plan=plan)


@pytest.mark.parametrize("mutation", ["self", "digest", "stale", "future", "extra", "missing"])
def test_approval_cannot_be_reused_or_self_approved(mutation: str) -> None:
    receipt = {
        "manifest_sha256": canonical_digest(manifest()),
        "reviewer": "independent-reviewer",
        "approved_at": (NOW - timedelta(minutes=1)).isoformat(),
    }
    if mutation == "self":
        receipt["reviewer"] = "RELEASE-AUTHOR"
    if mutation == "digest":
        receipt["manifest_sha256"] = "e" * 64
    if mutation == "stale":
        receipt["approved_at"] = (NOW - timedelta(hours=1)).isoformat()
    if mutation == "future":
        receipt["approved_at"] = (NOW + timedelta(minutes=1)).isoformat()
    if mutation == "extra":
        receipt["approved"] = "true"
    if mutation == "missing":
        del receipt["reviewer"]
    assert check(manifest(), approval=receipt)


def test_replay_reservation_survives_restart_and_relabel(tmp_path: Path) -> None:
    ledger = tmp_path / "local-demonstration.sqlite"
    reserve_offline_once(ledger, manifest())
    data = manifest()
    data.update(run_id="99999:1", created_at=NOW.isoformat())
    with pytest.raises(sqlite3.IntegrityError):
        reserve_offline_once(ledger, data)


def test_concurrent_replay_has_one_winner(tmp_path: Path) -> None:
    ledger = tmp_path / "local-demonstration.sqlite"

    def reserve(_: int) -> bool:
        try:
            reserve_offline_once(ledger, manifest())
            return True
        except sqlite3.IntegrityError:
            return False

    with ThreadPoolExecutor(max_workers=8) as workers:
        assert list(workers.map(reserve, range(8))).count(True) == 1


def ruleset() -> dict[str, Any]:
    return {
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": True,
                    "require_last_push_approval": True,
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {"context": "IaC quality gate", "integration_id": 15368},
                        {"context": "Runtime quality gate", "integration_id": 15368},
                    ],
                },
            },
            {"type": "deletion"},
            {"type": "non_fast_forward"},
        ],
    }


@pytest.mark.parametrize(
    "mutation",
    ["none", "review-count", "stale", "last-push", "bypass", "branch", "inactive", "checks"],
)
def test_main_rules_require_independent_review(mutation: str) -> None:
    data = deepcopy(ruleset())
    if mutation == "review-count":
        data["rules"][0]["parameters"]["required_approving_review_count"] = 0
    if mutation == "stale":
        data["rules"][0]["parameters"]["dismiss_stale_reviews_on_push"] = False
    if mutation == "last-push":
        data["rules"][0]["parameters"]["require_last_push_approval"] = False
    if mutation == "bypass":
        data["bypass_actors"] = [{"actor_type": "RepositoryRole", "actor_id": 5}]
    if mutation == "branch":
        data["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
    if mutation == "inactive":
        data["enforcement"] = "evaluate"
    if mutation == "checks":
        data["rules"][1]["parameters"]["required_status_checks"] = []
    assert bool(ruleset_errors(data)) is (mutation != "none")


def test_no_cloud_credentials_apply_or_plan_upload() -> None:
    workflow = (ROOT / ".github/workflows/ota-aws-deploy.yml").read_text()
    assert "id-token: write" not in workflow and "terraform apply" not in workflow
    backend = (ROOT / "infra/terraform/environments/ota-aws/backend.tf.example").read_text()
    assert "use_lockfile = true" in backend and "encrypt      = true" in backend
    assert "access_key" not in backend and "secret_key" not in backend


def test_manifest_schema_is_closed() -> None:
    data = manifest()
    data["approved"] = True
    assert check(data)
    del data["approved"]
    del data["state_serial"]
    assert check(data)


def test_dry_run_rechecks_live_main_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.iac import deploy_governance as module

    for key, value in {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": module.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_SHA": "a" * 40,
    }.items():
        monkeypatch.setenv(key, value)
    changed = ruleset()

    def api(path: str) -> Any:
        if path.endswith("/rulesets/24828733"):
            return changed
        if path.endswith("/branches/main"):
            return {"protected": True, "commit": {"sha": "a" * 40}}
        if "/actions/runs?" in path:
            return {"workflow_runs": []}
        return {}

    monkeypatch.setattr(module, "gh", api)
    monkeypatch.setattr(module, "environment_errors", lambda *_: [])
    monkeypatch.setattr(module, "quality_errors", lambda *_: [])
    assert module.preflight("a" * 40, "dry-run")["main_review_rules_verified"] is True
    changed["rules"][0]["parameters"]["required_approving_review_count"] = 0
    with pytest.raises(ValueError, match="approval"):
        module.preflight("a" * 40, "dry-run")


def test_s3_probe_rejects_real_endpoints_before_client_creation(tmp_path: Path) -> None:
    from scripts.iac.state_lock_probe import probe

    for endpoint in (
        "https://s3.amazonaws.com",
        "http://127.0.0.1:4566.evil",
        "https://127.0.0.1:4566",
    ):
        with pytest.raises(ValueError, match="loopback"):
            probe(tmp_path, endpoint, {})
    with pytest.raises(ValueError, match="dummy"):
        probe(tmp_path, "http://127.0.0.1:4566", {})


def test_day26_evidence_rejects_relabel_or_missing_scenario(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from xml.etree import ElementTree

    from scripts.iac import day26_evidence as module

    baseline = {"provenance": {"commit": "a" * 40, "run_id": "12345:1"}, "junit_sha256": "b" * 64}
    monkeypatch.setattr(module, "static_evidence", lambda _: baseline)
    document = ElementTree.Element("testsuites")
    suite = ElementTree.SubElement(document, "testsuite")
    properties = ElementTree.SubElement(suite, "properties")
    for key, value in {
        "day26_commit": "a" * 40,
        "day26_run_id": "12345:1",
        "day26_source_sha256": module.source_digest(),
    }.items():
        ElementTree.SubElement(properties, "property", name=key, value=value)
    for name in module.SCENARIOS:
        ElementTree.SubElement(suite, "testcase", name=name)
    path = tmp_path / "cases.xml"
    ElementTree.ElementTree(document).write(path)
    assert module.evidence(path)["production_apply_enabled"] is False
    properties[0].set("value", "c" * 40)
    ElementTree.ElementTree(document).write(path)
    with pytest.raises(ValueError, match="attestation"):
        module.evidence(path)
    properties[0].set("value", "a" * 40)
    suite.remove(suite[-1])
    ElementTree.ElementTree(document).write(path)
    with pytest.raises(ValueError, match="scenarios"):
        module.evidence(path)
