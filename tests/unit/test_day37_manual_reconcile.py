from pathlib import Path

import pytest
import yaml

from scripts import day37_plan_transport as t

ROOT = Path(__file__).resolve().parents[2]


def test_manual_reconcile_workflow_stays_separate_protected_environment():
    w = yaml.safe_load((ROOT / ".github/workflows/day37-reconcile.yml").read_text())
    assert w["jobs"]["reconcile"]["environment"] == "aws-staging-recovery"
    assert w["concurrency"]["group"] == "day37-aws-staging-exclusive"
    assert w["permissions"]["contents"] == "read"
    assert "id-token" not in w["permissions"]
    body = "\n".join(x.get("run", "") for x in w["jobs"]["reconcile"]["steps"])
    assert "-detailed-exitcode" in body
    assert body.index("describe-images") < body.index("close-fence")
    assert body.index("-detailed-exitcode") < body.index("close-fence")
    assert 'terraform -chdir="${DAY37_TF_ROOT}" apply' not in body


def test_manual_closure_wrong_role_fails_before_s3(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("DAY37_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("DAY37_PLAN_BUCKET", "cv-ota-staging-plan")
    monkeypatch.setenv("DAY37_PLAN_PREFIX", "connected-vehicle/day37-plans/v1")
    monkeypatch.setenv("DAY37_PLAN_KMS_ARN", "arn:aws:kms:ap-northeast-1:123456789012:key/123")
    monkeypatch.setenv("DAY37_BACKEND_KMS_ARN", "arn:aws:kms:ap-northeast-1:123456789012:key/123")
    monkeypatch.setenv("DAY37_ROLE_ARN", "arn:aws:iam::123456789012:role/cv-ota-staging-deploy")
    with pytest.raises(ValueError, match="Recovery Role"):
        t.close_fence(tmp_path / "missing", allow=True)
