from __future__ import annotations

from typing import Any

import pytest

from scripts import day40_rotation_audit as audit

ACCOUNT = "123456789012"


def test_wrong_aws_account_stops_before_resource_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def wrong_identity(*args: str) -> str:
        assert args[:2] == ("sts", "get-caller-identity")
        return "999999999999"

    monkeypatch.setattr(audit, "aws", wrong_identity)
    result = audit.collect(ACCOUNT)
    assert result["checks"] == {"account": "ACCOUNT_MISMATCH"}
    assert result["decision"] == "BLOCKED"
    assert result["release_authorized"] is False


def test_audit_denial_preserves_block_without_secret_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*args: str) -> Any:
        if args[:2] == ("sts", "get-caller-identity"):
            return ACCOUNT
        assert args[1] in {
            "describe-secret",
            "list-versions-by-function",
            "describe-db-instances",
            "describe-replication-groups",
        }
        raise audit.AuditUnavailable("ACCESS_DENIED")

    monkeypatch.setattr(audit, "aws", denied)
    result = audit.collect(ACCOUNT)
    assert result["decision"] == "BLOCKED"
    assert result["aws_rotation_verified"] is False
    assert result["checks"]["application_secret"] == "ACCESS_DENIED"
    assert result["checks"]["redis_lambda"] == "ACCESS_DENIED"
    assert result["checks"]["live_rotation_and_client_continuity"] == "NOT_EXECUTED"
