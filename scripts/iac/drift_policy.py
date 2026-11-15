"""Read-only drift classification and release/state/resource reconciliation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def _changes(value: Any) -> bool:
    if not isinstance(value, list):
        raise ValueError("plan changes must be arrays")
    changed = False
    for resource in value:
        actions = resource["change"]["actions"]
        if (
            not isinstance(actions, list)
            or not actions
            or any(
                a not in {"no-op", "read", "create", "update", "delete", "forget"} for a in actions
            )
        ):
            raise ValueError("unsupported/malformed plan actions")
        changed |= actions != ["no-op"]
    return changed


def drift_report(
    refresh_code: int, refresh: dict[str, Any], normal_code: int, normal: dict[str, Any]
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "decision": "ERROR",
        "state_drift": False,
        "configuration_drift": False,
        "automatic_remediation": False,
        "production_apply_enabled": False,
        "new_review_required": True,
    }
    try:
        for code, plan in ((refresh_code, refresh), (normal_code, normal)):
            if (
                type(code) is not int
                or code not in {0, 2}
                or plan.get("format_version") != "1.2"
                or plan.get("terraform_version") != "1.14.7"
                or plan.get("errored") is True
                or plan.get("complete") is not True
                or plan.get("deferred_changes")
            ):
                raise ValueError("plan failed, incomplete, deferred or unsupported")
            resource_changes = _changes(plan.get("resource_changes", []))
            resource_drift = _changes(plan.get("resource_drift", []))
            changed = resource_changes or resource_drift
            outputs = plan.get("output_changes", {})
            if not isinstance(outputs, dict):
                raise ValueError("invalid plan outputs")
            changed |= _changes([{"change": change} for change in outputs.values()])
            if (code == 0 and changed) or (code == 2 and not changed):
                raise ValueError("exit code contradicts plan changes")
        result["state_drift"] = _changes(refresh.get("resource_drift", [])) or refresh_code == 2
        result["configuration_drift"] = (
            _changes(normal.get("resource_changes", [])) or normal_code == 2
        )
        result["decision"] = (
            "REVIEW_REQUIRED" if result["state_drift"] or result["configuration_drift"] else "CLEAR"
        )
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        result["error"] = str(exc)
    return result


def reconciliation_errors(
    *,
    release: dict[str, Any],
    expected: dict[str, Any],
    state: dict[str, Any],
    resource: dict[str, Any],
    drift: dict[str, Any],
    authenticate: Callable[[dict[str, Any]], bool],
) -> list[str]:
    """Expected release context and independent resource reads are trust inputs."""
    try:
        fields = {
            "commit",
            "run_id",
            "account",
            "environment",
            "bucket",
            "key",
            "version_id",
            "sha256",
            "lineage",
            "serial",
            "resource_id",
            "resource_fingerprint",
        }
        if (
            set(expected) != fields
            or set(release) != fields | {"status"}
            or release["status"] != "VERIFIED"
        ):
            raise ValueError(
                "closed fresh release context required; interrupted/READY cannot resume"
            )
        if any(
            type(release[k]) is not type(expected[k]) or release[k] != expected[k] for k in fields
        ):
            raise ValueError("release differs from current trusted context")
        if any(state[k] != expected[k] for k in fields - {"resource_id", "resource_fingerprint"}):
            raise ValueError("release/state association mismatch")
        if resource != {k: expected[k] for k in ("resource_id", "resource_fingerprint")}:
            raise ValueError("actual resource identity/configuration differs")
        if (
            drift.get("decision") != "CLEAR"
            or drift.get("state_drift") is not False
            or drift.get("configuration_drift") is not False
        ):
            raise ValueError("drift/error requires fresh plan and independent review")
        if authenticate(dict(release)) is not True:
            raise ValueError("release authority unavailable or rejected")
    except Exception as exc:
        return [str(exc) or type(exc).__name__]
    return []
