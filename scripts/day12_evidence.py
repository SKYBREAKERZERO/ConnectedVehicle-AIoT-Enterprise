"""Check every required local acceptance artifact and publish a sanitized manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ALERTS = {
    "DeviceAuthenticationBlocked",
    "VehicleCommandOrderStalled",
    "DeviceLedgerCapacityWarning",
    "RuntimeReportDeliveryStalled",
    "RuntimeCollectorUnavailable",
}
STAGES = (
    "12a-migrations",
    "12a-rls",
    "12b-identity-matrix",
    "12c-alert-lifecycle",
    "12d-restore",
    "migration-failure-retry",
    "migration-scale-locks",
)


def validate(directory: Path) -> dict[str, Any]:
    reports = {}
    digests = {}
    for stage in STAGES:
        path = directory / f"day12-{stage}.json"
        data = path.read_bytes()
        reports[stage] = json.loads(data)
        digests[path.name] = hashlib.sha256(data).hexdigest()
    migration = reports["12a-migrations"]
    expected = {
        "fresh": "passed",
        "existing": "passed",
        "repeat_upgrade": "no changes",
        "existing_rows": "preserved",
        "policies": "identical",
    }
    if any(migration.get(key) != value for key, value in expected.items()):
        raise ValueError("Migration acceptance incomplete")
    if (
        migration["source"]["kind"] != "released-day11-pg-dump"
        or migration["source"]["release_commit"] != "819061de39eb2adb0ce47b61d465cd0f7891a3c1"
        or migration["security_and_schema_converged"] is not True
        or set(migration["historical_data"])
        != {"vehicles", "remote_commands", "command_reports", "telemetry_samples", "outbox_events"}
        or any(
            migration["migration_identity"][key] is not False
            for key in (
                "rolsuper",
                "rolbypassrls",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
            )
        )
        or any(
            row["rows"] < 1 or len(row["tenant_row_counts"]) != 2
            for row in migration["historical_data"].values()
        )
        or migration["steps"][1]["schema_sha256"] != migration["steps"][2]["schema_sha256"]
    ):
        raise ValueError("Released-backup/non-superuser migration evidence incomplete")
    failure = reports["migration-failure-retry"]
    scale = reports["migration-scale-locks"]
    if (
        failure["rollback_complete"] is not True
        or failure["retry_succeeded"] is not True
        or failure["schema_before_sha256"] != failure["schema_after_failure_sha256"]
        or failure["data_before"] != failure["data_after_failure"]
        or failure["revision_before"] != failure["revision_after_failure"]
        or scale["postgres_lock_wait_observed"] is not True
        or scale["lock_timeout_rolled_back"] is not True
        or scale["data_preserved"] is not True
        or scale["runtime_read_write_transactions"] < 10
        or scale["rows"]["telemetry_samples"]["rows"] < 50000
    ):
        raise ValueError("Migration rollback/scale evidence incomplete")
    rls = reports["12a-rls"]
    if (
        rls["dedicated_roles"] != 6
        or any(
            rls[key] != "denied"
            for key in (
                "cross_tenant_read",
                "foreign_insert",
                "binding_modification",
                "runtime_ddl",
            )
        )
        or rls["cross_tenant_update"] != "zero rows"
    ):
        raise ValueError("RLS acceptance incomplete")
    policy = reports["12b-identity-matrix"]
    for kind in ("secret", "kms"):
        matrix = policy["configuration_matrix"][kind]
        if len(matrix) != 36 or sum(row["decision"] == "allow" for row in matrix) != 6:
            raise ValueError("Permission matrix acceptance incomplete")
    if policy["iam_enforcement_verified"] is not False:
        raise ValueError("Local evidence cannot claim real AWS enforcement")
    alerts = reports["12c-alert-lifecycle"]["alerts"]
    if len(alerts) != 5 or {row["alert"] for row in alerts} != ALERTS:
        raise ValueError("Five alert lifecycle records required")
    for row in alerts:
        firing, resolved = row["webhook_firing"], row["webhook_resolved"]
        if (
            row["prometheus"] != "FIRING"
            or firing["status"] != "firing"
            or resolved["status"] != "resolved"
            or firing["starts_at"] != resolved["starts_at"]
            or firing["received_at"] > resolved["received_at"]
        ):
            raise ValueError("Alert delivery/recovery evidence incomplete")
    recovery = reports["12d-restore"]
    if (
        not all(
            recovery[key] is True
            for key in (
                "sha256_verified",
                "identity_preserved",
                "dedup_preserved",
                "ack_order_preserved",
            )
        )
        or recovery["event_and_restore_audit"] != "passed"
    ):
        raise ValueError("Recovery acceptance incomplete")
    return {
        "status": "passed",
        "scope": "local-only",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "commit": os.environ.get("GITHUB_SHA", "local-working-tree"),
        "iam_enforcement_verified": False,
        "artifacts_sha256": digests,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path(".runtime-reports"))
    args = parser.parse_args()
    result = validate(args.directory)
    (args.directory / "day12-acceptance.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print("Day12 local acceptance: passed")


if __name__ == "__main__":
    main()
