"""Check every required local acceptance artifact and publish a sanitized manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from enterprise_platform.database.credentials import DATABASE_USERS, runtime_database_user

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
    "migration-guards",
)
CATALOG_SECTIONS = {
    "tables",
    "columns",
    "indexes",
    "constraints",
    "functions",
    "policies",
    "table_grants",
    "column_grants",
    "function_grants",
    "schema_grants",
    "database_grants",
    "default_grants",
    "roles",
    "memberships",
    "sequences",
}
LEGACY = "a37e610c952d"
HEAD = "b48f720da63e"


def source_commit() -> str:
    commit = (
        os.environ.get("GITHUB_SHA")
        or subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1], text=True
        ).strip()
    )
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("Evidence requires a full commit SHA")
    return commit


def write_evidence(stage: str, result: dict[str, Any], directory: Path) -> None:
    if re.fullmatch(r"[a-z0-9-]+", stage) is None:
        raise ValueError("Invalid evidence stage")
    record = dict(
        result,
        _provenance={
            "version": 2,
            "commit": source_commit(),
            "run_id": os.environ.get("DAY12_EVIDENCE_RUN_ID", "unscoped"),
            "generated_at_utc": datetime.now(UTC).isoformat(),
        },
    )
    directory.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory, prefix=".day12-evidence-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(record, stream, indent=2, allow_nan=False)
            stream.write("\n")
        os.replace(temporary, directory / f"day12-{stage}.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def json_sha(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Evidence timestamp must include a timezone")
    return parsed.astimezone(UTC)


def catalog_changes(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    changes = {}
    for section, rows in before.items():
        old = {json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows}
        new = {json.dumps(row, sort_keys=True, separators=(",", ":")) for row in after[section]}
        if old != new:
            changes[section] = {
                "removed": [json.loads(row) for row in sorted(old - new)],
                "added": [json.loads(row) for row in sorted(new - old)],
            }
    return changes


def validate_catalog(migration: dict[str, Any]) -> None:
    steps = migration["steps"]
    before, after = migration["catalog_before"], migration["catalog_after"]
    if (
        set(before) != CATALOG_SECTIONS
        or set(after) != CATALOG_SECTIONS
        or [row["name"] for row in steps] != ["restored", "upgraded", "repeat"]
        or [row["revision"] for row in steps] != [LEGACY, HEAD, HEAD]
        or steps[0]["schema_sha256"] != json_sha(before)
        or steps[1]["schema_sha256"] != json_sha(after)
        or steps[2]["schema_sha256"] != json_sha(after)
        or migration["schema_diff"] != catalog_changes(before, after)
        or set(migration["relationship_violations"])
        != {"command_vehicle", "report_command_vehicle", "telemetry_vehicle", "outbox_command"}
        or any(value != 0 for value in migration["relationship_violations"].values())
        or migration["source"]["revision"] != LEGACY
        or re.fullmatch(r"[0-9a-f]{64}", migration["source"]["backup_sha256"]) is None
    ):
        raise ValueError("Catalog/digest/revision/relationship evidence inconsistent")
    for step in steps:
        if (
            timestamp(step["started_at_utc"]) > timestamp(step["finished_at_utc"])
            or not math.isfinite(step["seconds"])
            or step["seconds"] < 0
        ):
            raise ValueError("Migration step timing invalid")
    for catalog in (before, after):
        roles = {row["rolname"]: row for row in catalog["roles"]}
        if set(roles) != {"migration_owner", *DATABASE_USERS.values()} or catalog["memberships"]:
            raise ValueError("Migration fixture role boundary invalid")
        if any(
            row[key] is not False
            for row in roles.values()
            for key in (
                "rolsuper",
                "rolbypassrls",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
            )
        ):
            raise ValueError("Catalog contains privileged migration/runtime roles")
    if migration["migration_identity"]["name"] != "migration_owner":
        raise ValueError("Unexpected migration identity")
    for data in migration["historical_data"].values():
        counts = data["tenant_row_counts"]
        if (
            len(counts) != 2
            or any(type(count) is not int or count < 1 for count in counts)
            or sum(counts) != data["rows"]
            or re.fullmatch(r"[0-9a-f]{64}", data["sha256"]) is None
        ):
            raise ValueError("Historical tenant/data digest evidence invalid")


def validate_matrix(policy: dict[str, Any]) -> None:
    owners = {}
    summaries = policy["runtime_and_kms"]
    if len(summaries) != 2 or len({row["tenant_id"] for row in summaries}) != 2:
        raise ValueError("Two distinct permission-matrix tenants required")
    for summary in summaries:
        roles = summary["roles"]
        if (
            len(roles) != 3
            or {row["runtime"] for row in roles} != set(DATABASE_USERS)
            or summary["iam_policy_configuration"] != "passed"
            or summary["kms_context_roundtrip"] != "passed"
            or summary["iam_enforcement_verified"] is not False
        ):
            raise ValueError("Runtime/KMS verification incomplete")
        for row in roles:
            pair = (summary["tenant_id"], row["runtime"])
            if (
                row["login"] != runtime_database_user(row["runtime"], summary["tenant_id"])
                or row["contract"] != "passed"
            ):
                raise ValueError("Runtime login ownership mismatch")
            owners[pair] = row["secret_arn"]
    targets = set(owners.values())
    if len(targets) != 6:
        raise ValueError("Runtime secrets must be distinct")
    for kind in ("secret", "kms"):
        rows = policy["configuration_matrix"][kind]
        probes = (
            targets
            if kind == "secret"
            else {
                "own",
                "foreign-secret",
                "missing-context",
                "wrong-service",
                "wrong-region",
                "wrong-key",
            }
        )
        expected = {(tenant, runtime, target) for tenant, runtime in owners for target in probes}
        seen = set()
        for row in rows:
            identity = (row["tenant"], row["runtime"])
            target = row["target" if kind == "secret" else "probe"]
            key = (*identity, target)
            if key not in expected or key in seen:
                raise ValueError("Missing/duplicate/foreign permission-matrix coordinate")
            seen.add(key)
            own = target == (owners[identity] if kind == "secret" else "own")
            if row["decision"] != ("allow" if own else "deny"):
                raise ValueError("Cross-identity or invalid-context permission allowed")
        if seen != expected:
            raise ValueError("Permission matrix coordinates incomplete")


def validate(
    directory: Path, *, expected_commit: str | None = None, expected_run_id: str | None = None
) -> dict[str, Any]:
    commit = expected_commit or source_commit()
    run_id = expected_run_id or os.environ.get("DAY12_EVIDENCE_RUN_ID")
    if not run_id or run_id == "unscoped":
        raise ValueError("Set DAY12_EVIDENCE_RUN_ID for the complete acceptance run")
    reports = {}
    digests = {}
    for stage in STAGES:
        path = directory / f"day12-{stage}.json"
        data = path.read_bytes()
        reports[stage] = json.loads(data)
        provenance = reports[stage].get("_provenance", {})
        if (
            provenance.get("version") != 2
            or provenance.get("commit") != commit
            or provenance.get("run_id") != run_id
        ):
            raise ValueError(f"Stale/mixed/unscoped evidence: {stage}")
        timestamp(provenance["generated_at_utc"])
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
    validate_catalog(migration)
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
    guards = reports["migration-guards"]
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
        or failure["retry_revision"] != HEAD
        or failure["revision_before"] != LEGACY
        or failure["data_before"] != migration["historical_data"]
        or failure["schema_before_sha256"] != migration["steps"][0]["schema_sha256"]
        or guards["concurrent_upgrade_exit_codes"] != [0, 0]
        or guards["advisory_waiters_observed"] != 2
        or guards["shared_timeout_sqlstate"] != "57014"
        or guards["autocommit_rejected"] is not True
        or any(
            guards[key] is not True
            for key in (
                "data_preserved",
                "timeout_rollback_complete",
                "shared_settings_restored",
                "advisory_lock_released",
                "retry_succeeded",
            )
        )
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
    validate_matrix(policy)
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
        "evidence_version": 2,
        "run_id": run_id,
        "scope": "local-only",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "commit": commit,
        "iam_enforcement_verified": False,
        "artifacts_sha256": digests,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path(".runtime-reports"))
    parser.add_argument("--commit", help="Trusted checkout SHA for downloaded CI artifacts")
    parser.add_argument("--run-id", help="Trusted workflow run ID:attempt, or local batch ID")
    args = parser.parse_args()
    result = validate(args.directory, expected_commit=args.commit, expected_run_id=args.run_id)
    (args.directory / "day12-acceptance.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print("Day12 local acceptance: passed")


if __name__ == "__main__":
    main()
