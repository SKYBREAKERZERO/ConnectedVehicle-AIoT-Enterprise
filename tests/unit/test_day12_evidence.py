from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from enterprise_platform.database.credentials import DATABASE_USERS, runtime_database_user
from scripts.day12_evidence import (
    ALERTS,
    CATALOG_SECTIONS,
    STAGES,
    json_sha,
    validate,
    write_evidence,
)

COMMIT = "1" * 40
RUN = "unit-evidence-run"
TIME = "2026-10-12T00:00:00+00:00"


def reports() -> dict[str, Any]:
    catalog: dict[str, Any] = {key: [] for key in CATALOG_SECTIONS}
    flags = {
        key: False
        for key in ("rolsuper", "rolbypassrls", "rolcreatedb", "rolcreaterole", "rolreplication")
    }
    catalog["roles"] = [
        {"rolname": role, **flags} for role in ("migration_owner", *DATABASE_USERS.values())
    ]
    new = deepcopy(catalog)
    binding = {"relname": "runtime_tenant_bindings", "owner": "migration_owner"}
    new["tables"].append(binding)
    data = {
        table: {"rows": count, "tenant_row_counts": [count // 2] * 2, "sha256": "a" * 64}
        for table, count in {
            "vehicles": 6,
            "remote_commands": 18,
            "command_reports": 36,
            "telemetry_samples": 12,
            "outbox_events": 18,
        }.items()
    }
    steps = [
        {
            "name": name,
            "revision": revision,
            "schema_sha256": json_sha(state),
            "started_at_utc": TIME,
            "finished_at_utc": TIME,
            "seconds": 0,
        }
        for name, revision, state in (
            ("restored", "a37e610c952d", catalog),
            ("upgraded", "b48f720da63e", new),
            ("repeat", "b48f720da63e", new),
        )
    ]
    summaries: list[dict[str, Any]] = []
    for tenant in ("matrix-a", "matrix-b"):
        summaries.append(
            {
                "tenant_id": tenant,
                "iam_policy_configuration": "passed",
                "kms_context_roundtrip": "passed",
                "iam_enforcement_verified": False,
                "roles": [
                    {
                        "runtime": runtime,
                        "login": runtime_database_user(runtime, tenant),
                        "contract": "passed",
                        "secret_arn": f"secret-{tenant}-{runtime}",
                    }
                    for runtime in DATABASE_USERS
                ],
            }
        )
    owners = {
        (summary["tenant_id"], row["runtime"]): row["secret_arn"]
        for summary in summaries
        for row in summary["roles"]
    }
    matrix = {
        "secret": [
            {
                "tenant": tenant,
                "runtime": runtime,
                "target": target,
                "decision": "allow" if target == own else "deny",
            }
            for (tenant, runtime), own in owners.items()
            for target in owners.values()
        ],
        "kms": [
            {
                "tenant": tenant,
                "runtime": runtime,
                "probe": probe,
                "decision": "allow" if probe == "own" else "deny",
            }
            for tenant, runtime in owners
            for probe in (
                "own",
                "foreign-secret",
                "missing-context",
                "wrong-service",
                "wrong-region",
                "wrong-key",
            )
        ],
    }
    return {
        "12a-migrations": {
            "fresh": "passed",
            "existing": "passed",
            "repeat_upgrade": "no changes",
            "existing_rows": "preserved",
            "policies": "identical",
            "source": {
                "kind": "released-day11-pg-dump",
                "release_commit": "819061de39eb2adb0ce47b61d465cd0f7891a3c1",
                "revision": "a37e610c952d",
                "backup_sha256": "b" * 64,
            },
            "security_and_schema_converged": True,
            "migration_identity": {"name": "migration_owner", **flags},
            "historical_data": data,
            "steps": steps,
            "catalog_before": catalog,
            "catalog_after": new,
            "schema_diff": {"tables": {"removed": [], "added": [binding]}},
            "relationship_violations": dict.fromkeys(
                (
                    "command_vehicle",
                    "report_command_vehicle",
                    "telemetry_vehicle",
                    "outbox_command",
                ),
                0,
            ),
        },
        "migration-failure-retry": {
            "rollback_complete": True,
            "retry_succeeded": True,
            "schema_before_sha256": json_sha(catalog),
            "schema_after_failure_sha256": json_sha(catalog),
            "data_before": data,
            "data_after_failure": data,
            "revision_before": "a37e610c952d",
            "revision_after_failure": "a37e610c952d",
            "retry_revision": "b48f720da63e",
        },
        "migration-scale-locks": {
            "postgres_lock_wait_observed": True,
            "lock_timeout_rolled_back": True,
            "data_preserved": True,
            "runtime_read_write_transactions": 10,
            "rows": {"telemetry_samples": {"rows": 50012}},
        },
        "migration-guards": {
            "concurrent_upgrade_exit_codes": [0, 0],
            "advisory_waiters_observed": 2,
            "shared_timeout_sqlstate": "57014",
            "autocommit_rejected": True,
            **dict.fromkeys(
                (
                    "data_preserved",
                    "timeout_rollback_complete",
                    "shared_settings_restored",
                    "advisory_lock_released",
                    "retry_succeeded",
                ),
                True,
            ),
        },
        "12a-rls": {
            "dedicated_roles": 6,
            "cross_tenant_read": "denied",
            "foreign_insert": "denied",
            "binding_modification": "denied",
            "runtime_ddl": "denied",
            "cross_tenant_update": "zero rows",
        },
        "credential-rotation": {
            "scope": "localstack-and-postgresql",
            "roles": 3,
            "iam_enforcement_verified": False,
            "failure_cases": [
                {"failure": method, "passwords_and_current_restored": True}
                for method in ("put_secret_value", "update_secret_version_stage")
            ],
            "explicit_recovery": True,
            "retry_succeeded": True,
            "journals_secret_free": True,
        },
        "12b-identity-matrix": {
            "configuration_matrix": matrix,
            "runtime_and_kms": summaries,
            "iam_enforcement_verified": False,
        },
        "12c-alert-lifecycle": {
            "alerts": [
                {
                    "alert": name,
                    "prometheus": "FIRING",
                    "webhook_firing": {"status": "firing", "starts_at": TIME, "received_at": 1},
                    "webhook_resolved": {"status": "resolved", "starts_at": TIME, "received_at": 2},
                }
                for name in sorted(ALERTS)
            ]
        },
        "12d-restore": {
            **dict.fromkeys(
                ("sha256_verified", "identity_preserved", "dedup_preserved", "ack_order_preserved"),
                True,
            ),
            "event_and_restore_audit": "passed",
        },
    }


def save(directory: Path, values: dict[str, Any]) -> None:
    for stage, record in values.items():
        record["_provenance"] = {
            "version": 2,
            "commit": COMMIT,
            "run_id": RUN,
            "generated_at_utc": TIME,
        }
        (directory / f"day12-{stage}.json").write_text(json.dumps(record))


def check(directory: Path) -> dict[str, Any]:
    return validate(directory, expected_commit=COMMIT, expected_run_id=RUN)


def test_complete_batch_is_accepted_with_all_file_digests(tmp_path: Path) -> None:
    save(tmp_path, reports())
    result = check(tmp_path)
    assert result["status"] == "passed" and result["run_id"] == RUN
    assert len(result["artifacts_sha256"]) == len(STAGES)


def test_privileged_catalog_rejected_even_with_matching_digests(tmp_path: Path) -> None:
    values = reports()
    migration = values["12a-migrations"]
    previous = migration["catalog_before"]["roles"][0]
    current = migration["catalog_after"]["roles"][0]
    current["rolsuper"] = True
    digest = json_sha(migration["catalog_after"])
    migration["steps"][1]["schema_sha256"] = digest
    migration["steps"][2]["schema_sha256"] = digest
    migration["schema_diff"]["roles"] = {"removed": [previous], "added": [current]}
    save(tmp_path, values)
    with pytest.raises(ValueError, match="privileged"):
        check(tmp_path)


def test_unscoped_artifacts_cannot_generate_acceptance(tmp_path: Path) -> None:
    save(tmp_path, reports())
    with pytest.raises(ValueError, match="DAY12_EVIDENCE_RUN_ID"):
        validate(tmp_path, expected_commit=COMMIT, expected_run_id="unscoped")


@pytest.mark.parametrize("kind", ["secret", "kms"])
def test_permission_swaps_with_same_allow_count_are_rejected(tmp_path: Path, kind: str) -> None:
    values = reports()
    rows = values["12b-identity-matrix"]["configuration_matrix"][kind]
    allowed = next(row for row in rows if row["decision"] == "allow")
    denied = next(row for row in rows if row["decision"] == "deny")
    allowed["decision"], denied["decision"] = "deny", "allow"
    save(tmp_path, values)
    with pytest.raises(ValueError):
        check(tmp_path)


@pytest.mark.parametrize("kind", ["secret", "kms"])
def test_duplicate_matrix_coordinates_are_rejected(tmp_path: Path, kind: str) -> None:
    values = reports()
    rows = values["12b-identity-matrix"]["configuration_matrix"][kind]
    rows[-1] = deepcopy(rows[-2])
    save(tmp_path, values)
    with pytest.raises(ValueError, match="duplicate"):
        check(tmp_path)


@pytest.mark.parametrize(
    "change", ["catalog", "diff", "revision", "relationships", "counts", "time"]
)
def test_migration_summary_cannot_hide_inconsistent_details(tmp_path: Path, change: str) -> None:
    values = reports()
    migration = values["12a-migrations"]
    if change == "catalog":
        migration["catalog_after"]["roles"][0]["rolsuper"] = True
    elif change == "diff":
        migration["schema_diff"] = {}
    elif change == "revision":
        migration["steps"][1]["revision"] = "unknown"
    elif change == "relationships":
        migration["relationship_violations"]["outbox_command"] = 1
    elif change == "counts":
        migration["historical_data"]["vehicles"]["tenant_row_counts"] = [1, 1]
    else:
        migration["steps"][0]["finished_at_utc"] = "2026-10-11T00:00:00+00:00"
    save(tmp_path, values)
    with pytest.raises(ValueError):
        check(tmp_path)


@pytest.mark.parametrize(
    "field,value", [("commit", "2" * 40), ("run_id", "earlier-run"), ("version", 1)]
)
def test_mixed_or_stale_batch_cannot_be_restamped(
    tmp_path: Path, field: str, value: object
) -> None:
    save(tmp_path, reports())
    path = tmp_path / "day12-12a-rls.json"
    record = json.loads(path.read_text())
    record["_provenance"][field] = value
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="Stale"):
        check(tmp_path)


def test_writer_records_actual_commit_and_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_SHA", COMMIT)
    monkeypatch.setenv("DAY12_EVIDENCE_RUN_ID", RUN)
    write_evidence("12a-rls", {"_provenance": {"commit": "forged"}}, tmp_path)
    record = json.loads((tmp_path / "day12-12a-rls.json").read_text())
    assert record["_provenance"]["commit"] == COMMIT
    assert record["_provenance"]["run_id"] == RUN
    assert not list(tmp_path.glob(".day12-evidence-*"))
