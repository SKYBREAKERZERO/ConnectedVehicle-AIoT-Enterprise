"""Explicit migration-owner OTA operations. Never called with runtime credentials."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text

from connected_vehicle.ota.artifacts import verify_signature
from connected_vehicle.ota.device_proof import verify_boot
from connected_vehicle.ota.execution_contracts import (
    ClaimResult,
    ExecutionView,
    InstallationProof,
    SignedManifest,
)
from connected_vehicle.ota.publisher_keys import records
from connected_vehicle.ota.service import fingerprint
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import migration_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.management_identity import verify_migration_identity


async def operate(
    settings: Settings,
    action: str,
    tenant: str,
    operation: str,
    actor: str,
    reason: str,
    body: dict[str, Any],
) -> None:
    UUID(operation)
    if (
        not tenant.strip()
        or not 1 <= len(actor.strip()) <= 255
        or not 1 <= len(reason.strip()) <= 500
    ):
        raise ValueError("Explicit tenant, operator and reason required")
    if action not in {
        "bootstrap",
        "publisher-register",
        "publisher-revoke",
        "quarantine",
        "reconcile",
    }:
        raise ValueError("Unknown OTA management action")
    configured = migration_database_settings(settings)
    engine = create_database_engine(configured)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(
                lambda sync: verify_migration_identity(sync, configured.database_username)
            )
            await connection.execute(
                text("SELECT set_config('app.tenant_id',:tenant,true)"), {"tenant": tenant}
            )
            await connection.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                {"key": "ota-management:" + tenant},
            )
            previous = (
                (
                    await connection.execute(
                        text("SELECT * FROM ota_authority.management_audit WHERE operation=:op"),
                        {"op": operation},
                    )
                )
                .mappings()
                .first()
            )
            if previous:
                if (
                    previous["tenant_id"],
                    previous["action"],
                    previous["actor"],
                    previous["reason"],
                    previous["payload"],
                ) != (tenant, action, actor, reason, body):
                    raise ValueError("Management operation ID conflict")
                return
            if action == "bootstrap":
                if (
                    not re.fullmatch("[0-9a-f]{64}", body["sha256"])
                    or type(body["security_version"]) is not int
                    or body["security_version"] < 0
                ):
                    raise ValueError("Trusted bootstrap digest/counter required")
                target = (
                    (
                        await connection.execute(
                            text(
                                (
                                    "SELECT * FROM ecu_inventory WHERE "
                                    "tenant_id=:t AND vehicle_id=:v "
                                    "AND id=:e FOR UPDATE"
                                )
                            ),
                            {"t": tenant, "v": body["vehicle_id"], "e": body["ecu_id"]},
                        )
                    )
                    .mappings()
                    .one()
                )
                if await connection.scalar(
                    text(
                        "SELECT EXISTS(SELECT FROM ota_jobs WHERE tenant_id=:t AND "
                        "ecu_id=:e AND status IN ('verified','downloading','installing'))"
                    ),
                    {"t": tenant, "e": body["ecu_id"]},
                ):
                    raise ValueError("Reconcile outstanding execution before bootstrap")
                if (
                    target["bootstrap_confirmed"]
                    or target["security_version"] > body["security_version"]
                ):
                    raise ValueError(
                        "Bootstrap is immutable and cannot reset an existing trusted floor"
                    )
                await connection.execute(
                    text(
                        "INSERT INTO ota_authority.ecu_bootstrap VALUES(:t,:e,:v,:f,:s,:h,:a,:r,:o)"
                    ),
                    dict(
                        t=tenant,
                        e=body["ecu_id"],
                        v=body["vehicle_id"],
                        f=body["firmware_version"],
                        s=body["security_version"],
                        h=body["sha256"],
                        a=actor,
                        r=reason,
                        o=operation,
                    ),
                )
                await connection.execute(
                    text(
                        "UPDATE ecu_inventory SET "
                        "firmware_version=:f,security_version=:s,bootstrap_confirmed=true "
                        "WHERE tenant_id=:t AND id=:e"
                    ),
                    dict(
                        f=body["firmware_version"],
                        s=body["security_version"],
                        t=tenant,
                        e=body["ecu_id"],
                    ),
                )
            elif action == "publisher-register":
                for key, item in body["keys"].items():
                    existing = (
                        (
                            await connection.execute(
                                text(
                                    (
                                        "SELECT * FROM ota_authority.publisher_keys "
                                        "WHERE tenant_id=:t "
                                        "AND key_id=:k"
                                    )
                                ),
                                {"t": tenant, "k": key},
                            )
                        )
                        .mappings()
                        .first()
                    )
                    start, end = (
                        datetime.fromisoformat(item[name]) for name in ("not_before", "not_after")
                    )
                    if existing and (
                        existing["public_key"] != item["public_key"]
                        or existing["not_before"] != start
                        or existing["not_after"] != end
                        or existing["revoked"]
                    ):
                        raise ValueError(
                            "Publisher key ID cannot be rebound or revived; rotate using a new ID"
                        )
                    await connection.execute(
                        text(
                            "INSERT INTO ota_authority.publisher_keys "
                            "VALUES(:t,:k,:p,:s,:e,:r) ON CONFLICT DO NOTHING"
                        ),
                        dict(
                            t=tenant, k=key, p=item["public_key"], s=start, e=end, r=item["revoked"]
                        ),
                    )
            elif action == "publisher-revoke":
                updated = await connection.execute(
                    text(
                        "UPDATE ota_authority.publisher_keys SET revoked=true WHERE "
                        "tenant_id=:t AND key_id=:k"
                    ),
                    {"t": tenant, "k": body["key_id"]},
                )
                if updated.rowcount != 1:
                    raise ValueError("Publisher key not registered")
            else:
                job = (
                    (
                        await connection.execute(
                            text("SELECT * FROM ota_jobs WHERE tenant_id=:t AND id=:j FOR UPDATE"),
                            {"t": tenant, "j": body["job_id"]},
                        )
                    )
                    .mappings()
                    .one()
                )
                execution = (
                    (
                        await connection.execute(
                            text(
                                (
                                    "SELECT * FROM ota_executions WHERE tenant_id=:t AND id=:j FOR "
                                    "UPDATE"
                                )
                            ),
                            {"t": tenant, "j": job["id"]},
                        )
                    )
                    .mappings()
                    .one()
                )
                if job["status"] not in {"verified", "downloading", "installing"}:
                    raise ValueError(
                        "Only outstanding verified execution can be quarantined/reconciled"
                    )
                if action == "quarantine":
                    await connection.execute(
                        text(
                            "INSERT INTO ota_authority.claim_quarantines "
                            "VALUES(:t,:j,false,:op,CAST(:e AS jsonb))"
                        ),
                        dict(
                            t=tenant,
                            j=job["id"],
                            op=operation,
                            e=json.dumps(
                                dict(actor=actor, reason=reason, execution=dict(execution)),
                                default=str,
                            ),
                        ),
                    )
                    if execution["device_id"] is None:
                        await connection.execute(
                            text(
                                "UPDATE ota_jobs SET status='failed',updated_at=now() WHERE "
                                "tenant_id=:t AND id=:j"
                            ),
                            dict(t=tenant, j=job["id"]),
                        )
                        await connection.execute(
                            text(
                                "UPDATE ota_authority.claim_quarantines SET resolved=true WHERE "
                                "tenant_id=:t AND job_id=:j"
                            ),
                            dict(t=tenant, j=job["id"]),
                        )
                else:
                    quarantine = await connection.scalar(
                        text(
                            "SELECT NOT resolved FROM ota_authority.claim_quarantines WHERE "
                            "tenant_id=:t AND job_id=:j FOR UPDATE"
                        ),
                        {"t": tenant, "j": job["id"]},
                    )
                    if quarantine is not True:
                        raise ValueError(
                            "Quarantine and freeze the old device before reconciliation"
                        )
                    quarantine_time = await connection.scalar(
                        text(
                            "SELECT a.occurred_at FROM ota_authority.claim_quarantines q JOIN "
                            "ota_authority.management_audit a ON a.operation=q.operation "
                            "WHERE q.tenant_id=:t AND q.job_id=:j"
                        ),
                        dict(t=tenant, j=job["id"]),
                    )
                    proof = InstallationProof.model_validate(body["proof"])
                    if proof.booted_at < quarantine_time:
                        raise ValueError(
                            "Observe the device only after quarantine and physical/process fencing"
                        )
                    if (
                        abs((datetime.now(UTC) - proof.booted_at).total_seconds()) > 120
                        or not settings.ota_device_keys_file
                    ):
                        raise ValueError("Fresh independent observed-boot proof required")
                    claim = ClaimResult(
                        job=ExecutionView.model_validate(
                            {key: job[key] for key in ExecutionView.model_fields}
                        ),
                        device_id=execution["device_id"],
                        claim_token=execution["claim_token"],
                        manifest=SignedManifest.model_validate(execution["manifest"]),
                        signature=execution["signature"],
                        install_challenge=execution["install_challenge"],
                    )
                    verify_boot(Path(settings.ota_device_keys_file), claim, proof, observed=True)
                    candidate = claim.manifest
                    succeeded = (proof.sha256, proof.firmware_version, proof.security_version) == (
                        candidate.sha256,
                        candidate.version,
                        candidate.security_version,
                    )
                    if succeeded:
                        if job["status"] != "installing" or execution["report_sequence"] != 1:
                            raise ValueError(
                                "Cannot adopt success without acknowledged installing stage"
                            )
                        if not settings.ota_trusted_keys_file:
                            raise ValueError("Current publisher trust required for adopted success")
                        verify_signature(
                            Path(settings.ota_trusted_keys_file), candidate, execution["signature"]
                        )
                        trusted = await connection.scalar(
                            text(
                                "SELECT EXISTS(SELECT FROM "
                                "ota_authority.publisher_keys WHERE tenant_id=:t "
                                "AND key_id=:k AND NOT revoked AND "
                                "not_before<=now() AND not_after>now())"
                            ),
                            dict(t=tenant, k=candidate.key_id),
                        )
                        active = await connection.scalar(
                            text(
                                "SELECT status='active' FROM vehicles WHERE "
                                "tenant_id=:t AND id=:v FOR SHARE"
                            ),
                            dict(t=tenant, v=job["vehicle_id"]),
                        )
                        if not trusted or not active:
                            raise ValueError(
                                "Revoked publication or inactive vehicle remains quarantined"
                            )
                        applied = await connection.execute(
                            text(
                                "UPDATE ecu_inventory SET "
                                "firmware_version=:f,security_version=:s WHERE "
                                "tenant_id=:t AND id=:e AND security_version<:s"
                            ),
                            dict(
                                f=proof.firmware_version,
                                s=proof.security_version,
                                t=tenant,
                                e=job["ecu_id"],
                            ),
                        )
                        if applied.rowcount != 1:
                            raise ValueError(
                                "Observed candidate would regress/conflict with the installed floor"
                            )
                        report = dict(
                            event_id=operation,
                            claim_token=execution["claim_token"],
                            sequence=2,
                            status="succeeded",
                            occurred_at=proof.booted_at.isoformat(),
                            observed_sha256=proof.sha256,
                            failure_code=None,
                            installation_proof=body["proof"],
                        )
                        await connection.execute(
                            text(
                                "INSERT INTO ota_execution_reports "
                                "VALUES(:t,:id,:j,2,CAST(:p AS json),now())"
                            ),
                            dict(t=tenant, id=operation, j=job["id"], p=json.dumps(report)),
                        )
                        await connection.execute(
                            text(
                                "UPDATE ota_executions SET report_sequence=2 "
                                "WHERE tenant_id=:t AND id=:j"
                            ),
                            dict(t=tenant, j=job["id"]),
                        )
                        accepted = dict(
                            protocol="cv-management-reconcile/1",
                            manifest=candidate.model_dump(mode="json"),
                            ecu_id=job["ecu_id"],
                            vehicle_id=job["vehicle_id"],
                            report=report,
                            operation=operation,
                            actor=actor,
                            reason=reason,
                        )
                        await connection.execute(
                            text(
                                "INSERT INTO ota_authority.installation_receipts "
                                "VALUES(:t,:j,CAST(:p AS jsonb),:mac)"
                            ),
                            dict(
                                t=tenant,
                                j=job["id"],
                                p=json.dumps(accepted),
                                mac="management:" + operation,
                            ),
                        )
                    else:
                        old = (
                            (
                                await connection.execute(
                                    text(
                                        (
                                            "SELECT * FROM ota_authority.ecu_bootstrap "
                                            "WHERE tenant_id=:t AND "
                                            "ecu_id=:e"
                                        )
                                    ),
                                    {"t": tenant, "e": job["ecu_id"]},
                                )
                            )
                            .mappings()
                            .one()
                        )
                        known = (proof.sha256, proof.firmware_version, proof.security_version) == (
                            old["sha256"],
                            old["firmware_version"],
                            old["security_version"],
                        )
                        if not known:
                            known = bool(
                                await connection.scalar(
                                    text(
                                        "SELECT EXISTS(SELECT FROM "
                                        "ota_authority.installation_receipts "
                                        "WHERE tenant_id=:t AND payload->>'ecu_id'=:ecu "
                                        "AND payload->>'vehicle_id'=:vehicle "
                                        "AND payload->'manifest'->>'sha256'=:h AND "
                                        "payload->'manifest'->>'version'=:v AND "
                                        "payload->'manifest'->>'security_version'=:s)"
                                    ),
                                    dict(
                                        t=tenant,
                                        ecu=job["ecu_id"],
                                        vehicle=job["vehicle_id"],
                                        h=proof.sha256,
                                        v=proof.firmware_version,
                                        s=str(proof.security_version),
                                    ),
                                )
                            )
                        if not known:
                            raise ValueError(
                                "Observed bank is neither trusted baseline nor a known installed "
                                "bank"
                            )
                    await connection.execute(
                        text(
                            "UPDATE ota_jobs SET status=:s,updated_at=now() WHERE "
                            "tenant_id=:t AND id=:j"
                        ),
                        dict(s="succeeded" if succeeded else "failed", t=tenant, j=job["id"]),
                    )
                    await connection.execute(
                        text(
                            "UPDATE ota_authority.claim_quarantines SET "
                            "resolved=true,evidence=CAST(:p AS jsonb) WHERE tenant_id=:t AND "
                            "job_id=:j"
                        ),
                        dict(
                            p=json.dumps(
                                dict(
                                    proof=body["proof"],
                                    status="succeeded" if succeeded else "failed",
                                    device_id=execution["device_id"],
                                    job_id=job["id"],
                                )
                            ),
                            t=tenant,
                            j=job["id"],
                        ),
                    )
                    await connection.execute(
                        text(
                            "INSERT INTO ota_audit_events "
                            "VALUES(:t,:id,'job',:j,'reconcile',:a,:op,:hash,:r,now())"
                        ),
                        dict(
                            t=tenant,
                            id=str(uuid4()),
                            j=job["id"],
                            a=actor,
                            op=operation,
                            hash=fingerprint(body),
                            r=reason,
                        ),
                    )
            await connection.execute(
                text(
                    "INSERT INTO ota_authority.management_audit(operation,tenant_id,ac"
                    "tion,actor,reason,payload) VALUES(:o,:t,:a,:actor,:r,CAST(:p AS "
                    "jsonb))"
                ),
                dict(
                    o=operation,
                    t=tenant,
                    a=action,
                    actor=actor,
                    r=reason,
                    p=json.dumps(body, sort_keys=True),
                ),
            )
    finally:
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=["bootstrap", "publisher-register", "publisher-revoke", "quarantine", "reconcile"],
    )
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--body", type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.body.read_text(encoding="utf-8"))
    if args.action == "publisher-register":
        document = {"keys": records(args.body, args.tenant)}
    asyncio.run(
        operate(
            Settings(), args.action, args.tenant, args.operation, args.actor, args.reason, document
        )
    )
