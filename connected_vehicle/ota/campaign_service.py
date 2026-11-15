"""Campaign control is atomic; artifact IO never holds a rollout transaction open."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from connected_vehicle.ota.artifacts import ArtifactVerifier, verify_signature
from connected_vehicle.ota.campaign_contracts import (
    CampaignAction,
    CampaignCreate,
    CampaignFreeze,
    CampaignTarget,
    CampaignView,
)
from connected_vehicle.ota.campaign_retry import CampaignLeaseLost, database_retry
from connected_vehicle.ota.execution_contracts import SignedManifest, VerificationRequest
from connected_vehicle.ota.execution_service import OTAExecutionService
from connected_vehicle.ota.install_receipt import load_key
from connected_vehicle.ota.publisher_keys import public_key
from connected_vehicle.ota.service import OTAService
from enterprise_platform.errors.base import (
    ConflictError,
    DependencyUnavailableError,
    ResourceNotFoundError,
)


class CampaignService:
    def __init__(self, base: OTAService, artifacts: ArtifactVerifier) -> None:
        self.base, self.artifacts = base, artifacts

    async def command(
        self,
        tenant: str,
        actor: str,
        identifier: str,
        command: str,
        operation: str,
        body: dict[str, Any],
        reason: str,
    ) -> CampaignView:
        path = self.artifacts.settings.ota_install_receipt_keys_file
        if not path:
            raise DependencyUnavailableError("Independent campaign authority is not configured")
        try:
            key_id, key = load_key(Path(path), tenant)
            payload = json.dumps(
                dict(
                    protocol="cv-campaign/1",
                    tenant_id=tenant,
                    key_id=key_id,
                    expires=int(time.time()) + 60,
                    request=dict(
                        campaign_id=identifier,
                        command=command,
                        operation_id=operation,
                        actor=actor,
                        reason=reason,
                        body=body,
                    ),
                ),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            mac = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise DependencyUnavailableError("Campaign authority unavailable") from exc

        async def execute() -> CampaignView:
            try:
                async with self.base.transaction(tenant) as session:
                    result = await session.scalar(
                        text("SELECT public.ota_campaign_command(:p,:m)"), dict(p=payload, m=mac)
                    )
                    return CampaignView.model_validate(result)
            except DBAPIError as exc:
                state = getattr(exc.orig, "sqlstate", None)
                if state == "P0002":
                    raise ResourceNotFoundError() from exc
                if state == "55000":
                    raise CampaignLeaseLost("Dispatcher lease expired") from exc
                if state in {"23514", "23505", "42501"}:
                    raise ConflictError(
                        "Campaign state, operation or execution policy conflicts"
                    ) from exc
                raise

        return await database_retry(execute)

    async def row(self, tenant: str, identifier: str) -> dict[str, Any]:
        async with self.base.transaction(tenant) as session:
            result = (
                (
                    await session.execute(
                        text("SELECT * FROM ota_campaigns WHERE tenant_id=:t AND id=:id"),
                        dict(t=tenant, id=identifier),
                    )
                )
                .mappings()
                .first()
            )
            if result is None:
                raise ResourceNotFoundError()
            return dict(result)

    async def get(self, tenant: str, identifier: str) -> CampaignView:
        async with self.base.transaction(tenant) as session:
            result = await session.scalar(
                text("SELECT public.ota_campaign_summary(:t,:id)"), dict(t=tenant, id=identifier)
            )
            if result is None:
                raise ResourceNotFoundError()
            return CampaignView.model_validate(result)

    async def listing(self, tenant: str, after: str, limit: int) -> list[CampaignView]:
        async with self.base.transaction(tenant) as session:
            rows = await session.scalars(
                text(
                    "SELECT public.ota_campaign_summary(:t,id) FROM ota_campaigns "
                    "WHERE tenant_id=:t AND id>:after ORDER BY id LIMIT :limit"
                ),
                dict(t=tenant, after=after, limit=limit),
            )
            return [CampaignView.model_validate(row) for row in rows]

    async def running(self, tenant: str, after: str) -> list[str]:
        async with self.base.transaction(tenant) as session:
            return list(
                await session.scalars(
                    text(
                        "SELECT id FROM ota_campaigns WHERE tenant_id=:t AND status='running' "
                        "AND id>:after ORDER BY id LIMIT 100"
                    ),
                    dict(t=tenant, after=after),
                )
            )

    async def prior(self, tenant: str, operation: str) -> bool:
        async with self.base.transaction(tenant) as session:
            return bool(
                await session.scalar(
                    text(
                        "SELECT EXISTS(SELECT FROM ota_campaign_events "
                        "WHERE tenant_id=:t AND operation_id=CAST(:op AS uuid))"
                    ),
                    dict(t=tenant, op=operation),
                )
            )

    async def targets(
        self, tenant: str, identifier: str, after: str, limit: int
    ) -> list[CampaignTarget]:
        await self.row(tenant, identifier)
        async with self.base.transaction(tenant) as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT t.ecu_id,t.vehicle_id,t.wave,t.job_id,t.dispatched,"
                        "t.firmware_version,t.security_version,j.status AS job_status "
                        "FROM ota_campaign_targets t LEFT JOIN ota_jobs j "
                        "ON j.tenant_id=t.tenant_id AND j.id=t.job_id "
                        "WHERE t.tenant_id=:t AND t.campaign_id=:id AND t.ecu_id>:after "
                        "ORDER BY t.ecu_id LIMIT :limit"
                    ),
                    dict(t=tenant, id=identifier, after=after, limit=limit),
                )
            ).mappings()
            return [CampaignTarget.model_validate(dict(row)) for row in rows]

    async def create(self, tenant: str, actor: str, request: CampaignCreate) -> CampaignView:
        release = await self.base.get_firmware(tenant, str(request.release_id))
        manifest = SignedManifest(
            tenant_id=tenant,
            release_id=release.id,
            ecu_type=release.ecu_type,
            hardware_version=release.hardware_version,
            version=release.version,
            artifact_bucket=release.artifact_bucket,
            artifact_key=release.artifact_key,
            artifact_version=release.artifact_version,
            sha256=release.sha256,
            size_bytes=release.size_bytes,
            security_version=request.security_version,
            key_id=request.key_id,
        )
        path = self.artifacts.settings.ota_trusted_keys_file
        if not path:
            raise DependencyUnavailableError("Publisher trust is not configured")
        try:
            if not await self.prior(tenant, str(request.operation_id)):
                verify_signature(Path(path), manifest, request.signature)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ConflictError("Campaign publisher signature is not trusted") from exc
        identifier = str(uuid5(NAMESPACE_URL, tenant + ":campaign:" + str(request.operation_id)))
        body = request.model_dump(
            mode="json", exclude={"operation_id", "release_id", "security_version", "key_id"}
        )
        body["manifest"] = manifest.model_dump(mode="json")
        return await self.command(
            tenant,
            actor,
            identifier,
            "create",
            str(request.operation_id),
            body,
            "Create signed rollout intent",
        )

    async def freeze(
        self, tenant: str, actor: str, identifier: str, request: CampaignFreeze
    ) -> CampaignView:
        row = await self.row(tenant, identifier)
        # Verified pinned bytes before snapshot creation; no open transaction during S3 IO.
        if not await self.prior(tenant, str(request.operation_id)):
            handle = await self.artifacts.fetch_file(
                SignedManifest.model_validate(row["manifest"]), row["signature"]
            )
            handle.close()
        return await self.command(
            tenant,
            actor,
            identifier,
            "freeze",
            str(request.operation_id),
            request.model_dump(mode="json", exclude={"operation_id"}),
            "Freeze explicit target set and wave assignment",
        )

    async def action(
        self, tenant: str, actor: str, identifier: str, action: str, request: CampaignAction
    ) -> CampaignView:
        await self.row(tenant, identifier)
        return await self.command(
            tenant, actor, identifier, action, str(request.operation_id), {}, request.reason
        )

    async def tick(
        self,
        tenant: str,
        actor: str,
        identifier: str,
        operation: str,
        *,
        dispatch_owner: str | None = None,
    ) -> CampaignView:
        row = await self.row(tenant, identifier)
        valid = False
        try:
            path = self.artifacts.settings.ota_trusted_keys_file
            if path:
                public_key(Path(path), tenant, row["manifest"]["key_id"])
                valid = True
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return await self.command(
            tenant,
            actor,
            identifier,
            "tick",
            operation,
            {
                "publisher_valid": valid,
                **({"dispatch_owner": dispatch_owner} if dispatch_owner else {}),
            },
            "Reconcile and evaluate rollout gate",
        )

    async def claim(self, tenant: str, owner: str, identifier: str | None = None) -> str | None:
        async def execute() -> str | None:
            async with self.base.transaction(tenant) as session:
                claimed = await session.scalar(
                    text("SELECT public.ota_campaign_claim(:t,CAST(:o AS uuid),:c,150)"),
                    dict(t=tenant, o=owner, c=identifier),
                )
                return str(claimed) if claimed is not None else None

        return await database_retry(execute)

    async def release(self, tenant: str, owner: str, identifier: str) -> None:
        async def execute() -> None:
            async with self.base.transaction(tenant) as session:
                await session.execute(
                    text("SELECT public.ota_campaign_release(:t,CAST(:o AS uuid),:c)"),
                    dict(t=tenant, o=owner, c=identifier),
                )

        await database_retry(execute)

    async def dispatch(self, tenant: str, identifier: str) -> CampaignView:
        owner = str(uuid4())
        if await self.claim(tenant, owner, identifier) is None:
            return await self.get(tenant, identifier)
        try:
            return await self._dispatch_claimed(tenant, identifier, owner)
        finally:
            await self.release(tenant, owner, identifier)

    async def _dispatch_claimed(self, tenant: str, identifier: str, owner: str) -> CampaignView:
        actor = "campaign-dispatcher"
        try:
            view = await self.tick(tenant, actor, identifier, str(uuid4()), dispatch_owner=owner)
        except CampaignLeaseLost:
            return await self.get(tenant, identifier)
        except ConflictError:
            current_view = await self.get(tenant, identifier)
            if current_view.status == "running":
                try:
                    return await self.command(
                        tenant,
                        actor,
                        identifier,
                        "pause",
                        str(uuid4()),
                        {"dispatch_owner": owner},
                        "dispatch_conflict_requires_reconciliation",
                    )
                except CampaignLeaseLost:
                    return await self.get(tenant, identifier)
            return current_view
        if view.status != "running":
            return view
        async with self.base.transaction(tenant) as session:
            pending = list(
                await session.scalars(
                    text(
                        "SELECT j.id FROM ota_campaign_targets t JOIN ota_jobs j "
                        "ON j.tenant_id=t.tenant_id AND j.id=t.job_id WHERE t.tenant_id=:t "
                        "AND t.campaign_id=:id AND t.dispatched "
                        "AND j.status='pending_verification' "
                        "ORDER BY t.ecu_id LIMIT 100"
                    ),
                    dict(t=tenant, id=identifier),
                )
            )
        row = await self.row(tenant, identifier)
        execution = OTAExecutionService(self.base.sessions, self.artifacts)
        for job in pending:
            current_row = await self.row(tenant, identifier)
            if (
                str(current_row["dispatch_owner"]) != owner
                or current_row["dispatch_until"] is None
                or current_row["dispatch_until"] <= datetime.now(UTC)
                or current_row["status"] != "running"
            ):
                return await self.get(tenant, identifier)
            try:
                await execution.verify(
                    tenant,
                    actor,
                    job,
                    VerificationRequest(
                        operation_id=uuid5(NAMESPACE_URL, "campaign-verify:" + job),
                        key_id=row["manifest"]["key_id"],
                        security_version=row["manifest"]["security_version"],
                        signature=row["signature"],
                    ),
                )
            except (ConflictError, DependencyUnavailableError, ValueError):
                current = await self.get(tenant, identifier)
                lease = await self.row(tenant, identifier)
                if current.status == "running" and str(lease["dispatch_owner"]) == owner:
                    try:
                        return await self.command(
                            tenant,
                            actor,
                            identifier,
                            "pause",
                            str(uuid4()),
                            {"dispatch_owner": owner},
                            "verification_failed_requires_reconciliation",
                        )
                    except CampaignLeaseLost:
                        return await self.get(tenant, identifier)
                return current
        return await self.get(tenant, identifier)
