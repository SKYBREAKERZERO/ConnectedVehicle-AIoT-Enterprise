from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from connected_vehicle.ota.contracts import (
    ECURegistration,
    ECUResult,
    ECUView,
    FirmwareRegistration,
    FirmwareResult,
    FirmwareView,
    JobResult,
    JobView,
)
from connected_vehicle.ota.execution_contracts import ACTIVE_STATES
from connected_vehicle.ota.models import ECUModel, FirmwareModel, JobModel
from connected_vehicle.vehicle.persistence.models import VehicleModel
from enterprise_platform.database.tenant import set_tenant_scope
from enterprise_platform.errors.base import (
    ConflictError,
    InvalidRequestError,
    ResourceNotFoundError,
)


def fingerprint(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def operation_key(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 255 or any(ord(c) < 32 for c in value):
        raise InvalidRequestError(
            "A nonempty Idempotency-Key of at most 255 characters is required."
        )
    return value


def legacy_job(row: JobModel) -> JobView:
    if row.status not in {"pending_verification", "cancelled"}:
        raise ConflictError("Job opted into execution v2; query /v2/ota/jobs/" + row.id)
    return JobView.model_validate(row)


class OTAService:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    @asynccontextmanager
    async def transaction(self, tenant: str) -> AsyncIterator[AsyncSession]:
        try:
            async with self.sessions() as session, session.begin():
                await set_tenant_scope(session, tenant)
                await session.execute(text("SET LOCAL lock_timeout = '2s'"))
                await session.execute(text("SET LOCAL statement_timeout = '5s'"))
                yield session
        except IntegrityError as exc:
            raise ConflictError(
                "OTA ownership, compatibility or uniqueness constraint failed."
            ) from exc

    async def lock(self, session: AsyncSession, *parts: str) -> None:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
            {"key": json.dumps(["ota", *parts])},
        )

    async def vehicle(self, session: AsyncSession, tenant: str, vehicle: str) -> VehicleModel:
        row = await session.scalar(
            select(VehicleModel).where(VehicleModel.tenant_id == tenant, VehicleModel.id == vehicle)
        )
        if row is None:
            raise ResourceNotFoundError()
        return row

    async def ecu(self, session: AsyncSession, tenant: str, vehicle: str, ecu: str) -> ECUModel:
        await self.vehicle(session, tenant, vehicle)
        row = await session.scalar(
            select(ECUModel).where(
                ECUModel.tenant_id == tenant, ECUModel.vehicle_id == vehicle, ECUModel.id == ecu
            )
        )
        if row is None:
            raise ResourceNotFoundError()
        return row

    async def audit(
        self,
        session: AsyncSession,
        *,
        tenant: str,
        actor: str,
        resource: str,
        identifier: str,
        action: str,
        key: str,
        body: object,
        reason: str,
    ) -> None:
        if not actor.strip() or len(actor) > 255:
            raise InvalidRequestError("An authenticated actor is required.")
        await session.execute(
            text("""SELECT public.ota_append_intent_audit(
            :tenant,:id,:resource,:identifier,:action,:actor,:key,:hash,:reason)"""),
            dict(
                tenant=tenant,
                id=str(uuid4()),
                resource=resource,
                identifier=identifier,
                action=action,
                actor=actor,
                key=key,
                hash=fingerprint(body),
                reason=reason,
            ),
        )

    async def register_ecu(
        self,
        tenant: str,
        actor: str,
        vehicle: str,
        ecu: str,
        body: ECURegistration,
    ) -> ECUResult:
        async with self.transaction(tenant) as session:
            await self.vehicle(session, tenant, vehicle)
            await self.lock(session, tenant, "ecu", ecu)
            previous = await session.get(ECUModel, (tenant, ecu))
            if previous is not None:
                if previous.vehicle_id != vehicle or any(
                    getattr(previous, key) != value for key, value in body.model_dump().items()
                ):
                    raise ConflictError("ECU identity is immutable; registration conflicts.")
                return ECUResult(created=False, ecu=ECUView.model_validate(previous))
            row = ECUModel(
                tenant_id=tenant,
                id=ecu,
                vehicle_id=vehicle,
                **body.model_dump(),
                created_at=datetime.now(UTC),
                created_by=actor,
            )
            session.add(row)
            await session.flush()
            await self.audit(
                session,
                tenant=tenant,
                actor=actor,
                resource="ecu",
                identifier=ecu,
                action="register",
                key=ecu,
                body={"vehicle_id": vehicle, **body.model_dump()},
                reason="Inventory registration",
            )
            return ECUResult(created=True, ecu=ECUView.model_validate(row))

    async def list_ecus(self, tenant: str, vehicle: str, limit: int, after: str) -> list[ECUView]:
        async with self.transaction(tenant) as session:
            await self.vehicle(session, tenant, vehicle)
            rows = (
                await session.scalars(
                    select(ECUModel)
                    .where(
                        ECUModel.tenant_id == tenant,
                        ECUModel.vehicle_id == vehicle,
                        ECUModel.id > after,
                    )
                    .order_by(ECUModel.id)
                    .limit(limit)
                )
            ).all()
            return [ECUView.model_validate(row) for row in rows]

    async def get_ecu(self, tenant: str, vehicle: str, ecu: str) -> ECUView:
        async with self.transaction(tenant) as session:
            return ECUView.model_validate(await self.ecu(session, tenant, vehicle, ecu))

    async def register_firmware(
        self,
        tenant: str,
        actor: str,
        key: str,
        body: FirmwareRegistration,
    ) -> FirmwareResult:
        key = operation_key(key)
        async with self.transaction(tenant) as session:
            await self.lock(session, tenant, "release", key)
            previous = await session.scalar(
                select(FirmwareModel).where(
                    FirmwareModel.tenant_id == tenant, FirmwareModel.idempotency_key == key
                )
            )
            if previous is not None:
                if any(
                    getattr(previous, name) != value for name, value in body.model_dump().items()
                ):
                    raise ConflictError("Idempotency-Key belongs to different firmware metadata.")
                return FirmwareResult(created=False, release=FirmwareView.model_validate(previous))
            row = FirmwareModel(
                tenant_id=tenant,
                id=str(uuid4()),
                idempotency_key=key,
                **body.model_dump(),
                created_at=datetime.now(UTC),
                created_by=actor,
            )
            session.add(row)
            await session.flush()
            await self.audit(
                session,
                tenant=tenant,
                actor=actor,
                resource="release",
                identifier=row.id,
                action="register",
                key=key,
                body=body.model_dump(),
                reason="Unverified firmware metadata registration",
            )
            return FirmwareResult(created=True, release=FirmwareView.model_validate(row))

    async def get_firmware(self, tenant: str, release: str) -> FirmwareView:
        async with self.transaction(tenant) as session:
            row = await session.get(FirmwareModel, (tenant, release))
            if row is None:
                raise ResourceNotFoundError()
            return FirmwareView.model_validate(row)

    async def list_firmware(self, tenant: str, limit: int, after: str) -> list[FirmwareView]:
        async with self.transaction(tenant) as session:
            rows = (
                await session.scalars(
                    select(FirmwareModel)
                    .where(FirmwareModel.tenant_id == tenant, FirmwareModel.id > after)
                    .order_by(FirmwareModel.id)
                    .limit(limit)
                )
            ).all()
            return [FirmwareView.model_validate(row) for row in rows]

    async def create_job(
        self,
        tenant: str,
        actor: str,
        vehicle: str,
        ecu: str,
        release: str,
        key: str,
    ) -> JobResult:
        key = operation_key(key)
        async with self.transaction(tenant) as session:
            await self.lock(session, tenant, "job", key)
            target = await self.ecu(session, tenant, vehicle, ecu)
            firmware = await session.get(FirmwareModel, (tenant, release))
            if firmware is None:
                raise ResourceNotFoundError()
            previous = await session.scalar(
                select(JobModel).where(
                    JobModel.tenant_id == tenant, JobModel.idempotency_key == key
                )
            )
            if previous is not None:
                if (previous.vehicle_id, previous.ecu_id, previous.release_id) != (
                    vehicle,
                    ecu,
                    release,
                ):
                    raise ConflictError("Idempotency-Key belongs to a different OTA job.")
                return JobResult(created=False, job=legacy_job(previous))
            if (target.ecu_type, target.hardware_version) != (
                firmware.ecu_type,
                firmware.hardware_version,
            ):
                raise ConflictError("Firmware is incompatible with the ECU hardware.")
            if target.firmware_version == firmware.version:
                raise ConflictError("Firmware version is already recorded on this ECU.")
            if (await self.vehicle(session, tenant, vehicle)).status != "active":
                raise ConflictError("Only active vehicles can receive OTA jobs.")
            await self.lock(session, tenant, "ecu", ecu)
            active = await session.scalar(
                select(JobModel.id).where(
                    JobModel.tenant_id == tenant,
                    JobModel.ecu_id == ecu,
                    JobModel.status.in_(ACTIVE_STATES),
                )
            )
            if active is not None:
                raise ConflictError("ECU already has an outstanding OTA job.")
            now = datetime.now(UTC)
            row = JobModel(
                tenant_id=tenant,
                id=str(uuid4()),
                vehicle_id=vehicle,
                ecu_id=ecu,
                release_id=release,
                ecu_type=target.ecu_type,
                hardware_version=target.hardware_version,
                status="pending_verification",
                idempotency_key=key,
                created_at=now,
                updated_at=now,
                created_by=actor,
            )
            session.add(row)
            await session.flush()
            await self.audit(
                session,
                tenant=tenant,
                actor=actor,
                resource="job",
                identifier=row.id,
                action="create",
                key=key,
                body={"vehicle_id": vehicle, "ecu_id": ecu, "release_id": release},
                reason="OTA intent awaiting artifact verification",
            )
            return JobResult(created=True, job=JobView.model_validate(row))

    async def get_job(self, tenant: str, job: str) -> JobView:
        async with self.transaction(tenant) as session:
            row = await session.get(JobModel, (tenant, job))
            if row is None:
                raise ResourceNotFoundError()
            return legacy_job(row)

    async def list_jobs(
        self,
        tenant: str,
        vehicle: str,
        ecu: str,
        limit: int,
        after: str,
    ) -> list[JobView]:
        async with self.transaction(tenant) as session:
            await self.ecu(session, tenant, vehicle, ecu)
            rows = (
                await session.scalars(
                    select(JobModel)
                    .where(
                        JobModel.tenant_id == tenant,
                        JobModel.vehicle_id == vehicle,
                        JobModel.ecu_id == ecu,
                        JobModel.id > after,
                        JobModel.status.in_(("pending_verification", "cancelled")),
                    )
                    .order_by(JobModel.id)
                    .limit(limit)
                )
            ).all()
            return [JobView.model_validate(row) for row in rows]

    async def cancel_job(self, tenant: str, actor: str, job: str, key: str, reason: str) -> JobView:
        key = operation_key(key)
        async with self.transaction(tenant) as session:
            await self.lock(session, tenant, "cancel", key)
            await self.lock(session, tenant, "execution", job)
            row = await session.get(JobModel, (tenant, job))
            if row is None:
                raise ResourceNotFoundError()
            body = {"job_id": job, "reason": reason}
            await session.execute(
                text("""SELECT public.ota_cancel_pending(
                :tenant,:job,:actor,:key,:reason,:hash,:audit)"""),
                dict(
                    tenant=tenant,
                    job=job,
                    actor=actor,
                    key=key,
                    reason=reason,
                    hash=fingerprint(body),
                    audit=str(uuid4()),
                ),
            )
            await session.refresh(row)
            return JobView.model_validate(row)
