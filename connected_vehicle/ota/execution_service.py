from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from connected_vehicle.ota.artifacts import ArtifactVerifier
from connected_vehicle.ota.contracts import FirmwareRegistration
from connected_vehicle.ota.execution_contracts import (
    ClaimRequest,
    ClaimResult,
    ExecutionECUView,
    ExecutionView,
    OTAReport,
    SignedManifest,
    VerificationRequest,
)
from connected_vehicle.ota.models import (
    ECUModel,
    FirmwareModel,
    JobModel,
    OTAExecutionModel,
    OTAReportModel,
)
from connected_vehicle.ota.service import OTAService, fingerprint
from enterprise_platform.errors.base import ConflictError, ResourceNotFoundError


class OTAExecutionService:
    def __init__(
        self, sessions: async_sessionmaker[AsyncSession], artifacts: ArtifactVerifier
    ) -> None:
        self.base = OTAService(sessions)
        self.artifacts = artifacts

    async def job(
        self,
        session: AsyncSession,
        tenant: str,
        identifier: str,
        *,
        vehicle: str | None = None,
        ecu: str | None = None,
        lock: bool = False,
    ) -> JobModel:
        statement = select(JobModel).where(JobModel.tenant_id == tenant, JobModel.id == identifier)
        if vehicle is not None:
            statement = statement.where(JobModel.vehicle_id == vehicle, JobModel.ecu_id == ecu)
        if lock:
            statement = statement.with_for_update()
        row = await session.scalar(statement)
        if row is None:
            raise ResourceNotFoundError()
        return row

    async def read(self, tenant: str, identifier: str) -> ExecutionView:
        async with self.base.transaction(tenant) as session:
            return ExecutionView.model_validate(await self.job(session, tenant, identifier))

    async def inventory(self, tenant: str, vehicle: str, ecu: str) -> ExecutionECUView:
        async with self.base.transaction(tenant) as session:
            return ExecutionECUView.model_validate(
                await self.base.ecu(session, tenant, vehicle, ecu)
            )

    async def available(
        self, tenant: str, device: str, vehicle: str, ecu: str
    ) -> list[ExecutionView]:
        async with self.base.transaction(tenant) as session:
            await self.base.ecu(session, tenant, vehicle, ecu)
            rows = (
                await session.scalars(
                    select(JobModel)
                    .join(
                        OTAExecutionModel,
                        (OTAExecutionModel.tenant_id == JobModel.tenant_id)
                        & (OTAExecutionModel.job_id == JobModel.id),
                    )
                    .where(
                        JobModel.tenant_id == tenant,
                        JobModel.vehicle_id == vehicle,
                        JobModel.ecu_id == ecu,
                        JobModel.status.in_(("verified", "downloading", "installing")),
                        (OTAExecutionModel.device_id.is_(None))
                        | (OTAExecutionModel.device_id == device),
                    )
                    .order_by(JobModel.created_at, JobModel.id)
                    .limit(1)
                )
            ).all()
            return [ExecutionView.model_validate(row) for row in rows]

    async def verify(
        self,
        tenant: str,
        actor: str,
        identifier: str,
        request: VerificationRequest,
    ) -> ExecutionView:
        digest = fingerprint(request.model_dump(mode="json"))
        async with self.base.transaction(tenant) as session:
            job = await self.job(session, tenant, identifier)
            previous = await session.get(OTAExecutionModel, (tenant, identifier))
            if previous is not None:
                if previous.verification_sha256 != digest:
                    raise ConflictError("Verification parameters are immutable.")
                return ExecutionView.model_validate(job)
            if job.status != "pending_verification":
                raise ConflictError("Job is not awaiting verification.")
            release = await session.get(FirmwareModel, (tenant, job.release_id))
            assert release is not None
            ecu = await self.base.ecu(session, tenant, job.vehicle_id, job.ecu_id)
            if (
                request.security_version <= ecu.security_version
                or release.version == ecu.firmware_version
            ):
                raise ConflictError("Firmware violates the ECU anti-rollback floor.")
            manifest = SignedManifest(
                **FirmwareRegistration.model_validate(release).model_dump(),
                tenant_id=tenant,
                release_id=UUID(release.id),
                key_id=request.key_id,
                security_version=request.security_version,
            )
        # Never hold a row lock/transaction while reading an external object.
        await self.artifacts.fetch(manifest, request.signature)
        async with self.base.transaction(tenant) as session:
            job = await self.job(session, tenant, identifier, lock=True)
            previous = await session.get(OTAExecutionModel, (tenant, identifier))
            if previous is not None:
                if previous.verification_sha256 != digest:
                    raise ConflictError("Concurrent verification conflicts.")
                return ExecutionView.model_validate(job)
            locked_ecu = await session.scalar(
                select(ECUModel)
                .where(
                    ECUModel.tenant_id == tenant,
                    ECUModel.id == job.ecu_id,
                    ECUModel.vehicle_id == job.vehicle_id,
                )
                .with_for_update()
            )
            assert locked_ecu is not None
            vehicle = await self.base.vehicle(session, tenant, job.vehicle_id)
            if job.status != "pending_verification" or vehicle.status != "active":
                raise ConflictError("Job or vehicle changed during verification.")
            if manifest.security_version <= locked_ecu.security_version:
                raise ConflictError("ECU security version advanced during verification.")
            session.add(
                OTAExecutionModel(
                    tenant_id=tenant,
                    job_id=identifier,
                    release_id=job.release_id,
                    verification_operation=str(request.operation_id),
                    verification_sha256=digest,
                    manifest=manifest.model_dump(mode="json"),
                    signature=request.signature,
                    verified_at=datetime.now(UTC),
                    report_sequence=0,
                )
            )
            job.status, job.updated_at = "verified", datetime.now(UTC)
            await self.base.audit(
                session,
                tenant=tenant,
                actor=actor,
                resource="job",
                identifier=identifier,
                action="verify",
                key=str(request.operation_id),
                body=request.model_dump(mode="json"),
                reason="Pinned bytes and trusted Ed25519 manifest verified",
            )
            return ExecutionView.model_validate(job)

    async def claim(
        self,
        tenant: str,
        device: str,
        vehicle: str,
        ecu: str,
        identifier: str,
        request: ClaimRequest,
    ) -> ClaimResult:
        async with self.base.transaction(tenant) as session:
            job = await self.job(session, tenant, identifier, vehicle=vehicle, ecu=ecu, lock=True)
            execution = await session.get(OTAExecutionModel, (tenant, identifier))
            if execution is None:
                raise ConflictError("Only verified firmware may be claimed.")
            manifest = SignedManifest.model_validate(execution.manifest)
            if execution.device_id is not None:
                if execution.device_id != device or execution.claim_operation != str(
                    request.operation_id
                ):
                    raise ConflictError("Job already belongs to another device claim.")
            else:
                target = await self.base.ecu(session, tenant, vehicle, ecu)
                owned = await self.base.vehicle(session, tenant, vehicle)
                if (
                    job.status != "verified"
                    or owned.status != "active"
                    or manifest.security_version <= target.security_version
                ):
                    raise ConflictError("Job is no longer eligible for device delivery.")
                execution.device_id, execution.claim_operation = device, str(request.operation_id)
                execution.claim_token = str(uuid4())
                job.status, job.updated_at = "downloading", datetime.now(UTC)
                await self.base.audit(
                    session,
                    tenant=tenant,
                    actor=device,
                    resource="job",
                    identifier=identifier,
                    action="claim",
                    key=str(request.operation_id),
                    body={"job_id": identifier, "device_id": device},
                    reason="Device-bound claim retained until execution is reconciled",
                )
            assert execution.claim_token is not None
            return ClaimResult(
                job=ExecutionView.model_validate(job),
                device_id=device,
                claim_token=UUID(execution.claim_token),
                manifest=manifest,
                signature=execution.signature,
            )

    async def artifact(
        self,
        tenant: str,
        device: str,
        vehicle: str,
        ecu: str,
        identifier: str,
        token: str,
    ) -> bytes:
        async with self.base.transaction(tenant) as session:
            job = await self.job(session, tenant, identifier, vehicle=vehicle, ecu=ecu)
            execution = await session.get(OTAExecutionModel, (tenant, identifier))
            if (
                execution is None
                or execution.device_id != device
                or execution.claim_token != token
                or job.status not in {"downloading", "installing"}
            ):
                raise ConflictError("Stale or unauthorized artifact claim.")
            manifest = SignedManifest.model_validate(execution.manifest)
            signature = execution.signature
        return await self.artifacts.fetch(manifest, signature)

    async def report(
        self,
        tenant: str,
        device: str,
        vehicle: str,
        ecu: str,
        identifier: str,
        report: OTAReport,
    ) -> ExecutionView:
        async with self.base.transaction(tenant) as session:
            job = await self.job(session, tenant, identifier, vehicle=vehicle, ecu=ecu, lock=True)
            execution = await session.get(OTAExecutionModel, (tenant, identifier))
            if (
                execution is None
                or execution.device_id != device
                or execution.claim_token != str(report.claim_token)
            ):
                raise ConflictError("Stale or unauthorized execution report.")
            body = report.model_dump(mode="json")
            previous = await session.get(OTAReportModel, (tenant, str(report.event_id)))
            if previous is not None:
                if previous.job_id != identifier or previous.payload != body:
                    raise ConflictError("Report identity belongs to a different payload.")
                return ExecutionView.model_validate(job)
            if report.sequence != execution.report_sequence + 1:
                raise ConflictError("Report sequence has a gap or regressed.")
            if execution.report_sequence:
                prior = await session.scalar(
                    select(OTAReportModel).where(
                        OTAReportModel.tenant_id == tenant,
                        OTAReportModel.job_id == identifier,
                        OTAReportModel.sequence == execution.report_sequence,
                    )
                )
                assert prior is not None
                if report.occurred_at < datetime.fromisoformat(str(prior.payload["occurred_at"])):
                    raise ConflictError("Report timestamp regressed behind an acknowledged stage.")
            if report.occurred_at < job.created_at or report.occurred_at > datetime.now(
                UTC
            ) + timedelta(minutes=5):
                raise ConflictError("Report timestamp is outside the execution window.")
            if (
                (report.status == "installing" and job.status != "downloading")
                or (report.status == "succeeded" and job.status != "installing")
                or (report.status == "failed" and job.status not in {"downloading", "installing"})
            ):
                raise ConflictError("Execution state transition is invalid.")
            if bool(report.failure_code) != (report.status == "failed"):
                raise ConflictError("Only failed reports require a failure code.")
            manifest = SignedManifest.model_validate(execution.manifest)
            if report.status == "succeeded":
                if report.observed_sha256 != manifest.sha256:
                    raise ConflictError(
                        "Installed image digest does not match the verified artifact."
                    )
                target = await session.scalar(
                    select(ECUModel)
                    .where(
                        ECUModel.tenant_id == tenant,
                        ECUModel.vehicle_id == vehicle,
                        ECUModel.id == ecu,
                    )
                    .with_for_update()
                )
                assert target is not None
                if manifest.security_version <= target.security_version:
                    raise ConflictError("Installed security counter would regress.")
                target.firmware_version, target.security_version = (
                    manifest.version,
                    manifest.security_version,
                )
            job.status, job.updated_at = report.status, datetime.now(UTC)
            execution.report_sequence = report.sequence
            session.add(
                OTAReportModel(
                    tenant_id=tenant,
                    id=str(report.event_id),
                    job_id=identifier,
                    sequence=report.sequence,
                    payload=body,
                    received_at=datetime.now(UTC),
                )
            )
            await self.base.audit(
                session,
                tenant=tenant,
                actor=device,
                resource="job",
                identifier=identifier,
                action="report",
                key=str(report.event_id),
                body=body,
                reason="Authenticated device execution report",
            )
            return ExecutionView.model_validate(job)
