from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from connected_vehicle.ota.artifacts import ArtifactHandle, ArtifactVerifier, verify_signature
from connected_vehicle.ota.contracts import FirmwareRegistration
from connected_vehicle.ota.device_proof import verify_boot
from connected_vehicle.ota.execution_contracts import (
    ClaimRequest,
    ClaimResult,
    ExecutionECUView,
    ExecutionView,
    OTAReport,
    SignedManifest,
    VerificationRequest,
)
from connected_vehicle.ota.install_receipt import sign_receipt
from connected_vehicle.ota.models import (
    ECUModel,
    FirmwareModel,
    JobModel,
    OTAExecutionModel,
    OTAReportModel,
)
from connected_vehicle.ota.publisher_keys import public_key
from connected_vehicle.ota.service import OTAService, fingerprint
from enterprise_platform.errors.base import (
    ConflictError,
    DependencyUnavailableError,
    ResourceNotFoundError,
)


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
            await self.base.lock(session, tenant, "execution", identifier)
        row = await session.scalar(statement)
        if row is None:
            raise ResourceNotFoundError()
        return row

    async def policy(
        self, session: AsyncSession, tenant: str, job: str, key: str | None = None
    ) -> None:
        if not await session.scalar(
            text("SELECT public.ota_execution_ready(:tenant,:job)"), dict(tenant=tenant, job=job)
        ):
            raise ConflictError(
                "Active vehicle, trusted bootstrap and unquarantined claim required."
            )
        if key and not await session.scalar(
            text("SELECT public.ota_publisher_trusted(:tenant,:key)"), dict(tenant=tenant, key=key)
        ):
            raise ConflictError("Publisher key is unregistered, expired or revoked.")
        if key:
            try:
                configured = self.artifacts.settings.ota_trusted_keys_file
                if not configured:
                    raise ValueError("Missing publisher trust")
                public_key(Path(configured), tenant, key)
            except (OSError, KeyError, TypeError, ValueError) as exc:
                raise ConflictError(
                    "Publisher trust file is revoked, expired or unavailable."
                ) from exc

    async def transition(
        self,
        session: AsyncSession,
        job: JobModel,
        manifest: SignedManifest,
        signature: str,
        action: str,
        actor: str,
        operation: str,
        body: object,
        **values: object,
    ) -> None:
        path = self.artifacts.settings.ota_install_receipt_keys_file
        if not path:
            raise DependencyUnavailableError("OTA transition authority is not configured.")
        try:
            payload, mac = sign_receipt(
                Path(path),
                job.tenant_id,
                job_id=job.id,
                vehicle_id=job.vehicle_id,
                ecu_id=job.ecu_id,
                expected_status=job.status,
                manifest=manifest.model_dump(mode="json"),
                signature=signature,
                action=action,
                actor=actor,
                operation=operation,
                request_sha256=fingerprint(body),
                report_sha256=fingerprint(body),
                audit_id=str(uuid4()),
                reason="Authenticated OTA " + action,
                **values,
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise DependencyUnavailableError("OTA transition authority unavailable.") from exc
        await session.execute(
            text("SELECT public.ota_transition(:payload,:mac)"), dict(payload=payload, mac=mac)
        )
        await session.refresh(job)

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
                        text("public.ota_execution_ready(ota_jobs.tenant_id,ota_jobs.id)"),
                        text(
                            "public.ota_publisher_trusted(ota_jobs.tenant_id,ota_executions.ma"
                            "nifest->>'key_id')"
                        ),
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
            await self.policy(session, tenant, identifier, request.key_id)
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
        validated = await self.artifacts.fetch_file(manifest, request.signature)
        validated.close()
        async with self.base.transaction(tenant) as session:
            job = await self.job(session, tenant, identifier, lock=True)
            previous = await session.get(OTAExecutionModel, (tenant, identifier))
            if previous is not None:
                if previous.verification_sha256 != digest:
                    raise ConflictError("Concurrent verification conflicts.")
                return ExecutionView.model_validate(job)
            locked_ecu = await session.scalar(
                select(ECUModel).where(
                    ECUModel.tenant_id == tenant,
                    ECUModel.id == job.ecu_id,
                    ECUModel.vehicle_id == job.vehicle_id,
                )
            )
            assert locked_ecu is not None
            vehicle = await self.base.vehicle(session, tenant, job.vehicle_id)
            if job.status != "pending_verification" or vehicle.status != "active":
                raise ConflictError("Job or vehicle changed during verification.")
            if manifest.security_version <= locked_ecu.security_version:
                raise ConflictError("ECU security version advanced during verification.")
            await self.transition(
                session,
                job,
                manifest,
                request.signature,
                "verify",
                actor,
                str(request.operation_id),
                request.model_dump(mode="json"),
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
            await self.policy(session, tenant, identifier, manifest.key_id)
            recorded = await self.base.ecu(session, tenant, vehicle, ecu)
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
                await self.transition(
                    session,
                    job,
                    manifest,
                    execution.signature,
                    "claim",
                    device,
                    str(request.operation_id),
                    {"job_id": identifier, "device_id": device},
                    device_id=device,
                    claim_token=str(uuid4()),
                    install_challenge=str(uuid4()),
                )
                await session.refresh(execution)
            assert execution.claim_token is not None
            return ClaimResult(
                job=ExecutionView.model_validate(job),
                device_id=device,
                claim_token=UUID(execution.claim_token),
                manifest=manifest,
                signature=execution.signature,
                recorded_security_version=recorded.security_version,
                recorded_firmware_version=recorded.firmware_version,
                install_challenge=UUID(execution.install_challenge)
                if execution.install_challenge
                else None,
            )

    async def artifact(
        self,
        tenant: str,
        device: str,
        vehicle: str,
        ecu: str,
        identifier: str,
        token: str,
    ) -> ArtifactHandle:
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
            await self.policy(session, tenant, identifier, manifest.key_id)
        result = await self.artifacts.fetch_file(manifest, signature)
        try:
            async with self.base.transaction(tenant) as session:
                await self.policy(session, tenant, identifier, manifest.key_id)
            return result
        except BaseException:
            result.close()
            raise

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
            manifest = SignedManifest.model_validate(execution.manifest)
            await self.policy(session, tenant, identifier, manifest.key_id)
            if bool(report.failure_code) != (report.status == "failed"):
                raise ConflictError("Failure reports require a failure code.")
            if report.status == "succeeded":
                if not report.installation_proof or report.observed_sha256 != manifest.sha256:
                    raise ConflictError("Independent confirmed-boot proof required.")
                trust = self.artifacts.settings.ota_trusted_keys_file
                devices = self.artifacts.settings.ota_device_keys_file
                if not trust or not devices:
                    raise ConflictError("Installation trust is not configured.")
                claim = ClaimResult(
                    job=ExecutionView.model_validate(job),
                    device_id=device,
                    claim_token=report.claim_token,
                    manifest=manifest,
                    signature=execution.signature,
                    install_challenge=UUID(execution.install_challenge)
                    if execution.install_challenge
                    else None,
                )
                try:
                    verify_signature(Path(trust), manifest, execution.signature)
                    verify_boot(Path(devices), claim, report.installation_proof)
                except (OSError, ValueError, KeyError, InvalidSignature) as exc:
                    raise ConflictError("Untrusted installation/boot proof.") from exc
            await self.transition(
                session,
                job,
                manifest,
                execution.signature,
                "report",
                device,
                str(report.event_id),
                body,
                device_id=device,
                report=body,
                boot_verified=report.status == "succeeded",
            )
            return ExecutionView.model_validate(job)
