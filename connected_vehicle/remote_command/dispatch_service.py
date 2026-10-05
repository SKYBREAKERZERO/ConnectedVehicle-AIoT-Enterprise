from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from connected_vehicle.remote_command.dispatching import (
    RemoteCommandDispatchAction,
    decide_remote_command_dispatch_action,
)
from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandId,
    RemoteCommandStatus,
)
from connected_vehicle.remote_command.persistence.repository import (
    SQLAlchemyRemoteCommandRepository,
)
from connected_vehicle.remote_command.publisher import (
    RemoteCommandPublisher,
)
from enterprise_platform.database.unit_of_work import (
    SQLAlchemyUnitOfWork,
)


class RemoteCommandDispatchError(RuntimeError):
    """Base error for remote-command dispatch processing."""


class RemoteCommandDispatchCommandNotFoundError(RemoteCommandDispatchError):
    """Raised when an SQS event references a missing command."""


class RemoteCommandDispatchOutcome(StrEnum):
    PUBLISHED = "published"
    EXPIRED = "expired"
    ALREADY_HANDLED = "already_handled"


@dataclass(frozen=True, slots=True)
class RemoteCommandDispatchResult:
    command: RemoteCommand
    outcome: RemoteCommandDispatchOutcome


@dataclass(frozen=True, slots=True)
class _PreparedDispatch:
    command: RemoteCommand
    outcome: RemoteCommandDispatchOutcome | None


class RemoteCommandDispatchService:
    """Advance and publish a remote command using short DB transactions."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        publisher: RemoteCommandPublisher,
    ) -> None:
        self._session_factory = session_factory
        self._publisher = publisher

    async def dispatch(
        self,
        command_id: RemoteCommandId,
        *,
        now: datetime | None = None,
    ) -> RemoteCommandDispatchResult:
        timestamp = self._resolve_timestamp(now)

        prepared = await self._prepare_for_publish(
            command_id,
            now=timestamp,
        )

        if prepared.outcome is not None:
            return RemoteCommandDispatchResult(
                command=prepared.command,
                outcome=prepared.outcome,
            )

        # Deliberately outside every database transaction.
        #
        # If this succeeds and the process crashes before SENT is
        # persisted, the command remains DISPATCHING and a later
        # SQS redelivery is allowed to publish it again.
        await self._publisher.publish(prepared.command)

        sent = await self._mark_sent(
            command_id,
            now=timestamp,
        )

        return RemoteCommandDispatchResult(
            command=sent,
            outcome=RemoteCommandDispatchOutcome.PUBLISHED,
        )

    async def _prepare_for_publish(
        self,
        command_id: RemoteCommandId,
        *,
        now: datetime,
    ) -> _PreparedDispatch:
        # At most two persisted forward transitions are required:
        #
        # REQUESTED -> QUEUED
        # QUEUED -> DISPATCHING
        #
        # A third iteration observes DISPATCHING and returns it
        # for publication.
        for _ in range(3):
            async with SQLAlchemyUnitOfWork(self._session_factory) as uow:
                repository = SQLAlchemyRemoteCommandRepository(uow.session)

                command = await repository.get_for_update(command_id)

                if command is None:
                    raise (
                        RemoteCommandDispatchCommandNotFoundError(
                            "Remote command referenced by the dispatch event was not found."
                        )
                    )

                action = decide_remote_command_dispatch_action(
                    command,
                    now=now,
                )

                if action is RemoteCommandDispatchAction.ACKNOWLEDGE:
                    return _PreparedDispatch(
                        command=command,
                        outcome=(RemoteCommandDispatchOutcome.ALREADY_HANDLED),
                    )

                if action is RemoteCommandDispatchAction.EXPIRE:
                    expired = command.transition_to(
                        RemoteCommandStatus.EXPIRED,
                        now=now,
                    )

                    await self._save_or_fail(
                        repository,
                        expired,
                    )

                    await uow.commit()

                    return _PreparedDispatch(
                        command=expired,
                        outcome=(RemoteCommandDispatchOutcome.EXPIRED),
                    )

                if action is RemoteCommandDispatchAction.QUEUE:
                    queued = command.transition_to(
                        RemoteCommandStatus.QUEUED,
                        now=now,
                    )

                    await self._save_or_fail(
                        repository,
                        queued,
                    )

                    await uow.commit()

                    continue

                if action is RemoteCommandDispatchAction.START_DISPATCH:
                    dispatching = command.transition_to(
                        RemoteCommandStatus.DISPATCHING,
                        now=now,
                    )

                    await self._save_or_fail(
                        repository,
                        dispatching,
                    )

                    await uow.commit()

                    return _PreparedDispatch(
                        command=dispatching,
                        outcome=None,
                    )

                if action is RemoteCommandDispatchAction.PUBLISH:
                    return _PreparedDispatch(
                        command=command,
                        outcome=None,
                    )

                raise RemoteCommandDispatchError(
                    f"Unsupported remote-command dispatch action: {action.value!r}."
                )

        raise RemoteCommandDispatchError("Remote command could not reach DISPATCHING state.")

    async def _mark_sent(
        self,
        command_id: RemoteCommandId,
        *,
        now: datetime,
    ) -> RemoteCommand:
        async with SQLAlchemyUnitOfWork(self._session_factory) as uow:
            repository = SQLAlchemyRemoteCommandRepository(uow.session)

            command = await repository.get_for_update(command_id)

            if command is None:
                raise (
                    RemoteCommandDispatchCommandNotFoundError(
                        "Remote command disappeared after successful publication."
                    )
                )

            if command.status is RemoteCommandStatus.DISPATCHING:
                transition_time = max(
                    now,
                    command.updated_at,
                )

                sent = command.transition_to(
                    RemoteCommandStatus.SENT,
                    now=transition_time,
                )

                await self._save_or_fail(
                    repository,
                    sent,
                )

                await uow.commit()

                return sent

            if (
                command.status
                in {
                    RemoteCommandStatus.SENT,
                    RemoteCommandStatus.ACKNOWLEDGED,
                }
                or command.is_terminal
            ):
                return command

            raise RemoteCommandDispatchError(
                "Remote command changed to an unexpected "
                "state after publication: "
                f"{command.status.value!r}."
            )

    @staticmethod
    async def _save_or_fail(
        repository: SQLAlchemyRemoteCommandRepository,
        command: RemoteCommand,
    ) -> None:
        saved = await repository.save(command)

        if not saved:
            raise RemoteCommandDispatchCommandNotFoundError(
                "Remote command disappeared while persisting a dispatch transition."
            )

    @staticmethod
    def _resolve_timestamp(
        now: datetime | None,
    ) -> datetime:
        timestamp = now if now is not None else datetime.now(UTC)

        if timestamp.tzinfo is None:
            raise ValueError("Remote command dispatch time must be timezone-aware.")

        return timestamp
