from __future__ import annotations

from typing import Annotated, cast

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
)

from connected_vehicle.remote_command.service import (
    IssueRemoteCommandService,
)


def get_session_factory(
    request: Request,
) -> async_sessionmaker[AsyncSession]:
    session_factory = getattr(
        request.app.state,
        "session_factory",
        None,
    )

    if session_factory is None:
        raise RuntimeError("Database session factory is not initialized.")

    return cast(
        async_sessionmaker[AsyncSession],
        session_factory,
    )


def get_issue_remote_command_service(
    session_factory: Annotated[
        async_sessionmaker[AsyncSession],
        Depends(get_session_factory),
    ],
) -> IssueRemoteCommandService:
    return IssueRemoteCommandService(
        session_factory,
    )
