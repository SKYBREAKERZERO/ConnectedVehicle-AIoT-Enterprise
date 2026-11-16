"""AWS Staging DB bootstrap must bind all credentials to an exact tenant."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from database.provision_runtime_credentials import provision
from enterprise_platform.config.environment import AppEnvironment, CloudRuntime
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DATABASE_USERS, runtime_database_user


@pytest.mark.asyncio
async def test_tenant_credentials_never_fall_back_to_global_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = "staging-tenant-001"
    settings = Settings(
        app_env=AppEnvironment.STAGING,
        cloud_runtime=CloudRuntime.AWS,
        aws_endpoint_url=None,
        database_tenant_id=tenant,
        application_database_secret_id="/connected-vehicle/staging/database/application",
        outbox_database_secret_id="/connected-vehicle/staging/database/outbox",
        remote_command_database_secret_id="/connected-vehicle/staging/database/remote-command",
    )
    roles = {
        runtime: runtime_database_user(runtime, tenant)
        for runtime in DATABASE_USERS
    }
    for runtime, base in DATABASE_USERS.items():
        monkeypatch.setenv(f"{base.upper()}_PASSWORD", f"candidate-{runtime}-secure")
    prepare = AsyncMock()
    grants = AsyncMock()
    ready = AsyncMock(return_value=None)
    rotate = AsyncMock()

    @asynccontextmanager
    async def manager(_settings: Settings, _targets: Any) -> AsyncIterator[object]:
        yield object()

    with (
        patch("database.provision_runtime_credentials.AWSClientFactory") as factory,
        patch("database.provision_runtime_credentials.prepare_roles", prepare),
        patch("database.provision_runtime_credentials.grant_runtimes", grants),
        patch("database.provision_runtime_credentials.ready_version", ready),
        patch("database.provision_runtime_credentials.password_manager", manager),
        patch("database.provision_runtime_credentials.rotate", rotate),
    ):
        factory.return_value.secrets_manager.return_value = object()
        await provision(settings)

    assert all(role.endswith(roles[runtime].rsplit("__", 1)[1]) for runtime, role in roles.items())
    assert all(roles[runtime] != DATABASE_USERS[runtime] for runtime in DATABASE_USERS)
    assert set(rotate.await_args.args[2]) == set(roles.values())
    targets = rotate.await_args.args[1]
    assert {target.runtime: target.role for target in targets} == roles
    assert all(target.tenant == tenant for target in targets)
    assert {target.secret_id for target in targets} == {
        "/connected-vehicle/staging/database/application",
        "/connected-vehicle/staging/database/outbox",
        "/connected-vehicle/staging/database/remote-command",
    }
    prepare.assert_awaited_once_with(settings, roles)
    grants.assert_awaited_once_with(settings, roles, tenant)
    assert ready.await_count == 3
