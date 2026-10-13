"""Controlled role/Schema provisioning and recoverable Secrets publication."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from database.bootstrap_cluster import SQLDriver as SQLDriver
from database.credential_journal import RecoveryScope
from database.credential_rotation import Target, current_version, password_manager, recover, rotate
from database.schema_permissions import grant_runtimes, prepare_roles
from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DATABASE_USERS


async def provision(settings: Settings) -> None:
    passwords = {user: os.environ[f"{user.upper()}_PASSWORD"] for user in DATABASE_USERS.values()}
    if any(not password for password in passwords.values()) or len(set(passwords.values())) != 3:
        raise ValueError("Provide three nonempty, distinct runtime passwords")
    if any(
        credential is not None and credential.get_secret_value() in passwords.values()
        for credential in (
            settings.bootstrap_database_password,
            settings.migration_database_password,
        )
    ):
        raise ValueError("Runtime passwords must differ from management passwords")
    roles = dict(DATABASE_USERS)
    ids = {
        "application": settings.application_database_secret_id,
        "outbox": settings.outbox_database_secret_id,
        "remote-command": settings.remote_command_database_secret_id,
    }
    targets = [
        Target(
            runtime,
            role,
            ids[runtime]
            or f"{settings.database_secret_prefix}/{settings.app_env.value}/database/{runtime}",
        )
        for runtime, role in roles.items()
    ]
    client = AWSClientFactory(settings).secrets_manager()
    # Reject absent Terraform containers before role or Schema provisioning.
    for target in targets:
        await current_version(client, target.secret_id)
    await prepare_roles(settings, roles)
    await grant_runtimes(settings, roles)
    async with password_manager(settings, targets) as backend:
        await rotate(settings, targets, passwords, client, backend)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--recover", type=Path, help="Recover a sanitized credential-operation journal"
    )
    parser.add_argument(
        "--recover-scope",
        choices=("runtimes", "observability"),
        help="Explicitly select the independently configured recovery identity group",
    )
    args = parser.parse_args()
    if args.recover is None and args.recover_scope is not None:
        parser.error("--recover-scope requires --recover")
    settings = Settings()
    if args.recover is not None:
        scope: RecoveryScope = args.recover_scope or "runtimes"
        asyncio.run(
            recover(
                settings, args.recover, AWSClientFactory(settings).secrets_manager(), scope=scope
            )
        )
    else:
        asyncio.run(provision(settings))


if __name__ == "__main__":
    main()
