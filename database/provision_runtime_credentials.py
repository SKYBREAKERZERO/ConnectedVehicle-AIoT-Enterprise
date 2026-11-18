"""Controlled role/Schema provisioning and recoverable Secrets publication."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from database.bootstrap_cluster import SQLDriver as SQLDriver
from database.credential_journal import RecoveryScope, expected_targets
from database.credential_rotation import (
    Target,
    password_manager,
    ready_version,
    recover,
    retire,
    rotate,
)
from database.schema_permissions import grant_runtimes, prepare_roles
from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DATABASE_USERS, runtime_database_user


async def provision(settings: Settings) -> None:
    """Provision the exact pinned tenant roles/Secrets, never global fallback roles."""
    roles = {
        runtime: runtime_database_user(runtime, settings.database_tenant_id)
        for runtime in DATABASE_USERS
    }
    passwords = {
        roles[runtime]: os.environ[f"{base.upper()}_PASSWORD"]
        for runtime, base in DATABASE_USERS.items()
    }
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
    targets = [
        Target(target.runtime, target.role, target.secret_id, target.tenant)
        for target in expected_targets(settings, "runtimes")
    ]
    if {target.role for target in targets} != set(passwords):
        raise ValueError("Credential target roles differ from tenant-bound passwords")
    client = AWSClientFactory(settings).secrets_manager()
    # Every Secret container must exist before role, grant or password changes.
    for target in targets:
        await ready_version(client, target.secret_id)
    await prepare_roles(settings, roles)
    await grant_runtimes(settings, roles, settings.database_tenant_id)
    async with password_manager(settings, targets) as backend:
        await rotate(settings, targets, passwords, client, backend)


def main() -> None:
    parser = argparse.ArgumentParser()
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument(
        "--recover", type=Path, help="Recover a sanitized credential-operation journal"
    )
    operation.add_argument("--retire", type=Path, help="Retire owned Pending on a terminal journal")
    parser.add_argument(
        "--recover-scope",
        "--scope",
        choices=("runtimes", "observability"),
        help="Explicitly select the independently configured recovery identity group",
    )
    args = parser.parse_args()
    if args.recover is None and args.retire is None and args.recover_scope is not None:
        parser.error("--scope requires --recover or --retire")
    settings = Settings()
    if args.recover is not None or args.retire is not None:
        scope: RecoveryScope = args.recover_scope or "runtimes"
        asyncio.run(
            (recover if args.recover is not None else retire)(
                settings,
                args.recover or args.retire,
                AWSClientFactory(settings).secrets_manager(),
                scope=scope,
            )
        )
    else:
        asyncio.run(provision(settings))


if __name__ == "__main__":
    main()
