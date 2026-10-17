"""Explicit operator key registration; never uses runtime credentials or generates keys."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from sqlalchemy import text

from connected_vehicle.ota.install_receipt import load_key
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import migration_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.management_identity import verify_migration_identity


async def provision(settings: Settings, tenant: str, key_file: Path) -> None:
    key_id, secret = load_key(key_file, tenant)
    migration = migration_database_settings(settings)
    engine = create_database_engine(migration)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(
                lambda sync: verify_migration_identity(sync, migration.database_username)
            )
            # Immutable key IDs: rotating requires a new ID, never silently replacing a key.
            await connection.execute(
                text("""INSERT INTO ota_authority.receipt_keys
                (tenant_id,key_id,secret) VALUES (:tenant,:key,:secret) ON CONFLICT DO NOTHING"""),
                {"tenant": tenant, "key": key_id, "secret": secret},
            )
            existing = await connection.scalar(
                text("""SELECT secret FROM ota_authority.receipt_keys
                WHERE tenant_id=:tenant AND key_id=:key AND enabled"""),
                {"tenant": tenant, "key": key_id},
            )
            if existing != secret:
                raise ValueError("Receipt key ID is disabled or belongs to different material")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(provision(Settings(), args.tenant, args.key_file))
