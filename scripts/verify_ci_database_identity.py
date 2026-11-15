"""Prove the shared CI default cannot authenticate or inherit management credentials."""

from __future__ import annotations

import asyncio
import os

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.engine import create_database_engine


async def verify() -> None:
    if any(name.startswith(("MIGRATION_DATABASE_", "BOOTSTRAP_DATABASE_")) for name in os.environ):
        raise ValueError("management credentials leaked into the runtime step")
    settings = Settings()
    if settings.database_username != "app_user":
        raise ValueError("implicit CI identity must be the restricted application role")
    engine = create_database_engine(settings)
    try:
        try:
            async with engine.connect():
                pass
        except Exception as exc:
            # Accept only PostgreSQL invalid_password, never network/timeout failures.
            original = getattr(exc, "orig", exc)
            if getattr(original, "sqlstate", None) != "28P01":
                raise
            print("Shared PostgreSQL rejected implicit runtime login; no management fallback")
        else:
            raise ValueError(
                "implicit login unexpectedly authorized; use explicit scoped credentials"
            )
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(verify())
