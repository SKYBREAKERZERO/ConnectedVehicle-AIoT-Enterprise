from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from enterprise_platform.config.settings import Settings
from enterprise_platform.security.factory import create_aws_secrets_manager_provider
from enterprise_platform.security.secrets import SecretProvider

DatabaseRuntime = Literal["application", "outbox", "remote-command"]
DATABASE_USERS: dict[DatabaseRuntime, str] = {
    "application": "app_user",
    "outbox": "outbox_worker",
    "remote-command": "remote_command_worker",
}


class DatabaseCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    engine: Literal["postgres"] = "postgres"
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    dbname: str = Field(min_length=1)
    username: str
    password: SecretStr = Field(min_length=1)


async def load_runtime_database_settings(
    settings: Settings,
    runtime: DatabaseRuntime,
    *,
    provider: SecretProvider | None = None,
) -> Settings:
    """Load exactly one runtime secret; never fall back to administrative credentials."""
    secret_ids = {
        "application": settings.application_database_secret_id,
        "outbox": settings.outbox_database_secret_id,
        "remote-command": settings.remote_command_database_secret_id,
    }
    secret_id = secret_ids[runtime] or (
        f"{settings.database_secret_prefix}/{settings.app_env.value}/database/{runtime}"
    )
    backend = provider or create_aws_secrets_manager_provider(settings)
    payload = await backend.get_secret(secret_id)
    try:
        credentials = DatabaseCredentials.model_validate_json(payload)
        if credentials.username != DATABASE_USERS[runtime]:
            raise ValueError("Unexpected database user")
    except ValueError:
        raise ValueError(f"Invalid database credentials for {runtime}") from None
    return settings.model_copy(
        update={
            "database_host": credentials.host,
            "database_port": credentials.port,
            "database_name": credentials.dbname,
            "database_username": credentials.username,
            "database_password": credentials.password,
        }
    )


def migration_database_settings(settings: Settings) -> Settings:
    """Require explicit, independent administrator credentials for Alembic."""
    if (
        not settings.migration_database_username
        or not settings.migration_database_password
        or settings.migration_database_username in DATABASE_USERS.values()
    ):
        raise ValueError("Alembic requires independent MIGRATION_DATABASE_USERNAME/PASSWORD")
    return settings.model_copy(
        update={
            "database_username": settings.migration_database_username,
            "database_password": settings.migration_database_password,
        }
    )
