from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from enterprise_platform.config.environment import AppEnvironment, CloudRuntime


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "connected-vehicle-aiot-enterprise"
    app_env: AppEnvironment = AppEnvironment.LOCAL
    app_host: str = "0.0.0.0"
    app_port: int = Field(default=8000, ge=1, le=65535)

    cloud_runtime: CloudRuntime = CloudRuntime.LOCALSTACK

    aws_region: str = "ap-northeast-1"
    aws_endpoint_url: str | None = "http://localhost:4566"
    aws_connect_timeout_seconds: float = Field(default=3.0, gt=0)
    aws_read_timeout_seconds: float = Field(default=10.0, gt=0)
    aws_max_attempts: int = Field(default=3, ge=1, le=10)

    vehicle_command_queue_name: str = Field(
        default="connected-vehicle-command",
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9_-]+$",
    )

    database_host: str = "localhost"
    database_port: int = Field(default=5432, ge=1, le=65535)
    database_name: str = "connected_vehicle"
    database_username: str = "connected_vehicle"
    database_password: SecretStr = SecretStr("connected_vehicle")

    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=200)
    database_pool_timeout_seconds: float = Field(default=30.0, gt=0)
    database_connect_timeout_seconds: float = Field(default=5.0, gt=0)
    database_health_timeout_seconds: float = Field(default=3.0, gt=0)

    redis_host: str = Field(default="localhost", min_length=1)
    redis_port: int = Field(default=16379, ge=1, le=65535)
    redis_db: int = Field(default=0, ge=0)

    redis_username: str | None = None
    redis_password: SecretStr | None = None

    redis_connect_timeout_seconds: float = Field(default=3.0, gt=0)
    redis_socket_timeout_seconds: float = Field(default=5.0, gt=0)
    redis_health_timeout_seconds: float = Field(default=5.0, gt=0)
    redis_max_connections: int = Field(default=50, ge=1, le=1000)

    redis_key_prefix: str = Field(
        default="connected-vehicle",
        min_length=1,
        max_length=100,
    )
    log_level: str = "INFO"
    log_format: str = "json"
    tracing_enabled: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
