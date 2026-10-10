from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
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
    api_service_token: SecretStr | None = None
    api_service_tenant_id: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_public_key_file: str | None = None
    oidc_token_profile: Literal["oidc", "cognito"] = "oidc"
    oidc_tenant_claim: str = "tenant_id"
    oidc_scope_prefix: str = ""
    oidc_timeout_seconds: float = Field(default=3.0, gt=0, le=10)
    metrics_token: SecretStr | None = None
    otlp_endpoint: str | None = None
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

    database_secret_prefix: str = "/connected-vehicle"
    application_database_secret_id: str | None = None
    outbox_database_secret_id: str | None = None
    remote_command_database_secret_id: str | None = None
    migration_database_username: str | None = None
    migration_database_password: SecretStr | None = None

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
    mqtt_host: str = Field(default="localhost", min_length=1)
    mqtt_port: int = Field(default=1883, ge=1, le=65535)
    mqtt_username: str | None = None
    mqtt_password: SecretStr | None = None
    mqtt_tls_enabled: bool = False
    mqtt_ca_file: str | None = None
    mqtt_cert_file: str | None = None
    mqtt_key_file: str | None = None
    mqtt_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    worker_poll_interval_seconds: float = Field(default=1.0, gt=0, le=60)
    worker_error_delay_seconds: float = Field(default=2.0, gt=0, le=60)
    worker_shutdown_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    worker_operation_timeout_seconds: float = Field(default=25.0, gt=0, le=300)
    remote_command_wait_seconds: int = Field(default=5, ge=0, le=20)
    outbox_max_attempts: int = Field(default=10, ge=1, le=100)
    outbox_batch_size: int = Field(default=10, ge=1, le=100)
    outbox_lease_seconds: int = Field(default=60, ge=1, le=600)
    log_level: str = "INFO"
    log_format: str = "json"
    tracing_enabled: bool = True

    @model_validator(mode="after")
    def validate_runtime_contracts(self) -> Settings:
        if self.metrics_token and len(self.metrics_token.get_secret_value()) < 32:
            raise ValueError("Metrics token must contain at least 32 characters.")
        if self.otlp_endpoint:
            endpoint = urlsplit(self.otlp_endpoint)
            if endpoint.scheme not in {"http", "https"} or not endpoint.hostname:
                raise ValueError("OTLP exporter requires a valid HTTP(S) endpoint.")
            if self.app_env not in {AppEnvironment.LOCAL, AppEnvironment.TEST} and (
                endpoint.scheme != "https"
                and endpoint.hostname not in {"localhost", "127.0.0.1", "::1"}
            ):
                raise ValueError("Remote OTLP export requires HTTPS.")
        if self.oidc_issuer:
            if not self.oidc_audience or not (self.oidc_jwks_url or self.oidc_public_key_file):
                raise ValueError("OIDC requires issuer, audience and a trusted key source.")
            if (
                urlsplit(self.oidc_issuer).scheme != "https"
                or not urlsplit(self.oidc_issuer).hostname
            ):
                raise ValueError("OIDC issuer requires HTTPS.")
            if self.oidc_jwks_url and (
                urlsplit(self.oidc_jwks_url).scheme != "https"
                or not urlsplit(self.oidc_jwks_url).hostname
            ):
                raise ValueError("OIDC JWKS requires HTTPS.")
            if self.oidc_public_key_file and self.app_env not in {
                AppEnvironment.LOCAL,
                AppEnvironment.TEST,
            }:
                raise ValueError("Static OIDC key fixtures are only supported locally.")
        elif any((self.oidc_audience, self.oidc_jwks_url, self.oidc_public_key_file)):
            raise ValueError("OIDC key configuration requires an issuer.")
        if self.api_service_token and self.app_env not in {
            AppEnvironment.LOCAL,
            AppEnvironment.TEST,
        }:
            raise ValueError(
                "Static API service tokens are only supported locally; configure OIDC."
            )
        if bool(self.api_service_token) != bool(self.api_service_tenant_id):
            raise ValueError("API service token and tenant must be configured together.")
        if self.api_service_token and len(self.api_service_token.get_secret_value()) < 32:
            raise ValueError("API service token must contain at least 32 characters.")
        if self.api_service_tenant_id and not self.api_service_tenant_id.strip():
            raise ValueError("API service tenant must not be blank.")
        if self.outbox_lease_seconds <= self.worker_operation_timeout_seconds:
            raise ValueError("Outbox lease must exceed the worker operation timeout.")
        if self.worker_operation_timeout_seconds <= (
            self.remote_command_wait_seconds + self.mqtt_timeout_seconds
        ):
            raise ValueError("Worker deadline must exceed SQS polling plus MQTT timeout.")
        if self.worker_operation_timeout_seconds >= 60:
            raise ValueError("Worker deadline must be shorter than the idempotency lease (60s).")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
