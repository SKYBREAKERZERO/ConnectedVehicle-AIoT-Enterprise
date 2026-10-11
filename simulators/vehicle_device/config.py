from __future__ import annotations

import ssl
from pathlib import Path
from uuid import UUID

from pydantic import Field, HttpUrl, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DeviceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DEVICE_", extra="ignore", hide_input_in_errors=True
    )
    database: Path = Path(".device/tbox.sqlite")
    tenant_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    vehicle_id: UUID
    api_url: HttpUrl
    token_file: Path
    mqtt_host: str = "127.0.0.1"
    mqtt_port: int = Field(default=1883, ge=1, le=65535)
    mqtt_username: str | None = None
    mqtt_password: SecretStr | None = None
    mqtt_ca_file: Path | None = None
    mqtt_cert_file: Path | None = None
    mqtt_key_file: Path | None = None
    allow_insecure_local: bool = False
    can_port: int = Field(default=19000, ge=1, le=65535)
    gateway_port: int = Field(default=19002, ge=1, le=65535)
    max_pending_commands: int = Field(default=1000, ge=1)
    max_quarantine_records: int = Field(default=1000, ge=1)
    min_free_bytes: int = Field(default=33554432, ge=0)
    crash_after: str | None = Field(default=None, pattern=r"^(command_commit|result_commit)$")

    @model_validator(mode="after")
    def secure_transport(self) -> DeviceSettings:
        if (
            self.api_url.username
            or self.api_url.password
            or self.api_url.query
            or self.api_url.fragment
        ):
            raise ValueError("API base URL must not contain credentials, a query or a fragment.")
        if self.allow_insecure_local:
            if self.mqtt_host not in ("localhost", "127.0.0.1") or self.api_url.host not in (
                "localhost",
                "127.0.0.1",
            ):
                raise ValueError("Insecure simulator transport is loopback only.")
        elif self.api_url.scheme != "https" or self.mqtt_ca_file is None:
            raise ValueError(
                "HTTPS and an MQTT CA are required; local simulation needs explicit opt-in."
            )
        if bool(self.mqtt_cert_file) != bool(self.mqtt_key_file):
            raise ValueError("MQTT certificate and private key must be supplied together.")
        if self.can_port == self.gateway_port:
            raise ValueError("T-Box and Gateway need different CAN ports.")
        return self

    @property
    def topic(self) -> str:
        return f"tenants/{self.tenant_id}/vehicles/{self.vehicle_id}/commands"

    def tls_context(self) -> ssl.SSLContext | None:
        if self.mqtt_ca_file is None:
            return None
        context = ssl.create_default_context(cafile=str(self.mqtt_ca_file))
        if self.mqtt_cert_file is not None and self.mqtt_key_file is not None:
            context.load_cert_chain(str(self.mqtt_cert_file), str(self.mqtt_key_file))
        return context
