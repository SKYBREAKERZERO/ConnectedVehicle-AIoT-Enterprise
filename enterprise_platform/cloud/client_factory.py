from __future__ import annotations

from typing import Protocol, cast

import boto3
from botocore.client import BaseClient
from botocore.config import Config

from enterprise_platform.cloud.endpoints import (
    resolve_aws_client_configuration,
)
from enterprise_platform.cloud.runtime import resolve_cloud_runtime
from enterprise_platform.config.settings import Settings


class Boto3ClientCreator(Protocol):
    def __call__(
        self,
        service_name: str,
        **kwargs: object,
    ) -> BaseClient: ...


class AWSClientFactory:
    def __init__(self, settings: Settings) -> None:
        self._runtime = resolve_cloud_runtime(settings)
        self._client_creator = cast(Boto3ClientCreator, boto3.client)

        self._sdk_config = Config(
            connect_timeout=settings.aws_connect_timeout_seconds,
            read_timeout=settings.aws_read_timeout_seconds,
            retries={
                "total_max_attempts": settings.aws_max_attempts,
                "mode": "standard",
            },
        )

    def create(self, service_name: str) -> BaseClient:
        config = resolve_aws_client_configuration(self._runtime)

        client_kwargs: dict[str, object] = {
            "region_name": config.region_name,
            "config": self._sdk_config,
        }

        if config.endpoint_url is not None:
            client_kwargs["endpoint_url"] = config.endpoint_url

        return self._client_creator(
            service_name,
            **client_kwargs,
        )

    def s3(self) -> BaseClient:
        return self.create("s3")

    def sqs(self) -> BaseClient:
        return self.create("sqs")

    def sns(self) -> BaseClient:
        return self.create("sns")

    def eventbridge(self) -> BaseClient:
        return self.create("events")

    def kms(self) -> BaseClient:
        return self.create("kms")

    def secrets_manager(self) -> BaseClient:
        return self.create("secretsmanager")
