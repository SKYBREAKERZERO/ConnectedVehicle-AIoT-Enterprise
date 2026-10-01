from __future__ import annotations

from dataclasses import dataclass

from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import Settings


@dataclass(frozen=True, slots=True)
class CloudRuntimeConfiguration:
    runtime: CloudRuntime
    region: str
    endpoint_url: str | None

    @property
    def is_local(self) -> bool:
        return self.runtime is CloudRuntime.LOCALSTACK

    @property
    def is_aws(self) -> bool:
        return self.runtime is CloudRuntime.AWS


def resolve_cloud_runtime(settings: Settings) -> CloudRuntimeConfiguration:
    if settings.cloud_runtime is CloudRuntime.LOCALSTACK:
        endpoint_url = settings.aws_endpoint_url or "http://localhost:4566"

        return CloudRuntimeConfiguration(
            runtime=CloudRuntime.LOCALSTACK,
            region=settings.aws_region,
            endpoint_url=endpoint_url,
        )

    return CloudRuntimeConfiguration(
        runtime=CloudRuntime.AWS,
        region=settings.aws_region,
        endpoint_url=None,
    )
