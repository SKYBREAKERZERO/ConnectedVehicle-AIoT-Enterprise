from __future__ import annotations

from dataclasses import dataclass

from enterprise_platform.cloud.runtime import CloudRuntimeConfiguration


@dataclass(frozen=True, slots=True)
class AWSClientConfiguration:
    region_name: str
    endpoint_url: str | None


def resolve_aws_client_configuration(
    runtime: CloudRuntimeConfiguration,
) -> AWSClientConfiguration:
    return AWSClientConfiguration(
        region_name=runtime.region,
        endpoint_url=runtime.endpoint_url,
    )
