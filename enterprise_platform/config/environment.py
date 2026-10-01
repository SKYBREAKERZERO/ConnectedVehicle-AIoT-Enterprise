from __future__ import annotations

from enum import StrEnum


class AppEnvironment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    AWS_DEV = "aws-dev"
    STAGING = "staging"
    PRODUCTION = "production"


class CloudRuntime(StrEnum):
    LOCALSTACK = "localstack"
    AWS = "aws"
