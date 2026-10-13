"""Small stateful Secrets test service, including real staging-label semantics."""

from __future__ import annotations

import json
from typing import Any, cast
from uuid import uuid4

from botocore.exceptions import ClientError


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, dict[str, str]] = {}
        self.labels: dict[str, dict[str, list[str]]] = {}
        self.fail_method: str | None = None
        self.fail_call = 0
        self.calls: dict[str, int] = {}

    def fault(self, method: str) -> None:
        self.calls[method] = self.calls.get(method, 0) + 1
        if method == self.fail_method and self.calls[method] == self.fail_call:
            raise RuntimeError("simulated network failure; sensitive-candidate-do-not-log")

    def create_secret(self, *, Name: str) -> dict[str, str]:
        self.fault("create_secret")
        self.values[Name], self.labels[Name] = {}, {}
        return {"ARN": Name}

    def describe_secret(self, *, SecretId: str) -> dict[str, Any]:
        self.fault("describe_secret")
        if SecretId not in self.values:
            raise ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "DescribeSecret")
        return {"VersionIdsToStages": self.labels[SecretId]}

    def put_secret_value(
        self,
        *,
        SecretId: str,
        SecretString: str,
        ClientRequestToken: str | None = None,
        VersionStages: list[str] | None = None,
    ) -> dict[str, str]:
        self.fault("put_secret_value")
        version = ClientRequestToken or uuid4().hex
        first = not self.values[SecretId]
        self.values[SecretId][version] = SecretString
        stages = list(VersionStages or ["AWSCURRENT"])
        if first and "AWSCURRENT" not in stages:
            stages.append("AWSCURRENT")
        for labels in self.labels[SecretId].values():
            labels[:] = [stage for stage in labels if stage not in stages]
        self.labels[SecretId][version] = list(stages)
        return {"VersionId": version}

    def get_secret_value(self, *, SecretId: str, VersionId: str) -> dict[str, str]:
        self.fault("get_secret_value")
        return {"SecretString": self.values[SecretId][VersionId], "VersionId": VersionId}

    def update_secret_version_stage(
        self,
        *,
        SecretId: str,
        VersionStage: str,
        MoveToVersionId: str | None = None,
        RemoveFromVersionId: str | None = None,
    ) -> None:
        self.fault("update_secret_version_stage")
        if RemoveFromVersionId is not None:
            self.labels[SecretId][RemoveFromVersionId].remove(VersionStage)
            if VersionStage == "AWSCURRENT" and RemoveFromVersionId != MoveToVersionId:
                for stages in self.labels[SecretId].values():
                    if "AWSPREVIOUS" in stages:
                        stages.remove("AWSPREVIOUS")
                self.labels[SecretId][RemoveFromVersionId].append("AWSPREVIOUS")
        if MoveToVersionId is not None:
            self.labels[SecretId][MoveToVersionId].append(VersionStage)

    def current(self, secret: str) -> dict[str, Any] | None:
        for version, stages in self.labels[secret].items():
            if "AWSCURRENT" in stages:
                return cast(dict[str, Any], json.loads(self.values[secret][version]))
        return None
