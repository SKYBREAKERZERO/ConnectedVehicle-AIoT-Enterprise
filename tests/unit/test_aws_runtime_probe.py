from __future__ import annotations

import base64
import json
import os
from types import SimpleNamespace
from typing import Any

import pytest
from botocore.exceptions import ClientError

from scripts.aws_runtime_probe import RUNTIMES, run_probe


def target() -> dict[str, Any]:
    account, region = "123456789012", "us-east-1"
    return {
        "account": account,
        "region": region,
        "profile": "explicit-read-only",
        "roles": {name: f"arn:aws:iam::{account}:role/{name}" for name in RUNTIMES},
        "secrets": {
            name: f"arn:aws:secretsmanager:{region}:{account}:secret:{name}-abcdef"
            for name in RUNTIMES
        },
        "kms_keys": dict.fromkeys(RUNTIMES, f"arn:aws:kms:{region}:{account}:key/1234-abcd"),
        "kms_ciphertexts": dict.fromkeys(RUNTIMES, base64.b64encode(b"valid-fixture").decode()),
    }


class Session:
    def __init__(self, config: dict[str, Any], runtime: str | None = None) -> None:
        self.target, self.runtime = config, runtime
        self.broadened = False
        self.error = "AccessDeniedException"

    def client(self, service: str, **kwargs: Any) -> Any:
        self.meta = SimpleNamespace(endpoint_url=f"https://{service}.us-east-1.amazonaws.com")
        return self

    def get_caller_identity(self) -> dict[str, str]:
        arn = (
            "source"
            if self.runtime is None
            else (f"arn:aws:sts::123456789012:assumed-role/{self.runtime}/runtime-acceptance")
        )
        return {"Account": "123456789012", "Arn": arn}

    def assume_role(self, *, RoleArn: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "Credentials": {
                "AccessKeyId": RoleArn.rsplit("/", 1)[1],
                "SecretAccessKey": "private-key",
                "SessionToken": "private-token",
            }
        }

    def describe_secret(self, *, SecretId: str) -> dict[str, str]:
        return {"ARN": SecretId, "KmsKeyId": self.target["kms_keys"]["api"]}

    def describe_key(self, *, KeyId: str) -> dict[str, Any]:
        return {"KeyMetadata": {"Arn": KeyId}}

    def get_secret_value(self, *, SecretId: str) -> dict[str, str]:
        if self.broadened or SecretId == self.target["secrets"][self.runtime]:
            return {"ARN": SecretId, "SecretString": "private-database-password"}
        raise ClientError(
            {"Error": {"Code": self.error, "Message": "private failure"}}, "GetSecretValue"
        )

    def decrypt(self, *, KeyId: str, **kwargs: Any) -> dict[str, Any]:
        if self.runtime is None:
            return {"KeyId": KeyId, "Plaintext": b"valid plaintext"}
        raise ClientError({"Error": {"Code": self.error}}, "Decrypt")


def factory(
    config: dict[str, Any], *, broadened: bool = False, error: str = "AccessDeniedException"
) -> Any:
    def create(**kwargs: Any) -> Session:
        session = Session(config, kwargs.get("aws_access_key_id"))
        session.broadened, session.error = broadened, error
        return session

    return create


def test_default_never_constructs_session_or_contacts_aws() -> None:
    def forbidden(**kwargs: Any) -> None:
        pytest.fail("Dry run contacted AWS")

    result = run_probe(target(), session_factory=forbidden)
    assert result["status"] == "not_executed" and not result["iam_enforcement_verified"]


def test_assumed_roles_require_own_access_and_foreign_denials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in list(os.environ):
        if key.startswith("AWS_ENDPOINT_URL"):
            monkeypatch.delenv(key)
    config = target()
    result = run_probe(config, execute=True, session_factory=factory(config))
    assert result["status"] == "passed" and result["iam_enforcement_verified"]
    assert result["kms_via_secrets_manager_verified"] and result["direct_kms_boundary_verified"]
    assert len(result["secret_access"]) == 9
    assert "private" not in json.dumps(result) and "plaintext" not in json.dumps(result)
    for changed in (
        factory(config, broadened=True),
        factory(config, error="ResourceNotFoundException"),
    ):
        bad = run_probe(config, execute=True, session_factory=changed)
        assert bad["status"] == "failed" and not bad["iam_enforcement_verified"]


def test_execute_rejects_localstack_before_creating_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:4566")
    with pytest.raises(ValueError, match="endpoint overrides"):
        run_probe(
            target(), execute=True, session_factory=lambda **kwargs: pytest.fail("AWS contacted")
        )


@pytest.mark.parametrize("field", ["account", "roles", "secrets", "kms_keys", "profile"])
def test_missing_explicit_identity_rejected(field: str) -> None:
    config = target()
    del config[field]
    with pytest.raises(ValueError):
        run_probe(config)
