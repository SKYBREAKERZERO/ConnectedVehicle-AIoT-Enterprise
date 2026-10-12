from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, cast

import boto3
import pytest

from database.provision_tenant_local import provision_tenant
from enterprise_platform.config.settings import Settings
from scripts.verify_tenant_local import verify_matrix
from tests.integration.day12.conftest import evidence, migration_environment


@pytest.mark.integration
async def test_six_roles_secret_and_kms_positive_negative_matrix(
    local_environment: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    env = migration_environment(local_environment)
    env.pop("DATABASE_TENANT_ID", None)
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=env,
        check=True,
        capture_output=True,
    )
    documents = [
        await provision_tenant(local_environment, tenant) for tenant in ("matrix-a", "matrix-b")
    ]
    result = await verify_matrix(documents, local_environment)
    matrix = result["configuration_matrix"]
    assert len(matrix["secret"]) == 36
    assert sum(row["decision"] == "allow" for row in matrix["secret"]) == 6
    assert len(matrix["kms"]) == 36
    assert sum(row["decision"] == "allow" for row in matrix["kms"]) == 6
    evidence("12b-identity-matrix", result)
    iam = boto3.client(
        "iam",
        endpoint_url=local_environment.aws_endpoint_url,
        region_name=local_environment.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    role = cast(Any, documents[0]["identities"])["application"]["role_arn"].rsplit("/", 1)[1]
    original = iam.get_role_policy(RoleName=role, PolicyName="own-database-secret")[
        "PolicyDocument"
    ]
    broadened = json.loads(json.dumps(original))
    broadened["Statement"][0]["Resource"] = "*"
    iam.put_role_policy(
        RoleName=role, PolicyName="own-database-secret", PolicyDocument=json.dumps(broadened)
    )
    try:
        with pytest.raises(RuntimeError, match="security contract"):
            await verify_matrix(documents, local_environment)
    finally:
        iam.put_role_policy(
            RoleName=role, PolicyName="own-database-secret", PolicyDocument=json.dumps(original)
        )
