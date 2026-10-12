from __future__ import annotations

import asyncio
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretStr

from database.bootstrap_cluster import bootstrap
from enterprise_platform.config.settings import Settings
from scripts.day12_evidence import write_evidence
from tests.e2e.test_independent_runtimes import LOCALSTACK, docker


@pytest.fixture(scope="module")
def local_environment() -> Iterator[Settings]:
    prefix = "vehicle-day12-" + uuid4().hex[:10]
    containers: list[str] = []
    try:
        for name, port, image, arguments in (
            (prefix + "-db", 5432, "postgres:16-alpine", ["-e", "POSTGRES_PASSWORD=test-admin"]),
            (prefix + "-aws", 4566, LOCALSTACK, ["-e", "SERVICES=iam,kms,secretsmanager,sts"]),
        ):
            docker("run", "-d", "--name", name, "-p", f"127.0.0.1::{port}", *arguments, image)
            containers.append(name)
        db_port = int(docker("port", containers[0], "5432").split(":")[-1])
        aws_port = int(docker("port", containers[1], "4566").split(":")[-1])
        endpoint = f"http://127.0.0.1:{aws_port}"
        deadline = time.monotonic() + 90
        while True:
            ready = (
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        containers[0],
                        "pg_isready",
                        "-h",
                        "127.0.0.1",
                        "-U",
                        "postgres",
                    ],
                    capture_output=True,
                ).returncode
                == 0
            )
            try:
                with urllib.request.urlopen(
                    endpoint + "/_localstack/health", timeout=2
                ) as response:
                    ready = ready and response.status == 200
            except (OSError, urllib.error.URLError):
                ready = False
            if ready:
                break
            if time.monotonic() > deadline:
                raise TimeoutError("Dedicated Day12 dependencies did not start")
            time.sleep(0.2)
        settings = Settings.model_construct(
            database_host="127.0.0.1",
            database_port=db_port,
            database_name="postgres",
            database_username="postgres",
            database_password=SecretStr("test-admin"),
            migration_database_username="migration_owner",
            migration_database_password=SecretStr("test-migration"),
            bootstrap_database_username="postgres",
            bootstrap_database_password=SecretStr("test-admin"),
            aws_endpoint_url=endpoint,
        )
        asyncio.run(bootstrap(settings))
        yield settings
    finally:
        for container in reversed(containers):
            docker("rm", "-f", container)


def migration_environment(settings: Settings) -> dict[str, str]:
    environment = dict(
        os.environ,
        DATABASE_HOST=settings.database_host,
        DATABASE_PORT=str(settings.database_port),
        DATABASE_NAME=settings.database_name,
        MIGRATION_DATABASE_USERNAME="migration_owner",
        MIGRATION_DATABASE_PASSWORD="test-migration",
        AWS_ACCESS_KEY_ID="test",
        AWS_SECRET_ACCESS_KEY="test",
    )
    environment.pop("DATABASE_TENANT_ID", None)
    return environment


def evidence(stage: str, result: dict[str, object]) -> None:
    directory = Path(os.environ.get("RUNTIME_EVIDENCE_DIR", ".runtime-reports"))
    write_evidence(stage, result, directory)
