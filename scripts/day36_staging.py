"""Disposable local staging exercise; never authorizes production or changes AWS.

Two immutable images, real PostgreSQL grants, real HTTP and process failures.
No database downgrade, force-unlock, shared Docker name or production credential.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

import boto3
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr
from sqlalchemy import text

from database.bootstrap_cluster import bootstrap
from database.schema_permissions import grant_runtimes, prepare_roles
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DATABASE_USERS, runtime_database_user
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.runtime_security import verify_runtime_database_security

ROOT = Path(__file__).resolve().parents[1]


class Frontdoor:
    """Loopback-only test ingress; never retries a failed write on another backend."""

    def __init__(self) -> None:
        self.target = ""
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                data = self.rfile.read(int(self.headers.get("Content-Length", "0"))) or None
                request = Request(
                    owner.target + self.path,
                    data=data,
                    headers=dict(self.headers),
                    method=self.command,
                )
                try:
                    with urlopen(request, timeout=8) as response:
                        code, body = response.status, response.read()
                except HTTPError as error:
                    code, body = error.code, error.read()
                except OSError:
                    code, body = 503, b'{"detail":"staging backend unavailable"}'
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def command(args: list[str], *, env: dict[str, str] | None = None, timeout: int = 120) -> str:
    result = subprocess.run(
        args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        # Do not expose environment, Secrets Manager payloads or bootstrap SQL.
        raise RuntimeError(f"Local command failed ({result.returncode}): {args[:3]}")
    return result.stdout.strip()


def http(base: str, path: str, token: str = "", payload: dict[str, Any] | None = None) -> Any:
    headers = {"Authorization": "Bearer " + token, "Idempotency-Key": "day36-smoke"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = Request(
        base + path, data=json.dumps(payload).encode() if payload else None, headers=headers
    )
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def ready(base: str, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if http(base, "/health/ready") == {"status": "ready"}:
                return
        except (OSError, URLError, ValueError):
            pass
        time.sleep(0.5)
    raise TimeoutError("Local staging readiness deadline exceeded")


class Staging:
    def __init__(self, env: dict[str, str], project: str) -> None:
        self.env = env
        self.project = project

    def compose(self, *args: str) -> str:
        return command(
            ["docker", "compose", "-p", self.project, "-f", "infra/staging/compose.yml", *args],
            env=self.env,
        )

    def container(self, service: str) -> str:
        identifier = self.compose("ps", "-aq", service)
        if not identifier or "\n" in identifier:
            raise ValueError("Expected exactly one isolated service container")
        return identifier

    def inspect(self, service: str) -> dict[str, Any]:
        return json.loads(command(["docker", "inspect", self.container(service)]))[0]  # type: ignore[no-any-return]

    def port(self, service: str, port: int) -> int:
        return int(self.compose("port", service, str(port)).rsplit(":", 1)[1])

    def endpoint(self, service: str) -> str:
        return f"http://127.0.0.1:{self.port(service, 8000)}"

    def assert_image(self, service: str, digest: str) -> None:
        inspected = self.inspect(service)
        assert inspected["Image"] == digest, "Container image ID mismatch"
        assert inspected["Config"]["User"] == "10001:10001"
        assert inspected["HostConfig"]["ReadonlyRootfs"] is True
        assert not any(
            entry.startswith(("MIGRATION_DATABASE_", "BOOTSTRAP_DATABASE_"))
            for entry in inspected["Config"]["Env"]
        ), "Management credentials leaked into API"


async def provision(settings: Settings, tenant: str, password: str, vehicle: str) -> str:
    assert settings.migration_database_password is not None
    await bootstrap(settings)
    environment = {
        **os.environ,
        "DATABASE_HOST": "127.0.0.1",
        "DATABASE_PORT": str(settings.database_port),
        "DATABASE_NAME": "postgres",
        "MIGRATION_DATABASE_USERNAME": "migration_owner",
        "MIGRATION_DATABASE_PASSWORD": settings.migration_database_password.get_secret_value(),
    }
    environment.pop("DATABASE_TENANT_ID", None)
    command([sys.executable, "-m", "alembic", "upgrade", "head"], env=environment)
    roles = {runtime: runtime_database_user(runtime, tenant) for runtime in DATABASE_USERS}
    await prepare_roles(settings, roles)
    await grant_runtimes(settings, roles, tenant)
    engine = create_database_engine(settings)
    try:
        async with engine.begin() as connection:
            literal = await connection.scalar(text("SELECT quote_literal(:p)"), {"p": password})
            await connection.execute(text(f"ALTER ROLE {roles['application']} PASSWORD {literal}"))
            await connection.execute(
                text(
                    "INSERT INTO vehicles (id,tenant_id,vin,status,created_at,updated_at) "
                    "VALUES (:v,:t,:vin,'active',now(),now())"
                ),
                {"v": vehicle, "t": tenant, "vin": uuid4().hex[:17].upper()},
            )
            head = str(await connection.scalar(text("SELECT version_num FROM alembic_version")))
    finally:
        await engine.dispose()
    runtime = create_database_engine(
        settings.model_copy(
            update={
                "database_username": roles["application"],
                "database_password": SecretStr(password),
                "database_tenant_id": tenant,
            }
        )
    )
    try:
        await verify_runtime_database_security(runtime, "application", tenant_id=tenant)
    finally:
        await runtime.dispose()
    return head


async def snapshot(settings: Settings, tenant: str) -> dict[str, Any]:
    engine = create_database_engine(settings)
    try:
        async with engine.connect() as connection:
            result: dict[str, Any] = {}
            for table in ("vehicles", "remote_commands", "outbox_events", "ota_jobs"):
                rows: list[str] = list(
                    (
                        await connection.execute(
                            text(
                                f"SELECT row_to_json(t)::text FROM {table} t WHERE tenant_id=:t "
                                "ORDER BY 1"
                            ),
                            {"t": tenant},
                        )
                    )
                    .scalars()
                    .all()
                )
                result[table] = {
                    "count": len(rows),
                    "sha256": hashlib.sha256(json.dumps(rows).encode()).hexdigest(),
                }
            result["migration_head"] = await connection.scalar(
                text("SELECT version_num FROM alembic_version")
            )
            return result
    finally:
        await engine.dispose()


def exercise(baseline: str, candidate: str) -> dict[str, Any]:
    """Requires immutable local image IDs, never accepts a remote deployment target."""
    if sys.flags.optimize:
        raise RuntimeError("Optimized Python disables staging invariants")
    for digest in (baseline, candidate):
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError("Use a locally inspected immutable image ID")
    project = "cv-day36-" + uuid4().hex[:12]
    password, runtime_password = secrets.token_hex(24), secrets.token_hex(24)
    tenant, vehicle = "day36-" + uuid4().hex, str(uuid4())
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {
            "iss": "https://day36.local.invalid",
            "aud": "day36-staging",
            "sub": "day36-smoke",
            "tenant_id": tenant,
            "scope": "vehicle:command ota:read",
            "iat": int(time.time()),
            "exp": int(time.time()) + 1800,
        },
        private,
        algorithm="RS256",
    )
    with tempfile.TemporaryDirectory(prefix="cv-day36-") as temporary:
        public = Path(temporary) / "public.pem"
        public.write_bytes(
            private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        env = {
            **os.environ,
            "DAY36_DB_PASSWORD": password,
            "DAY36_TENANT": tenant,
            "DAY36_PUBLIC_KEY": str(public),
            "DAY36_BASELINE_IMAGE": baseline,
            "DAY36_CANDIDATE_IMAGE": candidate,
        }
        staging = Staging(env, project)
        frontdoor = Frontdoor()
        report: dict[str, Any] = {
            "project": project,
            "baseline_image_digest": baseline,
            "image_digest": candidate,
            "faults": [],
        }
        try:
            staging.compose("up", "-d", "postgres", "redis", "localstack")
            deadline = time.monotonic() + 90
            while True:
                try:
                    command(
                        [
                            "docker",
                            "exec",
                            staging.container("postgres"),
                            "pg_isready",
                            "-h",
                            "127.0.0.1",
                            "-U",
                            "postgres",
                        ]
                    )
                    break
                except RuntimeError:
                    if time.monotonic() > deadline:
                        raise TimeoutError("PostgreSQL startup failed") from None
                    time.sleep(1)
            settings = Settings(
                database_host="127.0.0.1",
                database_port=staging.port("postgres", 5432),
                database_name="postgres",
                database_username="postgres",
                database_password=SecretStr(password),
                bootstrap_database_username="postgres",
                bootstrap_database_password=SecretStr(password),
                migration_database_username="migration_owner",
                migration_database_password=SecretStr(secrets.token_hex(24)),
            )
            report["migration_head"] = asyncio.run(
                provision(settings, tenant, runtime_password, vehicle)
            )
            client = boto3.client(
                "secretsmanager",
                endpoint_url=f"http://127.0.0.1:{staging.port('localstack', 4566)}",
                region_name="ap-northeast-1",
                aws_access_key_id="test",
                aws_secret_access_key="test",
            )
            deadline = time.monotonic() + 90
            while True:
                try:
                    client.list_secrets()
                    break
                except Exception:
                    if time.monotonic() > deadline:
                        raise TimeoutError("Isolated LocalStack startup failed") from None
                    time.sleep(1)
            client.create_secret(
                Name="day36-application",
                SecretString=json.dumps(
                    {
                        "host": "postgres",
                        "port": 5432,
                        "dbname": "postgres",
                        "tenant_id": tenant,
                        "username": runtime_database_user("application", tenant),
                        "password": runtime_password,
                    }
                ),
            )
            staging.compose("up", "-d", "blue", "green")
            for service, digest in (("blue", baseline), ("green", candidate)):
                ready(staging.endpoint(service))
                staging.assert_image(service, digest)
            frontdoor.target = staging.endpoint("blue")
            path = f"/vehicles/{vehicle}/commands"
            payload = {"command_type": "lock"}
            accepted = http(frontdoor.url, path, token, payload)
            assert accepted["created"] is True
            before = asyncio.run(snapshot(settings, tenant))
            assert before["remote_commands"]["count"] == 1
            assert before["outbox_events"]["count"] == 1
            assert http(staging.endpoint("green"), "/v2/ota/campaigns", token) == []
            report["smoke_test"] = {"authenticated_command": True, "campaign_query": True}

            def replay() -> None:
                response = http(frontdoor.url, path, token, payload)
                assert response["command_id"] == accepted["command_id"]
                assert response["created"] is False
                assert asyncio.run(snapshot(settings, tenant)) == before
                staging.assert_image("blue", baseline)

            # New container exits immediately: it cannot be promoted.
            failed = staging.compose(
                "run", "-d", "--no-deps", "green", "python", "-c", "raise SystemExit(36)"
            )
            try:
                command(["docker", "wait", failed])
                info = json.loads(command(["docker", "inspect", failed]))[0]
                assert info["State"]["ExitCode"] == 36
                assert info["State"]["Status"] == "exited"
                replay()
                report["faults"].append(
                    {"name": "startup_exit", "rejected": True, "rollback_verified": True}
                )
            finally:
                command(["docker", "rm", "-f", failed])
            # Revoke just the candidate's DB reachability; baseline stays healthy.
            networks = staging.inspect("green")["NetworkSettings"]["Networks"]
            network = next(iter(networks))
            frontdoor.target = staging.endpoint("green")
            command(["docker", "network", "disconnect", network, staging.container("green")])
            try:
                probe = command(
                    [
                        "docker",
                        "exec",
                        staging.container("green"),
                        "python",
                        "-c",
                        "import urllib.request,urllib.error\n"
                        "try:\n urllib.request.urlopen('http://127.0.0.1:8000/health/ready',timeout=8)\n"
                        "except urllib.error.HTTPError as e:\n print(e.code)",
                    ]
                )
                assert probe == "503", "Readiness did not fail closed"
                frontdoor.target = staging.endpoint("blue")
                replay()
                report["faults"].append(
                    {"name": "readiness_503", "rejected": True, "rollback_verified": True}
                )
            finally:
                command(["docker", "network", "connect", network, staging.container("green")])
            staging.compose("up", "-d", "--force-recreate", "green")
            ready(staging.endpoint("green"))
            frontdoor.target = staging.endpoint("green")
            # Accepted candidate command, then SIGKILL before retry. Reuse key on old image.
            again = http(frontdoor.url, path, token, payload)
            assert again["command_id"] == accepted["command_id"]
            command(["docker", "kill", staging.container("green")])
            try:
                http(frontdoor.url, "/health/ready")
            except HTTPError as error:
                assert error.code == 503
            else:
                raise AssertionError("Terminated candidate remained routable")
            assert (
                asyncio.run(snapshot(settings, tenant))["migration_head"]
                == before["migration_head"]
            ), "Schema changed: automatic image rollback blocked"
            staging.compose("stop", "blue")
            staging.compose("up", "-d", "--force-recreate", "blue")
            ready(staging.endpoint("blue"))
            frontdoor.target = staging.endpoint("blue")
            replay()
            report["faults"].append(
                {"name": "candidate_sigkill", "rejected": True, "rollback_verified": True}
            )
            report.update(
                {
                    "rollback_verified": True,
                    "database_consistency_verified": True,
                    "before": before,
                    "after": asyncio.run(snapshot(settings, tenant)),
                    "schema_rollback_executed": False,
                    "stable_ingress_verified": True,
                    "runtime_security_verified": True,
                }
            )
            return report
        finally:
            frontdoor.close()
            # Deletes only this randomly named disposable Compose project's resources.
            staging.compose("down", "--volumes", "--remove-orphans")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-image", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = exercise(args.baseline_image, args.candidate_image)
    result.update(
        {
            "environment": "local_staging",
            "production_authorized": False,
            "candidate_sha": command(["git", "rev-parse", "HEAD"]),
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
            "generated_at": datetime.now(UTC).isoformat(),
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)


if __name__ == "__main__":
    main()
