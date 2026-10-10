"""Real sockets, three real processes, four isolated dependencies, no service mocks."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO
from uuid import uuid4

import aiomqtt
import boto3
import httpx2 as httpx
import pytest
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from connected_vehicle.vehicle import VIN, Vehicle, VehicleId, VehicleStatus
from connected_vehicle.vehicle.persistence.repository import SQLAlchemyVehicleRepository
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.messaging.sqs_runtime import normalize_localstack_queue_url

if TYPE_CHECKING:
    from mypy_boto3_sqs.literals import QueueAttributeNameType

ROOT = Path(__file__).resolve().parents[2]
LOCALSTACK = (
    "localstack/localstack:3.8.1@sha256:"
    "b279c01f4cfb8f985a482e4014cabc1e2697b9d7a6c8c8db2e40f4d9f93687c7"
)


def docker(*args: str) -> str:
    return subprocess.check_output(["docker", *args], text=True, stderr=subprocess.STDOUT).strip()


async def eventually(check: Callable[[], Awaitable[bool]], *, timeout: float = 40) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await check():
            return
        await asyncio.sleep(0.2)
    raise AssertionError("E2E condition did not become true before the deadline.")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.e2e
@pytest.mark.integration
def test_three_process_api_outbox_sqs_mqtt(tmp_path: Path) -> None:
    # aiomqtt requires a SelectorEventLoop on Windows; no global test policy change.
    with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
        runner.run(exercise(tmp_path))


async def exercise(tmp_path: Path) -> None:
    prefix = f"vehicle-e2e-{uuid4().hex[:10]}"
    containers: list[str] = []
    processes: dict[str, subprocess.Popen[bytes]] = {}
    logs: dict[str, BinaryIO] = {}
    admin = None
    config_dir = tmp_path / "mqtt"
    config_dir.mkdir()
    (config_dir / "mosquitto.conf").write_text(
        "listener 1883\nallow_anonymous true\npersistence false\nlog_dest stdout\n"
    )
    # Remove inherited infrastructure credentials/config, including developer .env.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(
            (
                "AWS_",
                "DATABASE_",
                "MIGRATION_",
                "APPLICATION_DATABASE_",
                "OUTBOX_DATABASE_",
                "REMOTE_COMMAND_DATABASE_",
                "REDIS_",
                "MQTT_",
                "API_SERVICE_",
                "APP_",
                "WORKER_",
                "OUTBOX_",
                "REMOTE_COMMAND_",
                "TF_",
                "LOCALSTACK_",
            )
        )
    }
    env.update(
        {
            "PYTHONUNBUFFERED": "1",
            "APP_ENV": "local",
            "CLOUD_RUNTIME": "localstack",
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_REGION": "ap-northeast-1",
            "AWS_MAX_ATTEMPTS": "1",
            "AWS_CONNECT_TIMEOUT_SECONDS": "1",
            "AWS_READ_TIMEOUT_SECONDS": "3",
            "AWS_CONFIG_FILE": str(tmp_path / "no-aws-config"),
            "AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "no-aws-creds"),
            "TRACING_ENABLED": "false",
            "APP_HOST": "127.0.0.1",
            "APP_PORT": str(free_port()),
            "API_SERVICE_TOKEN": uuid4().hex + uuid4().hex,
            "API_SERVICE_TENANT_ID": "e2e-tenant",
            "WORKER_POLL_INTERVAL_SECONDS": "0.1",
            "WORKER_ERROR_DELAY_SECONDS": "0.2",
            "WORKER_SHUTDOWN_TIMEOUT_SECONDS": "5",
            "WORKER_OPERATION_TIMEOUT_SECONDS": "10",
            "REMOTE_COMMAND_WAIT_SECONDS": "1",
            "MQTT_TIMEOUT_SECONDS": "1",
            "OUTBOX_BATCH_SIZE": "2",
            "OUTBOX_MAX_ATTEMPTS": "10",
            "OUTBOX_LEASE_SECONDS": "15",
        }
    )

    def start_container(service: str, port: int, image: str, *args: str) -> int:
        name = f"{prefix}-{service}"
        host_port = free_port()
        docker("run", "-d", "--name", name, "-p", f"127.0.0.1:{host_port}:{port}", *args, image)
        containers.append(name)
        return int(docker("port", name, str(port)).split(":")[-1])

    def launch(role: str) -> None:
        logs[role] = (tmp_path / f"{role}.log").open("wb")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        processes[role] = subprocess.Popen(
            [sys.executable, "-m", f"apps.{role}"],
            cwd=tmp_path,
            env=env,
            stdout=logs[role],
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )

    def log(role: str) -> str:
        return (tmp_path / f"{role}.log").read_text(errors="replace")

    try:
        pg_port = start_container(
            "pg", 5432, "postgres:16-alpine", "-e", "POSTGRES_PASSWORD=e2e-admin"
        )
        redis_port = start_container("redis", 6379, "redis:7-alpine")
        aws_port = start_container(
            "aws",
            4566,
            LOCALSTACK,
            "-e",
            "SERVICES=sqs,secretsmanager",
            "-e",
            "EAGER_SERVICE_LOADING=1",
        )
        mqtt_port = start_container(
            "mqtt",
            1883,
            "eclipse-mosquitto:2.1.1-alpine",
            "-v",
            f"{config_dir.resolve()}:/mosquitto/config:ro",
        )
        endpoint = f"http://127.0.0.1:{aws_port}"
        env.update(
            {
                "AWS_ENDPOINT_URL": endpoint,
                "DATABASE_HOST": "127.0.0.1",
                "DATABASE_PORT": str(pg_port),
                "DATABASE_NAME": "postgres",
                "REDIS_HOST": "127.0.0.1",
                "REDIS_PORT": str(redis_port),
                "REDIS_KEY_PREFIX": prefix,
                "MQTT_HOST": "127.0.0.1",
                "MQTT_PORT": str(mqtt_port),
                "VEHICLE_COMMAND_QUEUE_NAME": prefix,
            }
        )
        settings = Settings.model_construct(
            database_host="127.0.0.1",
            database_port=pg_port,
            database_name="postgres",
            database_username="postgres",
            database_password=SecretStr("e2e-admin"),
        )
        admin = create_database_engine(settings)

        async def database_ready() -> bool:
            try:
                async with admin.connect() as connection:
                    await connection.execute(text("SELECT 1"))
                return True
            except (OSError, DBAPIError):
                return False

        await eventually(database_ready)
        config = Config(connect_timeout=1, read_timeout=3, retries={"max_attempts": 0})
        sqs = boto3.client(
            "sqs",
            endpoint_url=endpoint,
            region_name="ap-northeast-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
            config=config,
        )
        secrets = boto3.client(
            "secretsmanager",
            endpoint_url=endpoint,
            region_name="ap-northeast-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
            config=config,
        )

        async def aws_ready() -> bool:
            try:
                await asyncio.to_thread(sqs.list_queues)
                await asyncio.to_thread(secrets.list_secrets)
                return True
            except (BotoCoreError, ClientError):
                return False

        await eventually(aws_ready, timeout=90)
        migration_env = env | {
            "MIGRATION_DATABASE_USERNAME": "postgres",
            "MIGRATION_DATABASE_PASSWORD": "e2e-admin",
        }
        subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"), "upgrade", "head"],
            cwd=tmp_path,
            env=migration_env,
            check=True,
            capture_output=True,
            timeout=60,
        )
        for runtime in ["application", "outbox", "remote-command"]:
            secrets.create_secret(Name=f"/connected-vehicle/local/database/{runtime}")
        provision_env = migration_env | {
            "APP_USER_PASSWORD": uuid4().hex,
            "OUTBOX_WORKER_PASSWORD": uuid4().hex,
            "REMOTE_COMMAND_WORKER_PASSWORD": uuid4().hex,
        }
        # Provisioning is a separate admin process; runtimes inherit none of these credentials.
        subprocess.run(
            [sys.executable, str(ROOT / "database/provision_runtime_credentials.py")],
            cwd=tmp_path,
            env=provision_env,
            check=True,
            capture_output=True,
            timeout=60,
        )
        dlq_url = sqs.create_queue(QueueName=f"{prefix}-dlq")["QueueUrl"]
        dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]
        attributes: dict[QueueAttributeNameType, str] = {
            "VisibilityTimeout": "3",
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 5}),
        }
        queue_url = sqs.create_queue(QueueName=prefix, Attributes=attributes)["QueueUrl"]
        queue_url = normalize_localstack_queue_url(queue_url, endpoint_url=endpoint)
        dlq_url = normalize_localstack_queue_url(dlq_url, endpoint_url=endpoint)
        vehicle = Vehicle.create(
            vehicle_id=VehicleId.new(), vin=VIN("ABC12345678901234"), tenant_id="e2e-tenant"
        ).transition_to(VehicleStatus.ACTIVE)
        foreign_vehicle = Vehicle.create(
            vehicle_id=VehicleId.new(), vin=VIN("ABC12345678901235"), tenant_id="other-tenant"
        ).transition_to(VehicleStatus.ACTIVE)
        sessions = create_session_factory(admin)
        async with sessions() as session:
            repository = SQLAlchemyVehicleRepository(session)
            repository.add(vehicle)
            repository.add(foreign_vehicle)
            await session.commit()
        # Deliberate broker outage proves failed MQTT publication is not acknowledged.
        docker("stop", f"{prefix}-mqtt")
        for role in ["api", "outbox", "remote_command"]:
            launch(role)
        base_url = f"http://127.0.0.1:{env['APP_PORT']}"
        async with httpx.AsyncClient(base_url=base_url, timeout=3) as http:

            async def api_ready() -> bool:
                for role, process in processes.items():
                    assert process.poll() is None, f"{role} exited: {log(role)}"
                try:
                    return (await http.get("/health/live")).status_code == 200
                except httpx.TransportError:
                    return False

            await eventually(api_ready)
            assert (await http.get("/health/ready")).status_code == 200
            path = f"/vehicles/{vehicle.id}/commands"
            headers = {
                "Authorization": f"Bearer {env['API_SERVICE_TOKEN']}",
                "Idempotency-Key": "e2e-first",
            }
            assert (await http.post(path, json={"command_type": "lock"})).status_code == 401
            denied = await http.post(
                path,
                headers=headers | {"Authorization": "Bearer invalid"},
                json={"command_type": "lock"},
            )
            assert denied.status_code == 401
            foreign = await http.post(
                f"/vehicles/{foreign_vehicle.id}/commands",
                headers=headers,
                json={"command_type": "lock"},
            )
            assert foreign.status_code == 404
            response = await http.post(path, headers=headers, json={"command_type": "lock"})
            assert response.status_code == 202, response.text
            command_id = response.json()["command_id"]

            async def state_is(value: str, command: str = command_id) -> bool:
                async with admin.connect() as connection:
                    return bool(
                        await connection.scalar(
                            text("SELECT status FROM remote_commands WHERE id=:id"), {"id": command}
                        )
                        == value
                    )

            await eventually(lambda: state_is("dispatching"))
            await eventually(lambda: async_bool("failed=1" in log("remote_command")))
            assert not await state_is("sent")
            docker("start", f"{prefix}-mqtt")

            async def broker_ready() -> bool:
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", mqtt_port)
                    writer.close()
                    await writer.wait_closed()
                    return True
                except OSError:
                    return False

            await eventually(broker_ready, timeout=10)
            async with aiomqtt.Client("127.0.0.1", port=mqtt_port, timeout=5) as subscriber:
                await subscriber.subscribe("tenants/e2e-tenant/vehicles/+/commands", qos=1)
                async with asyncio.timeout(35):
                    message = await anext(subscriber.messages)
                payload = json.loads(bytes(message.payload))
                assert payload["command_id"] == command_id
                assert payload["vehicle_id"] == str(vehicle.id)
                assert payload["command_type"] == "lock"
                assert str(message.topic) == f"tenants/e2e-tenant/vehicles/{vehicle.id}/commands"
                assert message.qos == 1 and not message.retain
                await eventually(lambda: state_is("sent"))
                replay = await http.post(path, headers=headers, json={"command_type": "lock"})
                assert replay.status_code == 202 and replay.json()["command_id"] == command_id
                assert replay.json()["created"] is False
                async with admin.connect() as connection:
                    rows = (
                        await connection.execute(
                            text("SELECT status, event_body FROM outbox_events")
                        )
                    ).all()
                    assert len(rows) == 1 and rows[0].status == "published"
                    body = rows[0].event_body
                    users: set[str] = set(
                        (
                            await connection.execute(
                                text(
                                    "SELECT DISTINCT usename FROM pg_stat_activity "
                                    "WHERE datname=current_database()"
                                )
                            )
                        ).scalars()
                    )
                    assert {"app_user", "outbox_worker", "remote_command_worker"} <= users
                sqs.send_message(QueueUrl=queue_url, MessageBody=body)
                await eventually(lambda: async_bool("duplicates=1" in log("remote_command")))
                with pytest.raises(TimeoutError):
                    async with asyncio.timeout(2):
                        await anext(subscriber.messages)
                # Poison SQS event must eventually redrive; valid subsequent work still flows.
                sqs.send_message(QueueUrl=queue_url, MessageBody="not-json")
                response = await http.post(
                    path,
                    headers=headers | {"Idempotency-Key": "e2e-second"},
                    json={"command_type": "honk"},
                )
                assert response.status_code == 202
                second = response.json()["command_id"]
                async with asyncio.timeout(35):
                    message = await anext(subscriber.messages)
                assert json.loads(bytes(message.payload))["command_id"] == second
                await eventually(lambda: state_is("sent", second))

                async def poison_redriven() -> bool:
                    result = await asyncio.to_thread(
                        sqs.receive_message, QueueUrl=dlq_url, WaitTimeSeconds=0
                    )
                    return any(row["Body"] == "not-json" for row in result.get("Messages", []))

                await eventually(poison_redriven)
                # Real SQS outage: durable API acceptance, persisted backoff, then recovery.
                docker("pause", f"{prefix}-aws")
                response = await http.post(
                    path,
                    headers=headers | {"Idempotency-Key": "e2e-third"},
                    json={"command_type": "flash_lights"},
                )
                assert response.status_code == 202
                third = response.json()["command_id"]

                async def outbox_retried() -> bool:
                    async with admin.connect() as connection:
                        return bool(
                            await connection.scalar(
                                text(
                                    "SELECT count(*) FROM outbox_events "
                                    "WHERE status='pending' AND attempts>=1"
                                )
                            )
                        )

                await eventually(outbox_retried)
                docker("unpause", f"{prefix}-aws")
                async with asyncio.timeout(35):
                    message = await anext(subscriber.messages)
                assert json.loads(bytes(message.payload))["command_id"] == third
                await eventually(lambda: state_is("sent", third))
                # Malformed Outbox item is isolated and persisted FAILED, not retried forever.
                async with admin.begin() as connection:
                    await connection.execute(
                        text(
                            "INSERT INTO outbox_events "
                            "(id,event_id,event_type,destination,event_body,status,attempts,"
                            "created_at,available_at) "
                            "VALUES (:id,:id,'bad','vehicle-command','bad-json',"
                            "'pending',0,now(),now())"
                        ),
                        {"id": str(uuid4())},
                    )

                async def outbox_failed() -> bool:
                    async with admin.connect() as connection:
                        return bool(
                            await connection.scalar(
                                text(
                                    "SELECT count(*) FROM outbox_events "
                                    "WHERE status='failed' AND failure_code='non_retryable'"
                                )
                            )
                        )

                await eventually(outbox_failed)
        # Real process termination signal, no forced terminate in the success path.
        for role in ["outbox", "remote_command", "api"]:
            process = processes[role]
            process.send_signal(
                signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGTERM
            )
            await asyncio.to_thread(process.wait, timeout=12)
            if role == "api":
                assert "Application shutdown complete" in log(role)
            else:
                assert process.returncode == 0 and "worker_stopped" in log(role), log(role)
        async with admin.connect() as connection:
            remaining = await connection.scalar(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE usename IN ('app_user','outbox_worker','remote_command_worker')"
                )
            )
            assert remaining == 0
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
                await asyncio.to_thread(process.wait, timeout=10)
        for stream in logs.values():
            stream.close()
        if admin is not None:
            await admin.dispose()
        for name in reversed(containers):
            if docker("inspect", "-f", "{{.State.Paused}}", name) == "true":
                docker("unpause", name)
            docker("rm", "-f", name)


async def async_bool(value: bool) -> bool:
    return value
