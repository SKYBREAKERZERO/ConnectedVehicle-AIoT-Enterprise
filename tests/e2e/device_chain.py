from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

import aiomqtt
import httpx2 as httpx

from tests.e2e.test_independent_runtimes import eventually


class Launch(Protocol):
    def __call__(
        self,
        role: str,
        *,
        module: str | None = None,
        arguments: list[str] | None = None,
        process_env: dict[str, str] | None = None,
    ) -> None: ...


def udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def exercise_device_chain(
    tmp_path: Path,
    http: httpx.AsyncClient,
    path: str,
    headers: dict[str, str],
    vehicle: str,
    mqtt_port: int,
    token: str,
    operator_headers: dict[str, str],
    launch: Launch,
    processes: dict[str, subprocess.Popen[bytes]],
    log: Callable[[str], str],
    restart_broker: Callable[[], object],
) -> None:
    tbox_db, body_db = tmp_path / "tbox.sqlite", tmp_path / "body.sqlite"
    token_file = tmp_path / "device.jwt"
    token_file.write_text(token, encoding="utf-8")
    tbox_port, gateway_port, gateway_body_port, body_port = (udp_port() for _ in range(4))
    gateway_db = tmp_path / "gateway.sqlite"
    # Device processes receive neither cloud database credentials nor AWS keys.
    device_env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PYTHONPATH")
    }
    ecu_env = device_env | {"PYTHONUNBUFFERED": "1"}
    device_env.update(
        {
            "PYTHONUNBUFFERED": "1",
            "DEVICE_DATABASE": str(tbox_db),
            "DEVICE_TENANT_ID": "e2e-tenant",
            "DEVICE_VEHICLE_ID": vehicle,
            "DEVICE_API_URL": str(http.base_url),
            "DEVICE_TOKEN_FILE": str(token_file),
            "DEVICE_MQTT_HOST": "127.0.0.1",
            "DEVICE_MQTT_PORT": str(mqtt_port),
            "DEVICE_ALLOW_INSECURE_LOCAL": "true",
            "DEVICE_MAX_PENDING_COMMANDS": "1",
            "DEVICE_CAN_PORT": str(tbox_port),
            "DEVICE_GATEWAY_PORT": str(gateway_port),
        }
    )
    body_args = [
        "--database",
        str(body_db),
        "--port",
        str(body_port),
        "--gateway-port",
        str(gateway_body_port),
        "--crash-after-execution",
    ]

    async def stop(role: str) -> None:
        process = processes[role]
        if process.poll() is None:
            number = signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGTERM
            process.send_signal(number)
            await asyncio.to_thread(process.wait, timeout=8)
            assert process.returncode == 0, log(role)
        processes.pop(role)

    async def ready(role: str, message: str, previous: int) -> bool:
        assert processes[role].poll() is None, log(role)
        return log(role).count(message) > previous

    async def start_tbox(overrides: dict[str, str] | None = None) -> None:
        previous = log("tbox").count("device_mqtt_ready") if (tmp_path / "tbox.log").exists() else 0
        launch(
            "tbox",
            module="simulators.vehicle_device",
            process_env=device_env | (overrides or {}),
        )
        await eventually(lambda: ready("tbox", "device_mqtt_ready", previous), timeout=15)

    async def start_gateway(crash: bool = False) -> None:
        previous = (
            log("gateway").count("gateway_ready") if (tmp_path / "gateway.log").exists() else 0
        )
        arguments = [
            "--database",
            str(gateway_db),
            "--port",
            str(gateway_port),
            "--tbox-port",
            str(tbox_port),
            "--body-bus-port",
            str(gateway_body_port),
            "--body-port",
            str(body_port),
        ]
        if crash:
            arguments.append("--crash-after-route")
        launch("gateway", module="simulators.gateway", arguments=arguments, process_env=ecu_env)
        await eventually(lambda: ready("gateway", "gateway_ready", previous), timeout=15)

    async def start_body(crash: bool = False) -> None:
        previous = log("body").count("body_ecu_ready") if (tmp_path / "body.log").exists() else 0
        launch(
            "body",
            module="simulators.body_ecu",
            arguments=body_args if crash else body_args[:-1],
            process_env=ecu_env,
        )
        await eventually(lambda: ready("body", "body_ecu_ready", previous), timeout=15)

    async def issue(key: str, kind: str = "lock") -> str:
        response = await http.post(
            path, headers=headers | {"Idempotency-Key": key}, json={"command_type": kind}
        )
        assert response.status_code == 202, response.text
        return str(response.json()["command_id"])

    async def state(command: str, expected: str) -> bool:
        with sqlite3.connect(tbox_db) as db:
            result = db.execute("SELECT state FROM commands WHERE id=?", (command,)).fetchone()
            reports = db.execute(
                "SELECT count(*) FROM reports WHERE command_id=? AND state='delivered'", (command,)
            ).fetchone()[0]
        response = await http.get(f"{path}/{command}", headers=operator_headers)
        assert response.status_code == 200, response.text
        return bool(
            result
            and result[0] == expected
            and reports == 2
            and response.json()["status"] == expected
        )

    async def exited(role: str, code: int) -> bool:
        result = processes[role].poll()
        if result is None:
            return False
        assert result == code, log(role)
        return True

    def count_executions(command: str) -> int:
        with sqlite3.connect(body_db) as db:
            return int(
                db.execute(
                    "SELECT count(*) FROM executions WHERE command_id=?", (command,)
                ).fetchone()[0]
            )

    async def pressure_observed(previous: int) -> bool:
        assert processes["tbox"].poll() is None, log("tbox")
        return log("tbox").count("CapacityError") > previous

    async def durable_result(command: str) -> bool:
        with sqlite3.connect(tbox_db) as db:
            row = db.execute("SELECT state FROM commands WHERE id=?", (command,)).fetchone()
            return bool(row and row[0] == "succeeded")

    try:
        await start_body()
        await start_gateway()
        await start_tbox()
        first = await issue("day11-normal")
        await eventually(lambda: state(first, "succeeded"))
        assert count_executions(first) == 1
        with sqlite3.connect(body_db) as db:
            assert db.execute("SELECT locked FROM body").fetchone()[0] == 1
        with sqlite3.connect(tbox_db) as db:
            wire = db.execute("SELECT payload FROM commands WHERE id=?", (first,)).fetchone()[0]
        async with aiomqtt.Client("127.0.0.1", port=mqtt_port) as publisher:
            await publisher.publish(f"tenants/e2e-tenant/vehicles/{vehicle}/commands", wire, qos=1)
        await asyncio.sleep(0.3)
        assert count_executions(first) == 1

        # Crash between SQLite acceptance and MQTT PUBACK. Then crash the Body ECU
        # after execution commit but before CAN response; HTTP is also unavailable.
        await stop("tbox")
        await stop("body")
        await stop("gateway")
        await start_body(crash=True)
        await start_gateway(crash=True)
        unavailable = {
            "DEVICE_API_URL": f"http://127.0.0.1:{udp_port()}",
            "DEVICE_CRASH_AFTER": "command_commit",
        }
        await start_tbox(unavailable)
        second = await issue("day11-command-crash")
        await eventually(lambda: exited("tbox", 70))
        await start_tbox(unavailable)
        await eventually(lambda: exited("gateway", 72))
        await start_gateway(crash=True)
        await eventually(lambda: exited("body", 71))
        await start_body(crash=True)
        await eventually(lambda: durable_result(second))
        with sqlite3.connect(tbox_db) as db:
            assert (
                db.execute(
                    "SELECT count(*) FROM reports WHERE command_id=? AND state='pending'", (second,)
                ).fetchone()[0]
                == 2
            )
        unsupported = await issue("day11-unsupported", "honk")
        previous_pressure = log("tbox").count("CapacityError")
        await eventually(lambda: pressure_observed(previous_pressure))
        with sqlite3.connect(tbox_db) as db:
            assert (
                db.execute("SELECT 1 FROM commands WHERE id=?", (unsupported,)).fetchone() is None
            )
        await stop("tbox")
        await start_tbox()
        await eventually(lambda: state(second, "succeeded"))
        await eventually(lambda: state(unsupported, "failed"))
        assert count_executions(second) == 1

        # Persisted terminal result must survive an abrupt exit before HTTP delivery.
        await stop("tbox")
        await start_tbox({"DEVICE_CRASH_AFTER": "result_commit"})
        third = await issue("day11-result-crash", "unlock")
        await eventually(lambda: exited("tbox", 70))
        await start_tbox({"DEVICE_CRASH_AFTER": "result_commit"})
        await eventually(lambda: state(third, "succeeded"))
        assert count_executions(third) == 1
        with sqlite3.connect(body_db) as db:
            assert db.execute("SELECT locked FROM body").fetchone()[0] == 0

        unsupported = await issue("day11-unsupported", "honk")
        await eventually(lambda: state(unsupported, "failed"))
        assert count_executions(unsupported) == 0

        # Existing persistent MQTT subscription buffers a command during T-Box downtime.
        await stop("tbox")
        async with aiomqtt.Client("127.0.0.1", port=mqtt_port) as observer:
            await observer.subscribe(f"tenants/e2e-tenant/vehicles/{vehicle}/commands", qos=1)
            fifth = await issue("day11-offline-session")
            async with asyncio.timeout(15):
                message = await anext(observer.messages)
            assert json.loads(message.payload)["command_id"] == fifth
        # Graceful broker restart flushes its durable session and queued command to disk.
        await asyncio.to_thread(restart_broker)
        await start_tbox()
        await eventually(lambda: state(fifth, "succeeded"))
        assert count_executions(fifth) == 1
        # Exercise the same operator inspection commands documented for recovery.
        snapshots = {}
        for role, module, arguments in (
            ("tbox", "simulators.vehicle_device", ["--reconcile", str(tbox_db)]),
            ("gateway", "simulators.gateway", ["--database", str(gateway_db), "--inspect"]),
            ("body", "simulators.body_ecu", ["--database", str(body_db), "--inspect"]),
        ):
            output = await asyncio.to_thread(
                subprocess.check_output,
                [sys.executable, "-m", module, *arguments],
                cwd=tmp_path,
                env=device_env,
                text=True,
                timeout=8,
            )
            snapshots[role] = json.loads(output)
        assert len(snapshots["tbox"]["commands"]) == 5
        assert len(snapshots["tbox"]["reports"]) == 10
        assert all(row["state"] == "delivered" for row in snapshots["tbox"]["reports"])
        assert len(snapshots["gateway"]["routes"]) == 4
        assert all(row["state"] == "completed" for row in snapshots["gateway"]["routes"])
        assert len(snapshots["body"]["executions"]) == 4
        assert snapshots["body"]["locked"] is True
        evidence = {
            "scope": "local-virtual-can",
            "independent_processes": 6,
            "commands": [first, second, third, unsupported, fifth],
            "crash_recovery": ["command_commit", "route_commit", "ecu_commit", "result_commit"],
            "http_outage_recovered": True,
            "broker_restart_recovered": True,
            "capacity_backpressure_recovered": True,
            "duplicate_execution_count": 1,
            "physical_can_proven": False,
        }
        (tmp_path / "day11-evidence.json").write_text(
            json.dumps(evidence, indent=2), encoding="utf-8"
        )
        if directory := os.environ.get("RUNTIME_EVIDENCE_DIR"):
            target = Path(directory)
            target.mkdir(parents=True, exist_ok=True)
            (target / "day11-evidence.json").write_text(
                json.dumps(evidence, indent=2), encoding="utf-8"
            )
    finally:
        for role in ("tbox", "gateway", "body"):
            if role in processes:
                await stop(role)
        assert "device_stopped" in log("tbox")
        assert "body_ecu_stopped" in log("body")
        assert "gateway_stopped" in log("gateway")
