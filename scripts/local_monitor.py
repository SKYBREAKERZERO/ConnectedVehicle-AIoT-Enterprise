"""Local-only collector, metrics exporter and Alertmanager webhook receiver."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def device_health(path: Path) -> dict[str, float]:
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1) as db:
        records = db.execute(
            "SELECT (SELECT count(*) FROM commands)+(SELECT count(*) FROM archived_commands)"
            "+(SELECT count(*) FROM report_replays)"
        ).fetchone()[0]
        blocked = db.execute(
            "SELECT count(*) FROM reports WHERE state='blocked' AND error='AUTH_RETRY_EXHAUSTED'"
        ).fetchone()[0]
        oldest = db.execute(
            "SELECT min(json_extract(payload,'$.occurred_at')) FROM reports "
            "WHERE state!='delivered'"
        ).fetchone()[0]
    age = max(0, time.time() - datetime.fromisoformat(oldest).timestamp()) if oldest else 0
    return {
        "vehicle_auth_blocked_reports": float(blocked),
        "vehicle_ledger_records": float(records),
        "vehicle_report_oldest_age_seconds": age,
    }


async def cloud_health(
    endpoint: str,
    secret_id: str,
    *,
    region: str = "ap-northeast-1",
) -> dict[str, float]:
    if urlparse(endpoint).hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("Monitor is LocalStack-only")
    import boto3
    from pydantic import SecretStr
    from sqlalchemy import text

    from enterprise_platform.config.settings import Settings
    from enterprise_platform.database.engine import create_database_engine

    client = boto3.client(
        "secretsmanager",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    payload = json.loads(
        (await asyncio.to_thread(client.get_secret_value, SecretId=secret_id))["SecretString"]
    )
    if payload["username"] != "observability_reader" or payload["host"] not in {
        "127.0.0.1",
        "localhost",
    }:
        raise ValueError("Monitor requires restricted loopback observability identity")
    settings = Settings.model_construct(
        database_host=payload["host"],
        database_port=payload["port"],
        database_name=payload["dbname"],
        database_username=payload["username"],
        database_password=SecretStr(payload["password"]),
    )
    engine = create_database_engine(settings)
    try:
        async with engine.connect() as connection:
            unsafe = await connection.scalar(
                text("""SELECT
                r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole
                OR r.rolreplication OR has_schema_privilege('public','CREATE')
                OR has_database_privilege(current_database(),'CREATE,TEMP')
                OR EXISTS (SELECT FROM pg_auth_members WHERE member=r.oid)
                OR EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname='public' AND c.relkind IN ('r','p') AND
                    (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE')
                     OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE')))
                FROM pg_roles r WHERE r.rolname=current_user""")
            )
            if unsafe:
                raise ValueError("Unsafe monitoring database identity")
            result = await connection.scalar(text("SELECT public.runtime_health_summary()"))
        return {
            "vehicle_stalled_vehicles": float(result["stalled_vehicles"]),
            "vehicle_waiting_commands": float(result["waiting_commands"]),
        }
    finally:
        await engine.dispose()


def collect(config: dict[str, Any]) -> dict[str, float]:
    values = {
        "vehicle_auth_blocked_reports": 0.0,
        "vehicle_ledger_records": 0.0,
        "vehicle_report_oldest_age_seconds": 0.0,
    }
    utilization = 0.0
    seen: set[Path] = set()
    for device in config["devices"]:
        path = Path(device["path"]).resolve()
        if path in seen or not isinstance(device["capacity"], int) or device["capacity"] < 1:
            raise ValueError("Device capacity must be positive and ledger paths unique")
        seen.add(path)
        health = device_health(path)
        utilization = max(utilization, health["vehicle_ledger_records"] / device["capacity"])
        for name, value in health.items():
            values[name] = (
                max(values[name], value) if name.endswith("age_seconds") else values[name] + value
            )
    values["vehicle_ledger_utilization_ratio"] = utilization
    values.update(
        asyncio.run(
            cloud_health(
                config["endpoint"],
                config["secret_id"],
                region=config.get("region", "ap-northeast-1"),
            )
        )
    )
    return values


def render_metrics(state: dict[str, Any], *, now: float | None = None) -> str:
    age = max(0, (now if now is not None else time.time()) - float(state.get("timestamp", 0)))
    values = dict(state.get("metrics", {}))
    values["vehicle_monitor_collection_success"] = float(bool(state.get("success")) and age <= 30)
    values["vehicle_monitor_sample_age_seconds"] = age
    return "".join(
        f"# TYPE {name} gauge\n{name} {float(value)}\n" for name, value in sorted(values.items())
    )


def server(mode: str, directory: Path, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if self.path != "/metrics" or mode != "exporter":
                self.send_error(404)
                return
            try:
                state = json.loads((directory / "health.json").read_text(encoding="utf-8"))
                body = render_metrics(state).encode()
            except (OSError, ValueError, TypeError):
                body = render_metrics({}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            if self.path != "/alerts" or mode != "receiver":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    raise ValueError("invalid length")
                value = json.loads(self.rfile.read(length))
                if not isinstance(value.get("alerts"), list):
                    raise ValueError("invalid alerts")
                directory.mkdir(parents=True, exist_ok=True)
                with (directory / "alerts.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"received_at": time.time(), "payload": value}) + "\n")
            except (OSError, ValueError, TypeError):
                self.send_error(400)
                return
            self.send_response(200)
            self.end_headers()

    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["collect", "exporter", "receiver"])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    if args.mode != "collect":
        server(args.mode, args.directory, args.port)
        return
    if args.config is None:
        parser.error("collect requires --config")
    args.directory.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            config = json.loads(args.config.read_text(encoding="utf-8"))
            state = {"timestamp": time.time(), "success": True, "metrics": collect(config)}
        except Exception as exc:  # Keep the collector alive; publish failed health without secrets.
            state = {"timestamp": time.time(), "success": False, "error_type": type(exc).__name__}
        temporary = args.directory / ".health.tmp"
        temporary.write_text(json.dumps(state) + "\n", encoding="utf-8")
        os.replace(temporary, args.directory / "health.json")
        time.sleep(5)


if __name__ == "__main__":
    main()
