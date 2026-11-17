"""Read-only AWS ECS Worker identity/digest/scale verification (NOT OTA acceptance)."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

KINDS = {
    "outbox": ["python", "-m", "apps.outbox_worker.main"],
    "remote_command": ["python", "-m", "apps.remote_command_worker.main"],
    "campaign": ["python", "-m", "apps.campaign"],
}
Reader = Callable[..., dict[str, Any]]


def require(value: Any, message: str) -> None:
    if not value:
        raise ValueError("DAY39 WORKER BLOCKED: " + message)


def aws(*args: str) -> dict[str, Any]:
    result = subprocess.run(
        ["aws", *args, "--region", "ap-northeast-1", "--output", "json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    require(result.returncode == 0, "AWS read-only call failed")
    value = json.loads(result.stdout)
    require(isinstance(value, dict), "malformed AWS response")
    return cast(dict[str, Any], value)


def inspect(
    read: Reader,
    *,
    account: str,
    cluster: str,
    tenant: str,
    digest: str,
    counts: dict[str, int],
) -> dict[str, Any]:
    require(bool(re.fullmatch(r"[0-9]{12}", account)), "invalid account")
    require(cluster == "cv-ota-staging", "foreign ECS cluster")
    require(bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", tenant)), "invalid tenant")
    require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", digest)), "invalid manifest digest")
    require(
        set(counts) == set(KINDS) and all(type(v) is int and 0 <= v <= 2 for v in counts.values()),
        "invalid Worker cardinality",
    )
    identity = read("sts", "get-caller-identity")
    require(
        identity.get("Account") == account
        and str(identity.get("Arn", "")).startswith(
            f"arn:aws:sts::{account}:assumed-role/cv-ota-staging-verify/"
        ),
        "independent Staging verify role required",
    )
    # A scaled-to-zero service must remain ACTIVE in ECS, not vanish from
    # Terraform for_each/state. Never treat 0 desired as resource deletion.
    verified: dict[str, Any] = {}
    for kind, count in counts.items():
        name = "cv-ota-staging-" + kind.replace("_", "-")
        responses = read("ecs", "describe-services", "--cluster", cluster, "--services", name)
        rows = responses.get("services", [])
        require(len(rows) == 1 and not responses.get("failures"), "ECS service missing")
        service = rows[0]
        require(
            service.get("serviceName") == name
            and service.get("status") == "ACTIVE"
            and service.get("desiredCount") == count
            and service.get("runningCount") == count
            and service.get("pendingCount") == 0
            and any(
                d.get("status") == "PRIMARY" and d.get("rolloutState") == "COMPLETED"
                for d in service.get("deployments", [])
            ),
            "ECS Worker has not reached stable approved count",
        )
        if count == 0:
            items = read(
                "ecs", "list-tasks", "--cluster", cluster,
                "--service-name", name, "--desired-status", "RUNNING",
            )
            require(
                not items.get("taskArns") and not items.get("nextToken"),
                "Scaled-to-zero Worker still has RUNNING tasks",
            )
            verified[kind] = {
                "service": name,
                "running_count": 0,
                "task_definition": service.get("taskDefinition"),
                "task_arns": [],
            }
            continue
        items = read(
            "ecs",
            "list-tasks",
            "--cluster",
            cluster,
            "--service-name",
            name,
            "--desired-status",
            "RUNNING",
        )
        task_ids = items.get("taskArns", [])
        require(
            len(task_ids) == count and not items.get("nextToken"),
            "Worker Task listing is incomplete",
        )
        data = read("ecs", "describe-tasks", "--cluster", cluster, "--tasks", *task_ids)
        tasks = data.get("tasks", [])
        require(len(tasks) == count and not data.get("failures"), "missing running Worker Task")
        definition_arn = service.get("taskDefinition")
        td = read("ecs", "describe-task-definition", "--task-definition", definition_arn)
        definition = td.get("taskDefinition", {})
        containers = definition.get("containerDefinitions", [])
        expected_name = "worker-" + kind.replace("_", "-")
        require(
            len(containers) == 1
            and containers[0].get("name") == expected_name
            and containers[0].get("image", "").endswith("@" + digest)
            and containers[0].get("command") == KINDS[kind]
            and containers[0].get("readonlyRootFilesystem") is True
            and containers[0].get("stopTimeout") == 120
            and definition.get("taskRoleArn") == f"arn:aws:iam::{account}:role/{name}"
            and definition.get("executionRoleArn") == f"arn:aws:iam::{account}:role/{name}-exec",
            "Worker Task Definition differs from approved image/role/command",
        )
        environment = {
            row["name"]: row["value"]
            for row in containers[0].get("environment", [])
            if "name" in row and "value" in row
        }
        require(
            environment.get("DATABASE_TENANT_ID") == tenant
            and environment.get("CLOUD_RUNTIME") == "aws"
            and environment.get("AWS_ENDPOINT_URL") == "",
            "Worker tenant or AWS runtime mismatch",
        )
        for task in tasks:
            actual = task.get("containers", [])
            require(
                task.get("lastStatus") == "RUNNING"
                and task.get("launchType") == "FARGATE"
                and task.get("taskDefinitionArn") == definition_arn
                and len(actual) == 1
                and actual[0].get("lastStatus") == "RUNNING"
                and actual[0].get("imageDigest") == digest,
                "Worker Task is unhealthy or not running approved image",
            )
        verified[kind] = {
            "service": name,
            "running_count": count,
            "task_definition": definition_arn,
            "task_arns": task_ids,
        }
    return {
        "decision": (
            "WORKER_IDENTITY_VERIFIED" if any(counts.values())
            else "WORKER_SCALED_TO_ZERO_VERIFIED"
        ),
        "release_authorized": False,
        "aws_account_id": account,
        "region": "ap-northeast-1",
        "image_digest": digest,
        "verified": verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--counts-json", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.output.exists() and not args.output.is_symlink(), "existing receipt")
        counts = json.loads(args.counts_json)
        require(isinstance(counts, dict), "invalid Worker counts JSON")
        report = inspect(
            aws,
            account=args.account_id,
            cluster=args.cluster,
            tenant=args.tenant,
            digest=args.digest,
            counts=counts,
        )
        require(
            report["decision"] in {
                "WORKER_IDENTITY_VERIFIED", "WORKER_SCALED_TO_ZERO_VERIFIED"
            },
            "Worker Service is missing or not safely scaled to zero",
        )
        report["observed_at_utc"] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
        print("DAY39: Worker Task identity verified; OTA Runtime remains unverified")
        return 0
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        print("DAY39 WORKER BLOCKED: independent Runtime proof missing", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
