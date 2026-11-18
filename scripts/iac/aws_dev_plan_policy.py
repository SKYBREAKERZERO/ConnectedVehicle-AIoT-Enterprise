"""Fail-closed policy for first-stage real AWS dev foundation plan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ALLOWED = {
    "aws_vpc", "aws_subnet", "aws_route_table", "aws_route_table_association",
    "aws_security_group", "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule", "aws_vpc_endpoint",
    "aws_ecr_repository", "aws_cloudwatch_log_group", "aws_ecs_cluster",
    "aws_iam_role", "aws_iam_role_policy",
}
EXPECTED = {"aws_vpc", "aws_subnet", "aws_vpc_endpoint", "aws_ecr_repository",
            "aws_ecs_cluster", "aws_iam_role", "aws_iam_role_policy",
            "aws_cloudwatch_log_group"}


def evaluate(plan: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if not isinstance(plan, dict) or not str(plan.get("format_version", "")).startswith("1."):
        return ["Unsupported or missing Terraform plan format"]
    if plan.get("errored") or plan.get("complete") is False or plan.get("deferred_changes"):
        issues.append("Incomplete/errored/deferred plan")
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        return [*issues, "Missing resource changes"]
    kinds: set[str] = set()
    for resource in changes:
        if resource.get("mode", "managed") != "managed":
            continue
        addr = str(resource.get("address", "unknown"))
        kind = resource.get("type")
        kinds.add(str(kind))
        if kind not in ALLOWED:
            issues.append(f"{addr}: unapproved resource type {kind}")
        change = resource.get("change", {})
        actions = change.get("actions", [])
        if actions not in (["create"], ["no-op"], ["read"]):
            issues.append(f"{addr}: mutation beyond first provisioning not approved: {actions}")
        if kind == "aws_iam_role":
            after = change.get("after") or {}
            raw = after.get("assume_role_policy")
            try:
                policy = json.loads(raw)
                statement = policy["Statement"][0]
                if (
                    statement.get("Principal") != {"Service": "ecs-tasks.amazonaws.com"}
                    or statement.get("Action") != "sts:AssumeRole"
                    or not statement.get("Condition", {})
                    .get("StringEquals", {})
                    .get("aws:SourceAccount")
                    or not statement.get("Condition", {})
                    .get("ArnLike", {})
                    .get("aws:SourceArn")
                ):
                    issues.append(f"{addr}: weak ECS trust policy")
            except (ValueError, TypeError, KeyError, IndexError):
                issues.append(f"{addr}: unreadable ECS trust policy")
        if kind == "aws_iam_role_policy":
            after = change.get("after") or {}
            try:
                statements = json.loads(after["policy"])["Statement"]
                for s in statements:
                    acts = s.get("Action", [])
                    acts = [acts] if isinstance(acts, str) else acts
                    if s.get("Effect") != "Allow" or not acts or any("*" in a for a in acts):
                        issues.append(f"{addr}: broad IAM action")
                    if s.get("Resource") == "*" and acts != ["ecr:GetAuthorizationToken"]:
                        issues.append(f"{addr}: broad IAM resource")
            except (ValueError, TypeError, KeyError):
                issues.append(f"{addr}: unreadable IAM policy")
    if not EXPECTED.issubset(kinds):
        issues.append(f"Missing foundation resource kinds: {sorted(EXPECTED-kinds)}")
    if plan.get("planned_values") is None:
        issues.append("Missing planned values")
    return sorted(set(issues))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan", type=Path)
    args = parser.parse_args()
    try:
        issues = evaluate(json.loads(args.plan.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        issues = ["Invalid or missing plan JSON"]
    for issue in issues:
        print(issue)
    print(f"AWS dev plan gate: {'FAIL' if issues else 'PASS'}")
    return int(bool(issues))


if __name__ == "__main__":
    raise SystemExit(main())
