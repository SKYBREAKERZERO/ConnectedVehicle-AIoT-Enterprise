"""Adversarial ECS live Task-level digest checks (mocks are not AWS evidence)."""

from __future__ import annotations

import pytest

from scripts import day37_aws as a

ACCOUNT = "123456789012"
URI = (
    f"{ACCOUNT}.dkr.ecr.ap-northeast-1.amazonaws.com/cv-ota-staging/vehicle-api@sha256:" + "b" * 64
)
DEF = f"arn:aws:ecs:ap-northeast-1:{ACCOUNT}:task-definition/cv-ota-staging-api:15"


def responses():
    svc = {
        "status": "ACTIVE",
        "desiredCount": 2,
        "runningCount": 2,
        "pendingCount": 0,
        "taskDefinition": DEF,
        "deployments": [{"status": "PRIMARY", "rolloutState": "COMPLETED"}],
    }

    def task(n):
        return {
            "taskArn": f"arn:aws:ecs:ap-northeast-1:{ACCOUNT}:task/cv-ota-staging/{n}",
            "taskDefinitionArn": DEF,
            "lastStatus": "RUNNING",
            "desiredStatus": "RUNNING",
            "healthStatus": "HEALTHY",
            "group": "service:cv-ota-staging-api",
            "launchType": "FARGATE",
            "containers": [
                {
                    "name": "vehicle-api",
                    "image": URI,
                    "imageDigest": URI.split("@")[1],
                    "lastStatus": "RUNNING",
                    "healthStatus": "HEALTHY",
                }
            ],
            "attachments": [
                {
                    "type": "ElasticNetworkInterface",
                    "details": [{"name": "privateIPv4Address", "value": f"10.77.1.{n}"}],
                }
            ],
        }

    return {
        "describe-services": {"services": [svc], "failures": []},
        "describe-task-definition": {
            "taskDefinition": {
                "containerDefinitions": [{"name": "vehicle-api", "image": URI}],
                "requiresCompatibilities": ["FARGATE"],
            }
        },
        "list-tasks": {"taskArns": [task(1)["taskArn"], task(2)["taskArn"]]},
        "describe-tasks": {"tasks": [task(1), task(2)], "failures": []},
        "describe-target-health": {
            "TargetHealthDescriptions": [
                {
                    "Target": {"Id": f"10.77.1.{n}", "Port": 8000},
                    "TargetHealth": {"State": "healthy"},
                }
                for n in (1, 2)
            ]
        },
    }


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setattr(a, "account", lambda x: None)
    monkeypatch.setattr(
        a, "context", lambda: {"commit": "a" * 40, "run_id": "123", "run_attempt": "1"}
    )
    r = responses()
    monkeypatch.setattr(a, "aws", lambda *args: r[args[1]])
    return r


def check():
    return a.service_readback(
        ACCOUNT,
        "cv-ota-staging",
        "cv-ota-staging-api",
        "arn:aws:elasticloadbalancing:ap-northeast-1:" + ACCOUNT + ":targetgroup/cv/123",
        URI,
        2,
    )


def test_all_running_tasks_match_exact_ecr_manifest(fake):
    out = check()
    assert out["decision"] == "ECS_TASK_DIGEST_HEALTH_VERIFIED"
    assert len(out["tasks"]) == 2
    assert all(x["image_digest"] == URI.split("@")[1] for x in out["tasks"])


@pytest.mark.parametrize(
    "mutation", ["digest", "health", "taskdef", "eni", "alb", "pagination", "thirdtask"]
)
def test_single_task_mutation_fails_closed(fake, mutation):
    t = fake["describe-tasks"]["tasks"]
    if mutation == "digest":
        t[1]["containers"][0]["imageDigest"] = "sha256:" + "f" * 64
    elif mutation == "health":
        t[1]["healthStatus"] = "UNKNOWN"
    elif mutation == "taskdef":
        t[1]["taskDefinitionArn"] = DEF[:-1] + "9"
    elif mutation == "eni":
        t[1]["attachments"][0]["details"][0]["value"] = "10.77.1.1"
    elif mutation == "alb":
        fake["describe-target-health"]["TargetHealthDescriptions"][1]["TargetHealth"]["State"] = (
            "unhealthy"
        )
    elif mutation == "pagination":
        fake["list-tasks"]["nextToken"] = "token"
    else:
        fake["list-tasks"]["taskArns"].append("third")
    with pytest.raises(ValueError):
        check()
