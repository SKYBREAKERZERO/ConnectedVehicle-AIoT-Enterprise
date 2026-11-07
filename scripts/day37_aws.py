"""Bounded ECR immutable promotion and ECS Staging deployment proof/recovery.

Use only after branch-protected admission and separate GitHub Environment OIDC.
No database downgrade, Terraform State access outside Terraform, or production Apply.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from scripts.day37_gate import DIGEST, PRODUCTION_FALSE, SHA, dump, strict_load

REGION = "ap-northeast-1"
REPO = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"


def command(args: list[str], *, input_text: str | None = None, timeout: int = 240) -> str:
    result = subprocess.run(args, text=True, input=input_text, capture_output=True, timeout=timeout)
    if result.returncode:
        operation = args[1] if len(args) > 1 else ""
        raise ValueError(f"Staging command failed: {args[0]} {operation} ({result.returncode})")
    return result.stdout.strip()


def aws(*args: str) -> dict[str, Any]:
    value = json.loads(command(["aws", *args, "--region", REGION, "--output", "json"]))
    if not isinstance(value, dict):
        raise ValueError("Invalid AWS JSON response")
    return value


def account(expected: str) -> None:
    if not re.fullmatch(r"[0-9]{12}", expected):
        raise ValueError("Staging account configuration missing")
    identity = aws("sts", "get-caller-identity")
    if identity.get("Account") != expected:
        raise ValueError("AWS STS account mismatch")
    role = os.environ.get("DAY37_ROLE_ARN", "")
    match = re.fullmatch(
        r"arn:aws:iam::([0-9]{12}):role/(?:[A-Za-z0-9_+=,.@/-]*/)?([A-Za-z0-9_+=,.@-]*staging[A-Za-z0-9_+=,.@-]*)",
        role,
    )
    if not match or match.group(1) != expected:
        raise ValueError("Only an exact staging-scoped configured IAM role is allowed")
    if not identity.get("Arn", "").startswith(
        f"arn:aws:sts::{expected}:assumed-role/{match.group(2)}/"
    ):
        raise ValueError("STS caller differs from the protected Staging environment role")


def context() -> dict[str, str]:
    result = {
        "commit": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    if not SHA.fullmatch(result["commit"]) or not all(result.values()):
        raise ValueError("Missing exact GitHub execution context")
    return result


def check_ecr(repo: str, account_id: str) -> str:
    account(account_id)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]{1,120}", repo) or "staging" not in repo:
        raise ValueError("Only scoped staging ECR Repository accepted")
    data = aws("ecr", "describe-repositories", "--repository-names", repo)
    rows = data.get("repositories", [])
    uri = f"{account_id}.dkr.ecr.{REGION}.amazonaws.com/{repo}"
    if (
        len(rows) != 1
        or rows[0].get("repositoryUri") != uri
        or rows[0].get("registryId") != account_id
        or rows[0].get("imageTagMutability") != "IMMUTABLE"
        or rows[0].get("encryptionConfiguration", {}).get("encryptionType") not in {"AES256", "KMS"}
    ):
        raise ValueError("Exact immutable encrypted staging ECR not verified")
    return uri


def read_manifest(repo: str, tag: str, account_id: str) -> dict[str, str]:
    tagged = aws(
        "ecr", "describe-images", "--repository-name", repo, "--image-ids", "imageTag=" + tag
    )
    rows = tagged.get("imageDetails", [])
    if len(rows) != 1:
        raise ValueError("Missing ECR tagged image")
    digest = rows[0].get("imageDigest", "")
    if not DIGEST.fullmatch(digest):
        raise ValueError("Invalid ECR Registry Manifest Digest")
    data = aws(
        "ecr", "batch-get-image", "--repository-name", repo, "--image-ids", "imageDigest=" + digest
    )
    if data.get("failures") or len(data.get("images", [])) != 1:
        raise ValueError("ECR BatchGetImage failed")
    record = data["images"][0]
    manifest = record.get("imageManifest", "")
    if (
        record.get("imageId", {}).get("imageDigest") != digest
        or "sha256:" + hashlib.sha256(manifest.encode()).hexdigest() != digest
    ):
        raise ValueError("ECR digest does not authenticate manifest bytes")
    info = json.loads(manifest)
    config = info.get("config", {}).get("digest")
    if not DIGEST.fullmatch(config or ""):
        raise ValueError("Expected single-platform OCI/Docker image manifest with config digest")
    return {
        "registry_digest": digest,
        "config_digest": config,
        "image_uri": f"{account_id}.dkr.ecr.{REGION}.amazonaws.com/{repo}@{digest}",
    }


def publish(
    folder: Path, image_id: str, account_id: str, repo: str, output: Path
) -> dict[str, Any]:
    meta = strict_load(folder / "images.json")
    candidate = meta["candidate"]
    ctx = context()
    supply = strict_load(folder / "supply-chain.json")
    record = supply["images"]["candidate"]
    if (
        meta.get("candidate_sha") != ctx["commit"]
        or candidate.get("revision") != ctx["commit"]
        or candidate.get("image_digest") != image_id
        or not DIGEST.fullmatch(image_id)
        or record.get("image_digest") != image_id
        or record.get("revision") != ctx["commit"]
        or not DIGEST.fullmatch(record.get("config_digest", ""))
    ):
        raise ValueError("Day36 candidate build/config/SBOM identity mismatch")
    inspection = json.loads(command(["docker", "image", "inspect", image_id]))
    if (
        len(inspection) != 1
        or inspection[0].get("Id") != image_id
        or inspection[0]
        .get("Config", {})
        .get("Labels", {})
        .get("org.opencontainers.image.revision")
        != ctx["commit"]
    ):
        raise ValueError("Local Docker image config/source mismatch")
    registry = check_ecr(repo, account_id)
    tag = f"sha-{ctx['commit']}-run-{ctx['run_id']}-a{ctx['run_attempt']}"
    # Immutable tag must not exist; retries use a new attempt. No overwrite.
    probe = subprocess.run(
        [
            "aws",
            "ecr",
            "describe-images",
            "--repository-name",
            repo,
            "--image-ids",
            "imageTag=" + tag,
            "--region",
            REGION,
        ],
        capture_output=True,
        text=True,
    )
    if probe.returncode == 0:
        raise ValueError("Staging immutable tag already exists")
    # Other failures besides ImageNotFound must block rather than be interpreted as absence.
    if "ImageNotFoundException" not in probe.stderr:
        raise ValueError("Cannot establish absent immutable ECR tag")
    password = command(["aws", "ecr", "get-login-password", "--region", REGION])
    command(
        ["docker", "login", "--username", "AWS", "--password-stdin", registry.split("/")[0]],
        input_text=password + "\n",
    )
    command(["docker", "tag", image_id, f"{registry}:{tag}"])
    command(["docker", "push", f"{registry}:{tag}"], timeout=1200)
    manifest = read_manifest(repo, tag, account_id)
    if manifest["config_digest"] != record["config_digest"]:
        raise ValueError("Registry Manifest config differs from Day36 inspected/scanned config")
    command(["cosign", "sign", "--yes", manifest["image_uri"]], timeout=300)
    # Publish the *verified Day36 CycloneDX SBOM* as a signed OCI attestation.
    sbom = folder / "candidate-sbom.json"
    if sbom.is_symlink() or not sbom.is_file() or sbom.stat().st_size > 12_000_000:
        raise ValueError("Missing/unsafe Day36 candidate SBOM")
    command(
        [
            "cosign",
            "attest",
            "--yes",
            "--predicate",
            str(sbom),
            "--type",
            "cyclonedx",
            manifest["image_uri"],
        ],
        timeout=300,
    )
    # Exact workflow certificate identity and GitHub issuer must match, not just any signature.
    identity = f"https://github.com/{REPO}/.github/workflows/day37-aws-staging.yml@refs/heads/main"
    command(
        [
            "cosign",
            "verify",
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            manifest["image_uri"],
        ],
        timeout=180,
    )
    command(
        [
            "cosign",
            "verify-attestation",
            "--type",
            "cyclonedx",
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            manifest["image_uri"],
        ],
        timeout=180,
    )
    result = {
        **ctx,
        **manifest,
        "aws_account_id": account_id,
        "region": REGION,
        "repository": repo,
        "day36_run_id": os.environ.get("UPSTREAM_DAY36_RUN_ID"),
        "day36_attempt": os.environ.get("UPSTREAM_DAY36_ATTEMPT"),
        "image_id": image_id,
        "sbom_sha256": hashlib.sha256(sbom.read_bytes()).hexdigest(),
        "scan_sha256": record["scan_sha256"],
        "tag": tag,
        "signature_verified": True,
        "sbom_attestation_verified": True,
        "day36_upstream_verified": True,
        "decision": "SIGNED_IMMUTABLE_ECR_IMAGE",
        **PRODUCTION_FALSE,
    }
    dump(output, result)
    return result


def verify_release(path: Path, account_id: str, repo: str, output: Path) -> dict[str, Any]:
    evidence = strict_load(path)
    if any(evidence.get(k) != v for k, v in context().items()):
        raise ValueError("Release artifact does not belong to this GitHub Run/Attempt")
    if (
        evidence.get("aws_account_id") != account_id
        or evidence.get("repository") != repo
        or evidence.get("signature_verified") is not True
        or evidence.get("sbom_attestation_verified") is not True
        or evidence.get("decision") != "SIGNED_IMMUTABLE_ECR_IMAGE"
    ):
        raise ValueError("Unsigned, foreign, or malformed ECR release record")
    check_ecr(repo, account_id)
    found = read_manifest(repo, evidence["tag"], account_id)
    if any(evidence.get(k) != v for k, v in found.items()):
        raise ValueError("ECR record drift or incorrect manifest/config digest")
    identity = f"https://github.com/{REPO}/.github/workflows/day37-aws-staging.yml@refs/heads/main"
    command(
        [
            "cosign",
            "verify",
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            found["image_uri"],
        ],
        timeout=180,
    )
    command(
        [
            "cosign",
            "verify-attestation",
            "--type",
            "cyclonedx",
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            found["image_uri"],
        ],
        timeout=180,
    )
    result = {
        **context(),
        **found,
        "aws_account_id": account_id,
        "decision": "SIGNED_ECR_MANIFEST_REVERIFIED",
        **PRODUCTION_FALSE,
    }
    dump(output, result)
    return result


def bootstrap_verify(account_id: str, repo: str, cluster: str, output: Path) -> dict[str, Any]:
    check_ecr(repo, account_id)
    result = aws("ecs", "describe-clusters", "--clusters", cluster)
    clusters = result.get("clusters", [])
    if (
        result.get("failures")
        or len(clusters) != 1
        or clusters[0].get("status") != "ACTIVE"
        or clusters[0].get("clusterName") != cluster
    ):
        raise ValueError("Staging ECS Cluster not independently verified")
    evidence = {
        **context(),
        "decision": "STAGING_INFRA_BOOTSTRAPPED",
        "aws_account_id": account_id,
        "region": REGION,
        "cluster": cluster,
        "ecr_repository": repo,
        **PRODUCTION_FALSE,
    }
    dump(output, evidence)
    return evidence


def checkpoint(account_id: str, cluster: str, service: str, output: Path) -> dict[str, Any]:
    account(account_id)
    rows = aws("ecs", "describe-services", "--cluster", cluster, "--services", service).get(
        "services", []
    )
    alive = [x for x in rows if x.get("status") == "ACTIVE"]
    if len(alive) > 1:
        raise ValueError("Ambiguous ECS staging service")
    result: dict[str, Any] = {
        **context(),
        "aws_account_id": account_id,
        "cluster": cluster,
        "service": service,
        "exists": bool(alive),
        **PRODUCTION_FALSE,
    }
    if alive:
        task = alive[0]["taskDefinition"]
        if not task.startswith(f"arn:aws:ecs:{REGION}:{account_id}:task-definition/cv-ota-staging"):
            raise ValueError("Preexisting task definition outside staging family")
        result["previous_task_definition"] = task
        result["previous_desired_count"] = alive[0].get("desiredCount", 0)
        if alive[0].get("runningCount", 0) < 1:
            raise ValueError("Cannot designate unhealthy service as recovery baseline")
    dump(output, result)
    return result


def service_readback(
    account_id: str, cluster: str, service: str, target_group: str, uri: str, desired: int
) -> dict[str, Any]:
    """Read actual RUNNING Fargate tasks, not merely their Task Definition.

    A PRIMARY deployment alone cannot prove the digest of live containers. Require
    an exact running task set and match every task's container imageDigest and ENI
    private IP to a healthy ALB target (no foreign target accepted as evidence).
    """
    account(account_id)
    expected_prefix = f"{account_id}.dkr.ecr.{REGION}.amazonaws.com/"
    expected_digest = uri.rsplit("@", 1)[-1]
    if (
        not uri.startswith(expected_prefix)
        or "@" not in uri
        or not DIGEST.fullmatch(expected_digest)
        or desired < 1
    ):
        raise ValueError("ECS image URI must use exact staging ECR manifest digest")
    data = aws("ecs", "describe-services", "--cluster", cluster, "--services", service)
    rows = data.get("services", [])
    if data.get("failures") or len(rows) != 1:
        raise ValueError("ECS service not found")
    svc = rows[0]
    deployments = svc.get("deployments", [])
    if (
        svc.get("status") != "ACTIVE"
        or svc.get("desiredCount") != desired
        or svc.get("runningCount") != desired
        or svc.get("pendingCount") != 0
        or len(deployments) != 1
        or deployments[0].get("status") != "PRIMARY"
        or deployments[0].get("rolloutState") != "COMPLETED"
    ):
        raise ValueError("ECS deployment not stable at exact desired count")
    task_def = svc.get("taskDefinition", "")
    if not task_def.startswith(f"arn:aws:ecs:{REGION}:{account_id}:task-definition/cv-ota-staging"):
        raise ValueError("ECS Task Definition outside reviewed Staging family")
    definition = aws("ecs", "describe-task-definition", "--task-definition", task_def)[
        "taskDefinition"
    ]
    definitions = definition.get("containerDefinitions", [])
    if (
        len(definitions) != 1
        or definitions[0].get("name") != "vehicle-api"
        or definitions[0].get("image") != uri
    ):
        raise ValueError("ECS Task Definition does not reference verified manifest digest")
    if "FARGATE" not in definition.get("requiresCompatibilities", []):
        raise ValueError("Unexpected ECS launch type")

    listed = aws(
        "ecs",
        "list-tasks",
        "--cluster",
        cluster,
        "--service-name",
        service,
        "--desired-status",
        "RUNNING",
        "--max-results",
        "100",
    )
    arns = listed.get("taskArns", [])
    if (
        listed.get("nextToken")
        or not isinstance(arns, list)
        or len(arns) != desired
        or len(set(arns)) != desired
    ):
        raise ValueError("Incomplete, ambiguous or paginated running ECS Task list")
    described = aws("ecs", "describe-tasks", "--cluster", cluster, "--tasks", *arns)
    tasks = described.get("tasks", [])
    if (
        described.get("failures")
        or len(tasks) != desired
        or {t.get("taskArn") for t in tasks} != set(arns)
    ):
        raise ValueError("ECS describe-tasks mismatch")
    task_proofs = []
    private_ips = set()
    for task in tasks:
        containers = task.get("containers", [])
        if (
            task.get("lastStatus") != "RUNNING"
            or task.get("desiredStatus") != "RUNNING"
            or task.get("healthStatus") != "HEALTHY"
            or task.get("taskDefinitionArn") != task_def
            or task.get("group") != "service:" + service
            or task.get("launchType") != "FARGATE"
            or len(containers) != 1
        ):
            raise ValueError("Non-healthy, foreign or stale ECS running Task")
        container = containers[0]
        if (
            container.get("name") != "vehicle-api"
            or container.get("image") != uri
            or container.get("imageDigest") != expected_digest
            or container.get("lastStatus") != "RUNNING"
            or container.get("healthStatus") != "HEALTHY"
        ):
            raise ValueError("Actual ECS container imageDigest or health mismatch")
        addresses = [
            item.get("value")
            for attachment in task.get("attachments", [])
            if attachment.get("type") == "ElasticNetworkInterface"
            for item in attachment.get("details", [])
            if item.get("name") == "privateIPv4Address"
        ]
        if len(addresses) != 1 or not addresses[0] or addresses[0] in private_ips:
            raise ValueError("Cannot bind Task to unique ENI private IP")
        private_ips.add(addresses[0])
        task_proofs.append(
            {
                "task_arn": task["taskArn"],
                "image_digest": expected_digest,
                "task_definition": task_def,
                "private_ip": addresses[0],
                "health": "HEALTHY",
            }
        )

    target_data = aws("elbv2", "describe-target-health", "--target-group-arn", target_group)
    targets = target_data.get("TargetHealthDescriptions", [])
    healthy_ips = {
        x.get("Target", {}).get("Id")
        for x in targets
        if x.get("TargetHealth", {}).get("State") == "healthy"
        and x.get("Target", {}).get("Port") == 8000
    }
    if not private_ips.issubset(healthy_ips) or len(healthy_ips) < desired:
        raise ValueError("ALB target health does not cover the actual ECS Task ENIs")
    return {
        **context(),
        "decision": "ECS_TASK_DIGEST_HEALTH_VERIFIED",
        "aws_account_id": account_id,
        "region": REGION,
        "cluster": cluster,
        "service": service,
        "task_definition": task_def,
        "image_uri": uri,
        "registry_digest": expected_digest,
        "desired_count": desired,
        "running_count": desired,
        "tasks": sorted(task_proofs, key=lambda row: row["task_arn"]),
        "alb_healthy_targets": len(healthy_ips),
        **PRODUCTION_FALSE,
    }


def recover(checkpoint_file: Path, output: Path) -> dict[str, Any]:
    proof = strict_load(checkpoint_file)
    ctx = context()
    if any(proof.get(k) != v for k, v in ctx.items()):
        raise ValueError("Recovery checkpoint from different Commit/Run/Attempt")
    if (
        proof.get("aws_account_id") != os.environ.get("DAY37_ACCOUNT_ID")
        or proof.get("cluster") != os.environ.get("DAY37_CLUSTER")
        or proof.get("service") != os.environ.get("DAY37_SERVICE")
    ):
        raise ValueError("Recovery artifact targets an unapproved AWS Staging resource")
    account(proof["aws_account_id"])
    if not proof.get("exists"):
        raise ValueError("No previously healthy ECS Task Definition; manual recovery required")
    task = proof["previous_task_definition"]
    desired = proof["previous_desired_count"]
    cluster, service = proof["cluster"], proof["service"]
    aws(
        "ecs",
        "update-service",
        "--cluster",
        cluster,
        "--service",
        service,
        "--task-definition",
        task,
        "--desired-count",
        str(desired),
    )
    command(
        [
            "aws",
            "ecs",
            "wait",
            "services-stable",
            "--cluster",
            cluster,
            "--services",
            service,
            "--region",
            REGION,
        ],
        timeout=900,
    )
    current = aws("ecs", "describe-services", "--cluster", cluster, "--services", service)[
        "services"
    ]
    if (
        len(current) != 1
        or current[0]["taskDefinition"] != task
        or current[0].get("runningCount", 0) < desired
    ):
        raise ValueError("Old Staging Task Definition recovery failed")
    result = {
        **ctx,
        "decision": "STAGING_RECOVERY_EXECUTED_RELEASE_BLOCKED",
        "aws_account_id": proof["aws_account_id"],
        "old_task_definition": task,
        "schema_rollback_executed": False,
        "terraform_reconciliation_required": True,
        "recovery_fence_remains_active": True,
        **PRODUCTION_FALSE,
    }
    dump(output, result)
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "command",
        choices=(
            "publish",
            "verify-release",
            "bootstrap-verify",
            "checkpoint",
            "verify",
            "recover",
        ),
    )
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--account", default=os.getenv("DAY37_ACCOUNT_ID", ""))
    p.add_argument("--repository", default=os.getenv("DAY37_ECR_REPOSITORY", ""))
    p.add_argument("--folder", type=Path)
    p.add_argument("--input", type=Path)
    p.add_argument("--image-id")
    p.add_argument("--cluster", default=os.getenv("DAY37_CLUSTER", ""))
    p.add_argument("--service", default=os.getenv("DAY37_SERVICE", ""))
    p.add_argument("--target-group", default=os.getenv("DAY37_ALB_TARGET_GROUP_ARN", ""))
    p.add_argument("--image-uri")
    p.add_argument("--desired", type=int, default=2)
    p.add_argument("--checkpoint", type=Path)
    args = p.parse_args()
    try:
        if args.command == "publish":
            if args.folder is None or args.image_id is None:
                raise ValueError("Verified Day36 folder and immutable image ID required")
            publish(args.folder, args.image_id, args.account, args.repository, args.output)
        elif args.command == "verify-release":
            if args.input is None:
                raise ValueError("Release evidence required")
            verify_release(args.input, args.account, args.repository, args.output)
        elif args.command == "bootstrap-verify":
            bootstrap_verify(args.account, args.repository, args.cluster, args.output)
        elif args.command == "checkpoint":
            checkpoint(args.account, args.cluster, args.service, args.output)
        elif args.command == "recover":
            if args.checkpoint is None:
                raise ValueError("Checkpoint required")
            recover(args.checkpoint, args.output)
        else:
            if not args.image_uri:
                raise ValueError("Registry Digest URI required")
            dump(
                args.output,
                service_readback(
                    args.account,
                    args.cluster,
                    args.service,
                    args.target_group,
                    args.image_uri,
                    args.desired,
                ),
            )
    except (ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as error:
        dump(args.output, {"decision": "BLOCKED", "reason": str(error), **PRODUCTION_FALSE})
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
