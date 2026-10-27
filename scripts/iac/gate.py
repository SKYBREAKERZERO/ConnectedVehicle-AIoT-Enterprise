"""Portable IaC gate. All applies use an ephemeral LocalStack and copied state."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from uuid import uuid4

from scripts.iac.governance_schema import require_governance_schema
from scripts.iac.ota_database_policy import database_isolation_errors
from scripts.iac.plan_policy import evaluate
from scripts.iac.scan_policy import audit
from scripts.iac.state_lock_probe import probe as state_lock_probe

REPO = Path(__file__).resolve().parents[2]
# Public test image verified locally; no paid token or Docker socket mount required.
LOCALSTACK_IMAGE = (
    "localstack/localstack:4.14.0@"
    "sha256:3ebc37595918b8accb852f8048fef2aff047d465167edd655528065b07bc364a"
)
TFVARS: dict[str, Any] = {
    "project_name": "cv-iac-ci",
    "service_name": "connected-vehicle",
    "environment": "local",
    "owner": "iac-ci",
    "remote_command_queue_name": "cv-iac-command",
    "remote_command_dead_letter_queue_name": "cv-iac-command-dlq",
    "remote_command_encryption_mode": "kms",
    "remote_command_message_retention_seconds": 345600,
    "remote_command_dead_letter_message_retention_seconds": 1209600,
    "remote_command_visibility_timeout_seconds": 60,
    "remote_command_receive_wait_time_seconds": 20,
    "remote_command_delay_seconds": 0,
    "remote_command_max_message_size_bytes": 262144,
    "remote_command_max_receive_count": 5,
    "remote_command_kms_data_key_reuse_period_seconds": 300,
    "remote_command_enable_redrive_allow_policy": True,
}


def run(
    command: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    allowed: tuple[int, ...] = (0,),
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    if not quiet:
        print(result.stdout, end="", flush=True)
    if result.returncode not in allowed:
        if quiet:
            print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        raise RuntimeError(f"Command failed ({result.returncode}): {command[0]}")
    return result


def sandbox_environment(work: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(
            ("AWS_", "TF_", "CHECKOV_", "CKV_", "LOCALSTACK_", "TFC_", "TFE_", "HCP_", "BC_")
        )
        and key not in {"GH_TOKEN", "GITHUB_TOKEN"}
    }
    cli_config = work / "sandbox.tfrc"
    cli_config.write_text("disable_checkpoint = true\n", encoding="utf-8")
    env.update(
        {
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_DEFAULT_REGION": "ap-northeast-1",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_SHARED_CREDENTIALS_FILE": str(work / "no-credentials"),
            "AWS_CONFIG_FILE": str(work / "no-config"),
            "TF_CLI_CONFIG_FILE": str(cli_config),
            "TF_IN_AUTOMATION": "true",
            "TF_INPUT": "false",
            "CHECKOV_SKIP_DOWNLOAD": "true",
        }
    )
    # Reuse a download-only provider cache; Terraform state is never copied.
    cache = work / "provider-cache"
    cache.mkdir()
    env["TF_PLUGIN_CACHE_DIR"] = str(cache)
    return env


def copy_infra(source: Path, target: Path) -> None:
    shutil.copytree(
        source / "infra" / "terraform",
        target,
        ignore=shutil.ignore_patterns(
            ".terraform",
            "*.tfstate*",
            "*.tfplan",
            "*.tfvars",
            "*.auto.tfvars*",
            "*.tfvars.json",
            ".env*",
            "*.pem",
            "*.key",
            "*.log",
        ),
    )


def terraform(
    root: Path,
    *args: str,
    env: dict[str, str],
    quiet: bool = False,
    allowed: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    return run(["terraform", *args], cwd=root, env=env, quiet=quiet, allowed=allowed)


def initialize(root: Path, *, env: dict[str, str], lock: Path | None = None) -> None:
    print(f"Terraform init/validate: {root.name}", flush=True)
    if lock and not (root / ".terraform.lock.hcl").exists():
        shutil.copy2(lock, root / ".terraform.lock.hcl")
    if not (root / ".terraform.lock.hcl").exists():
        raise RuntimeError(f"Missing committed provider lock for {root.name}")
    parser = importlib.import_module("hcl2")
    docs = []
    if list(root.glob("*.tf.json")):
        raise RuntimeError("JSON backend declarations need an explicit isolation review")
    for file in root.glob("*.tf"):
        with file.open(encoding="utf-8") as stream:
            docs.append(parser.load(stream))
    require_local_backends(docs)
    # Only a validated relative local backend may be initialized in the copied root.
    terraform(root, "init", "-lockfile=readonly", "-no-color", env=env, quiet=True)
    terraform(root, "validate", "-no-color", env=env)


def require_local_backends(docs: list[dict[str, Any]]) -> None:
    for doc in docs:
        for block in doc.get("terraform", []):
            for backend in block.get("backend", []):
                if set(backend) != {"local"}:
                    raise RuntimeError("Gate backend must be local and stay inside its copied root")
                local = backend["local"]
                if set(local) != {"path"} or local["path"] not in (
                    "terraform.tfstate",
                    ["terraform.tfstate"],
                ):
                    raise RuntimeError("Gate backend must be local and stay inside its copied root")


def save_plan(root: Path, name: str, *, env: dict[str, str]) -> tuple[int, dict[str, Any]]:
    binary = root / f"{name}.tfplan"
    result = terraform(
        root,
        "plan",
        "-input=false",
        "-no-color",
        "-detailed-exitcode",
        "-var-file=ci.tfvars.json",
        f"-out={binary}",
        env=env,
        allowed=(0, 2),
    )
    shown = terraform(root, "show", "-json", str(binary), env=env, quiet=True)
    return result.returncode, json.loads(shown.stdout)


def require_policy(plan: dict[str, Any], phase: str) -> None:
    issues = evaluate(plan, "changes" if phase == "changes" else "resolved")
    if issues:
        raise RuntimeError("Plan policy rejected:\n" + "\n".join(issues))
    print(f"Plan policy ({phase}): PASS", flush=True)


def gate(repo: Path, baseline: Path, *, work: Path, report: Path, scanner_python: str) -> None:
    env = sandbox_environment(work)

    candidate = work / "candidate"
    original = work / "baseline"
    copy_infra(repo, candidate)
    copy_infra(baseline, original)
    (candidate / "environments/local/terraform.tfvars.json").write_text(
        json.dumps({**TFVARS, "aws_endpoint_url": "http://127.0.0.1:4566"}), encoding="utf-8"
    )
    terraform(candidate, "fmt", "-check", "-recursive", "-no-color", env=env)
    roots = sorted(p for p in (candidate / "environments").iterdir() if list(p.glob("*.tf")))
    old_roots = {
        p.name for p in (original / "environments").iterdir() if p.is_dir() and list(p.glob("*.tf"))
    }
    current_roots = {p.name for p in roots if p.is_dir() and list(p.glob("*.tf"))}
    if old_roots - current_roots:
        raise RuntimeError(f"Environment removal prohibited: {sorted(old_roots - current_roots)}")
    lock = candidate / "environments" / "local" / ".terraform.lock.hcl"
    contract_count = 0
    contract_runs = 0
    bootstrap_roots = [p.parent for p in (candidate / "bootstrap").rglob("versions.tf")]
    for root in (
        [p for p in roots if p.is_dir()]
        + bootstrap_roots
        + sorted((candidate / "modules").rglob("versions.tf"))
    ):
        root = root.parent if root.is_file() else root
        initialize(root, env=env, lock=lock if "modules" in root.parts else None)
        if root.name == "ota-governance":
            schema = terraform(root, "providers", "schema", "-json", env=env, quiet=True)
            require_governance_schema(json.loads(schema.stdout))
        tests = list((root / "tests").glob("*.tftest.hcl"))
        if "modules" in root.parts and not tests:
            raise RuntimeError(f"Module has no contract tests: {root.relative_to(candidate)}")
        if tests:
            tested = terraform(root, "test", "-no-color", env=env)
            passed = re.search(r"Success! ([0-9]+) passed", tested.stdout)
            if not passed or int(passed[1]) == 0:
                raise RuntimeError(f"No active contract assertions for {root.name}")
            contract_runs += int(passed[1])
            contract_count += len(tests)
        if root.parent.name == "environments" and root.name not in {"local", "ota-local"}:
            # No AWS deployment/state yet; adding one must not silently bypass policy.
            _, empty = _empty_root_plan(root, env)
            if empty.get("resource_changes") or empty.get("planned_values", {}).get(
                "root_module", {}
            ).get("resources"):
                raise RuntimeError(
                    "AWS root now has resources: add a read-only state-backed AWS plan gate first"
                )
    for label, directory in [
        ("deployment source", repo / "infra/terraform"),
        ("CI fixture", candidate),
    ]:
        scanned = run(
            [
                scanner_python,
                "-m",
                "checkov.main",
                "--config-file",
                str(repo / "scripts/iac/checkov.yaml"),
                "-d",
                str(directory),
            ],
            cwd=directory,
            env=env,
            allowed=(0, 1),
            quiet=True,
        )
        scan_report = json.loads(scanned.stdout)
        issues = audit(
            scan_report, json.loads((repo / "scripts/iac/scan_exceptions.json").read_text())
        )
        if issues:
            raise RuntimeError(f"Security scan ({label}) rejected:\n" + "\n".join(issues))
        print(f"Security scan ({label}): PASS (expiring exceptions audited)", flush=True)
    local = candidate / "environments/local"
    base_local = original / "environments/local"
    if not base_local.is_dir():
        raise RuntimeError("Missing baseline local environment; no deletion comparison possible")
    name = f"cv-iac-gate-{uuid4().hex[:12]}"
    started = False
    try:
        run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "-p",
                "127.0.0.1::4566",
                "-e",
                "SERVICES=iam,kms,secretsmanager,sqs,s3,sts",
                "-e",
                "PERSISTENCE=0",
                LOCALSTACK_IMAGE,
            ],
            cwd=work,
            env=env,
            quiet=True,
        )
        started = True
        published = run(["docker", "port", name, "4566"], cwd=work, env=env, quiet=True)
        port = published.stdout.strip().rsplit(":", 1)[-1]
        endpoint = f"http://127.0.0.1:{port}"
        for _ in range(120):
            try:
                with urllib.request.urlopen(
                    endpoint + "/_localstack/health", timeout=2
                ) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                time.sleep(0.5)
        else:
            raise RuntimeError("LocalStack readiness timed out")
        state_lock = state_lock_probe(work / "day26-lock-probe", endpoint, env)
        fault_env = {
            **env,
            "DAY27_LOCK_ENDPOINT": endpoint,
            "DAY27_LOCK_REPORT": str(report.parent / "day27-lock.json"),
        }
        # Only non-secret provenance crosses into the isolated test subprocess.
        for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
            if key in os.environ:
                fault_env[key] = os.environ[key]
        run(
            [
                scanner_python,
                "-m",
                "pytest",
                "-c",
                "scripts/iac/pytest.ini",
                "tests/integration/iac/test_state_lock_contention.py",
                "-q",
                f"--junitxml={report.parent / 'day27-lock.xml'}",
            ],
            cwd=repo,
            env=fault_env,
        )
        state_fault = json.loads((report.parent / "day27-lock.json").read_text(encoding="utf-8"))
        variables = {**TFVARS, "aws_endpoint_url": endpoint}
        for root in (base_local, local):
            (root / "ci.tfvars.json").write_text(json.dumps(variables), encoding="utf-8")
            (root / "terraform.tfvars.json").write_text(json.dumps(variables), encoding="utf-8")
        baseline_lock = base_local / ".terraform.lock.hcl"
        if not baseline_lock.is_file():
            raise RuntimeError("Missing baseline provider lock")

        # Reconcile official checksums in the disposable workspace.
        terraform(
            base_local,
            "get",
            "-no-color",
            env=env,
            quiet=True,
        )
        terraform(
            base_local,
            "providers",
            "lock",
            "-platform=linux_amd64",
            "-platform=windows_amd64",
            env=env,
            quiet=True,
        )
        initialize(base_local, env=env)
        terraform(
            base_local,
            "apply",
            "-input=false",
            "-auto-approve",
            "-no-color",
            "-var-file=ci.tfvars.json",
            env=env,
        )
        baseline_state = base_local / "terraform.tfstate"
        if not baseline_state.exists():
            raise RuntimeError("Baseline apply produced no state")
        shutil.copy2(baseline_state, local / "terraform.tfstate")
        _, change_plan = save_plan(local, "candidate", env=env)
        require_policy(change_plan, "changes")
        # This apply is exclusively to test-only resources in the ephemeral emulator.
        terraform(
            local,
            "apply",
            "-input=false",
            "-auto-approve",
            "-no-color",
            "candidate.tfplan",
            env=env,
        )
        exit_code, resolved = save_plan(local, "second", env=env)
        require_policy(resolved, "resolved")
        if exit_code != 0:
            raise RuntimeError("Second plan has changes; idempotency gate failed")
        ota_verified = False
        if (candidate / "environments/ota-local").is_dir():
            _ota_local_acceptance(candidate, original, endpoint, env)
            ota_verified = True
        summary = {
            "status": "passed",
            "day26_s3_lock_probe": state_lock,
            "day27_s3_failure_probe": state_fault,
            "contract_files": contract_count,
            "contract_runs": contract_runs,
            "destroy_actions": 0,
            "second_plan_exit_code": exit_code,
            "security_scan": "passed",
            "resolved_plan_policy": "passed",
            "ota_local_apply_second_plan": ota_verified,
            "ota_database_credential_isolation": ota_verified,
            "governance_acceptance": "offline-root-and-provider-schema-backed-mock-contracts",
            "aws_organizations_enforcement_verified": False,
        }
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    finally:
        if started:
            run(["docker", "rm", "-f", name], cwd=work, env=env, quiet=True)


def _empty_root_plan(root: Path, env: dict[str, str]) -> tuple[int, dict[str, Any]]:
    result = terraform(
        root, "plan", "-input=false", "-no-color", "-out=empty.tfplan", env=env, quiet=True
    )
    shown = terraform(root, "show", "-json", "empty.tfplan", env=env, quiet=True)
    return result.returncode, json.loads(shown.stdout)


def _ota_local_acceptance(
    candidate: Path, original: Path, endpoint: str, env: dict[str, str]
) -> None:
    """Deploy isolated OTA resources; never reuse the developer's IAM, secrets or state."""
    if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", endpoint):
        raise RuntimeError("OTA fixture endpoint must be the ephemeral loopback emulator")
    role = "cv-iac-ota-tenant-api"
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    sdk = importlib.import_module("boto3")
    config = importlib.import_module("botocore.config").Config(
        connect_timeout=5, read_timeout=10, retries={"max_attempts": 2}
    )
    client_args = {
        "endpoint_url": endpoint,
        "region_name": "ap-northeast-1",
        "aws_access_key_id": "test",
        "aws_secret_access_key": "test",
        "config": config,
    }
    sdk.client("iam", **client_args).create_role(RoleName=role, AssumeRolePolicyDocument=trust)
    local = candidate / "environments/local"
    platform = json.loads(terraform(local, "output", "-json", env=env, quiet=True).stdout)
    key = platform["platform_secrets"]["value"]["database_application"]["kms_key_arn"]
    secret = sdk.client("secretsmanager", **client_args).create_secret(
        Name="/cv-iac/local/tenants/contract/database/application", KmsKeyId=key
    )["ARN"]
    campaign_secret = sdk.client("secretsmanager", **client_args).create_secret(
        Name="/cv-iac/local/tenants/contract/database/campaign", KmsKeyId=key
    )["ARN"]
    variables = {
        "project_name": "cv-iac",
        "environment": "local",
        "tenant_id": "iac-contract",
        "aws_region": "ap-northeast-1",
        "aws_endpoint_url": endpoint,
        "api_runtime_role_name": role,
        "application_database_secret_arn": secret,
        "application_database_kms_key_arn": key,
        "campaign_database_secret_arn": campaign_secret,
        "campaign_database_kms_key_arn": key,
        "artifact_keys": ["firmware/body.bin"],
    }
    ota = candidate / "environments/ota-local"
    previous = original / "environments/ota-local"
    if previous.is_dir():
        initialize(previous, env=env)
        (previous / "ci.tfvars.json").write_text(json.dumps(variables), encoding="utf-8")
        terraform(
            previous,
            "apply",
            "-auto-approve",
            "-input=false",
            "-no-color",
            "-var-file=ci.tfvars.json",
            env=env,
        )
        shutil.copy2(previous / "terraform.tfstate", ota / "terraform.tfstate")
    (ota / "ci.tfvars.json").write_text(json.dumps(variables), encoding="utf-8")
    _, change = save_plan(ota, "ota-candidate", env=env)
    require_policy(change, "changes")
    terraform(
        ota, "apply", "-input=false", "-auto-approve", "-no-color", "ota-candidate.tfplan", env=env
    )
    exit_code, resolved = save_plan(ota, "ota-second", env=env)
    require_policy(resolved, "resolved")
    if exit_code != 0:
        raise RuntimeError("OTA second plan has changes")
    isolation_errors = database_isolation_errors(resolved, variables)
    if isolation_errors:
        raise RuntimeError("OTA database isolation: " + "; ".join(isolation_errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--scanner-python", default=sys.executable)
    parser.add_argument("--report", type=Path, default=REPO / ".iac-reports/summary.json")
    args = parser.parse_args()
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text('{"status": "running"}\n', encoding="utf-8")
    # TemporaryDirectory only deletes its newly allocated, resolved sandbox path.
    with tempfile.TemporaryDirectory(prefix="cv-iac-gate-") as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(Path(tempfile.gettempdir()).resolve()):
            raise RuntimeError("Invalid temporary workspace")
        try:
            gate(
                args.repo.resolve(),
                args.baseline.resolve(),
                work=work,
                report=args.report.resolve(),
                scanner_python=args.scanner_python,
            )
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
            report.write_text('{"status": "failed"}\n', encoding="utf-8")
            print(f"IaC quality gate FAILED: {exc}", file=sys.stderr)
            return 1
    print("IaC quality gate PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
