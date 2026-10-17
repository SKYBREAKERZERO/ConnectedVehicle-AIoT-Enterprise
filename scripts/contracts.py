"""Fail closed on module boundary violations, contract drift and breaking baseline schemas."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from apps.api.contracts import (
    ErrorResponseContract,
    IssueRemoteCommandRequest,
    IssueRemoteCommandResponse,
)
from connected_vehicle.device_data import CommandReport, TelemetrySample
from connected_vehicle.ota.contracts import (
    CancelJob,
    ECURegistration,
    ECUView,
    FirmwareRegistration,
    FirmwareView,
    JobRequest,
    JobView,
)
from connected_vehicle.ota.execution_contracts import (
    ClaimRequest,
    ClaimResult,
    ExecutionECUView,
    ExecutionView,
    InstallationProof,
    OTAReport,
    SignedManifest,
    VerificationRequest,
)
from connected_vehicle.remote_command.wire_contracts import DispatchPayload, RequestedPayload
from enterprise_platform.messaging.envelope import EventEnvelope

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path("contracts/platform-v1.json")
DAY17 = "cf08e437c79aaa041d25aa49dd572cfb15075048"
DAY17_HASH = "4b6c4c2baa1fbbb35a0aac277448cfa3725f39fb50ce88307dccb6aec401e06f"


def schemas() -> dict[str, Any]:
    return {
        "ota-boot-proof/1.0": InstallationProof.model_json_schema(),
        "command-report/1.0": CommandReport.model_json_schema(),
        "telemetry/1.0": TelemetrySample.model_json_schema(),
        "mqtt-dispatch/1.0": DispatchPayload.model_json_schema(),
        "command-requested/1.0": RequestedPayload.model_json_schema(),
        "event-envelope/1.0": TypeAdapter(EventEnvelope).json_schema(),
        "api-issue-request/1.0": IssueRemoteCommandRequest.model_json_schema(),
        "api-issue-response/1.0": IssueRemoteCommandResponse.model_json_schema(),
        "api-error/1.0": ErrorResponseContract.model_json_schema(),
        "ota-ecu-registration/1.0": ECURegistration.model_json_schema(),
        "ota-ecu/1.0": ECUView.model_json_schema(),
        "ota-firmware-registration/1.0": FirmwareRegistration.model_json_schema(),
        "ota-firmware/1.0": FirmwareView.model_json_schema(),
        "ota-job-request/1.0": JobRequest.model_json_schema(),
        "ota-job/1.0": JobView.model_json_schema(),
        "ota-job-cancel/1.0": CancelJob.model_json_schema(),
        "ota-execution/2.0": ExecutionView.model_json_schema(),
        "ota-inventory/2.0": ExecutionECUView.model_json_schema(),
        "ota-verification/2.0": VerificationRequest.model_json_schema(),
        "ota-claim-request/2.0": ClaimRequest.model_json_schema(),
        "ota-claim/2.0": ClaimResult.model_json_schema(),
        "ota-report/2.0": OTAReport.model_json_schema(),
        "ota-manifest/2.0": SignedManifest.model_json_schema(),
    }


def boundaries(root: Path) -> list[str]:
    errors: list[str] = []
    for package in ("enterprise_platform", "connected_vehicle", "apps", "simulators"):
        for path in (root / package).rglob("*.py"):
            module = ".".join(path.relative_to(root).with_suffix("").parts)
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                imports: list[str] = []
                if isinstance(node, ast.Import):
                    imports = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        parent = module.split(".")[: -node.level]
                        imports = [".".join(parent + (node.module or "").split("."))]
                    else:
                        imports = [node.module or ""]
                for imported in imports:
                    dependency = imported.split(".")[0]
                    forbidden = (
                        dependency == "database"
                        or (
                            package == "enterprise_platform"
                            and dependency in {"apps", "connected_vehicle"}
                        )
                        or (package == "connected_vehicle" and dependency == "apps")
                        or (package != "simulators" and dependency == "simulators")
                        or (package == "simulators" and dependency == "apps")
                    )
                    if forbidden:
                        location = f"{path.relative_to(root)}:{getattr(node, 'lineno', 0)}"
                        errors.append(f"{location}: forbidden {imported}")
    return errors


def compatible(old: Any, new: Any, path: str = "schema") -> list[str]:
    """Conservative compatibility: optional properties may be added; old contracts stay valid.

    A deliberate breaking contract needs a NEW version key, with the old consumer retained.
    Constraint, enum and reference changes require explicit review rather than guessing direction.
    """
    errors: list[str] = []
    if isinstance(old, dict) and isinstance(new, dict):
        for key, value in old.items():
            if key in {"title", "description", "examples"}:
                continue
            if key == "properties":
                for name, schema in value.items():
                    if name not in new.get(key, {}):
                        errors.append(f"{path}.{name}: field removed")
                    else:
                        errors.extend(compatible(schema, new[key][name], f"{path}.{name}"))
            elif key == "required":
                if not set(new.get(key, [])) <= set(value):
                    errors.append(f"{path}: new required fields")
            elif key not in new:
                errors.append(f"{path}.{key}: constraint removed")
            else:
                errors.extend(compatible(value, new[key], f"{path}.{key}"))
        if "required" not in old and new.get("required"):
            errors.append(f"{path}: new required fields")
        for key in new.keys() - old.keys():
            if key not in {"title", "description", "examples", "properties", "required", "$defs"}:
                errors.append(f"{path}.{key}: new constraint")
    elif old != new:
        errors.append(f"{path}: contract changed")
    return errors


def check(root: Path, baseline: Path | None = None) -> list[str]:
    errors = boundaries(root)
    expected = schemas()
    fixed = json.loads((ROOT / "contracts/day17-baseline.json").read_text(encoding="utf-8"))
    if fixed["commit"] != DAY17 or fixed["sha256"] != DAY17_HASH:
        errors.append("Pinned Day17 contract identity changed")
    for name, schema in fixed["contracts"].items():
        if name.startswith("ota-"):
            if name not in expected:
                errors.append(f"{name}: pinned Day17 OTA contract removed")
            else:
                errors.extend(compatible(schema, expected[name], name))
    committed = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if committed != expected:
        errors.append("Contract snapshot does not match runtime models; regenerate and review.")
    if baseline and (baseline / MANIFEST).exists():
        old = json.loads((baseline / MANIFEST).read_text(encoding="utf-8"))
        for name, schema in old.items():
            if name not in expected:
                errors.append(f"{name}: supported contract version removed")
            else:
                errors.extend(compatible(schema, expected[name], name))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--require-day17", action="store_true")
    args = parser.parse_args()
    if args.require_day17:
        raw = subprocess.check_output(
            ["git", "show", DAY17 + ":contracts/platform-v1.json"], cwd=ROOT
        )
        fixed = json.loads((ROOT / "contracts/day17-baseline.json").read_text(encoding="utf-8"))
        if hashlib.sha256(raw).hexdigest() != DAY17_HASH or fixed["contracts"] != json.loads(raw):
            raise ValueError("Frozen Day17 contracts differ from the pinned published commit")
    if args.write:
        (ROOT / MANIFEST).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / MANIFEST).write_text(
            json.dumps(schemas(), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
    errors = check(ROOT, args.baseline)
    if errors:
        print("\n".join(errors))
        return 1
    print("Module boundaries and versioned device contracts passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
