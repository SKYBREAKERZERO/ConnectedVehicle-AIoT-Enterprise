"""Day29 signed-local-identity / real LocalStack / native Terraform rehearsal.

Only the controlled fixture issuer owns keys. No GitHub/OIDC, human approval or
AWS deployment identity is represented by these per-run local credentials.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from scripts.iac.local_rehearsal_identity import LocalRehearsalIdentity
from scripts.iac.plan_admission import BOUND, canonical_digest
from scripts.iac.recovery_approval import RecoveryApprovals
from scripts.iac.release_admission import ReleaseStore
from scripts.iac.release_revalidation import ReleaseRevalidator, observation_binding
from scripts.iac.state_dr_probe import probe as state_dr_probe
from scripts.iac.trusted_state_registry import TrustedStateRegistry


def now() -> datetime:
    return datetime.now(UTC)


def services(
    path: Path, auth: LocalRehearsalIdentity, scope: dict[str, Any], target: dict[str, Any]
) -> tuple[TrustedStateRegistry, RecoveryApprovals, TrustedStateRegistry]:
    source = TrustedStateRegistry(
        path, scope=scope, registrars=frozenset({"publisher"}), authenticate=auth.authenticate
    )
    approvals = RecoveryApprovals(
        path,
        registry=source,
        targets=(target,),
        requesters=frozenset({"requester"}),
        reviewers=frozenset({"reviewer"}),
        authenticate=auth.authenticate,
        clock=now,
        localstack_rehearsal=True,
    )
    recovered = TrustedStateRegistry(
        path, scope=target, registrars=frozenset({"publisher"}), authenticate=auth.authenticate
    )
    return source, approvals, recovered


def verifier(
    path: Path, auth: LocalRehearsalIdentity, scope: dict[str, Any], target: dict[str, Any]
) -> ReleaseRevalidator:
    _, approvals, recovered = services(path, auth, scope, target)
    return ReleaseRevalidator(
        path,
        registry=recovered,
        approvals=approvals,
        clock=now,
        evidence_authority=lambda p: auth.observed("evidence", p),
        observation_authority=lambda p: auth.observed("observation", p),
        localstack_rehearsal=True,
    )


def manifest(record: dict[str, Any], plan: bytes, created: datetime, lock: Path) -> dict[str, Any]:
    return {
        "commit": record["commit"],
        "run_id": record["run_id"],
        "environment": "local",
        "account": "000000000000",
        "plan_role": "arn:aws:iam::000000000000:role/rehearsal-plan",
        "apply_role": "arn:aws:iam::000000000000:role/rehearsal-disabled",
        "state_bucket": record["bucket"],
        "state_key": record["key"],
        "state_region": "ap-northeast-1",
        "state_kms_key_arn": "localstack-aes256",
        "state_lineage": record["lineage"],
        "state_serial": record["serial"],
        "lockfile_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "terraform_version": "1.14.7",
        "plan_sha256": hashlib.sha256(plan).hexdigest(),
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(minutes=20)).isoformat(),
    }


def evidence(
    auth: LocalRehearsalIdentity, m: dict[str, Any], request_id: str, source: str
) -> dict[str, Any]:
    t = now()
    result = {
        "request_id": request_id,
        "manifest_sha256": canonical_digest(m),
        "source_sha256": source,
        "run_id": m["run_id"],
        "repository": "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise",
        "workflow": ".github/workflows/ci.yml",
        "conclusion": "success",
        "created_at": t.isoformat(),
        "expires_at": (t + timedelta(minutes=15)).isoformat(),
    }
    auth.observe("evidence", result)
    return result


def private_file(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def run_worker(bundle: Path, *, expected: int = 0) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "scripts.iac.day29_native_probe", str(bundle)],
        capture_output=True,
        text=True,
        timeout=40,
    )
    if result.returncode != expected:
        raise RuntimeError(
            "Local worker outcome mismatch: " + str(result.returncode) + " " + result.stderr[-1500:]
        )


def race(work: Path, bundles: list[dict[str, Any]]) -> list[int]:
    start = work / "start"
    processes = []
    try:
        for index, value in enumerate(bundles):
            path = work / f"worker-{index}.json"
            ready = work / f"ready-{index}"
            private_file(path, {**value, "start": str(start), "ready": str(ready)})
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-m", "scripts.iac.day29_native_probe", str(path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        deadline = time.monotonic() + 15
        while not all((work / f"ready-{i}").exists() for i in range(len(bundles))):
            if time.monotonic() > deadline:
                raise RuntimeError("worker start barrier timed out")
            time.sleep(0.02)
        start.write_text("go")
        errors = [p.communicate(timeout=40)[1] for p in processes]
        codes = [p.returncode for p in processes]
        if sorted(codes) != [0, 23]:
            raise RuntimeError("Expected one process winner: " + str(codes) + str(errors))
        return [int(code) for code in codes]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


def probe(
    work: Path, endpoint: str, env: dict[str, str], lock: Path, source_digest: str
) -> dict[str, Any]:
    work.mkdir()
    captured: dict[str, Any] = {}
    outcomes: dict[str, Any] = {}
    commit = (
        os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    )
    run_id = (
        os.environ.get("GITHUB_RUN_ID", "local") + ":" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    )
    auth = LocalRehearsalIdentity(
        secrets.token_bytes(32), endpoint=endpoint, commit=commit, run_id=run_id
    )
    path = work / "governance.sqlite"

    def hook(stage: str, context: dict[str, Any]) -> None:
        captured.update(context)
        if stage != "before-copy":
            return
        record = context["source_record"]
        scope = {k: record[k] for k in ("account", "environment", "bucket", "key")}
        target = {**scope, "bucket": context["target_bucket"]}
        source, approvals, _ = services(path, auth, scope, target)
        actual = context["client"].get_object(
            Bucket=record["bucket"], Key=record["key"], VersionId=record["version_id"]
        )
        raw = actual["Body"].read()
        if (
            actual["VersionId"] != record["version_id"]
            or hashlib.sha256(raw).hexdigest() != record["sha256"]
        ):
            raise RuntimeError("actual S3 source read mismatch")
        auth.observe("state-read", {"record_sha256": canonical_digest(record)})
        reg_race = work / "registry-race"
        reg_race.mkdir()
        shared = {
            "operation": "register",
            "db": str(path),
            "auth": auth.private_bundle(),
            "scope": scope,
            "target": target,
            "record": record,
            "raw": base64.b64encode(raw).decode(),
        }
        outcomes["registry_race_exit_codes"] = race(reg_race, [shared, shared])
        source.verify(raw, record)
        for candidate in (
            {**record, "version_id": "not-registered"},
            {**record, "serial": record["serial"] + 1},
            {**record, "account": "999999999999"},
        ):
            try:
                source.verify(raw, candidate)
            except ValueError:
                pass
            else:
                raise RuntimeError("unregistered/substituted version accepted")
        if source.is_current({**record, "version_id": "missing-version"}):
            raise RuntimeError("missing object version trusted")
        # Real native binary/JSON from the pre-fault clean snapshot, not mock plans.
        old = (context["source"] / "clean-normal.tfplan").read_bytes()
        m = manifest(record, old, context["source_started_at"], lock)
        e = evidence(auth, m, "origin-release", source_digest)
        store = ReleaseStore(path, localstack_rehearsal=True)
        store.request("origin-release", m, e, source_digest, "requester")
        common = {
            "manifest": m,
            "plan": old,
            "expected": {k: m[k] for k in BOUND},
            "evidence": e,
            "source": source_digest,
            "now": now(),
            "evidence_authority": lambda p: auth.observed("evidence", p),
        }
        store.advance("origin-release", "VERIFIED", **common)
        a = {
            "request_id": "origin-release",
            "binding_sha256": canonical_digest(
                {"manifest": m, "evidence": e, "source": source_digest}
            ),
            "reviewer": "reviewer",
            "approved_at": now().isoformat(),
            "expires_at": (now() + timedelta(minutes=5)).isoformat(),
            "approval_id": "origin-review",
        }
        signed = auth.issue("origin-review", "reviewer", a)
        common["now"] = now()
        store.advance(
            "origin-release",
            "APPROVED",
            **common,
            approval=a,
            approval_authority=lambda p: auth.verify(signed, "origin-review", "reviewer", p),
        )
        common["now"] = now()
        store.advance(
            "origin-release",
            "READY",
            **common,
            approval=a,
            approval_authority=lambda p: auth.verify(signed, "origin-review", "reviewer", p),
        )
        store.interrupt("origin-release")
        with auth.session("requester"):
            approvals.request(
                "revoked-request",
                record=record,
                target=target,
                previous_release_id="origin-release",
                actor="requester",
            )
        with auth.session("reviewer"):
            revoked = approvals.approve("revoked-request", "revoked-approval", reviewer="reviewer")
            approvals.revoke("revoked-approval", reviewer="reviewer")
        with auth.session("requester"):
            try:
                approvals.consume(revoked, actor="requester")
            except ValueError:
                outcomes["revoked_approval_denied"] = True
            else:
                raise RuntimeError("revoked approval accepted")
            approvals.request(
                "recovery-request",
                record=record,
                target=target,
                previous_release_id="origin-release",
                actor="requester",
            )
        with auth.session("reviewer"):
            token = approvals.approve("recovery-request", "recovery-approval", reviewer="reviewer")
        bundle = work / "lost-response.json"
        private_file(
            bundle,
            {
                "operation": "consume-exit",
                "db": str(path),
                "auth": auth.private_bundle(),
                "scope": scope,
                "target": target,
                "token": token,
            },
        )
        run_worker(bundle, expected=73)
        with auth.session("requester"):
            receipt = approvals.recover_consumed(token, actor="requester")
            try:
                approvals.consume(token, actor="requester")
            except ValueError:
                outcomes["lost_response_no_double_consume"] = True
            else:
                raise RuntimeError("lost response re-consumed")
        captured.update(scope=scope, target=target, receipt=receipt)
        outcomes["approval_consumed_before_copy"] = True

    dr = state_dr_probe(work / "native-dr", endpoint, env, lock, observer=hook)
    record = captured["target_record"]
    raw = captured["target_raw"]
    source, approvals, recovered = services(path, auth, captured["scope"], captured["target"])
    actual = captured["client"].get_object(
        Bucket=record["bucket"], Key=record["key"], VersionId=record["version_id"]
    )
    if actual["Body"].read() != raw:
        raise RuntimeError("target native snapshot differs")
    auth.observe("state-read", {"record_sha256": canonical_digest(record)})
    with auth.session("publisher"):
        recovered.register(raw, record, actor="publisher")

    def inputs(release_id: str, label: str, receipt: dict[str, Any]) -> dict[str, Any]:
        started = now()
        pair = captured["plans"](captured["restored"], label)
        binary = (captured["restored"] / (label + "-normal.tfplan")).read_bytes()
        refresh = json.loads(
            captured["tf"](captured["restored"], "show", "-json", label + "-refresh.tfplan").stdout
        )
        normal = json.loads(
            captured["tf"](captured["restored"], "show", "-json", label + "-normal.tfplan").stdout
        )
        m = manifest(record, binary, started, lock)
        e = evidence(auth, m, release_id, source_digest)
        value = {
            "receipt": receipt,
            "actor": "requester",
            "raw": raw,
            "record": record,
            "manifest": m,
            "plan": binary,
            "expected": {k: m[k] for k in BOUND},
            "evidence": e,
            "source": source_digest,
            "refresh_code": pair["refresh_exit"],
            "refresh_plan": refresh,
            "normal_code": pair["normal_exit"],
            "normal_plan": normal,
        }
        auth.observe(
            "observation",
            observation_binding(
                release_id,
                **{
                    k: value[k]
                    for k in (
                        "receipt",
                        "record",
                        "manifest",
                        "expected",
                        "evidence",
                        "source",
                        "refresh_code",
                        "refresh_plan",
                        "normal_code",
                        "normal_plan",
                    )
                },
            ),
        )
        return value

    current = verifier(path, auth, captured["scope"], captured["target"])
    blocked = inputs("drift-release", "day29-blocked", captured["receipt"])
    with auth.session("requester"):
        try:
            current.verify("drift-release", **blocked)
        except ValueError:
            outcomes["actual_dual_plan_drift_denied"] = True
        else:
            raise RuntimeError("native drift accepted")
    # Explicit signed fixture-operator reconciliation, AFTER the Day28 drift
    # assertions. The revalidator itself never modifies any resource or backend.
    with auth.session("operator"):
        if not auth.authenticate(
            "operator",
            "operator-reconcile-resource",
            canonical_digest({"resource": captured["resource_bucket"], "desired": "Enabled"}),
        ):
            raise RuntimeError("operator identity denied")
        captured["client"].put_bucket_versioning(
            Bucket=captured["resource_bucket"], VersioningConfiguration={"Status": "Enabled"}
        )
    positive = inputs("fresh-release", "day29-fresh", captured["receipt"])
    with auth.session("requester"):
        verified = current.verify("fresh-release", **positive)
    if verified["status"] != "VERIFIED" or verified["apply_authorized"] is not False:
        raise RuntimeError("verification improperly granted execution")
    final = captured["client"].get_object(Bucket=record["bucket"], Key=record["key"])
    if final["VersionId"] != record["version_id"] or final["Body"].read() != raw:
        raise RuntimeError("joint plans modified recovered state")
    with auth.session("requester"):
        try:
            current.verify("fresh-release", **positive)
        except ValueError:
            outcomes["verified_request_not_replayed"] = True
        else:
            raise RuntimeError("verified request replayed")
    with auth.session("reviewer"):
        approvals.revoke("recovery-approval", reviewer="reviewer")
    with auth.session("requester"):
        try:
            approvals.validate_consumed(captured["receipt"], actor="requester")
        except ValueError:
            outcomes["consumed_receipt_revocation_enforced"] = True
        else:
            raise RuntimeError("revoked receipt honored")
    with sqlite3.connect(path) as connection:
        consumptions = connection.execute("SELECT count(*) FROM day29_consumptions").fetchone()[0]
    if consumptions != 1:
        raise RuntimeError("consumption count changed after lost response")
    return {
        "status": "passed",
        "scope": "signed-local-identity-and-real-localstack",
        "outcomes": outcomes,
        "state_record": record,
        "source_state_record": captured["source_record"],
        "dr_rehearsal": dr,
        "joint_plan": {
            "refresh_exit": positive["refresh_code"],
            "normal_exit": positive["normal_code"],
            "normal_binary_sha256": positive["manifest"]["plan_sha256"],
            "normal_json_sha256": canonical_digest(positive["normal_plan"]),
            "refresh_json_sha256": canonical_digest(positive["refresh_plan"]),
        },
        "result": verified,
        "consumptions": consumptions,
        "production_apply_enabled": False,
        "aws_sts_verified": False,
        "github_identity_verified": False,
        "independent_human_approval_exercised": False,
        "cross_runner_coordination_verified": False,
    }


def worker(bundle: Path) -> int:
    value = json.loads(bundle.read_text(encoding="utf-8"))
    auth = LocalRehearsalIdentity.from_private_bundle(value["auth"])
    path = Path(value["db"])
    source, approvals, _ = services(path, auth, value["scope"], value["target"])
    if "ready" in value:
        Path(value["ready"]).write_text("ready")
        deadline = time.monotonic() + 15
        while not Path(value["start"]).exists():
            if time.monotonic() > deadline:
                raise RuntimeError("worker barrier timeout")
            time.sleep(0.02)
    try:
        if value["operation"] == "register":
            with auth.session("publisher"):
                source.register(base64.b64decode(value["raw"]), value["record"], actor="publisher")
        elif value["operation"] == "consume-exit":
            with auth.session("requester"):
                approvals.consume(value["token"], actor="requester")
            os._exit(73)
        else:
            raise ValueError("unknown local worker operation")
    except ValueError:
        return 23
    return 0


if __name__ == "__main__":
    sys.exit(worker(Path(sys.argv[1])))
