"""Real LocalStack/native-plan governance, with signed local rehearsal identities."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from scripts.iac.day29_native_probe import probe
from scripts.iac.deploy_governance import ROOT, run_identity
from scripts.iac.gate import sandbox_environment


def test_signed_registry_approval_and_native_release_revalidation(
    tmp_path: Path, record_testsuite_property: Callable[[str, object], None]
) -> None:
    from scripts.iac.day29_evidence import source_digest

    provenance = {
        "day29_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "day29_run_id": run_identity(),
        "day29_source_sha256": source_digest(),
    }
    for key, value in provenance.items():
        record_testsuite_property(key, value)
    env = sandbox_environment(tmp_path)
    if cache := os.environ.get("DAY29_PROVIDER_CACHE"):
        env["TF_PLUGIN_CACHE_DIR"] = str(Path(cache).resolve())
    result = probe(
        tmp_path / "rehearsal",
        os.environ["DAY29_ENDPOINT"],
        env,
        ROOT / "infra/terraform/environments/local/.terraform.lock.hcl",
        provenance["day29_source_sha256"],
    )
    result["provenance"] = provenance
    Path(os.environ["DAY29_NATIVE_REPORT"]).write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
