"""Opt-in disposable LocalStack DR; absent fixture fails instead of skipping."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from scripts.iac.deploy_governance import ROOT, run_identity
from scripts.iac.gate import sandbox_environment
from scripts.iac.state_dr_probe import probe


def test_versioned_state_recovery_and_both_drift_plans(
    tmp_path: Path, record_testsuite_property: Callable[[str, object], None]
) -> None:
    from scripts.iac.day28_evidence import source_digest

    provenance = {
        "day28_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "day28_run_id": run_identity(),
        "day28_source_sha256": source_digest(),
    }
    for key, value in provenance.items():
        record_testsuite_property(key, value)
    env = sandbox_environment(tmp_path)
    if cache := os.environ.get("DAY28_PROVIDER_CACHE"):
        path = Path(cache).resolve()
        if not path.is_dir():
            raise ValueError("Official provider cache directory missing")
        # Terraform still enforces the committed readonly checksums; never copy
        # .terraform/providers or enable cache-based lockfile overrides.
        env["TF_PLUGIN_CACHE_DIR"] = str(path)
    result = probe(
        tmp_path / "dr",
        os.environ["DAY28_DR_ENDPOINT"],
        env,
        ROOT / "infra/terraform/environments/local/.terraform.lock.hcl",
    )
    result["provenance"] = provenance
    assert result["missing_state_denied"] and result["corrupt_state_denied"]
    assert result["read_only_plans_preserved_state"] and result["interrupted_release_denied"]
    Path(os.environ["DAY28_DR_REPORT"]).write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
