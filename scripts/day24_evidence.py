"""Bind PostgreSQL and promtool acceptance to the exact CI source, run and artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from scripts.day12_evidence import source_commit
from scripts.day16_evidence import source_digest

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = frozenset(
    {
        "test_committed_campaign_wave_claim_job_metrics",
        "test_expired_lease_and_wave_recover",
        "test_recent_job_failure_window",
        "test_wrong_tenant_cannot_publish_business_metrics",
        "test_collection_lock_timeout_clears_stale_metrics",
        "test_runtime_cannot_change_protected_state",
        "test_authenticated_endpoint_exports_fixed_tenant_snapshot",
        "test_prometheus_alerts_fire_and_resolve",
    }
)


def evaluate(directory: Path, *, commit: str, run_id: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None or not run_id.strip():
        raise ValueError("Day24 requires explicit source commit and run identity")
    path = directory / "day24-postgres-alerts.xml"
    raw = path.read_bytes()
    if len(raw) > 2_000_000 or b"<!DOCTYPE" in raw.upper():
        raise ValueError("Invalid Day24 XML")
    document = ElementTree.fromstring(raw)
    if document.tag not in {"testsuite", "testsuites"}:
        raise ValueError("Invalid Day24 XML root")
    cases = document.findall(".//testcase")
    names = [case.attrib["name"] for case in cases]
    if len(names) != len(REQUIRED) or set(names) != REQUIRED:
        raise ValueError("Missing or duplicate Day24 scenario evidence")
    rule = ROOT / "infra/observability/day24-campaign.yml"
    scenarios = ROOT / "tests/fixtures/day24/alerts.test.yml"
    expected_stamp = {
        "day24_commit": commit,
        "day24_run_id": run_id,
        "day24_source_sha256": source_digest(),
        "day24_rule_sha256": hashlib.sha256(rule.read_bytes()).hexdigest(),
        "day24_scenario_sha256": hashlib.sha256(scenarios.read_bytes()).hexdigest(),
    }
    suites = [suite for suite in document.iter("testsuite") if suite.findall("./testcase")]
    if not suites or sum(len(suite.findall("./testcase")) for suite in suites) != len(cases):
        raise ValueError("Day24 cases must belong to attested test suites")
    for suite in suites:
        properties = suite.findall("./properties/property")
        stamp = {item.attrib["name"]: item.attrib["value"] for item in properties}
        if len(stamp) != len(properties) or any(
            stamp.get(k) != v for k, v in expected_stamp.items()
        ):
            raise ValueError("Day24 test-time provenance differs from expected source/run")
    for tag in ("failure", "error", "skipped"):
        if document.findall(f".//{tag}") or any(
            int(suite.attrib.get(tag + ("s" if tag != "skipped" else ""), "0")) != 0
            for suite in document.iter()
            if suite.tag in {"testsuite", "testsuites"}
        ):
            raise ValueError("Failed or skipped Day24 scenarios cannot pass acceptance")
    files = {
        "day24-postgres-alerts.xml": path,
        "campaign_alert_rules": ROOT / "infra/observability/day24-campaign.yml",
        "campaign_alert_scenarios": ROOT / "tests/fixtures/day24/alerts.test.yml",
    }
    return {
        "version": 1,
        "status": "passed",
        "scope": "local_postgresql_and_prometheus_rule_evaluation",
        "provenance": {"commit": commit, "run_id": run_id, "source_sha256": source_digest()},
        "tests": sorted(names),
        "proofs": {
            name: hashlib.sha256(file.read_bytes()).hexdigest() for name, file in files.items()
        },
        "real_aws_verified": False,
        "live_alert_delivery_verified": False,
        "physical_boot_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / ".runtime-reports")
    parser.add_argument("--check-existing", action="store_true")
    args = parser.parse_args()
    expected = evaluate(
        args.directory, commit=source_commit(), run_id=os.environ.get("DAY24_EVIDENCE_RUN_ID", "")
    )
    target = args.directory / "day24-acceptance.json"
    if args.check_existing:
        if json.loads(target.read_text(encoding="utf-8")) != expected:
            raise ValueError("Day24 evidence changed or belongs to another commit/run")
    else:
        target.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    print("Day24 PostgreSQL and alert acceptance: PASS")


if __name__ == "__main__":
    main()
