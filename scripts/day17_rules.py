"""Generate/verify local SLO alerts from the reviewed policy."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from enterprise_platform.reliability.slo import SLOPolicy

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config/operations/day17-slo.json"
RULES = ROOT / "infra/observability/day17-slo.yml"
RUNBOOK = (
    "https://github.com/SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
    "/blob/main/docs/DAY17_OPERATIONS.md"
)


def policy() -> SLOPolicy:
    return SLOPolicy.model_validate_json(POLICY.read_bytes())


def generated() -> str:
    ratio = (
        '(sum(rate(vehicle_http_requests_total{route="/health/ready",status!="200"}[5m])) '
        "or vector(0)) / clamp_min(sum(rate(vehicle_http_requests_total"
        '{route="/health/ready"}[5m])), 0.001)'
    )
    rules = {
        "groups": [
            {
                "name": "local-readiness-slo",
                "rules": [
                    {"record": "vehicle:readiness_error_ratio:5m", "expr": ratio},
                    {
                        "alert": "VehicleReadinessBudgetBurn",
                        "expr": "vehicle:readiness_error_ratio:5m > "
                        + format(2 * (1 - policy().readiness_availability), ".6g"),
                        "for": "2m",
                        "labels": {"severity": "warning", "profile": "local_drill"},
                        "annotations": {
                            "summary": "Readiness error budget is burning",
                            "runbook_url": RUNBOOK + "#readiness-budget-burn",
                        },
                    },
                    {
                        "alert": "VehicleRecoveryEscalated",
                        "expr": (
                            "sum(increase(vehicle_recovery_transitions_total"
                            '{state=~"ESCALATED|QUARANTINE"}[5m])) > 0'
                        ),
                        "labels": {"severity": "critical", "profile": "local_drill"},
                        "annotations": {
                            "summary": "Recovery requires reconciliation",
                            "runbook_url": RUNBOOK + "#recovery-escalated",
                        },
                    },
                ],
            }
        ]
    }
    return yaml.safe_dump(rules, sort_keys=False, width=120)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = generated()
    if args.write:
        RULES.write_text(expected, encoding="utf-8")
    elif RULES.read_text(encoding="utf-8") != expected:
        raise ValueError("Day17 alert rules drifted from SLO policy")
    print("Local SLO alert rules verified")


if __name__ == "__main__":
    main()
