"""No module may disappear, be counted twice, or pad the aggregate test count."""

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.module_contracts import GROUPS, merge_reports, partition


def reports() -> dict[str, dict[str, Any]]:
    return {
        group: {
            "status": "passed",
            "phase": "contracts",
            "contract_group": group,
            "contract_files": len(roots),
            "contract_runs": len(roots),
            "checked_roots": {name: {"files": 1, "passed": 1} for name in roots},
        }
        for group, roots in GROUPS.items()
    }


def test_module_partitions_cover_every_actual_tf_root_once() -> None:
    root = Path(__file__).resolve().parents[3] / "infra/terraform"
    discovered = sorted(
        {
            p.parent
            for base in ("modules", "bootstrap", "environments")
            for p in (root / base).rglob("*.tf")
            if ".terraform" not in p.parts
        }
    )
    selected = [p for group in GROUPS for p in partition(discovered, root, group)]
    assert len(selected) == len(set(selected)) == 17
    assert set(selected) == set(partition(discovered, root, "all"))
    assert merge_reports(reports())["contract_runs"] == 17


@pytest.mark.parametrize(
    "attack",
    [
        "missing-group",
        "extra-group",
        "wrong-group",
        "missing-root",
        "padded-count",
        "boolean-count",
        "zero-count",
        "negative-count",
    ],
)
def test_incomplete_or_fabricated_module_reports_are_denied(attack: str) -> None:
    data = deepcopy(reports())
    part = data["foundation"]
    if attack == "missing-group":
        del data["ota"]
    elif attack == "extra-group":
        data["unexpected"] = part
    elif attack == "wrong-group":
        part["contract_group"] = "ota"
    elif attack == "missing-root":
        del part["checked_roots"][GROUPS["foundation"][0]]
    elif attack == "padded-count":
        part["contract_runs"] += 10
    elif attack == "boolean-count":
        part["checked_roots"][GROUPS["foundation"][0]]["passed"] = True
    elif attack == "zero-count":
        part["contract_runs"] = 0
    else:
        part["checked_roots"][GROUPS["foundation"][0]]["files"] = -1
    with pytest.raises(ValueError, match="contract evidence"):
        merge_reports(data)


@pytest.mark.parametrize("attack", ["unlisted-module", "removed-root", "duplicate-root"])
def test_inventory_drift_cannot_be_silently_excluded(tmp_path: Path, attack: str) -> None:
    roots = [tmp_path / name for names in GROUPS.values() for name in names]
    for root in roots:
        root.mkdir(parents=True)
        (root / "main.tf").write_text("")
    if attack == "unlisted-module":
        extra = tmp_path / "modules/unreviewed"
        extra.mkdir()
        (extra / "main.tf").write_text("")
    elif attack == "removed-root":
        roots.pop()
    else:
        roots.append(roots[0])
    with pytest.raises(ValueError, match="inventory changed"):
        partition(roots, tmp_path, "foundation")
