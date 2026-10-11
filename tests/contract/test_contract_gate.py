from pathlib import Path

from scripts.contracts import ROOT, boundaries, check, compatible


def test_runtime_contracts_match_reviewed_snapshots() -> None:
    assert check(ROOT) == []


def test_breaking_schema_and_boundary_changes_fail(tmp_path: Path) -> None:
    assert compatible({"properties": {"event_id": {"type": "string"}}}, {"properties": {}})
    assert compatible({"required": ["event_id"]}, {"required": ["event_id", "vehicle_id"]})
    assert compatible({"enum": ["sent", "succeeded"]}, {"enum": ["sent"]})
    assert compatible({"type": "string"}, {"type": "integer"})
    assert not compatible(
        {"properties": {"id": {"type": "string"}}},
        {"properties": {"id": {"type": "string"}, "optional": {"type": "string"}}},
    )
    platform = tmp_path / "enterprise_platform"
    platform.mkdir()
    (platform / "bad.py").write_text("from apps.api import main\n")
    assert boundaries(tmp_path)


def test_cloud_cannot_depend_on_device_simulator(tmp_path: Path) -> None:
    app = tmp_path / "apps"
    app.mkdir()
    (app / "bad.py").write_text("from simulators.vehicle_device import runtime\n")
    simulator = tmp_path / "simulators"
    simulator.mkdir()
    (simulator / "bad.py").write_text("from database import migrations\n")
    assert len(boundaries(tmp_path)) == 2
