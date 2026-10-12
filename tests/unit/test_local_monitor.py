from pathlib import Path

from scripts.local_monitor import device_health, render_metrics
from simulators.vehicle_device.store import Store
from tests.unit.test_device_simulator import payload, settings


def test_auth_block_metrics_and_stale_heartbeat(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    try:
        store.accept(payload(config))
        ack = store.pending_report()
        assert ack is not None
        store.report_result(ack["sequence"], 401, 7)
        health = device_health(config.database)
        assert health["vehicle_auth_blocked_reports"] == 1
        text = render_metrics({"timestamp": 10, "success": True, "metrics": health}, now=15)
        assert "vehicle_monitor_collection_success 1.0" in text
        assert "vehicle_auth_blocked_reports 1.0" in text
        assert "vehicle_monitor_collection_success 0.0" in render_metrics(
            {"timestamp": 10, "success": True}, now=50
        )
    finally:
        store.close()
