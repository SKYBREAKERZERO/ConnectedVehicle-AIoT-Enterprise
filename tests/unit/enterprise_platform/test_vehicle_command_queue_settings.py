from __future__ import annotations

import pytest
from pydantic import ValidationError

from enterprise_platform.config.settings import Settings


def test_vehicle_command_queue_has_stable_default() -> None:
    settings = Settings(_env_file=None)

    assert settings.vehicle_command_queue_name == "connected-vehicle-command"


def test_vehicle_command_queue_can_be_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "VEHICLE_COMMAND_QUEUE_NAME",
        "connected-vehicle-command-dev",
    )

    settings = Settings(_env_file=None)

    assert settings.vehicle_command_queue_name == "connected-vehicle-command-dev"


@pytest.mark.parametrize(
    "queue_name",
    [
        "",
        "vehicle command",
        "vehicle.command",
        "x" * 81,
    ],
)
def test_vehicle_command_queue_rejects_invalid_names(
    queue_name: str,
) -> None:
    with pytest.raises(ValidationError):
        Settings(
            vehicle_command_queue_name=queue_name,
            _env_file=None,
        )
