from pathlib import Path

import pytest
import yaml
from pydantic import SecretStr

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    bootstrap_database_settings,
    migration_database_settings,
)


@pytest.mark.parametrize(
    "username", [None, "migration_owner", "app_user", "outbox_worker__abc", "observability_reader"]
)
def test_bootstrap_requires_independent_explicit_credentials(username: str | None) -> None:
    settings = Settings.model_construct(
        bootstrap_database_username=username,
        bootstrap_database_password=SecretStr("private"),
        migration_database_username="migration_owner",
        migration_database_password=SecretStr("schema"),
    )
    with pytest.raises(ValueError, match="independent") as error:
        bootstrap_database_settings(settings)
    assert "private" not in str(error.value)
    if username == "migration_owner":
        with pytest.raises(ValueError, match="independent"):
            migration_database_settings(settings)


def test_runtime_workflow_limits_cluster_credentials_to_bootstrap_step() -> None:
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/runtime.yml").read_text())
    job = workflow["jobs"]["runtime"]
    assert job["env"]["MIGRATION_DATABASE_USERNAME"] == "migration_owner"
    assert job["services"]["postgres"]["env"]["POSTGRES_USER"] == "cluster_bootstrap"
    assert not any(name.startswith("BOOTSTRAP_") for name in job["env"])
    steps = [row for row in job["steps"] if "BOOTSTRAP_DATABASE_PASSWORD" in row.get("env", {})]
    assert len(steps) == 1 and steps[0]["run"] == "python -m database.bootstrap_cluster"
    grants = (root / "database/runtime-grants.sql").read_text()
    assert "CREATE ROLE" not in grants and "ALTER ROLE" not in grants
