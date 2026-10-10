"""Validate raw test inputs without reading a developer dotenv file."""

from typing import Any

from enterprise_platform.config.settings import Settings


def isolated_settings(**values: Any) -> Settings:
    options: dict[str, Any] = {"_env_file": None}
    options.update(values)
    return Settings(**options)
