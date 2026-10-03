from __future__ import annotations

import logging

from enterprise_platform.observability.logging import resolve_log_level


def test_resolve_log_level_accepts_known_level() -> None:
    assert resolve_log_level("DEBUG") == logging.DEBUG
    assert resolve_log_level("INFO") == logging.INFO
    assert resolve_log_level("WARNING") == logging.WARNING
    assert resolve_log_level("ERROR") == logging.ERROR


def test_resolve_log_level_is_case_insensitive() -> None:
    assert resolve_log_level("debug") == logging.DEBUG
    assert resolve_log_level("Info") == logging.INFO


def test_resolve_log_level_defaults_to_info() -> None:
    assert resolve_log_level("invalid") == logging.INFO
