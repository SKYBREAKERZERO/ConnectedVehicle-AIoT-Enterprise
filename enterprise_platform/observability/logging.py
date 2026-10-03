from __future__ import annotations

import logging
import sys
from typing import cast

import structlog
from structlog.typing import EventDict, Processor, WrappedLogger

from enterprise_platform.config.settings import Settings
from enterprise_platform.observability.context import (
    merge_observability_context,
)

_LOG_LEVELS: dict[str, int] = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "WARN": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def resolve_log_level(value: str) -> int:
    return _LOG_LEVELS.get(
        value.strip().upper(),
        logging.INFO,
    )


def _static_context_processor(
    *,
    service: str,
    environment: str,
) -> Processor:
    def add_static_context(
        logger: WrappedLogger,
        method_name: str,
        event_dict: EventDict,
    ) -> EventDict:
        del logger, method_name

        event_dict.setdefault("service", service)
        event_dict.setdefault("environment", environment)

        return event_dict

    return add_static_context


def _resolve_renderer(log_format: str) -> Processor:
    if log_format.strip().lower() == "json":
        return structlog.processors.JSONRenderer()

    return structlog.dev.ConsoleRenderer(colors=False)


def configure_logging(settings: Settings) -> None:
    log_level = resolve_log_level(settings.log_level)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
        force=True,
    )

    processors: list[Processor] = [
        merge_observability_context,
        _static_context_processor(
            service=settings.app_name,
            environment=settings.app_env.value,
        ),
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(
            fmt="iso",
            utc=True,
        ),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _resolve_renderer(settings.log_format),
    ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    return cast(
        structlog.BoundLogger,
        structlog.get_logger(name),
    )
