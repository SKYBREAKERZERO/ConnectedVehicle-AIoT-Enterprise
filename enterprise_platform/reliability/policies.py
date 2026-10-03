from __future__ import annotations

from dataclasses import dataclass
from math import isfinite


def _require_positive_finite(
    value: float,
    *,
    field_name: str,
) -> None:
    if not isfinite(value) or value <= 0:
        raise ValueError(f"{field_name} must be a positive finite number.")


def _require_non_negative_finite(
    value: float,
    *,
    field_name: str,
) -> None:
    if not isfinite(value) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative finite number.")


@dataclass(frozen=True, slots=True)
class TimeoutPolicy:
    """Defines the application-level deadline for one operation."""

    timeout_seconds: float

    def __post_init__(self) -> None:
        _require_positive_finite(
            self.timeout_seconds,
            field_name="timeout_seconds",
        )


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Defines bounded retry, exponential backoff, and jitter."""

    max_attempts: int = 3
    base_delay_seconds: float = 0.1
    max_delay_seconds: float = 5.0
    jitter_ratio: float = 0.2

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1.")

        _require_non_negative_finite(
            self.base_delay_seconds,
            field_name="base_delay_seconds",
        )
        _require_non_negative_finite(
            self.max_delay_seconds,
            field_name="max_delay_seconds",
        )
        _require_non_negative_finite(
            self.jitter_ratio,
            field_name="jitter_ratio",
        )

        if self.max_delay_seconds < self.base_delay_seconds:
            raise ValueError(
                "max_delay_seconds must be greater than or equal to base_delay_seconds."
            )

        if self.jitter_ratio > 1:
            raise ValueError("jitter_ratio must be between 0 and 1.")


@dataclass(frozen=True, slots=True)
class ReliabilityPolicy:
    """Composes reliability policies for an operation boundary."""

    timeout: TimeoutPolicy
    retry: RetryPolicy | None = None
