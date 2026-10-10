from __future__ import annotations

import math
from typing import Any

import pytest

from enterprise_platform.reliability.policies import (
    ReliabilityPolicy,
    RetryPolicy,
    TimeoutPolicy,
)


def test_timeout_policy_accepts_positive_finite_timeout() -> None:
    policy = TimeoutPolicy(
        timeout_seconds=5.0,
    )

    assert policy.timeout_seconds == 5.0


@pytest.mark.parametrize(
    "timeout_seconds",
    [
        0.0,
        -1.0,
        math.inf,
        -math.inf,
        math.nan,
    ],
)
def test_timeout_policy_rejects_invalid_timeout(
    timeout_seconds: float,
) -> None:
    with pytest.raises(ValueError):
        TimeoutPolicy(
            timeout_seconds=timeout_seconds,
        )


def test_retry_policy_defaults_are_bounded() -> None:
    policy = RetryPolicy()

    assert policy.max_attempts == 3
    assert policy.base_delay_seconds == 0.1
    assert policy.max_delay_seconds == 5.0
    assert policy.jitter_ratio == 0.2


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("base_delay_seconds", -1.0),
        ("base_delay_seconds", math.inf),
        ("max_delay_seconds", -1.0),
        ("max_delay_seconds", math.inf),
        ("jitter_ratio", -0.1),
        ("jitter_ratio", math.inf),
        ("jitter_ratio", math.nan),
    ],
)
def test_retry_policy_rejects_invalid_numeric_configuration(
    field_name: str,
    value: float,
) -> None:
    kwargs: dict[str, Any] = {
        "max_attempts": 3,
        "base_delay_seconds": 0.1,
        "max_delay_seconds": 5.0,
        "jitter_ratio": 0.2,
    }
    kwargs[field_name] = value

    with pytest.raises(ValueError):
        RetryPolicy(**kwargs)


def test_retry_policy_rejects_invalid_attempt_count() -> None:
    with pytest.raises(ValueError):
        RetryPolicy(
            max_attempts=0,
        )


def test_retry_policy_rejects_max_delay_below_base_delay() -> None:
    with pytest.raises(ValueError):
        RetryPolicy(
            base_delay_seconds=2.0,
            max_delay_seconds=1.0,
        )


def test_retry_policy_rejects_jitter_ratio_above_one() -> None:
    with pytest.raises(ValueError):
        RetryPolicy(
            jitter_ratio=1.01,
        )


def test_reliability_policy_composes_timeout_and_retry() -> None:
    timeout = TimeoutPolicy(
        timeout_seconds=10.0,
    )
    retry = RetryPolicy(
        max_attempts=4,
    )

    policy = ReliabilityPolicy(
        timeout=timeout,
        retry=retry,
    )

    assert policy.timeout is timeout
    assert policy.retry is retry


def test_reliability_policy_allows_retry_to_be_disabled() -> None:
    policy = ReliabilityPolicy(
        timeout=TimeoutPolicy(
            timeout_seconds=2.0,
        )
    )

    assert policy.retry is None
