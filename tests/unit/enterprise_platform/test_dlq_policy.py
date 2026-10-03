from __future__ import annotations

import pytest

from enterprise_platform.reliability.dlq import (
    DeadLetterPolicy,
)


def test_dead_letter_policy_has_bounded_default() -> None:
    policy = DeadLetterPolicy()

    assert policy.max_receive_count == 5


def test_dead_letter_policy_accepts_custom_receive_count() -> None:
    policy = DeadLetterPolicy(
        max_receive_count=3,
    )

    assert policy.max_receive_count == 3


@pytest.mark.parametrize(
    "max_receive_count",
    [
        0,
        -1,
    ],
)
def test_dead_letter_policy_rejects_invalid_receive_count(
    max_receive_count: int,
) -> None:
    with pytest.raises(ValueError):
        DeadLetterPolicy(
            max_receive_count=max_receive_count,
        )
