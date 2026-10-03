from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DeadLetterPolicy:
    """Defines when repeated message delivery is dead-lettered."""

    max_receive_count: int = 5

    def __post_init__(self) -> None:
        if self.max_receive_count < 1:
            raise ValueError("max_receive_count must be at least 1.")
