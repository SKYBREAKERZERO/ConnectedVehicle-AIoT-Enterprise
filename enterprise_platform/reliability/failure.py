from __future__ import annotations

from enum import StrEnum
from typing import Protocol


class FailureDisposition(StrEnum):
    """High-level decision used by the retry executor."""

    RETRYABLE = "retryable"
    NON_RETRYABLE = "non_retryable"


class FailureClassifier(Protocol):
    """Classifies whether an operation failure may be retried."""

    def classify(
        self,
        error: Exception,
    ) -> FailureDisposition: ...


class ExceptionTypeFailureClassifier:
    """Classifies failures from an explicit allowlist of exception types."""

    def __init__(
        self,
        retryable_exceptions: tuple[type[Exception], ...],
    ) -> None:
        self._retryable_exceptions = retryable_exceptions

    def classify(
        self,
        error: Exception,
    ) -> FailureDisposition:
        if isinstance(
            error,
            self._retryable_exceptions,
        ):
            return FailureDisposition.RETRYABLE

        return FailureDisposition.NON_RETRYABLE
