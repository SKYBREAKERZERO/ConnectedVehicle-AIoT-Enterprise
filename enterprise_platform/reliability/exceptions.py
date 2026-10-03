from __future__ import annotations


class ReliabilityError(RuntimeError):
    """Base exception for reliability framework failures."""


class OperationTimeoutError(ReliabilityError):
    """Raised when an operation exceeds its configured deadline."""

    def __init__(
        self,
        *,
        operation_name: str,
        timeout_seconds: float,
    ) -> None:
        self.operation_name = operation_name
        self.timeout_seconds = timeout_seconds

        super().__init__(f"Operation '{operation_name}' exceeded its timeout.")


class RetryExhaustedError(ReliabilityError):
    """Raised when all retry attempts have been exhausted."""

    def __init__(
        self,
        *,
        operation_name: str,
        attempts: int,
    ) -> None:
        self.operation_name = operation_name
        self.attempts = attempts

        super().__init__(f"Operation '{operation_name}' failed after {attempts} attempts.")


class IdempotencyStoreError(ReliabilityError):
    """Raised when the idempotency persistence backend fails."""

    def __init__(self) -> None:
        super().__init__("Idempotency store operation failed.")


class IdempotencyStateError(ReliabilityError):
    """Raised when an invalid idempotency state transition is detected."""

    def __init__(self) -> None:
        super().__init__("Idempotency state transition failed.")
