from __future__ import annotations


class RemoteCommandDomainError(ValueError):
    """Base exception for Remote Command domain failures."""


class InvalidRemoteCommandIdError(RemoteCommandDomainError):
    """Raised when a remote command identifier is invalid."""


class InvalidRemoteCommandTransitionError(RemoteCommandDomainError):
    """Raised when a remote command status transition is invalid."""


class InvalidIdempotencyKeyError(RemoteCommandDomainError):
    """Raised when a remote command idempotency key is invalid."""


class InvalidRemoteCommandTTLError(RemoteCommandDomainError):
    """Raised when a remote command TTL is invalid."""
