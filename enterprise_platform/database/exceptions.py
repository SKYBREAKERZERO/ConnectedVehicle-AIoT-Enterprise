from __future__ import annotations


class DatabasePlatformError(RuntimeError):
    """Base exception for database platform errors."""


class UnitOfWorkNotStartedError(DatabasePlatformError):
    """Raised when a unit of work is used outside its context."""
