from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from enterprise_platform.security.identity import Principal
from enterprise_platform.security.permissions import Permission


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Security information associated with the current execution context."""

    principal: Principal
    granted_permissions: frozenset[Permission] = frozenset()


_security_context: ContextVar[SecurityContext | None] = ContextVar(
    "security_context",
    default=None,
)


def get_security_context() -> SecurityContext | None:
    return _security_context.get()


@contextmanager
def bind_security_context(
    context: SecurityContext,
) -> Iterator[None]:
    token = _security_context.set(context)

    try:
        yield
    finally:
        _security_context.reset(token)
