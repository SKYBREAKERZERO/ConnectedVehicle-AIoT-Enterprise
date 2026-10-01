from __future__ import annotations

from unittest.mock import Mock, patch

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from enterprise_platform.database.session import create_session_factory


def test_create_session_factory_uses_platform_defaults() -> None:
    engine = Mock(spec=AsyncEngine)
    expected_factory = Mock()

    with patch(
        "enterprise_platform.database.session.async_sessionmaker",
        return_value=expected_factory,
    ) as sessionmaker:
        factory = create_session_factory(engine)

    assert factory is expected_factory

    sessionmaker.assert_called_once_with(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
