"""Reuse isolated PostgreSQL bootstrap, with a Day35-bound JUnit envelope."""

from collections.abc import Callable

import pytest

from scripts.day34_evidence import binding
from tests.integration.day21.conftest import postgres as postgres
from tests.integration.day21.conftest import world as world


@pytest.fixture(scope="session", autouse=True)
def day35_junit_binding(record_testsuite_property: Callable[[str, str], None]) -> None:
    for name, value in binding().items():
        record_testsuite_property(name, value)
