import pytest

from tests.integration.day12.migration_support import normalized_constraint

SOURCE = (
    "CHECK (((status)::text = ANY ((ARRAY['requested'::character varying, "
    "'sent'::character varying])::text[])))"
)
RESTORED = (
    "CHECK (((status)::text = ANY (ARRAY[('requested'::character varying)::text, "
    "('sent'::character varying)::text])))"
)


def test_restore_cast_representation_normalizes_without_changing_predicate() -> None:
    assert normalized_constraint(SOURCE) == normalized_constraint(RESTORED)


@pytest.mark.parametrize(
    "changed",
    [
        RESTORED + " OR true",
        RESTORED.replace("'sent'", "'unsafe'"),
        RESTORED.replace("status", "command_type"),
    ],
)
def test_constraint_weakening_never_normalizes_to_original(changed: str) -> None:
    assert normalized_constraint(SOURCE) != normalized_constraint(changed)
