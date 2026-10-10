from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_alembic_has_exactly_one_head() -> None:
    root = Path(__file__).resolve().parents[2]
    scripts = ScriptDirectory.from_config(Config(str(root / "alembic.ini")))

    heads = scripts.get_heads()

    assert len(heads) == 1, f"Expected exactly one Alembic head, found: {heads}"


def test_device_reports_depend_on_remote_commands() -> None:
    root = Path(__file__).resolve().parents[2]
    scripts = ScriptDirectory.from_config(Config(str(root / "alembic.ini")))

    migration = scripts.get_revision("c7a018d3f219")

    assert migration is not None
    assert migration.down_revision == "a52bcd546e2d"
