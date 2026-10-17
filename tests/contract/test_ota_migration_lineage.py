"""The published execution line is authoritative; a second local branch is not a merge."""

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_single_published_ota_migration_line() -> None:
    scripts = ScriptDirectory.from_config(Config("alembic.ini"))
    assert scripts.get_heads() == ["e83c904a127f"]
    assert scripts.get_revision("e83c904a127f").down_revision == "d72fa60b319e"
    assert scripts.get_revision("d72fa60b319e").down_revision == "c61f98a742de"
    assert "d72a91b63ef0" not in {revision.revision for revision in scripts.walk_revisions()}
