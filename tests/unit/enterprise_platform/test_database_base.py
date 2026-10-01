from enterprise_platform.database.base import Base


def test_base_uses_stable_constraint_naming_convention() -> None:
    convention = Base.metadata.naming_convention

    assert convention is not None
    assert convention["pk"] == "pk_%(table_name)s"
    assert convention["fk"] == ("fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s")
    assert convention["uq"] == "uq_%(table_name)s_%(column_0_name)s"
    assert convention["ck"] == "ck_%(table_name)s_%(column_0_name)s"
    assert convention["ix"] == "ix_%(column_0_label)s"
