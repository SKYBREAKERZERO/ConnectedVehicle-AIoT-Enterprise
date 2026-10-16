"""Tenant-bound OTA inventory, immutable releases, intents and append-only audit."""

from pathlib import Path

from alembic import op

revision = "c61f98a742de"
down_revision = "b48f720da63e"
branch_labels = None
depends_on = None

TABLES = ("ecu_inventory", "firmware_releases", "ota_jobs", "ota_audit_events")


def upgrade() -> None:
    source = Path(__file__).resolve().parents[1] / "sql/c61f98a742de-ota-foundation.sql"
    for statement in source.read_text(encoding="utf-8").split(";"):
        if statement.strip():
            op.execute(statement)
    for table in TABLES:
        op.execute(f"REVOKE ALL ON public.{table} FROM PUBLIC")
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        predicate = (
            "tenant_id = COALESCE(public.runtime_tenant_binding(), "
            "nullif(current_setting('app.tenant_id', true), ''))"
        )
        op.execute(f"CREATE POLICY runtime_access ON public.{table} USING (true) WITH CHECK (true)")
        op.execute(
            f"CREATE POLICY tenant_guard ON public.{table} AS RESTRICTIVE "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )
    # Existing dedicated tenants must keep working after the schema-only upgrade.
    # Server-side iteration also preserves Alembic offline SQL generation.
    op.execute("""DO $$ DECLARE runtime_role record; BEGIN
      FOR runtime_role IN SELECT rolname FROM pg_roles
        WHERE rolname='app_user' OR rolname IN (
          SELECT role_name FROM public.runtime_tenant_bindings
          WHERE left(role_name,10)='app_user__') LOOP
        EXECUTE format('GRANT SELECT,INSERT ON public.ecu_inventory,public.firmware_releases,
                       public.ota_jobs,public.ota_audit_events TO %I',runtime_role.rolname);
        EXECUTE format('GRANT UPDATE (status,updated_at) ON public.ota_jobs TO %I',
                       runtime_role.rolname);
      END LOOP;
    END $$""")


def downgrade() -> None:
    raise RuntimeError("OTA records and audit require a reviewed forward recovery migration")
