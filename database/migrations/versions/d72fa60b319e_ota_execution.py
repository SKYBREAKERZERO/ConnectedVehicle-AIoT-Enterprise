"""Signed local OTA execution with device-bound claims and durable reports."""

from pathlib import Path

from alembic import op

revision = "d72fa60b319e"
down_revision = "c61f98a742de"
branch_labels = None
depends_on = None


def upgrade() -> None:
    path = Path(__file__).resolve().parents[1] / "sql/d72fa60b319e-ota-execution.sql"
    for statement in path.read_text(encoding="utf-8").split(";"):
        if statement.strip():
            op.execute(statement)
    op.execute("""CREATE FUNCTION public.ota_monotonic_version() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog AS $$
        BEGIN
          IF NEW.security_version < OLD.security_version OR
             (NEW.firmware_version IS DISTINCT FROM OLD.firmware_version AND
              NEW.security_version <= OLD.security_version) THEN
            RAISE EXCEPTION 'OTA security counter cannot regress' USING ERRCODE='23514';
          END IF;
          RETURN NEW;
        END;
        $$""")
    op.execute("REVOKE ALL ON FUNCTION public.ota_monotonic_version() FROM PUBLIC")
    op.execute("""CREATE TRIGGER ota_monotonic_version BEFORE UPDATE ON public.ecu_inventory
        FOR EACH ROW EXECUTE FUNCTION public.ota_monotonic_version()""")
    for table in ("ota_executions", "ota_execution_reports"):
        op.execute(f"REVOKE ALL ON public.{table} FROM PUBLIC")
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        predicate = (
            "tenant_id = COALESCE(public.runtime_tenant_binding(), "
            "nullif(current_setting('app.tenant_id',true),''))"
        )
        op.execute(f"CREATE POLICY runtime_access ON public.{table} USING (true) WITH CHECK (true)")
        op.execute(
            f"CREATE POLICY tenant_guard ON public.{table} AS RESTRICTIVE "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )
    op.execute("""DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT rolname FROM pg_roles WHERE rolname='app_user' OR rolname IN
        (SELECT role_name FROM public.runtime_tenant_bindings
         WHERE left(role_name,10)='app_user__') LOOP
        EXECUTE format('GRANT SELECT,INSERT ON public.ota_executions,
                       public.ota_execution_reports TO %I',r.rolname);
        EXECUTE format('GRANT UPDATE (device_id,claim_token,claim_operation,report_sequence)
                       ON public.ota_executions TO %I',r.rolname);
        EXECUTE format('GRANT UPDATE (firmware_version,security_version)
                       ON public.ecu_inventory TO %I',r.rolname);
      END LOOP;
    END $$""")


def downgrade() -> None:
    raise RuntimeError("Preserve installed counters and execution history; use forward recovery")
