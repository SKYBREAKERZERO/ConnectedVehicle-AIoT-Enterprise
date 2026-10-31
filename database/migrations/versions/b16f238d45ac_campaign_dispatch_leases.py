"""Recoverable dispatcher leases without granting runtime campaign/job mutations."""

from alembic import op

from enterprise_platform.database.ota_dispatch_contract import FUNCTIONS

revision = "b16f238d45ac"
down_revision = "a05e127c349b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE public.ota_campaigns ADD COLUMN dispatch_owner uuid")
    op.execute("ALTER TABLE public.ota_campaigns ADD COLUMN dispatch_until timestamptz")
    op.execute("""ALTER TABLE public.ota_campaigns ADD CONSTRAINT ck_campaign_dispatch_lease
      CHECK ((dispatch_owner IS NULL) = (dispatch_until IS NULL))""")
    op.execute("""CREATE INDEX ix_campaign_dispatch_available ON public.ota_campaigns
      (tenant_id,updated_at,id) WHERE status='running'""")
    signatures = []
    for name in ("ota_campaign_command", "ota_campaign_claim", "ota_campaign_release"):
        arguments, result, body = FUNCTIONS[name]
        op.execute(
            f"CREATE OR REPLACE FUNCTION public.{name}({arguments}) RETURNS {result} "
            f"LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ {body} $$"
        )
        signature = name + "(" + ",".join(p.split()[-1] for p in arguments.split(",")) + ")"
        signatures.append("public." + signature)
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
    op.execute(f"""DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT rolname FROM pg_roles WHERE rolname='app_user' OR rolname IN
        (SELECT role_name FROM public.runtime_tenant_bindings
         WHERE left(role_name,10)='app_user__') LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION {",".join(signatures)} TO %I',r.rolname);
      END LOOP;
    END $$""")


def downgrade() -> None:
    raise RuntimeError("Preserve dispatcher recovery and audit; use a reviewed forward migration")
