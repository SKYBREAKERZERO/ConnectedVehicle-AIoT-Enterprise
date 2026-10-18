"""Tenant-bound immutable campaign targets and controlled rollout commands."""

from alembic import op

from enterprise_platform.database.ota_campaign_contract import CAMPAIGN_READY, FUNCTIONS, TABLES

revision = "a05e127c349b"
down_revision = "f94d016b238a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE public.ota_campaigns(
      tenant_id varchar(255),id varchar(36),name varchar(128) NOT NULL,
      release_id varchar(36) NOT NULL,status text NOT NULL CHECK(status IN
        ('draft','frozen','running','paused','completed','cancelled')),
      manifest jsonb NOT NULL,signature varchar(88) NOT NULL,
      canary_size integer NOT NULL CHECK(canary_size BETWEEN 1 AND 100),
      wave_size integer NOT NULL CHECK(wave_size BETWEEN 1 AND 100),
      max_failures integer NOT NULL CHECK(max_failures>=0 AND max_failures<canary_size),
      observation_seconds integer NOT NULL CHECK(observation_seconds BETWEEN 0 AND 3600),
      wave_timeout_seconds integer NOT NULL CHECK(wave_timeout_seconds BETWEEN 30 AND 86400),
      current_wave integer NOT NULL DEFAULT -1 CHECK(current_wave>=-1),
      wave_started_at timestamptz,snapshot_sha256 varchar(64),pause_reason text,
      created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),created_by text NOT NULL,
      PRIMARY KEY(tenant_id,id),
      FOREIGN KEY(tenant_id,release_id) REFERENCES public.firmware_releases(tenant_id,id))""")
    op.execute("""CREATE TABLE public.ota_campaign_targets(
      tenant_id varchar(255),campaign_id varchar(36),ecu_id varchar(36),
      vehicle_id varchar(36) NOT NULL,wave integer NOT NULL CHECK(wave>=0),
      job_id varchar(36) NOT NULL,dispatched boolean NOT NULL DEFAULT false,
      firmware_version varchar(64) NOT NULL,
      security_version bigint NOT NULL CHECK(security_version>=0),
      PRIMARY KEY(tenant_id,campaign_id,ecu_id),UNIQUE(tenant_id,job_id),
      FOREIGN KEY(tenant_id,campaign_id) REFERENCES public.ota_campaigns(tenant_id,id),
      FOREIGN KEY(tenant_id,ecu_id) REFERENCES public.ecu_inventory(tenant_id,id))""")
    op.execute("""CREATE INDEX ix_campaign_wave ON public.ota_campaign_targets
      (tenant_id,campaign_id,wave,dispatched)""")
    op.execute("""CREATE INDEX ix_campaign_running ON public.ota_campaigns(tenant_id,status,id)""")
    op.execute("""CREATE TABLE public.ota_campaign_events(
      tenant_id varchar(255),operation_id uuid,campaign_id varchar(36) NOT NULL,
      request jsonb NOT NULL,result jsonb NOT NULL,
      occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      PRIMARY KEY(tenant_id,operation_id),
      FOREIGN KEY(tenant_id,campaign_id) REFERENCES public.ota_campaigns(tenant_id,id))""")
    for table in TABLES:
        op.execute(f"REVOKE ALL ON public.{table} FROM PUBLIC")
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        # No fallback to a user-settable tenant context, including for shared base roles.
        predicate = "tenant_id = public.runtime_tenant_binding()"
        op.execute(f"CREATE POLICY runtime_access ON public.{table} USING (true) WITH CHECK (true)")
        op.execute(
            f"CREATE POLICY tenant_guard ON public.{table} AS RESTRICTIVE "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )
    signatures = []
    for name, (arguments, result, body) in FUNCTIONS.items():
        op.execute(
            f"CREATE FUNCTION public.{name}({arguments}) RETURNS {result} "
            f"LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ {body} $$"
        )
        signature = name + "(" + ",".join(p.split()[-1] for p in arguments.split(",")) + ")"
        signatures.append("public." + signature)
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
    op.execute(
        "CREATE OR REPLACE FUNCTION public.ota_execution_ready(p_tenant text,p_job text) "
        "RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog "
        f"AS $$ {CAMPAIGN_READY} $$"
    )
    op.execute(f"""DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT rolname FROM pg_roles WHERE rolname='app_user' OR rolname IN
        (SELECT role_name FROM public.runtime_tenant_bindings
         WHERE left(role_name,10)='app_user__') LOOP
        EXECUTE format('GRANT SELECT ON {",".join("public." + t for t in TABLES)} TO %I',r.rolname);
        EXECUTE format('GRANT EXECUTE ON FUNCTION {",".join(signatures)} TO %I',r.rolname);
      END LOOP;
    END $$""")


def downgrade() -> None:
    raise RuntimeError("Preserve frozen campaign targets and audit; use reviewed forward recovery")
