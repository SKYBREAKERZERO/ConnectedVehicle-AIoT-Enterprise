"""Controlled OTA transitions, attested bootstrap and claim quarantine."""

from alembic import op

from enterprise_platform.database.ota_lifecycle_contract import FUNCTIONS, INITIAL_BODY

revision = "f94d016b238a"
down_revision = "e83c904a127f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE public.ota_executions ADD COLUMN install_challenge varchar(36)")
    op.execute(
        "ALTER TABLE public.ecu_inventory ADD COLUMN bootstrap_confirmed "
        "boolean NOT NULL DEFAULT false"
    )
    for statement in (
        (
            "CREATE TABLE ota_authority.ecu_bootstrap(tenant_id text,ecu_id "
            "text,vehicle_id text NOT NULL,firmware_version text NOT "
            "NULL,security_version bigint NOT NULL "
            "CHECK(security_version>=0),sha256 text NOT NULL,actor text NOT "
            "NULL,reason text NOT NULL,operation uuid NOT NULL UNIQUE,PRIMARY "
            "KEY(tenant_id,ecu_id))"
        ),
        (
            "CREATE TABLE ota_authority.claim_quarantines(tenant_id "
            "text,job_id text,resolved boolean NOT NULL DEFAULT "
            "false,operation uuid NOT NULL UNIQUE,evidence jsonb NOT "
            "NULL,PRIMARY KEY(tenant_id,job_id))"
        ),
        (
            "CREATE TABLE ota_authority.publisher_keys(tenant_id text,key_id "
            "text,public_key text NOT NULL,not_before timestamptz NOT "
            "NULL,not_after timestamptz NOT NULL,revoked boolean NOT NULL "
            "DEFAULT false,PRIMARY "
            "KEY(tenant_id,key_id),CHECK(not_after>not_before))"
        ),
        (
            "CREATE TABLE ota_authority.management_audit(operation uuid "
            "PRIMARY KEY,tenant_id text NOT NULL,action text NOT NULL,actor "
            "text NOT NULL,reason text NOT NULL,payload jsonb NOT "
            "NULL,occurred_at timestamptz NOT NULL DEFAULT now())"
        ),
        (
            "CREATE TABLE ota_authority.transition_receipts(tenant_id "
            "text,job_id text,operation text,payload jsonb NOT NULL,mac text "
            "NOT NULL,PRIMARY KEY(tenant_id,operation))"
        ),
    ):
        op.execute(statement)
    for name, (arguments, result, body) in FUNCTIONS.items():
        op.execute(
            f"CREATE FUNCTION public.{name}({arguments}) RETURNS {result} "
            f"LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ {body} $$"
        )
    op.execute(
        "CREATE FUNCTION public.ota_initial_intent() RETURNS trigger "
        f"LANGUAGE plpgsql SET search_path=pg_catalog AS $$ {INITIAL_BODY} $$"
    )
    op.execute("REVOKE ALL ON FUNCTION public.ota_initial_intent() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER ota_initial_intent BEFORE INSERT ON "
        "public.ota_jobs FOR EACH ROW EXECUTE FUNCTION "
        "public.ota_initial_intent()"
    )
    for function in (
        "ota_transition(text,text)",
        "ota_claim_resolution(text,text,text)",
        "ota_execution_ready(text,text)",
        "ota_publisher_trusted(text,text)",
        "ota_cancel_pending(text,text,text,text,text,text,text)",
        "ota_append_intent_audit(text,text,text,text,text,text,text,text,text)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION public.{function} FROM PUBLIC")
    signatures = ",".join(
        "public." + name + "(" + ",".join(part.split()[-1] for part in arguments.split(",")) + ")"
        for name, (arguments, _, _) in FUNCTIONS.items()
    )
    op.execute(f"""DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT rolname FROM pg_roles WHERE rolname='app_user' OR rolname IN
        (SELECT role_name FROM public.runtime_tenant_bindings
         WHERE left(role_name,10)='app_user__') LOOP
        EXECUTE format('REVOKE UPDATE ON public.ota_jobs,public.ota_executions FROM %I',r.rolname);
        EXECUTE format('REVOKE UPDATE(status,updated_at) ON public.ota_jobs FROM %I',r.rolname);
        EXECUTE format('REVOKE UPDATE(device_id,claim_token,claim_operation,report_sequence)
          ON public.ota_executions FROM %I',r.rolname);
        EXECUTE format('REVOKE INSERT ON public.ota_executions,public.ota_execution_reports,
          public.ota_audit_events FROM %I',r.rolname);
        EXECUTE format('REVOKE EXECUTE ON FUNCTION public.ota_apply_installation(text,text)
          FROM %I',r.rolname);
        EXECUTE format('GRANT EXECUTE ON FUNCTION {signatures} TO %I',r.rolname);
      END LOOP;
    END $$""")


def downgrade() -> None:
    raise RuntimeError("Preserve OTA proof and reconciliation history; use forward recovery")
