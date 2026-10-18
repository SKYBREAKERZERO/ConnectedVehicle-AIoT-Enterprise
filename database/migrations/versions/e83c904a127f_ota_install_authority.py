"""Remove runtime version writes; require independently authenticated install receipts."""

from alembic import op

from enterprise_platform.database.ota_authority_contract import FUNCTIONS

revision = "e83c904a127f"
down_revision = "d72fa60b319e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA ota_authority")
    op.execute("REVOKE ALL ON SCHEMA ota_authority FROM PUBLIC")
    op.execute("CREATE EXTENSION pgcrypto WITH SCHEMA ota_authority")
    op.execute("""CREATE TABLE ota_authority.receipt_keys(
      tenant_id text NOT NULL,key_id text NOT NULL,secret bytea NOT NULL
      CHECK(octet_length(secret)=32),enabled boolean NOT NULL DEFAULT true,
      PRIMARY KEY(tenant_id,key_id))""")
    op.execute("""CREATE TABLE ota_authority.installation_receipts(
      tenant_id text NOT NULL,job_id text NOT NULL,payload jsonb NOT NULL,mac text NOT NULL,
      PRIMARY KEY(tenant_id,job_id))""")
    op.execute("""CREATE TABLE ota_authority.device_nonces(
      tenant_id text NOT NULL,device_id text NOT NULL,nonce uuid NOT NULL,
      received_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,device_id,nonce))""")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA ota_authority FROM PUBLIC")
    for name, (arguments, body) in FUNCTIONS.items():
        op.execute(
            f"CREATE FUNCTION public.{name}({arguments}) RETURNS void "
            f"LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ {body} $$"
        )
    op.execute("REVOKE ALL ON FUNCTION public.ota_apply_installation(text,text) FROM PUBLIC")
    op.execute("REVOKE ALL ON FUNCTION public.ota_accept_device_nonce(text,text,uuid) FROM PUBLIC")
    # Existing tenant roles must be corrected as well as subsequently provisioned roles.
    op.execute("""DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT rolname FROM pg_roles WHERE rolname='app_user' OR rolname IN
        (SELECT role_name FROM public.runtime_tenant_bindings WHERE left(role_name,10)='app_user__')
      LOOP
        EXECUTE format('REVOKE UPDATE,INSERT ON public.ecu_inventory FROM %I',r.rolname);
        EXECUTE format('REVOKE UPDATE (firmware_version,security_version), INSERT
          ON public.ecu_inventory FROM %I',r.rolname);
        EXECUTE format('GRANT INSERT (tenant_id,id,vehicle_id,ecu_type,hardware_version,
          firmware_version,serial_number,created_at,created_by)
          ON public.ecu_inventory TO %I',r.rolname);
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.ota_apply_installation(text,text),
          public.ota_accept_device_nonce(text,text,uuid) TO %I',r.rolname);
      END LOOP;
    END $$""")


def downgrade() -> None:
    raise RuntimeError("Installation authority requires reviewed forward recovery")
