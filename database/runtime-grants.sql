-- Schema owner only. Cluster roles must already exist.
DO $$ DECLARE r record; BEGIN
  FOR r IN SELECT table_name, column_name FROM information_schema.columns
           WHERE table_schema = 'public' LOOP
    EXECUTE format('REVOKE ALL (%I) ON public.%I FROM PUBLIC, app_user, outbox_worker, remote_command_worker', r.column_name, r.table_name);
  END LOOP;
END $$;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, app_user, outbox_worker, remote_command_worker;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, app_user, outbox_worker, remote_command_worker;
REVOKE ALL ON SCHEMA public FROM app_user, outbox_worker, remote_command_worker;
DO $$ BEGIN
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC, app_user, outbox_worker, remote_command_worker', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO app_user, outbox_worker, remote_command_worker', current_database());
END $$;
GRANT USAGE ON SCHEMA public TO app_user, outbox_worker, remote_command_worker;
-- Current API reads vehicles and commands, inserts commands and outbox events.
GRANT SELECT ON public.vehicles, public.remote_commands TO app_user;
GRANT INSERT (id,vehicle_id,tenant_id,command_type,status,idempotency_key,
              created_at,updated_at,expires_at) ON public.remote_commands TO app_user;
GRANT INSERT ON public.outbox_events TO app_user;
GRANT SELECT ON public.outbox_events TO outbox_worker;
GRANT UPDATE (status, attempts, available_at, claim_token, lease_expires_at, published_at, failed_at, failure_code, failure_reason)
  ON public.outbox_events TO outbox_worker;
GRANT SELECT ON public.remote_commands TO remote_command_worker;
GRANT UPDATE (status, updated_at) ON public.remote_commands TO remote_command_worker;
-- New API device ingress has only append/read ledger privileges and status updates.
GRANT SELECT, INSERT ON public.command_reports, public.telemetry_samples TO app_user;
GRANT UPDATE (status, updated_at) ON public.remote_commands TO app_user;
-- OTA foundation: immutable inventory/releases, append-only audit, job status only.
-- The conditional also permits pre-OTA backup rehearsals to reset legacy grants.
DO $$ BEGIN
  IF to_regclass('public.ecu_inventory') IS NOT NULL THEN
    GRANT SELECT,INSERT ON public.ecu_inventory,public.firmware_releases,
      public.ota_jobs,public.ota_audit_events TO app_user;
    GRANT UPDATE (status,updated_at) ON public.ota_jobs TO app_user;
  END IF;
END $$;
DO $$ BEGIN
  IF to_regclass('public.ota_executions') IS NOT NULL THEN
    GRANT SELECT,INSERT ON public.ota_executions,public.ota_execution_reports TO app_user;
    GRANT UPDATE (device_id,claim_token,claim_operation,report_sequence) ON public.ota_executions TO app_user;
    -- Legacy revision grants are removed by the forward security migration.
    REVOKE UPDATE (firmware_version,security_version) ON public.ecu_inventory FROM app_user;
    IF to_regprocedure('public.ota_apply_installation(text,text)') IS NOT NULL THEN
      REVOKE INSERT ON public.ecu_inventory FROM app_user;
      GRANT INSERT (tenant_id,id,vehicle_id,ecu_type,hardware_version,firmware_version,
                    serial_number,created_at,created_by) ON public.ecu_inventory TO app_user;
      GRANT EXECUTE ON FUNCTION public.ota_apply_installation(text,text),
        public.ota_accept_device_nonce(text,text,uuid) TO app_user;
    END IF;
  END IF;
END $$;
DO $$ BEGIN
  IF to_regprocedure('public.ota_transition(text,text)') IS NOT NULL THEN
    REVOKE UPDATE (status,updated_at) ON public.ota_jobs FROM app_user;
    REVOKE UPDATE (device_id,claim_token,claim_operation,report_sequence)
      ON public.ota_executions FROM app_user;
    REVOKE INSERT ON public.ota_executions,public.ota_execution_reports,public.ota_audit_events
      FROM app_user;
    REVOKE EXECUTE ON FUNCTION public.ota_apply_installation(text,text) FROM app_user;
    GRANT EXECUTE ON FUNCTION public.ota_claim_resolution(text,text,text),public.ota_transition(text,text),public.ota_execution_ready(text,text),
      public.ota_publisher_trusted(text,text),public.ota_cancel_pending(text,text,text,text,text,text,text),
      public.ota_append_intent_audit(text,text,text,text,text,text,text,text,text) TO app_user;
  END IF;
END $$;
-- New migration-owned tables never automatically become accessible to runtimes.
DO $$ BEGIN
  IF to_regprocedure('public.ota_campaign_command(text,text)') IS NOT NULL THEN
    GRANT SELECT ON public.ota_campaigns,public.ota_campaign_targets,public.ota_campaign_events
      TO app_user;
    GRANT EXECUTE ON FUNCTION public.ota_campaign_command(text,text),
      public.ota_campaign_summary(text,text),public.ota_campaign_job_allowed(text,text)
      TO app_user;
  END IF;
END $$;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC, app_user, outbox_worker, remote_command_worker;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC, app_user, outbox_worker, remote_command_worker;

-- Day21 lease authority grants no direct campaign or Job UPDATE privileges.
DO $$ BEGIN
  IF to_regprocedure('public.ota_campaign_claim(text,uuid,text,integer)') IS NOT NULL THEN
    GRANT EXECUTE ON FUNCTION public.ota_campaign_claim(text,uuid,text,integer),
      public.ota_campaign_release(text,uuid,text) TO app_user;
  END IF;
END $$;
