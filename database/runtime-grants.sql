-- Run as the migration owner after Alembic, in the target database.
-- Passwords are set separately by the controlled provisioning tool.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user LOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'outbox_worker') THEN
    CREATE ROLE outbox_worker LOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'remote_command_worker') THEN
    CREATE ROLE remote_command_worker LOGIN;
  END IF;
END $$;
ALTER ROLE app_user NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE outbox_worker NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE remote_command_worker NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- Refuse legacy ownership; remove memberships that could bypass the allowlist.
DO $$ DECLARE r record; BEGIN
  IF EXISTS (SELECT FROM pg_class c JOIN pg_roles u ON c.relowner = u.oid
             WHERE u.rolname IN ('app_user', 'outbox_worker', 'remote_command_worker'))
     OR EXISTS (SELECT FROM pg_database d JOIN pg_roles u ON d.datdba = u.oid
                WHERE u.rolname IN ('app_user', 'outbox_worker', 'remote_command_worker'))
     OR EXISTS (SELECT FROM pg_namespace n JOIN pg_roles u ON n.nspowner = u.oid
                WHERE u.rolname IN ('app_user', 'outbox_worker', 'remote_command_worker')) THEN
    RAISE EXCEPTION 'Runtime roles must not own database objects; transfer ownership first';
  END IF;
  FOR r IN SELECT parent.rolname AS parent, child.rolname AS child
           FROM pg_auth_members m JOIN pg_roles parent ON parent.oid = m.roleid
           JOIN pg_roles child ON child.oid = m.member
           WHERE child.rolname IN ('app_user', 'outbox_worker', 'remote_command_worker') LOOP
    EXECUTE format('REVOKE %I FROM %I', r.parent, r.child);
  END LOOP;
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
GRANT INSERT ON public.remote_commands, public.outbox_events TO app_user;
GRANT SELECT ON public.outbox_events TO outbox_worker;
GRANT UPDATE (status, attempts, available_at, claim_token, lease_expires_at, published_at, failed_at, failure_code, failure_reason)
  ON public.outbox_events TO outbox_worker;
GRANT SELECT ON public.remote_commands TO remote_command_worker;
GRANT UPDATE (status, updated_at) ON public.remote_commands TO remote_command_worker;
-- New migration-owned tables never automatically become accessible to runtimes.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC, app_user, outbox_worker, remote_command_worker;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC, app_user, outbox_worker, remote_command_worker;
