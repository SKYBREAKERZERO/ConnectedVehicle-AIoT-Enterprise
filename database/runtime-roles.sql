-- Cluster role-manager only; Schema migrations must not execute this file.
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
                WHERE u.rolname IN ('app_user', 'outbox_worker', 'remote_command_worker'))
     OR EXISTS (SELECT FROM pg_proc p JOIN pg_roles u ON p.proowner = u.oid
                WHERE u.rolname IN ('app_user', 'outbox_worker', 'remote_command_worker')) THEN
    RAISE EXCEPTION 'Runtime roles must not own database objects; transfer ownership first';
  END IF;
  FOR r IN SELECT parent.rolname AS parent, child.rolname AS child
           FROM pg_auth_members m JOIN pg_roles parent ON parent.oid = m.roleid
           JOIN pg_roles child ON child.oid = m.member
           WHERE child.rolname IN ('app_user', 'outbox_worker', 'remote_command_worker') LOOP
    EXECUTE format('REVOKE %I FROM %I', r.parent, r.child);
  END LOOP;
END $$;
