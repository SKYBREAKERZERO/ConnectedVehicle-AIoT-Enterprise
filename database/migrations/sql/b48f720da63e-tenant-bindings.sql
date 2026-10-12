-- Owned only by migration identity. Runtime roles cannot alter tenant bindings.
CREATE TABLE IF NOT EXISTS public.runtime_tenant_bindings (
    role_name text PRIMARY KEY, tenant_id text NOT NULL CHECK (tenant_id <> '')
);
REVOKE ALL ON public.runtime_tenant_bindings FROM PUBLIC;
CREATE OR REPLACE FUNCTION public.runtime_tenant_binding() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $$ SELECT tenant_id FROM public.runtime_tenant_bindings WHERE role_name=session_user $$;
