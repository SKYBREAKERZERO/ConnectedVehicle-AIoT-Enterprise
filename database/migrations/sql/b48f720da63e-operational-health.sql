CREATE OR REPLACE FUNCTION public.runtime_health_summary() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $$ SELECT jsonb_build_object(
 'stalled_vehicles',(SELECT count(DISTINCT (tenant_id,vehicle_id)) FROM public.remote_commands
    WHERE status IN ('requested','queued','dispatching','sent','acknowledged')
      AND expires_at<now()),
 'waiting_commands',(SELECT count(*) FROM public.remote_commands c
    WHERE c.status IN ('requested','queued') AND EXISTS (
      SELECT 1 FROM public.remote_commands p WHERE p.tenant_id=c.tenant_id
      AND p.vehicle_id=c.vehicle_id AND p.dispatch_order<c.dispatch_order
      AND p.status IN ('requested','queued','dispatching','sent','acknowledged')))
) $$;
REVOKE ALL ON FUNCTION public.runtime_health_summary() FROM PUBLIC;
