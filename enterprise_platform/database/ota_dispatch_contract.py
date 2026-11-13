"""Day21 forward-only dispatcher contracts; Day19 migration sources stay immutable."""

from enterprise_platform.database.ota_campaign_contract import COMMAND as DAY19_COMMAND
from enterprise_platform.database.ota_campaign_contract import FUNCTIONS as DAY19_FUNCTIONS

# Check the lease only after the campaign row lock. A worker that lost its lease
# cannot advance a wave, even when it resumes after a long process suspension.
COMMAND = DAY19_COMMAND.replace(
    "  IF action='create' THEN",
    """  IF action IN ('tick','pause') AND b ? 'dispatch_owner' AND (
    c.dispatch_owner IS DISTINCT FROM (b->>'dispatch_owner')::uuid OR
    c.dispatch_until IS NULL OR c.dispatch_until <= clock_timestamp()) THEN
    RAISE EXCEPTION 'Dispatcher lease expired' USING ERRCODE='55000';
  END IF;
  IF action='create' THEN""",
)

CLAIM = """
DECLARE chosen text;
BEGIN
  IF public.runtime_tenant_binding() IS DISTINCT FROM p_tenant OR p_owner IS NULL
    OR p_seconds IS NULL OR p_seconds NOT BETWEEN 1 AND 300 THEN
    RAISE EXCEPTION 'Invalid dispatcher claim' USING ERRCODE='42501'; END IF;
  SELECT id INTO chosen FROM public.ota_campaigns
    WHERE tenant_id=p_tenant AND status='running'
      AND (p_campaign IS NULL OR id=p_campaign)
      AND (dispatch_owner=p_owner OR dispatch_until IS NULL OR dispatch_until<=clock_timestamp())
    ORDER BY (dispatch_owner=p_owner) DESC NULLS LAST,updated_at,id FOR UPDATE SKIP LOCKED LIMIT 1;
  IF chosen IS NULL THEN RETURN NULL; END IF;
  UPDATE public.ota_campaigns SET dispatch_owner=p_owner,
    dispatch_until=clock_timestamp()+make_interval(secs=>p_seconds)
    WHERE tenant_id=p_tenant AND id=chosen;
  RETURN chosen;
END;
"""

RELEASE = """
BEGIN
  IF public.runtime_tenant_binding() IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION 'Foreign dispatcher release' USING ERRCODE='42501'; END IF;
  UPDATE public.ota_campaigns SET dispatch_owner=NULL,dispatch_until=NULL
    WHERE tenant_id=p_tenant AND id=p_campaign AND dispatch_owner=p_owner;
  RETURN FOUND;
END;
"""

FUNCTIONS = {
    **DAY19_FUNCTIONS,
    "ota_campaign_command": ("p_payload text,p_mac text", "jsonb", COMMAND),
    "ota_campaign_claim": (
        "p_tenant text,p_owner uuid,p_campaign text,p_seconds integer",
        "text",
        CLAIM,
    ),
    "ota_campaign_release": ("p_tenant text,p_owner uuid,p_campaign text", "boolean", RELEASE),
}
