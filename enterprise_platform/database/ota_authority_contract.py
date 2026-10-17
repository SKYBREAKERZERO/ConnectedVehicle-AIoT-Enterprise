"""Reviewed database capability boundary; runtime credentials cannot mint receipts."""

NONCE_BODY = """
BEGIN
  IF public.runtime_tenant_binding() IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION 'ECU tenant binding required' USING ERRCODE='42501';
  END IF;
  INSERT INTO ota_authority.device_nonces(tenant_id,device_id,nonce)
    VALUES(p_tenant,p_device,p_nonce);
END;
"""

INSTALL_BODY = """
DECLARE
  r jsonb; k bytea; e public.ota_executions%ROWTYPE;
  j public.ota_jobs%ROWTYPE; m jsonb; evidence jsonb;
BEGIN
  IF octet_length(p_payload)>32768 OR p_mac !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Invalid installation receipt' USING ERRCODE='42501';
  END IF;
  r := p_payload::jsonb;
  IF public.runtime_tenant_binding() IS DISTINCT FROM r->>'tenant_id'
     OR r->>'protocol' IS DISTINCT FROM 'cv-install/1'
     OR jsonb_typeof(r->'expires') IS DISTINCT FROM 'number'
     OR (r->>'expires')::bigint < extract(epoch FROM clock_timestamp())
     OR (r->>'expires')::bigint > extract(epoch FROM clock_timestamp())+120 THEN
    RAISE EXCEPTION 'Expired or foreign installation receipt' USING ERRCODE='42501';
  END IF;
  SELECT secret INTO k FROM ota_authority.receipt_keys
    WHERE tenant_id=r->>'tenant_id' AND key_id=r->>'key_id' AND enabled;
  IF k IS NULL OR ota_authority.digest(
       ota_authority.hmac(convert_to(p_payload,'UTF8'),k,'sha256'),'sha256')
      IS DISTINCT FROM ota_authority.digest(decode(p_mac,'hex'),'sha256') THEN
    RAISE EXCEPTION 'Untrusted installation receipt' USING ERRCODE='42501';
  END IF;
  SELECT * INTO j FROM public.ota_jobs
    WHERE tenant_id=r->>'tenant_id' AND id=r->>'job_id' FOR UPDATE;
  SELECT * INTO e FROM public.ota_executions
    WHERE tenant_id=j.tenant_id AND id=j.id FOR UPDATE;
  SELECT payload::jsonb INTO evidence FROM public.ota_execution_reports
    WHERE tenant_id=j.tenant_id AND job_id=j.id AND id=r->'report'->>'event_id';
  m := r->'manifest';
  IF j.id IS NULL OR e.id IS NULL OR j.status<>'succeeded'
     OR j.vehicle_id IS DISTINCT FROM r->>'vehicle_id'
     OR j.ecu_id IS DISTINCT FROM r->>'ecu_id'
     OR j.release_id IS DISTINCT FROM m->>'release_id'
     OR j.ecu_type IS DISTINCT FROM m->>'ecu_type'
     OR j.hardware_version IS DISTINCT FROM m->>'hardware_version'
     OR e.manifest::jsonb IS DISTINCT FROM m
     OR e.signature IS DISTINCT FROM r->>'signature'
     OR e.device_id IS DISTINCT FROM r->>'device_id'
     OR e.claim_token IS DISTINCT FROM r->'report'->>'claim_token'
     OR e.report_sequence<>2 OR evidence IS DISTINCT FROM r->'report'
     OR evidence->>'status' IS DISTINCT FROM 'succeeded'
     OR evidence->>'sequence' IS DISTINCT FROM '2'
     OR evidence->>'observed_sha256' IS DISTINCT FROM m->>'sha256'
     OR NOT EXISTS (SELECT FROM public.ota_audit_events
       WHERE tenant_id=j.tenant_id AND resource_type='job' AND resource_id=j.id
         AND action='report' AND operation_key=evidence->>'event_id'
         AND actor_id=e.device_id AND payload_sha256=r->>'report_sha256') THEN
    RAISE EXCEPTION 'Installation receipt does not match execution' USING ERRCODE='42501';
  END IF;
  INSERT INTO ota_authority.installation_receipts(tenant_id,job_id,payload,mac)
    VALUES(j.tenant_id,j.id,r,p_mac);
  UPDATE public.ecu_inventory SET firmware_version=m->>'version',
    security_version=(m->>'security_version')::bigint
    WHERE tenant_id=j.tenant_id AND id=j.ecu_id AND vehicle_id=j.vehicle_id
      AND security_version<(m->>'security_version')::bigint;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Installation counter conflict' USING ERRCODE='23514';
  END IF;
END;
"""

FUNCTIONS = {
    "ota_accept_device_nonce": ("p_tenant text,p_device text,p_nonce uuid", NONCE_BODY),
    "ota_apply_installation": ("p_payload text,p_mac text", INSTALL_BODY),
}
