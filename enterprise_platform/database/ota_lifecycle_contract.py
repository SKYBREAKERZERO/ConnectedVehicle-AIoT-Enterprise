"""Database-owned OTA transitions. No runtime role can write execution state directly."""

READY_BODY = """
BEGIN
  RETURN public.runtime_tenant_binding() IS NOT DISTINCT FROM p_tenant
    AND EXISTS(SELECT FROM public.ota_jobs j JOIN public.vehicles v
      ON v.tenant_id=j.tenant_id AND v.id=j.vehicle_id
      JOIN ota_authority.ecu_bootstrap b ON b.tenant_id=j.tenant_id AND b.ecu_id=j.ecu_id
      JOIN public.ecu_inventory i ON i.tenant_id=j.tenant_id AND i.id=j.ecu_id
      WHERE j.tenant_id=p_tenant AND j.id=p_job AND v.status='active'
      AND i.bootstrap_confirmed AND b.vehicle_id=j.vehicle_id
      AND NOT EXISTS(SELECT FROM ota_authority.claim_quarantines q
                     WHERE q.tenant_id=j.tenant_id AND q.job_id=j.id ));
END;
"""

PUBLISHER_BODY = """
BEGIN
  RETURN public.runtime_tenant_binding() IS NOT DISTINCT FROM p_tenant
    AND EXISTS(SELECT FROM ota_authority.publisher_keys WHERE tenant_id=p_tenant
      AND key_id=p_key AND NOT revoked AND not_before<=clock_timestamp()
      AND not_after>clock_timestamp());
END;
"""

CANCEL_BODY = """
DECLARE j public.ota_jobs%ROWTYPE; previous public.ota_audit_events%ROWTYPE;
BEGIN
  IF public.runtime_tenant_binding() IS DISTINCT FROM p_tenant
     OR length(trim(p_actor)) NOT BETWEEN 1 AND 255
     OR length(trim(p_reason)) NOT BETWEEN 1 AND 500
     OR length(trim(p_key)) NOT BETWEEN 1 AND 255 THEN
    RAISE EXCEPTION 'Invalid cancellation identity' USING ERRCODE='23514';
  END IF;
  SELECT * INTO j FROM public.ota_jobs WHERE tenant_id=p_tenant AND id=p_job FOR UPDATE;
  SELECT * INTO previous FROM public.ota_audit_events WHERE tenant_id=p_tenant
    AND resource_type='job' AND action='cancel' AND operation_key=p_key;
  IF previous.id IS NOT NULL THEN
    IF previous.resource_id IS DISTINCT FROM p_job
      OR previous.payload_sha256 IS DISTINCT FROM p_hash
    THEN RAISE EXCEPTION 'Cancellation identity conflict' USING ERRCODE='23514'; END IF;
    RETURN;
  END IF;
  IF j.id IS NULL OR j.status<>'pending_verification' THEN
    RAISE EXCEPTION 'Only pending intent can be cancelled' USING ERRCODE='23514';
  END IF;
  UPDATE public.ota_jobs SET status='cancelled',updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant AND id=p_job;
  INSERT INTO public.ota_audit_events VALUES(p_tenant,p_audit,'job',p_job,'cancel',
    p_actor,p_key,p_hash,p_reason,clock_timestamp());
END;
"""

TRANSITION_BODY = """
DECLARE r jsonb; k bytea; j public.ota_jobs%ROWTYPE; e public.ota_executions%ROWTYPE;
  m jsonb; report jsonb; action text; counter bigint; old_time timestamptz;
BEGIN
  IF octet_length(p_payload)>65536 OR p_mac !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Invalid transition capability' USING ERRCODE='23514'; END IF;
  r:=p_payload::jsonb;
  IF public.runtime_tenant_binding() IS DISTINCT FROM r->>'tenant_id'
    OR r->>'protocol' IS DISTINCT FROM 'cv-install/1'
    OR jsonb_typeof(r->'expires') IS DISTINCT FROM 'number'
    OR (r->>'expires')::bigint<extract(epoch FROM clock_timestamp())
    OR (r->>'expires')::bigint>extract(epoch FROM clock_timestamp())+120 THEN
    RAISE EXCEPTION 'Expired or foreign transition' USING ERRCODE='23514'; END IF;
  SELECT secret INTO k FROM ota_authority.receipt_keys
    WHERE tenant_id=r->>'tenant_id' AND key_id=r->>'key_id' AND enabled;
  IF k IS NULL OR ota_authority.digest(
    ota_authority.hmac(convert_to(p_payload,'UTF8'),k,'sha256'),'sha256')
    IS DISTINCT FROM ota_authority.digest(decode(p_mac,'hex'),'sha256') THEN
    RAISE EXCEPTION 'Untrusted transition capability' USING ERRCODE='23514'; END IF;
  SELECT * INTO j FROM public.ota_jobs WHERE tenant_id=r->>'tenant_id'
    AND id=r->>'job_id' FOR UPDATE;
  IF j.id IS NULL OR NOT public.ota_execution_ready(j.tenant_id,j.id)
    OR j.vehicle_id IS DISTINCT FROM r->>'vehicle_id' OR j.ecu_id IS DISTINCT FROM r->>'ecu_id'
    OR j.status IS DISTINCT FROM r->>'expected_status' THEN
    RAISE EXCEPTION 'Execution policy or state changed' USING ERRCODE='23514'; END IF;
  PERFORM 1 FROM public.vehicles WHERE tenant_id=j.tenant_id AND id=j.vehicle_id
    AND status='active' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Vehicle inactive' USING ERRCODE='23514'; END IF;
  SELECT security_version INTO counter FROM public.ecu_inventory
    WHERE tenant_id=j.tenant_id AND id=j.ecu_id FOR UPDATE;
  SELECT * INTO e FROM public.ota_executions WHERE tenant_id=j.tenant_id AND id=j.id FOR UPDATE;
  m:=r->'manifest'; action:=r->>'action'; report:=r->'report';
  IF m->>'protocol' IS DISTINCT FROM 'cv-ota/2' OR m->>'tenant_id' IS DISTINCT FROM j.tenant_id
    OR m->>'release_id' IS DISTINCT FROM j.release_id OR m->>'ecu_type' IS DISTINCT FROM j.ecu_type
    OR m->>'hardware_version' IS DISTINCT FROM j.hardware_version
    OR NOT public.ota_publisher_trusted(j.tenant_id,m->>'key_id') THEN
    RAISE EXCEPTION 'Untrusted manifest binding' USING ERRCODE='23514'; END IF;
  IF action='verify' THEN
    IF j.status<>'pending_verification' OR e.id IS NOT NULL
      OR (m->>'security_version')::bigint<=counter
    THEN RAISE EXCEPTION 'Verification conflict' USING ERRCODE='23514'; END IF;
    INSERT INTO public.ota_executions(tenant_id,id,release_id,verification_operation,
      verification_sha256,manifest,signature,verified_at,report_sequence)
      VALUES(j.tenant_id,j.id,j.release_id,r->>'operation',r->>'request_sha256',m,
             r->>'signature',clock_timestamp(),0);
    UPDATE public.ota_jobs SET status='verified',updated_at=clock_timestamp()
      WHERE tenant_id=j.tenant_id AND id=j.id;
  ELSE
    IF e.id IS NULL OR e.manifest::jsonb IS DISTINCT FROM m
      OR e.signature IS DISTINCT FROM r->>'signature'
    THEN RAISE EXCEPTION 'Execution manifest changed' USING ERRCODE='23514'; END IF;
    IF action='claim' THEN
      IF j.status<>'verified' OR e.device_id IS NOT NULL
        OR (m->>'security_version')::bigint<=counter
      THEN RAISE EXCEPTION 'Claim conflict' USING ERRCODE='23514'; END IF;
      UPDATE public.ota_executions SET device_id=r->>'device_id',claim_token=r->>'claim_token',
        claim_operation=r->>'operation',install_challenge=r->>'install_challenge'
        WHERE tenant_id=j.tenant_id AND id=j.id;
      UPDATE public.ota_jobs SET status='downloading',updated_at=clock_timestamp()
        WHERE tenant_id=j.tenant_id AND id=j.id;
    ELSIF action='report' THEN
      IF e.device_id IS DISTINCT FROM r->>'device_id'
        OR e.claim_token IS DISTINCT FROM report->>'claim_token'
        OR (report->>'sequence')::integer<>e.report_sequence+1
        OR (report->>'occurred_at')::timestamptz<j.created_at
        OR (report->>'occurred_at')::timestamptz>clock_timestamp()+interval '5 minutes'
      THEN RAISE EXCEPTION 'Unauthorized report' USING ERRCODE='23514'; END IF;
      SELECT (payload->>'occurred_at')::timestamptz INTO old_time FROM public.ota_execution_reports
        WHERE tenant_id=j.tenant_id AND job_id=j.id AND sequence=e.report_sequence;
      IF (report->>'occurred_at')::timestamptz<old_time OR
        NOT ((report->>'status'='installing' AND j.status='downloading') OR
             (report->>'status'='succeeded' AND j.status='installing') OR
             (report->>'status'='failed' AND j.status IN ('downloading','installing'))) THEN
        RAISE EXCEPTION 'Invalid report transition' USING ERRCODE='23514'; END IF;
      IF report->>'status'='succeeded' AND
        (r->>'boot_verified' IS DISTINCT FROM 'true' OR
         report->'installation_proof'->>'protocol' IS DISTINCT FROM 'cv-boot/1' OR
         report->'installation_proof'->>'proof_source' IS DISTINCT FROM 'local_process' OR
         report->'installation_proof'->>'tenant_id' IS DISTINCT FROM j.tenant_id OR
         report->'installation_proof'->>'vehicle_id' IS DISTINCT FROM j.vehicle_id OR
         report->'installation_proof'->>'ecu_id' IS DISTINCT FROM j.ecu_id OR
         report->'installation_proof'->>'job_id' IS DISTINCT FROM j.id OR
         report->'installation_proof'->>'device_id' IS DISTINCT FROM e.device_id OR
         report->'installation_proof'->>'claim_token' IS DISTINCT FROM e.claim_token OR
         report->'installation_proof'->>'sha256' IS DISTINCT FROM m->>'sha256' OR
         report->'installation_proof'->>'firmware_version' IS DISTINCT FROM m->>'version' OR
         report->'installation_proof'->>'security_version'
           IS DISTINCT FROM m->>'security_version' OR
         report->'installation_proof'->>'challenge' IS DISTINCT FROM e.install_challenge OR
         report->'installation_proof'->>'boot_confirmed' IS DISTINCT FROM 'true') THEN
        RAISE EXCEPTION 'Confirmed boot proof required' USING ERRCODE='23514'; END IF;
      INSERT INTO public.ota_execution_reports VALUES(j.tenant_id,report->>'event_id',j.id,
        (report->>'sequence')::integer,report,clock_timestamp());
      UPDATE public.ota_executions SET report_sequence=(report->>'sequence')::integer
        WHERE tenant_id=j.tenant_id AND id=j.id;
      UPDATE public.ota_jobs SET status=report->>'status',updated_at=clock_timestamp()
        WHERE tenant_id=j.tenant_id AND id=j.id;
    ELSE RAISE EXCEPTION 'Unsupported transition' USING ERRCODE='23514'; END IF;
  END IF;
  INSERT INTO public.ota_audit_events VALUES(j.tenant_id,r->>'audit_id','job',j.id,action,
    r->>'actor',r->>'operation',r->>'request_sha256',r->>'reason',clock_timestamp());
  IF action='report' AND report->>'status'='succeeded' THEN
    PERFORM public.ota_apply_installation(p_payload,p_mac);
  END IF;
  INSERT INTO ota_authority.transition_receipts VALUES(j.tenant_id,j.id,r->>'operation',r,p_mac);
END;
"""

INITIAL_BODY = """
BEGIN
  IF NEW.status<>'pending_verification' THEN
    RAISE EXCEPTION 'New intent must await verification' USING ERRCODE='23514'; END IF;
  RETURN NEW;
END;
"""

AUDIT_BODY = """
BEGIN
  IF public.runtime_tenant_binding() IS DISTINCT FROM p_tenant
    OR p_action NOT IN ('register','create')
    OR p_resource NOT IN ('ecu','release','job') OR length(trim(p_actor)) NOT BETWEEN 1 AND 255
    OR length(trim(p_reason)) NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'Only intent audit can be appended' USING ERRCODE='23514'; END IF;
  INSERT INTO public.ota_audit_events VALUES(p_tenant,p_id,p_resource,p_resource_id,p_action,
    p_actor,p_key,p_hash,p_reason,clock_timestamp());
END;
"""

RESOLUTION_BODY = """
BEGIN
  IF public.runtime_tenant_binding() IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION 'Foreign claim resolution' USING ERRCODE='23514'; END IF;
  RETURN (SELECT jsonb_build_object('job_id',q.job_id,'device_id',e.device_id,
    'resolved',q.resolved,'evidence',q.evidence)
    FROM ota_authority.claim_quarantines q JOIN public.ota_executions e
    ON e.tenant_id=q.tenant_id AND e.id=q.job_id
    WHERE q.tenant_id=p_tenant AND q.job_id=p_job AND e.device_id=p_device);
END;
"""

FUNCTIONS = {
    "ota_claim_resolution": ("p_tenant text,p_job text,p_device text", "jsonb", RESOLUTION_BODY),
    "ota_append_intent_audit": (
        (
            "p_tenant text,p_id text,p_resource text,p_resource_id "
            "text,p_action text,p_actor text,p_key text,p_hash text,p_reason "
            "text"
        ),
        "void",
        AUDIT_BODY,
    ),
    "ota_execution_ready": ("p_tenant text,p_job text", "boolean", READY_BODY),
    "ota_publisher_trusted": ("p_tenant text,p_key text", "boolean", PUBLISHER_BODY),
    "ota_transition": ("p_payload text,p_mac text", "void", TRANSITION_BODY),
    "ota_cancel_pending": (
        "p_tenant text,p_job text,p_actor text,p_key text,p_reason text,p_hash text,p_audit text",
        "void",
        CANCEL_BODY,
    ),
}
