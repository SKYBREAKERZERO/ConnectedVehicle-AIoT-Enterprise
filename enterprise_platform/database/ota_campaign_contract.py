"""Migration-owned campaign mutations, signed independently of runtime DB credentials."""

from enterprise_platform.database.ota_lifecycle_contract import READY_BODY

TABLES = ("ota_campaigns", "ota_campaign_targets", "ota_campaign_events")

JOB_ALLOWED = """
BEGIN
  RETURN public.runtime_tenant_binding() IS NOT DISTINCT FROM p_tenant AND
    NOT EXISTS(SELECT FROM public.ota_campaign_targets t JOIN public.ota_campaigns c
      ON c.tenant_id=t.tenant_id AND c.id=t.campaign_id
      JOIN public.ota_jobs j ON j.tenant_id=t.tenant_id AND j.id=t.job_id
      WHERE t.tenant_id=p_tenant AND t.job_id=p_job
        AND (NOT t.dispatched OR
          (c.status<>'running' AND j.status NOT IN ('downloading','installing'))))
    AND NOT EXISTS(SELECT FROM public.ota_jobs j
      JOIN public.ota_campaign_targets t ON t.tenant_id=j.tenant_id AND t.ecu_id=j.ecu_id
      JOIN public.ota_campaigns c ON c.tenant_id=t.tenant_id AND c.id=t.campaign_id
      WHERE j.tenant_id=p_tenant AND j.id=p_job AND c.status IN ('frozen','running','paused')
        AND NOT EXISTS(SELECT FROM public.ota_campaign_targets own_target
          WHERE own_target.tenant_id=j.tenant_id AND own_target.job_id=j.id));
END;
"""

CAMPAIGN_READY = READY_BODY.replace(
    "AND EXISTS(SELECT FROM public.ota_jobs",
    "AND public.ota_campaign_job_allowed(p_tenant,p_job) AND EXISTS(SELECT FROM public.ota_jobs",
)

SUMMARY = """
DECLARE c public.ota_campaigns%ROWTYPE; result jsonb;
BEGIN
  IF public.runtime_tenant_binding() IS DISTINCT FROM p_tenant THEN
    RETURN NULL; END IF;
  SELECT * INTO c FROM public.ota_campaigns WHERE tenant_id=p_tenant AND id=p_id;
  IF c.id IS NULL THEN RETURN NULL; END IF;
  SELECT jsonb_build_object('id',c.id,'name',c.name,'release_id',c.release_id,
    'created_by',c.created_by,'canary_size',c.canary_size,'wave_size',c.wave_size,
    'max_failures',c.max_failures,'observation_seconds',c.observation_seconds,
    'wave_timeout_seconds',c.wave_timeout_seconds,'publisher_key_id',c.manifest->>'key_id',
    'status',c.status,'current_wave',c.current_wave,'snapshot_sha256',c.snapshot_sha256,
    'pause_reason',c.pause_reason,'created_at',c.created_at,'updated_at',c.updated_at,
    'target_count',count(*),'job_count',count(*) FILTER(WHERE t.dispatched),
    'succeeded',count(*) FILTER(WHERE j.status='succeeded'),
    'failed',count(*) FILTER(WHERE j.status IN ('failed','cancelled')))
  INTO result FROM public.ota_campaign_targets t LEFT JOIN public.ota_jobs j
    ON j.tenant_id=t.tenant_id AND j.id=t.job_id
    WHERE t.tenant_id=p_tenant AND t.campaign_id=p_id;
  RETURN result;
END;
"""

COMMAND = """
DECLARE r jsonb; q jsonb; b jsonb; k bytea; previous public.ota_campaign_events%ROWTYPE;
  c public.ota_campaigns%ROWTYPE; f public.firmware_releases%ROWTYPE; target record;
  action text; tenant text; identifier text; operation uuid; n integer;
  failures integer; pending integer; total integer; next_wave integer;
  completed_at timestamptz; result jsonb; m jsonb; bad boolean;
BEGIN
  IF octet_length(p_payload)>131072 OR p_mac !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Malformed campaign capability' USING ERRCODE='23514'; END IF;
  r:=p_payload::jsonb; q:=r->'request'; b:=q->'body';
  tenant:=r->>'tenant_id'; identifier:=q->>'campaign_id';
  action:=q->>'command'; operation:=(q->>'operation_id')::uuid;
  IF public.runtime_tenant_binding() IS DISTINCT FROM tenant
    OR r->>'protocol' IS DISTINCT FROM 'cv-campaign/1'
    OR jsonb_typeof(r->'expires') IS DISTINCT FROM 'number'
    OR (r->>'expires')::bigint<extract(epoch FROM clock_timestamp())
    OR (r->>'expires')::bigint>extract(epoch FROM clock_timestamp())+120
    OR length(trim(q->>'actor')) NOT BETWEEN 1 AND 255
    OR length(trim(q->>'reason')) NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'Foreign, expired or invalid campaign capability' USING ERRCODE='42501';
  END IF;
  SELECT secret INTO k FROM ota_authority.receipt_keys
    WHERE tenant_id=tenant AND key_id=r->>'key_id' AND enabled;
  IF k IS NULL OR ota_authority.digest(
      ota_authority.hmac(convert_to(p_payload,'UTF8'),k,'sha256'),'sha256')
      IS DISTINCT FROM ota_authority.digest(decode(p_mac,'hex'),'sha256') THEN
    RAISE EXCEPTION 'Untrusted campaign capability' USING ERRCODE='42501'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('campaign:'||tenant||':'||identifier,0));
  SELECT * INTO previous FROM public.ota_campaign_events
    WHERE tenant_id=tenant AND operation_id=operation;
  IF previous.operation_id IS NOT NULL THEN
    IF previous.request IS DISTINCT FROM q THEN
      RAISE EXCEPTION 'Campaign operation conflict' USING ERRCODE='23514'; END IF;
    RETURN previous.result;
  END IF;
  SELECT * INTO c FROM public.ota_campaigns
    WHERE tenant_id=tenant AND id=identifier FOR UPDATE;
  IF action='create' THEN
    IF c.id IS NOT NULL THEN
      RAISE EXCEPTION 'Campaign already exists' USING ERRCODE='23514'; END IF;
    m:=b->'manifest';
    SELECT * INTO f FROM public.firmware_releases
      WHERE tenant_id=tenant AND id=m->>'release_id';
    IF f.id IS NULL OR m->>'protocol' IS DISTINCT FROM 'cv-ota/2'
      OR m->>'tenant_id' IS DISTINCT FROM tenant
      OR m->>'ecu_type' IS DISTINCT FROM f.ecu_type
      OR m->>'hardware_version' IS DISTINCT FROM f.hardware_version
      OR m->>'version' IS DISTINCT FROM f.version
      OR m->>'sha256' IS DISTINCT FROM f.sha256
      OR m->>'artifact_version' IS DISTINCT FROM f.artifact_version
      OR m->>'artifact_bucket' IS DISTINCT FROM f.artifact_bucket
      OR m->>'artifact_key' IS DISTINCT FROM f.artifact_key
      OR (m->>'size_bytes')::bigint IS DISTINCT FROM f.size_bytes
      OR (m->>'security_version')::bigint<1
      OR NOT public.ota_publisher_trusted(tenant,m->>'key_id')
      OR (b->>'canary_size')::integer NOT BETWEEN 1 AND 100
      OR (b->>'wave_size')::integer NOT BETWEEN 1 AND 100
      OR (b->>'max_failures')::integer NOT BETWEEN 0 AND (b->>'canary_size')::integer-1
      OR (b->>'observation_seconds')::integer NOT BETWEEN 0 AND 3600
      OR (b->>'wave_timeout_seconds')::integer NOT BETWEEN 30 AND 86400 THEN
      RAISE EXCEPTION 'Invalid campaign policy or release' USING ERRCODE='23514'; END IF;
    INSERT INTO public.ota_campaigns(tenant_id,id,name,release_id,status,manifest,signature,
      canary_size,wave_size,max_failures,observation_seconds,wave_timeout_seconds,created_by)
      VALUES(tenant,identifier,b->>'name',f.id,'draft',m,b->>'signature',
        (b->>'canary_size')::integer,(b->>'wave_size')::integer,
        (b->>'max_failures')::integer,(b->>'observation_seconds')::integer,
        (b->>'wave_timeout_seconds')::integer,q->>'actor');
  ELSE
    IF c.id IS NULL THEN RAISE EXCEPTION 'Campaign not found' USING ERRCODE='P0002'; END IF;
    IF action='freeze' THEN
      IF c.status<>'draft' OR jsonb_array_length(b->'ecu_ids') NOT BETWEEN 1 AND 1000
        OR NOT public.ota_publisher_trusted(tenant,c.manifest->>'key_id') THEN
        RAISE EXCEPTION 'Immutable or empty snapshot' USING ERRCODE='23514'; END IF;
      n:=jsonb_array_length(b->'ecu_ids');
      PERFORM e.id FROM public.ecu_inventory e JOIN public.vehicles v
        ON v.tenant_id=e.tenant_id AND v.id=e.vehicle_id
        WHERE e.tenant_id=tenant AND e.id IN(SELECT jsonb_array_elements_text(b->'ecu_ids'))
        ORDER BY e.id FOR SHARE OF e,v;
      SELECT count(DISTINCT e.id) INTO total FROM public.ecu_inventory e
        JOIN public.vehicles v ON v.tenant_id=e.tenant_id AND v.id=e.vehicle_id
        JOIN ota_authority.ecu_bootstrap bootstrap
          ON bootstrap.tenant_id=e.tenant_id AND bootstrap.ecu_id=e.id
        WHERE e.tenant_id=tenant AND e.id IN(SELECT jsonb_array_elements_text(b->'ecu_ids'))
        AND v.status='active' AND e.bootstrap_confirmed AND bootstrap.vehicle_id=e.vehicle_id
        AND e.ecu_type=c.manifest->>'ecu_type'
        AND e.hardware_version=c.manifest->>'hardware_version'
        AND e.security_version<(c.manifest->>'security_version')::bigint
        AND NOT EXISTS(SELECT FROM public.ota_jobs j WHERE j.tenant_id=e.tenant_id
          AND j.ecu_id=e.id AND j.status IN ('pending_verification','verified',
                                            'downloading','installing'));
      IF total<>n OR n<c.canary_size THEN
        RAISE EXCEPTION 'Ineligible, missing or duplicate snapshot target' USING ERRCODE='23514';
      END IF;
      INSERT INTO public.ota_campaign_targets(tenant_id,campaign_id,ecu_id,vehicle_id,wave,
        job_id,firmware_version,security_version)
        SELECT tenant,identifier,id,vehicle_id,
          CASE WHEN ordinal<c.canary_size THEN 0
            ELSE 1+(ordinal-c.canary_size)/c.wave_size END,
          gen_random_uuid()::text,firmware_version,security_version FROM
          (SELECT e.*, (row_number() OVER(ORDER BY e.id)-1)::integer AS ordinal
           FROM public.ecu_inventory e WHERE e.tenant_id=tenant
             AND e.id IN(SELECT jsonb_array_elements_text(b->'ecu_ids'))) ordered;
      UPDATE public.ota_campaigns SET status='frozen',updated_at=clock_timestamp(),
        snapshot_sha256=(SELECT encode(ota_authority.digest(convert_to(
          jsonb_agg(jsonb_build_array(ecu_id,vehicle_id,wave,job_id,firmware_version,
            security_version) ORDER BY ecu_id)::text,'UTF8'),'sha256'),'hex')
          FROM public.ota_campaign_targets WHERE tenant_id=tenant AND campaign_id=identifier)
        WHERE tenant_id=tenant AND id=identifier;
    ELSIF action IN ('start','resume') THEN
      IF (action='start' AND c.status<>'frozen') OR
         (action='resume' AND c.status<>'paused') THEN
        RAISE EXCEPTION 'Invalid campaign start/resume' USING ERRCODE='23514'; END IF;
      SELECT count(*) INTO failures FROM public.ota_campaign_targets t JOIN public.ota_jobs j
        ON j.tenant_id=t.tenant_id AND j.id=t.job_id
        WHERE t.tenant_id=tenant AND t.campaign_id=identifier
          AND j.status IN ('failed','cancelled');
      IF failures>c.max_failures OR NOT public.ota_publisher_trusted(
        tenant,c.manifest->>'key_id') THEN
        RAISE EXCEPTION 'Canary failure or revoked publisher prevents resume'
          USING ERRCODE='23514'; END IF;
      UPDATE public.ota_campaigns SET status='running',pause_reason=NULL,
        updated_at=clock_timestamp() WHERE tenant_id=tenant AND id=identifier;
    ELSIF action='pause' THEN
      IF c.status<>'running' THEN
        RAISE EXCEPTION 'Only running campaign can pause' USING ERRCODE='23514'; END IF;
      UPDATE public.ota_campaigns SET status='paused',pause_reason=q->>'reason',
        updated_at=clock_timestamp() WHERE tenant_id=tenant AND id=identifier;
    ELSIF action='cancel' THEN
      IF c.status IN ('completed','cancelled') THEN
        RAISE EXCEPTION 'Terminal campaign' USING ERRCODE='23514'; END IF;
      UPDATE public.ota_campaigns SET status='cancelled',pause_reason=q->>'reason',
        updated_at=clock_timestamp() WHERE tenant_id=tenant AND id=identifier;
      FOR target IN SELECT j.id,j.status FROM public.ota_campaign_targets t
        JOIN public.ota_jobs j ON j.tenant_id=t.tenant_id AND j.id=t.job_id
        WHERE t.tenant_id=tenant AND t.campaign_id=identifier
          AND j.status IN ('pending_verification','verified') ORDER BY j.id FOR UPDATE OF j LOOP
        UPDATE public.ota_jobs SET status=CASE WHEN target.status='verified'
          THEN 'failed' ELSE 'cancelled' END,updated_at=clock_timestamp()
          WHERE tenant_id=tenant AND id=target.id;
        INSERT INTO public.ota_audit_events VALUES(tenant,gen_random_uuid()::text,'job',target.id,
          'campaign_cancel',q->>'actor','campaign-cancel:'||target.id,
          encode(ota_authority.digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),
          q->>'reason',clock_timestamp());
      END LOOP;
    ELSIF action='tick' AND c.status='running' THEN
      SELECT count(*) FILTER(WHERE j.status IN ('failed','cancelled')),
        count(*) FILTER(WHERE j.status NOT IN ('succeeded','failed','cancelled')),
        max(j.updated_at) INTO failures,pending,completed_at
        FROM public.ota_campaign_targets t JOIN public.ota_jobs j
          ON j.tenant_id=t.tenant_id AND j.id=t.job_id
        WHERE t.tenant_id=tenant AND t.campaign_id=identifier;
      SELECT EXISTS(SELECT FROM public.ota_campaign_targets t
        JOIN public.ecu_inventory e ON e.tenant_id=t.tenant_id AND e.id=t.ecu_id
        JOIN public.vehicles v ON v.tenant_id=e.tenant_id AND v.id=e.vehicle_id
        WHERE t.tenant_id=tenant AND t.campaign_id=identifier
          AND (v.status<>'active' OR
            (NOT t.dispatched AND (e.security_version<>t.security_version
              OR e.firmware_version<>t.firmware_version OR NOT e.bootstrap_confirmed)))) INTO bad;
      IF failures>c.max_failures OR bad OR b->>'publisher_valid' IS DISTINCT FROM 'true'
        OR NOT public.ota_publisher_trusted(tenant,c.manifest->>'key_id')
        OR (pending>0 AND c.wave_started_at+make_interval(secs=>c.wave_timeout_seconds)
          <clock_timestamp()) THEN
        UPDATE public.ota_campaigns SET status='paused',updated_at=clock_timestamp(),
          pause_reason=CASE WHEN failures>c.max_failures THEN 'failure_budget_exceeded'
            WHEN bad THEN 'target_policy_changed' WHEN pending>0 AND
              c.wave_started_at+make_interval(secs=>c.wave_timeout_seconds)<clock_timestamp()
              THEN 'wave_timeout' ELSE 'publisher_revoked_or_unavailable' END
          WHERE tenant_id=tenant AND id=identifier;
      ELSIF pending=0 AND (c.current_wave<0 OR completed_at+
        make_interval(secs=>c.observation_seconds)<=clock_timestamp()) THEN
        SELECT min(wave) INTO next_wave FROM public.ota_campaign_targets
          WHERE tenant_id=tenant AND campaign_id=identifier AND NOT dispatched;
        IF next_wave IS NULL THEN
          UPDATE public.ota_campaigns SET status='completed',updated_at=clock_timestamp()
            WHERE tenant_id=tenant AND id=identifier;
        ELSE
          FOR target IN SELECT * FROM public.ota_campaign_targets
            WHERE tenant_id=tenant AND campaign_id=identifier AND wave=next_wave
            ORDER BY ecu_id LOOP
            PERFORM pg_advisory_xact_lock(hashtextextended(
              json_build_array('ota',tenant,'ecu',target.ecu_id)::text,0));
            PERFORM 1 FROM public.vehicles WHERE tenant_id=tenant
              AND id=target.vehicle_id AND status='active' FOR SHARE;
            IF NOT FOUND THEN RAISE EXCEPTION 'Vehicle changed' USING ERRCODE='23514'; END IF;
            PERFORM 1 FROM public.ecu_inventory WHERE tenant_id=tenant AND id=target.ecu_id
              AND vehicle_id=target.vehicle_id AND bootstrap_confirmed
              AND security_version=target.security_version
              AND firmware_version=target.firmware_version FOR SHARE;
            IF NOT FOUND THEN
              RAISE EXCEPTION 'Frozen ECU baseline changed' USING ERRCODE='23514'; END IF;
            INSERT INTO public.ota_jobs(tenant_id,id,vehicle_id,ecu_id,release_id,ecu_type,
              hardware_version,status,idempotency_key,created_at,updated_at,created_by)
              VALUES(tenant,target.job_id,target.vehicle_id,target.ecu_id,c.release_id,
                c.manifest->>'ecu_type',c.manifest->>'hardware_version','pending_verification',
                'campaign:'||identifier||':'||target.ecu_id,clock_timestamp(),clock_timestamp(),
                q->>'actor');
            INSERT INTO public.ota_audit_events VALUES(tenant,gen_random_uuid()::text,
              'job',target.job_id,'create',q->>'actor','campaign:'||target.job_id,
              encode(ota_authority.digest(convert_to(c.manifest::text,'UTF8'),'sha256'),'hex'),
              'Frozen campaign target',clock_timestamp());
          END LOOP;
          UPDATE public.ota_campaign_targets SET dispatched=true
            WHERE tenant_id=tenant AND campaign_id=identifier AND wave=next_wave;
          UPDATE public.ota_campaigns SET current_wave=next_wave,wave_started_at=clock_timestamp(),
            updated_at=clock_timestamp() WHERE tenant_id=tenant AND id=identifier;
        END IF;
      END IF;
    ELSIF action<>'tick' THEN
      RAISE EXCEPTION 'Unsupported campaign command' USING ERRCODE='23514';
    END IF;
  END IF;
  result:=public.ota_campaign_summary(tenant,identifier);
  INSERT INTO public.ota_campaign_events(tenant_id,operation_id,campaign_id,request,result)
    VALUES(tenant,operation,identifier,q,result);
  RETURN result;
END;
"""

FUNCTIONS = {
    "ota_campaign_job_allowed": ("p_tenant text,p_job text", "boolean", JOB_ALLOWED),
    "ota_campaign_summary": ("p_tenant text,p_id text", "jsonb", SUMMARY),
    "ota_campaign_command": ("p_payload text,p_mac text", "jsonb", COMMAND),
}
