ALTER TABLE public.vehicles ADD CONSTRAINT uq_vehicles_tenant_id UNIQUE (tenant_id,id);
CREATE TABLE public.ecu_inventory (
 tenant_id varchar(255) NOT NULL, id varchar(36) NOT NULL,
 vehicle_id varchar(36) NOT NULL, ecu_type varchar(64) NOT NULL,
 hardware_version varchar(64) NOT NULL, firmware_version varchar(64) NOT NULL,
 serial_number varchar(64) NOT NULL, created_at timestamptz NOT NULL,
 created_by varchar(255) NOT NULL,
 PRIMARY KEY (tenant_id,id),
 CONSTRAINT fk_ecu_vehicle_tenant FOREIGN KEY (tenant_id,vehicle_id) REFERENCES public.vehicles(tenant_id,id),
 CONSTRAINT uq_ecu_serial UNIQUE (tenant_id,serial_number),
 CONSTRAINT uq_ecu_target UNIQUE (tenant_id,vehicle_id,id,ecu_type,hardware_version)
);
CREATE INDEX ix_ecu_vehicle ON public.ecu_inventory(tenant_id,vehicle_id,id);
CREATE TABLE public.firmware_releases (
 tenant_id varchar(255) NOT NULL, id varchar(36) NOT NULL,
 ecu_type varchar(64) NOT NULL, hardware_version varchar(64) NOT NULL,
 version varchar(64) NOT NULL, artifact_bucket varchar(63) NOT NULL,
 artifact_key varchar(1024) NOT NULL, artifact_version varchar(255) NOT NULL,
 sha256 varchar(64) NOT NULL, size_bytes bigint NOT NULL,
 idempotency_key varchar(255) NOT NULL, created_at timestamptz NOT NULL,
 created_by varchar(255) NOT NULL, PRIMARY KEY (tenant_id,id),
 CONSTRAINT uq_firmware_idempotency UNIQUE (tenant_id,idempotency_key),
 CONSTRAINT uq_firmware_version UNIQUE (tenant_id,ecu_type,hardware_version,version),
 CONSTRAINT uq_firmware_target UNIQUE (tenant_id,id,ecu_type,hardware_version),
 CONSTRAINT ck_firmware_size CHECK (size_bytes > 0 AND size_bytes <= 4294967296),
 CONSTRAINT ck_firmware_sha256 CHECK (sha256 ~ '^[0-9a-f]{64}$'),
 CONSTRAINT ck_firmware_pinned CHECK (artifact_version <> '' AND artifact_version <> 'null')
);
CREATE TABLE public.ota_jobs (
 tenant_id varchar(255) NOT NULL, id varchar(36) NOT NULL,
 vehicle_id varchar(36) NOT NULL, ecu_id varchar(36) NOT NULL,
 release_id varchar(36) NOT NULL, ecu_type varchar(64) NOT NULL,
 hardware_version varchar(64) NOT NULL, status varchar(32) NOT NULL,
 idempotency_key varchar(255) NOT NULL, created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL, created_by varchar(255) NOT NULL,
 PRIMARY KEY (tenant_id,id),
 CONSTRAINT fk_job_ecu FOREIGN KEY (tenant_id,vehicle_id,ecu_id,ecu_type,hardware_version)
 REFERENCES public.ecu_inventory(tenant_id,vehicle_id,id,ecu_type,hardware_version),
 CONSTRAINT fk_job_release FOREIGN KEY (tenant_id,release_id,ecu_type,hardware_version)
 REFERENCES public.firmware_releases(tenant_id,id,ecu_type,hardware_version),
 CONSTRAINT uq_job_idempotency UNIQUE (tenant_id,idempotency_key),
 CONSTRAINT ck_ota_job_status CHECK (status IN ('pending_verification','cancelled'))
);
CREATE UNIQUE INDEX uq_ota_active_ecu ON public.ota_jobs(tenant_id,ecu_id) WHERE status='pending_verification';
CREATE INDEX ix_ota_vehicle ON public.ota_jobs(tenant_id,vehicle_id,ecu_id,id);
CREATE TABLE public.ota_audit_events (
 tenant_id varchar(255) NOT NULL, id varchar(36) NOT NULL,
 resource_type varchar(32) NOT NULL, resource_id varchar(36) NOT NULL,
 action varchar(32) NOT NULL, actor_id varchar(255) NOT NULL,
 operation_key varchar(255) NOT NULL, payload_sha256 varchar(64) NOT NULL,
 reason varchar(500) NOT NULL, occurred_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id,id),
 CONSTRAINT uq_ota_audit_operation UNIQUE (tenant_id,resource_type,action,operation_key)
);
