ALTER TABLE public.ecu_inventory ADD COLUMN security_version bigint NOT NULL DEFAULT 0;
ALTER TABLE public.ecu_inventory ADD CONSTRAINT ck_ecu_security_version CHECK (security_version >= 0);
ALTER TABLE public.ota_jobs DROP CONSTRAINT ck_ota_job_status;
ALTER TABLE public.ota_jobs ADD CONSTRAINT ck_ota_job_status CHECK
 (status IN ('pending_verification','verified','downloading','installing','succeeded','failed','cancelled'));
ALTER TABLE public.ota_jobs ADD CONSTRAINT uq_ota_job_release_binding UNIQUE (tenant_id,id,release_id);
DROP INDEX public.uq_ota_active_ecu;
CREATE UNIQUE INDEX uq_ota_active_ecu ON public.ota_jobs(tenant_id,ecu_id)
 WHERE status IN ('pending_verification','verified','downloading','installing');
CREATE TABLE public.ota_executions (
 tenant_id varchar(255) NOT NULL,id varchar(36) NOT NULL,release_id varchar(36) NOT NULL,
 verification_operation varchar(36) NOT NULL,verification_sha256 varchar(64) NOT NULL,
 manifest json NOT NULL,signature varchar(88) NOT NULL,verified_at timestamptz NOT NULL,
 device_id varchar(255),claim_token varchar(36),claim_operation varchar(36),
 report_sequence integer NOT NULL DEFAULT 0,
 PRIMARY KEY (tenant_id,id),
 CONSTRAINT fk_ota_execution_job FOREIGN KEY (tenant_id,id,release_id)
 REFERENCES public.ota_jobs(tenant_id,id,release_id),
 CONSTRAINT uq_ota_verification_operation UNIQUE (tenant_id,verification_operation),
 CONSTRAINT ck_ota_report_sequence CHECK (report_sequence BETWEEN 0 AND 2)
);
CREATE TABLE public.ota_execution_reports (
 tenant_id varchar(255) NOT NULL,id varchar(36) NOT NULL,job_id varchar(36) NOT NULL,
 sequence integer NOT NULL,payload json NOT NULL,received_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id,id),
 CONSTRAINT fk_ota_report_job FOREIGN KEY (tenant_id,job_id) REFERENCES public.ota_jobs(tenant_id,id),
 CONSTRAINT uq_ota_report_sequence UNIQUE (tenant_id,job_id,sequence)
);
