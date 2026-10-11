-- Run after the generated tenant_id column migration.
DROP POLICY IF EXISTS tenant_guard ON outbox_events;
CREATE POLICY tenant_guard ON outbox_events AS RESTRICTIVE
USING (current_user = 'outbox_worker'
       OR tenant_id = nullif(current_setting('app.tenant_id', true), ''))
WITH CHECK (current_user = 'outbox_worker'
            OR tenant_id = nullif(current_setting('app.tenant_id', true), ''));
