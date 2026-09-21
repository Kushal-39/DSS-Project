-- 001_init.down.sql
-- Rollback for 001_init. Restore the pre-migration state: both tables gone.
--
-- Dropped in dependency order (spans has no foreign keys into audit_events,
-- but this order keeps the down script symmetric with the up script).
-- No CASCADE: if something unexpected still references these tables, the
-- rollback should fail loudly rather than silently cascade.

DROP TABLE IF EXISTS spans;
DROP TABLE IF EXISTS audit_events;
