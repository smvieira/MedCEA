-- medcea_db_008b_index.sql — migration 008b's telemetry steps (IAM plan 2.1, B14).
-- Run by apps/database/lib-db-apply.sh (step 4c) in AUTOCOMMIT as postgres:
-- CREATE INDEX CONCURRENTLY cannot run in a transaction, and the backfill
-- commits every batch so ingest never waits behind one long lock.
--
--   1. an index for the own_zone filter: (zone_id, measure_timestamp); an
--      INVALID one left by an interrupted build is dropped and rebuilt;
--   2. backfill, once (marker 008b:measurement_zone_backfilled), the zone of
--      rows stored before measurement_zone_trg existed. A row's board is
--      device.serial_number = device_id, else dns_name = device_dns; its zone:
--        the latest device_slot_history event at or before the reading -> to_zone_id,
--        else the earliest event after it -> from_zone_id,
--        else the device's current zone, only if it has no slot history at all.
--      Unregistered boards (cea-un-*) and rows that resolve to nothing stay
--      NULL. Batches walk the table by block range (TID range scan), about
--      10,000 rows each. Skipped while IAM_DB_ROLES=true: measurement is then
--      immutable for everyone, the owner included.

\set ON_ERROR_STOP on

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid
                WHERE c.relname = 'measurement_zone_ts_idx' AND c.relnamespace = 'medcea'::regnamespace
                  AND NOT i.indisvalid) THEN
        RAISE WARNING 'dropping the invalid index medcea.measurement_zone_ts_idx (an interrupted build) to rebuild it';
        DROP INDEX medcea.measurement_zone_ts_idx;
    END IF;
END $$;
-- CONCURRENTLY waits for older transactions to finish; give it longer than the
-- 5 s lock_timeout every other statement runs with.
SET lock_timeout = '120s';
CREATE INDEX CONCURRENTLY IF NOT EXISTS measurement_zone_ts_idx ON medcea.measurement (zone_id, measure_timestamp);
RESET lock_timeout;

SELECT medcea_auth.enforcing() AS iam_enforcing \gset
SELECT EXISTS (SELECT 1 FROM medcea.platform_setting WHERE key = '008b:measurement_zone_backfilled') AS zone_backfilled \gset
\if :iam_enforcing
DO $$ BEGIN
    RAISE WARNING 'IAM_DB_ROLES=true: the measurement.zone_id backfill is skipped (measurement is immutable)';
END $$;
\elif :zone_backfilled
\else
SET ROLE medcea_owner;
DO $$
DECLARE
    pages    bigint;
    per_row  numeric;
    step     bigint;
    b        bigint := 0;
    n        bigint;
    total    bigint := 0;
BEGIN
    SELECT pg_catalog.pg_relation_size('medcea.measurement') / current_setting('block_size')::bigint INTO pages;
    SELECT CASE WHEN c.relpages > 0 AND c.reltuples > 0 THEN c.reltuples / c.relpages ELSE 50 END INTO per_row
      FROM pg_catalog.pg_class c WHERE c.oid = 'medcea.measurement'::regclass;
    step := greatest(1, floor(10000 / greatest(per_row, 1)))::bigint;
    WHILE b < pages LOOP
        UPDATE medcea.measurement m SET zone_id = r.zone_id
          FROM (
            SELECT x.ctid AS tid,
                   coalesce(
                       (SELECT h.to_zone_id FROM medcea.device_slot_history h
                         WHERE h.device_id = d.device_id AND h.changed_at <= x.measure_timestamp
                         ORDER BY h.changed_at DESC, h.event_id DESC LIMIT 1),
                       (SELECT h.from_zone_id FROM medcea.device_slot_history h
                         WHERE h.device_id = d.device_id AND h.changed_at > x.measure_timestamp
                         ORDER BY h.changed_at, h.event_id LIMIT 1),
                       (SELECT d.zone_id WHERE NOT EXISTS (SELECT 1 FROM medcea.device_slot_history h
                                                           WHERE h.device_id = d.device_id))) AS zone_id
              FROM medcea.measurement x
              JOIN LATERAL (SELECT coalesce(
                                (SELECT dd.device_id FROM medcea.device dd WHERE dd.serial_number = x.device_id),
                                (SELECT dd.device_id FROM medcea.device dd WHERE dd.dns_name = x.device_dns)) AS device_id) di ON true
              JOIN medcea.device d ON d.device_id = di.device_id
             WHERE x.ctid >= pg_catalog.format('(%s,0)', b)::tid AND x.ctid < pg_catalog.format('(%s,0)', b + step)::tid
               AND x.zone_id IS NULL AND x.device_dns NOT LIKE 'cea-un-%'
          ) r
         WHERE m.ctid = r.tid AND r.zone_id IS NOT NULL;
        GET DIAGNOSTICS n = ROW_COUNT;
        total := total + n;
        b := b + step;
        COMMIT;
    END LOOP;
    INSERT INTO medcea.platform_setting (key, value) VALUES ('008b:measurement_zone_backfilled', now()::text)
    ON CONFLICT (key) DO NOTHING;
    COMMIT;
    RAISE WARNING 'migration 008b: zone_id backfilled on % measurement row(s)', total;
END $$;
RESET ROLE;
\endif
