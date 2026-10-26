-- medcea_db_migrations.sql
-- Post-DDL migrations applied by deploy.sh after pg_restore.
-- All statements are idempotent (IF NOT EXISTS / ON CONFLICT DO NOTHING).
-- Add new migrations at the bottom; never remove old ones.

-- ── Migration 001: Control Algorithm registry ────────────────────────────────

CREATE SEQUENCE IF NOT EXISTS medcea.control_algorithm_algorithm_id_seq
    AS integer START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;

CREATE TABLE IF NOT EXISTS medcea.control_algorithm (
    algorithm_id    INTEGER DEFAULT nextval('medcea.control_algorithm_algorithm_id_seq') NOT NULL,
    algorithm_code  VARCHAR(20) NOT NULL,
    algorithm_name  VARCHAR(100) NOT NULL,
    description     TEXT,
    default_params  JSONB NOT NULL DEFAULT '{}',
    is_active       VARCHAR(1) NOT NULL DEFAULT 'Y' CHECK (is_active IN ('Y','N'))
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'control_algorithm_pkey') THEN
        ALTER TABLE ONLY medcea.control_algorithm ADD CONSTRAINT control_algorithm_pkey PRIMARY KEY (algorithm_id);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'control_algorithm_code_uk') THEN
        ALTER TABLE ONLY medcea.control_algorithm ADD CONSTRAINT control_algorithm_code_uk UNIQUE (algorithm_code);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'control_algorithm_algorithm_id_seq' AND n.nspname = 'medcea'
          AND c.relkind = 'S'
    ) THEN
        NULL; -- sequence already handled by CREATE SEQUENCE IF NOT EXISTS above
    END IF;
    ALTER SEQUENCE IF EXISTS medcea.control_algorithm_algorithm_id_seq OWNED BY medcea.control_algorithm.algorithm_id;
END $$;

COMMENT ON TABLE  medcea.control_algorithm IS 'Registry of available feedback control algorithms. Each row defines an algorithm that can be selected per recipe-unit combination or per schedule run.';
COMMENT ON COLUMN medcea.control_algorithm.algorithm_id   IS 'Unique identifier for the control algorithm.';
COMMENT ON COLUMN medcea.control_algorithm.algorithm_code IS 'Short machine-readable code used in Python factory (e.g. IF_THEN_ELSE, PID, FLC, MPC, Q_LEARNING).';
COMMENT ON COLUMN medcea.control_algorithm.algorithm_name IS 'Human-readable display name shown in the UI.';
COMMENT ON COLUMN medcea.control_algorithm.description    IS 'Description of the algorithm and its intended use context.';
COMMENT ON COLUMN medcea.control_algorithm.default_params IS 'Default tuning parameters as JSON (e.g. {"kp":1.0,"ki":0.1}). Editable by admin from the UI. Used as the base when no override is provided.';
COMMENT ON COLUMN medcea.control_algorithm.is_active      IS 'Y if the algorithm is available for selection; N to hide it from the UI without deleting it.';

-- Seed the five supported algorithms (idempotent)
INSERT INTO medcea.control_algorithm (algorithm_code, algorithm_name, description, default_params) VALUES
  ('IF_THEN_ELSE', 'If-Then-Else',
   'Simple on/off hysteresis: actuator fully on below lower limit, off within range, fully on above upper limit. No tuning parameters required.',
   '{}'),
  ('PID', 'PID Controller',
   'Proportional-integral-derivative controller. Smooth continuous response. kp=proportional gain, ki=integral gain, kd=derivative gain.',
   '{"kp":1.0,"ki":0.1,"kd":0.05}'),
  ('FLC', 'Fuzzy Logic Control',
   'Fuzzy rule-based control. IEEE-validated for Pleurotus ostreatus cultivation (+37% yield vs if_then_else). deadband_fraction as fraction of setpoint span.',
   '{"deadband_fraction":0.1}'),
  ('MPC', 'Model Predictive Control',
   'Receding-horizon optimal control. Minimises actuator switching over a future horizon. horizon=number of 10s steps to look ahead, switching_cost=penalty weight.',
   '{"horizon":6,"switching_cost":0.1}'),
  ('Q_LEARNING', 'Q-Learning',
   'Reinforcement learning. Learns the chamber thermal dynamics over time. Q-table persisted per unit between recipe runs to avoid cold-start.',
   '{"alpha":0.1,"gamma":0.95,"epsilon":0.2,"epsilon_decay":0.995}')
ON CONFLICT (algorithm_code) DO NOTHING;

-- ── Migration 002: Algorithm selection on recipe_unit_permission ─────────────

ALTER TABLE medcea.recipe_unit_permission
    ADD COLUMN IF NOT EXISTS algorithm_id     INTEGER,
    ADD COLUMN IF NOT EXISTS algorithm_params JSONB DEFAULT NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'rup_algorithm_id_fkey') THEN
        ALTER TABLE ONLY medcea.recipe_unit_permission
            ADD CONSTRAINT rup_algorithm_id_fkey
            FOREIGN KEY (algorithm_id) REFERENCES medcea.control_algorithm(algorithm_id);
    END IF;
END $$;

COMMENT ON COLUMN medcea.recipe_unit_permission.algorithm_id     IS 'Default control algorithm for this recipe on this unit. Set by the operator in the Recipe x Unit permission matrix. NULL falls back to IF_THEN_ELSE at runtime.';
COMMENT ON COLUMN medcea.recipe_unit_permission.algorithm_params IS 'Optional parameter overrides for the selected algorithm, applied on top of control_algorithm.default_params for this recipe-unit combination.';

-- ── Migration 003: Algorithm state persistence (Q-table etc.) ────────────────

CREATE TABLE IF NOT EXISTS medcea.algorithm_state (
    unit_id     INTEGER NOT NULL,
    algorithm   VARCHAR(20) NOT NULL,
    channel     VARCHAR(50) NOT NULL,
    state       JSONB NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT algorithm_state_pkey PRIMARY KEY (unit_id, algorithm, channel)
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'algorithm_state_unit_fkey') THEN
        ALTER TABLE ONLY medcea.algorithm_state
            ADD CONSTRAINT algorithm_state_unit_fkey
            FOREIGN KEY (unit_id) REFERENCES medcea.cea_unit(unit_id);
    END IF;
END $$;

COMMENT ON TABLE  medcea.algorithm_state IS 'Persists in-memory algorithm state (e.g. Q-learning Q-table) between recipe cycle runs for a given unit and sensor channel. Allows stateful algorithms to accumulate knowledge about a specific chamber across runs rather than restarting from scratch each cycle.';
COMMENT ON COLUMN medcea.algorithm_state.unit_id    IS 'The production unit whose learned state is stored. Each unit builds its own policy independently.';
COMMENT ON COLUMN medcea.algorithm_state.algorithm  IS 'Algorithm code matching medcea.control_algorithm.algorithm_code (e.g. Q_LEARNING).';
COMMENT ON COLUMN medcea.algorithm_state.channel    IS 'Sensor channel the state applies to (e.g. air_temperature, co2, air_humidity, substrate_temperature). Each channel has an independent state.';
COMMENT ON COLUMN medcea.algorithm_state.state      IS 'Serialised algorithm state as JSON. For Q_LEARNING: {"q_table": {...}, "epsilon": 0.15}. Loaded at cycle start, saved at cycle end.';
COMMENT ON COLUMN medcea.algorithm_state.updated_at IS 'Timestamp of the last state save. Used to detect stale state after hardware changes.';

-- ── Migration 004: Network hostname on device — superseded by 005 ─────────────
-- Added a separate medcea.device.hostname for the Online check. Migration 005
-- made dns_name itself the hostname and drops that column, so 004 no longer adds
-- it (it would be re-added and dropped again on every deploy).

-- ── Migration 005: One device name — the DHCP hostname ──────────────────────
-- A device's name is lower(unit_code)-<s|c>-lower(zone_code), e.g.
-- unit02-c-zone02: its DHCP hostname, its dns_name here and the device_dns in
-- its MQTT payloads. It replaces both UNIT02_CONTROL_ZONE02 (not a resolvable
-- name) and the compressed u02-c-z02 (which changed whenever another unit was
-- added). edge/src/host/platform_db.py builds it the same way.
--
-- The name is unique only if the codes are, ignoring case: enforce that.

DO $$
DECLARE dup text;
BEGIN
    SELECT string_agg(c, ', ') INTO dup FROM (
        SELECT lower(unit_code) AS c FROM medcea.cea_unit
        GROUP BY lower(unit_code) HAVING count(*) > 1) x;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'unit codes that differ only in case: % — rename one in the Units tab, then redeploy the database', dup;
    END IF;
    SELECT string_agg(c, ', ') INTO dup FROM (
        SELECT u.unit_code || '/' || lower(z.zone_code) AS c
        FROM medcea.cea_zone z JOIN medcea.cea_unit u USING (unit_id)
        GROUP BY u.unit_code, lower(z.zone_code) HAVING count(*) > 1) x;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'zone codes repeated within a unit: % — rename one in the Units tab, then redeploy the database', dup;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS cea_unit_code_ci_uk ON medcea.cea_unit (lower(unit_code));
CREATE UNIQUE INDEX IF NOT EXISTS cea_zone_unit_code_ci_uk ON medcea.cea_zone (unit_id, lower(zone_code));

-- Rename slot devices to the rule. dns_name is unique, so when a slot holds more
-- than one row (a replaced board left in place), only the most recent row takes
-- the plain name; older ones keep it with their device_id appended.
UPDATE medcea.device d
SET dns_name = n.name
FROM (
    SELECT d2.device_id,
           lower(u.unit_code) || '-' || lower(left(d2.device_type, 1)) || '-' || lower(z.zone_code)
           || CASE WHEN row_number() OVER (PARTITION BY d2.zone_id, d2.device_type
                                           ORDER BY d2.device_id DESC) = 1
                   THEN '' ELSE '-' || d2.device_id END AS name
    FROM medcea.device d2
    JOIN medcea.cea_zone z ON z.zone_id = d2.zone_id
    JOIN medcea.cea_unit u ON u.unit_id = z.unit_id
    WHERE d2.device_type IN ('SENSE', 'CONTROL')
) n
WHERE d.device_id = n.device_id AND d.dns_name IS DISTINCT FROM n.name;

-- Migration 004's separate hostname column is now the same value as dns_name.
ALTER TABLE medcea.device DROP COLUMN IF EXISTS hostname;

COMMENT ON COLUMN medcea.device.dns_name IS 'DHCP hostname, lower(unit_code)-s|c-lower(zone_code) (e.g. unit02-c-zone02): the device''s network name, what the Online check pings, and device_dns in its MQTT payloads.';

NOTIFY pgrst, 'reload schema';

-- ── Migration 006: Device placement history (append-only) ──────────────────
-- Where each board has been. A row in medcea.device is one board (serial_number,
-- the MAC, is unique) and it follows the board when it moves to another slot
-- (edge/src/host/platform_db.py register, move_device_id) or when someone
-- changes its zone in the config UI. This keeps every placement:
--   placed    a device row was created
--   moved     its slot changed (zone_id and/or device_type)
--   renamed   only its name changed (a unit or zone code was renamed)
--   replaced  a different board (serial_number) took over the row
--   removed   the row was deleted
-- Written only by the trigger below. The API role may read it but not write,
-- update or delete it (see the grants in apps/database/deploy.sh), and there
-- is no foreign key, so the history outlives a deleted device row.

CREATE TABLE IF NOT EXISTS medcea.device_slot_history (
    event_id          BIGSERIAL PRIMARY KEY,
    device_id         INTEGER NOT NULL,
    event             VARCHAR(10) NOT NULL
                      CHECK (event IN ('placed', 'moved', 'renamed', 'replaced', 'removed')),
    serial_number     VARCHAR(255),
    from_serial       VARCHAR(255),
    from_zone_id      INTEGER,
    from_device_type  VARCHAR(255),
    from_dns_name     VARCHAR(255),
    to_zone_id        INTEGER,
    to_device_type    VARCHAR(255),
    to_dns_name       VARCHAR(255),
    changed_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS device_slot_history_device_idx
    ON medcea.device_slot_history (device_id, changed_at);
CREATE INDEX IF NOT EXISTS device_slot_history_serial_idx
    ON medcea.device_slot_history (serial_number, changed_at);

-- SECURITY DEFINER: runs as the table owner, so the trigger can append even
-- though the API role has no INSERT on the history table.
CREATE OR REPLACE FUNCTION medcea.log_device_slot() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE ev varchar(10);
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO medcea.device_slot_history
            (device_id, event, serial_number, to_zone_id, to_device_type, to_dns_name)
        VALUES (NEW.device_id, 'placed', NEW.serial_number, NEW.zone_id, NEW.device_type, NEW.dns_name);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO medcea.device_slot_history
            (device_id, event, serial_number, from_zone_id, from_device_type, from_dns_name)
        VALUES (OLD.device_id, 'removed', OLD.serial_number, OLD.zone_id, OLD.device_type, OLD.dns_name);
        RETURN OLD;
    END IF;
    IF NEW.serial_number IS DISTINCT FROM OLD.serial_number THEN
        ev := 'replaced';
    ELSIF NEW.zone_id IS DISTINCT FROM OLD.zone_id
       OR NEW.device_type IS DISTINCT FROM OLD.device_type THEN
        ev := 'moved';
    ELSIF NEW.dns_name IS DISTINCT FROM OLD.dns_name THEN
        ev := 'renamed';
    ELSE
        RETURN NEW;            -- a re-flash in place, or an unrelated field
    END IF;
    INSERT INTO medcea.device_slot_history
        (device_id, event, serial_number, from_serial,
         from_zone_id, from_device_type, from_dns_name,
         to_zone_id, to_device_type, to_dns_name)
    VALUES (NEW.device_id, ev, NEW.serial_number, OLD.serial_number,
            OLD.zone_id, OLD.device_type, OLD.dns_name,
            NEW.zone_id, NEW.device_type, NEW.dns_name);
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS device_slot_history_trg ON medcea.device;
CREATE TRIGGER device_slot_history_trg
    AFTER INSERT OR UPDATE OR DELETE ON medcea.device
    FOR EACH ROW EXECUTE FUNCTION medcea.log_device_slot();

-- Start the history where each existing device is now (once per device).
INSERT INTO medcea.device_slot_history
    (device_id, event, serial_number, to_zone_id, to_device_type, to_dns_name)
SELECT d.device_id, 'placed', d.serial_number, d.zone_id, d.device_type, d.dns_name
FROM medcea.device d
WHERE NOT EXISTS (SELECT 1 FROM medcea.device_slot_history h WHERE h.device_id = d.device_id);

COMMENT ON TABLE medcea.device_slot_history IS 'Append-only placement history of devices: placed, moved (slot changed), renamed, replaced (another board took the row), removed. Written by trigger device_slot_history_trg only; read-only to the API.';

NOTIFY pgrst, 'reload schema';

-- ── Migration 007: MQTT credentials (Mosquitto authentication, one per device) ─
-- The broker admits nobody anonymously. A board's username is its dns_name and
-- its password is minted by onboarding (edge/flash-device.sh), which stores the
-- Mosquitto hash here through register_mqtt_credential and the plaintext only on
-- the board. The mqtt-auth-sync sidecar in the Mosquitto pod reads this table
-- (role mqtt_auth, SELECT only), writes the broker's passwd/acl files and
-- reloads it. The API role (anon) cannot read the table at all — see the
-- REVOKE in apps/database/deploy.sh — it may only call the function.
CREATE TABLE IF NOT EXISTS medcea.mqtt_credential (
    username      text PRIMARY KEY,                       -- medcea.device.dns_name
    password_hash text NOT NULL,                          -- mosquitto $7$ (PBKDF2-SHA512), never plaintext
    device_id     integer NOT NULL REFERENCES medcea.device(device_id) ON DELETE CASCADE,
    role          text NOT NULL CHECK (role IN ('SENSE', 'CONTROL')),
    topic_base    text NOT NULL,                          -- <root>/<UNIT>/<ZONE>, codes as the board uses them
    active        boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_credential_device_uq ON medcea.mqtt_credential (device_id);

CREATE OR REPLACE FUNCTION medcea.register_mqtt_credential(
    p_username text, p_password_hash text, p_device_id integer, p_role text, p_topic_base text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    IF p_password_hash !~ '^\$7\$[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$' THEN
        RAISE EXCEPTION 'password_hash must be a mosquitto $7$ hash, not a password';
    END IF;
    -- mosquitto's files are line based: ':' splits a passwd line, whitespace an acl line
    IF p_username ~ '[:\s]' OR p_topic_base ~ '\s' OR p_username = '' THEN
        RAISE EXCEPTION 'username/topic_base cannot be empty or contain ":" or whitespace';
    END IF;
    -- a board re-onboarded under a new name keeps one credential
    DELETE FROM medcea.mqtt_credential WHERE device_id = p_device_id AND username <> p_username;
    INSERT INTO medcea.mqtt_credential (username, password_hash, device_id, role, topic_base)
    VALUES (p_username, p_password_hash, p_device_id, upper(p_role), p_topic_base)
    ON CONFLICT (username) DO UPDATE
       SET password_hash = EXCLUDED.password_hash, device_id = EXCLUDED.device_id,
           role = EXCLUDED.role, topic_base = EXCLUDED.topic_base,
           active = true, updated_at = now();
END $$;
REVOKE ALL ON FUNCTION medcea.register_mqtt_credential(text, text, integer, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION medcea.register_mqtt_credential(text, text, integer, text, text) TO anon;

COMMENT ON TABLE medcea.mqtt_credential IS 'Mosquitto credentials, one per board (username = dns_name). Written only through register_mqtt_credential (onboarding); read by the mqtt-auth-sync sidecar as role mqtt_auth. Not readable by the API role.';

NOTIFY pgrst, 'reload schema';
