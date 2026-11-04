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
-- anon's EXECUTE on it is a legacy grant of IAM_DB_ROLES=false and lives in
-- medcea_db_migrations_down_008b.sql: a migration re-run on every deploy must
-- not re-grant what the enforce bundle revoked.

COMMENT ON TABLE medcea.mqtt_credential IS 'Mosquitto credentials, one per board (username = dns_name). Written only through register_mqtt_credential (onboarding); read by the mqtt-auth-sync sidecar as role mqtt_auth. Not readable by the API role.';

NOTIFY pgrst, 'reload schema';

-- ── Migration 008a: the access policy's schemas and its hash-chained history ─
-- (codeplan IAM plan, Phase 1.1, Section 3.5.) Additive: nothing existing reads
-- these yet. Phase 2 (008b) moves every medcea object to medcea_owner and adds
-- the per-role grants; Phase 4 fills iam_policy with version 1.
--
--   medcea_owner   NOLOGIN; owns what this migration creates. Nobody logs in as
--                  it, and its SECURITY DEFINER functions are the only writers
--                  of the history.
--   medcea_auth    pre_request() and set_actor() arrive in Phase 2. PostgREST's
--                  anon will get USAGE here and nowhere else.
--   iam_policy     not in schema iam, which apps/access --purge-data drops.
--
-- The history (iam_policy.history) is a hash chain: each row stores the hash of
-- the one before it and hash = sha256(canonical JSON of the row, prev_hash
-- included). append_history() is its one writer; verify_chain() re-computes it.
-- Triggers refuse UPDATE, DELETE and TRUNCATE for every role, the owner
-- included. verify_chain() catches any edit that does not rebuild the chain; a
-- superuser who disables the triggers can still drop the newest events, or
-- rewrite one and re-hash everything after it. Only anchoring the head outside
-- the database (plan Section 7, not built) detects that.

DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'medcea_owner') THEN
        CREATE ROLE medcea_owner NOLOGIN;
    END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS medcea_auth AUTHORIZATION medcea_owner;
CREATE SCHEMA IF NOT EXISTS iam_policy AUTHORIZATION medcea_owner;
ALTER SCHEMA medcea_auth OWNER TO medcea_owner;
ALTER SCHEMA iam_policy OWNER TO medcea_owner;
REVOKE ALL ON SCHEMA medcea_auth, iam_policy FROM PUBLIC;

CREATE TABLE IF NOT EXISTS iam_policy.role (
    code      text PRIMARY KEY,
    db_role   text UNIQUE NOT NULL,
    includes  text[] NOT NULL DEFAULT '{}',
    retired   boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS iam_policy.resource_group (
    code        text PRIMARY KEY,
    data_class  text NOT NULL CHECK (data_class IN ('regulated', 'history', 'config', 'personal'))
);

-- regprocedure keeps a member pointing at a real function; note that pg_upgrade
-- refuses reg* columns other than regclass/regtype/regrole, so a major upgrade
-- of this database goes through dump and restore (as the Bitnami chart does).
CREATE TABLE IF NOT EXISTS iam_policy.member (
    member_id   serial PRIMARY KEY,
    group_code  text NOT NULL REFERENCES iam_policy.resource_group,
    mtype       text NOT NULL,
    object      regclass,
    func        regprocedure,
    on_level    char(1),
    locator     text,
    UNIQUE (mtype, locator)
);

CREATE TABLE IF NOT EXISTS iam_policy.version (
    version              int PRIMARY KEY,
    status               text NOT NULL CHECK (status IN ('draft', 'submitted', 'approved', 'applied', 'superseded')),
    reason               text NOT NULL,
    created_by_sub       uuid,
    submitted_by_person  text,
    approved_by_person   text,
    approved_by_sub      uuid,
    approved_at          timestamptz,
    applied_at           timestamptz,
    confirmed_by_person  text,          -- the bootstrap version only (plan 3.4)
    confirmed_at         timestamptz,
    checker_verdict      boolean,
    checker_digest       text,
    artefact_digest      text,
    CHECK (approved_by_person IS NULL OR approved_by_person <> submitted_by_person)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_applied ON iam_policy.version ((true)) WHERE status = 'applied';

-- One constraint_name + applies_to per cell: the per-level form of a cell
-- ({R: own_unit, O: assigned_run}, IAM 2.8) does not fit. Nothing writes entry
-- yet; 4.3's save_entry() needs a jsonb map or one row per level.
CREATE TABLE IF NOT EXISTS iam_policy.entry (
    version          int REFERENCES iam_policy.version,
    role             text REFERENCES iam_policy.role,
    group_code       text REFERENCES iam_policy.resource_group,
    levels           char(1)[] NOT NULL CHECK (levels <@ ARRAY['R','X','C','U','A','O','K','D']::char(1)[]),
    constraint_name  text,
    applies_to       char(1)[],
    PRIMARY KEY (version, role, group_code)
);

CREATE TABLE IF NOT EXISTS iam_policy.waiver (
    version     int REFERENCES iam_policy.version,
    id          text,
    invariant   text NOT NULL CHECK (invariant IN ('I10', 'I11')),
    subject     text,
    group_code  text,
    target      text,
    levels      char(1)[],
    review_by   date,
    rationale   text NOT NULL,
    controls    text NOT NULL,
    PRIMARY KEY (version, id)
);

CREATE TABLE IF NOT EXISTS iam_policy.user_zone (
    person_sub  uuid,
    zone_id     int REFERENCES medcea.cea_zone,
    PRIMARY KEY (person_sub, zone_id)
);

CREATE TABLE IF NOT EXISTS iam_policy.effective_route (
    version     int,
    service     text,
    method      text,
    path        text,
    group_code  text,
    level       char(1),
    PRIMARY KEY (version, service, method, path)
);

CREATE TABLE IF NOT EXISTS iam_policy.export_log (
    export_id     bigserial PRIMARY KEY,
    at            timestamptz DEFAULT now(),
    actor_sub     uuid,
    actor_person  text,
    actor_name    text,
    groups        text[],
    objects       text[]
);

CREATE TABLE IF NOT EXISTS iam_policy.history (
    event_id      bigserial PRIMARY KEY,
    at            timestamptz DEFAULT now(),
    actor_sub     uuid,
    actor_person  text,
    actor_name    text,
    event         text NOT NULL,
    version       int,
    reason        text,
    payload       jsonb NOT NULL,
    prev_hash     text NOT NULL,
    hash          text NOT NULL
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['role', 'resource_group', 'member', 'version', 'entry', 'waiver',
                             'user_zone', 'effective_route', 'export_log', 'history'] LOOP
        EXECUTE format('ALTER TABLE iam_policy.%I OWNER TO medcea_owner', t);
    END LOOP;
END $$;

-- Append-only, for the owner too: the records cannot be changed, only added to.
CREATE OR REPLACE FUNCTION iam_policy.refuse_change() RETURNS trigger
    LANGUAGE plpgsql SET search_path = iam_policy, pg_temp AS $$
BEGIN
    RAISE EXCEPTION '%.% is append-only: % refused', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END $$;
ALTER FUNCTION iam_policy.refuse_change() OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION iam_policy.refuse_change() FROM PUBLIC;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['history', 'export_log'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON iam_policy.%I', t || '_append_only', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON iam_policy.%I '
                       'FOR EACH ROW EXECUTE FUNCTION iam_policy.refuse_change()', t || '_append_only', t);
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON iam_policy.%I', t || '_no_truncate', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON iam_policy.%I '
                       'FOR EACH STATEMENT EXECUTE FUNCTION iam_policy.refuse_change()', t || '_no_truncate', t);
    END LOOP;
END $$;

-- The canonical text a history row is hashed over. One function, so the writer
-- and the verifier cannot drift apart. Time in UTC at microsecond precision
-- (the session's TimeZone must not change the hash); jsonb's text form sorts
-- keys and normalises spacing, so the same row always gives the same text.
CREATE OR REPLACE FUNCTION iam_policy.history_record(
    p_event_id bigint, p_at timestamptz, p_actor_sub uuid, p_actor_person text, p_actor_name text,
    p_event text, p_version int, p_reason text, p_payload jsonb, p_prev_hash text)
RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_build_object(
        'event_id', p_event_id,
        'at', to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'actor_sub', p_actor_sub, 'actor_person', p_actor_person, 'actor_name', p_actor_name,
        'event', p_event, 'version', p_version, 'reason', p_reason,
        'payload', p_payload, 'prev_hash', p_prev_hash)::text
$$;
ALTER FUNCTION iam_policy.history_record(bigint, timestamptz, uuid, text, text, text, int, text, jsonb, text) OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION iam_policy.history_record(bigint, timestamptz, uuid, text, text, text, int, text, jsonb, text) FROM PUBLIC;

-- append_history(event, payload, reason) → event_id. The only writer of the
-- chain (infrastructure_functions in defaults.yaml: EXECUTE for access_svc and
-- iam_svc, granted in Phase 2). The advisory lock serialises writers, so two
-- transactions never chain onto the same head; the head is read after the lock
-- is held, which READ COMMITTED guarantees and a snapshot-per-transaction
-- isolation level does not — so those are refused rather than allowed to fork
-- the chain. The actor is the database login until set_actor() (Phase 2)
-- records the person; `version` is taken from payload.version when present.
CREATE OR REPLACE FUNCTION iam_policy.append_history(p_event text, p_payload jsonb, p_reason text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam_policy, pg_temp AS $$
DECLARE
    v_id      bigint;
    v_at      timestamptz := now();
    v_name    text := 'db:' || session_user;
    v_version int;
    v_prev    text;
BEGIN
    IF coalesce(btrim(p_event), '') = '' THEN
        RAISE EXCEPTION 'append_history: event is required';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'append_history needs READ COMMITTED (is %): a transaction snapshot could miss the head',
            current_setting('transaction_isolation');
    END IF;
    p_payload := coalesce(p_payload, '{}'::jsonb);
    IF jsonb_typeof(p_payload -> 'version') = 'number' THEN
        v_version := (p_payload ->> 'version')::int;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('iam_policy.history'));
    SELECT h.hash INTO v_prev FROM iam_policy.history h ORDER BY h.event_id DESC LIMIT 1;
    v_prev := coalesce(v_prev, repeat('0', 64));
    v_id := nextval(pg_get_serial_sequence('iam_policy.history', 'event_id'));
    INSERT INTO iam_policy.history
        (event_id, at, actor_sub, actor_person, actor_name, event, version, reason, payload, prev_hash, hash)
    VALUES (v_id, v_at, NULL, NULL, v_name, p_event, v_version, p_reason, p_payload, v_prev,
            encode(sha256(convert_to(iam_policy.history_record(
                v_id, v_at, NULL, NULL, v_name, p_event, v_version, p_reason, p_payload, v_prev), 'UTF8')), 'hex'));
    RETURN v_id;
END $$;
ALTER FUNCTION iam_policy.append_history(text, jsonb, text) OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION iam_policy.append_history(text, jsonb, text) FROM PUBLIC;

-- verify_chain() → one row: ok, events, the first event that breaks the chain
-- (NULL when ok), why, and the head hash. Run by health-check.sh as postgres and by
-- the Policy UI's History tab as iam_svc (defaults.yaml). SECURITY DEFINER (IAM 4.4)
-- because history_record() is owner only and granting it would widen the skeleton; it
-- reads only the history, which iam_svc already reads, and returns the verdict.
CREATE OR REPLACE FUNCTION iam_policy.verify_chain(
    OUT ok boolean, OUT events bigint, OUT first_bad_event bigint, OUT detail text, OUT head text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = iam_policy, pg_temp AS $$
DECLARE
    r     record;
    prev  text := repeat('0', 64);
BEGIN
    ok := true; events := 0;
    FOR r IN SELECT * FROM iam_policy.history ORDER BY event_id LOOP
        events := events + 1;
        IF r.prev_hash <> prev THEN
            ok := false; first_bad_event := r.event_id;
            detail := 'prev_hash does not match the hash of the event before it';
            RETURN;
        END IF;
        IF r.hash <> encode(sha256(convert_to(iam_policy.history_record(
                r.event_id, r.at, r.actor_sub, r.actor_person, r.actor_name, r.event,
                r.version, r.reason, r.payload, r.prev_hash), 'UTF8')), 'hex') THEN
            ok := false; first_bad_event := r.event_id;
            detail := 'hash does not match the event''s contents';
            RETURN;
        END IF;
        prev := r.hash;
    END LOOP;
    head := CASE WHEN events = 0 THEN NULL ELSE prev END;
END $$;
ALTER FUNCTION iam_policy.verify_chain() OWNER TO medcea_owner;
REVOKE ALL ON FUNCTION iam_policy.verify_chain() FROM PUBLIC;

-- Platform settings the database needs to know: today the MQTT topic root
-- (PROJECT_NAME), written by apps/database/deploy.sh and read in Phase 2 by
-- register_mqtt_credential() instead of a literal. service_only in the policy:
-- deploy.sh revokes the API role's blanket grant on it.
CREATE TABLE IF NOT EXISTS medcea.platform_setting (
    key    text PRIMARY KEY,
    value  text NOT NULL
);
COMMENT ON TABLE medcea.platform_setting IS 'Deploy-time platform settings (mqtt_topic_root = PROJECT_NAME). Written by apps/database/deploy.sh; not readable by the API role.';

COMMENT ON SCHEMA iam_policy IS 'The access policy: versions, entries, waivers, unit assignments (user_unit; user_zone retired, kept for history), compiled routes, export log and the hash-chained history (codeplan IAM plan 3.5).';
COMMENT ON SCHEMA medcea_auth IS 'PostgREST role selection and the actor of a service session (Phase 2).';
COMMENT ON TABLE iam_policy.history IS 'Hash-chained, append-only history of the access policy. Written only by iam_policy.append_history(); checked by iam_policy.verify_chain().';
COMMENT ON TABLE iam_policy.export_log IS 'Append-only log of Database Management exports (Phase 2.6).';

NOTIFY pgrst, 'reload schema';

-- ── Migration 008b: database roles, actor, approvals (IAM plan Phase 2a) ─────
-- (codeplan IAM plan, tasks 2.1-2.3.) The ADDITIVE part: it applies on every
-- deploy whatever IAM_DB_ROLES says, and is safe for today's callers (every
-- service on postgres, the config UI and the wizard on PostgREST as anon). What
-- would break a current caller is in medcea_db_migrations_008b_enforce.sql and
-- the enforce mode of apps/iam/compiler/grants.py, applied only while
-- IAM_DB_ROLES=true; medcea_db_migrations_down_008b.sql is the false mode.
--
-- One transaction. deploy.sh passes -v deploy_nonce and reads it back from
-- medcea.platform_setting afterwards: a 008b that rolled back cannot match.
-- Every ALTER TABLE / CREATE TRIGGER / ADD CONSTRAINT is guarded by a catalog
-- check, and so is every CREATE INDEX (IF NOT EXISTS alone still takes the
-- SHARE lock before it looks at the name), so a steady-state deploy takes no
-- ACCESS EXCLUSIVE or SHARE lock.
--
-- Refusals: a POLICY refusal goes through medcea_auth.policy_refuse() — an
-- error while IAM_DB_ROLES=true, a WARNING before (assigned_run, approved-only,
-- commissioning, retention, digest mismatch). A STRUCTURAL refusal always
-- raises (bad ids, illegal transitions, forged actors, not_own_author,
-- unattributed authors, register v2, the control-column guard).
--
-- Owner writes: a SECURITY DEFINER function owned by medcea_owner runs as
-- medcea_owner, which is what the INVOKER guards test (current_user). The
-- DEFINER stamp trigger cannot see that, so the owner functions also mark
-- their writes in the actor store (_owner_write), which no other role can
-- write: the temporary table is owned by medcea_owner and every reader checks.

\if :{?deploy_nonce}
\else
\set deploy_nonce 'manual'
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';

-- A full rollback (medcea_db_migrations_down_008b.sql -v full=1) parks 008b's
-- tables in schema medcea_retired_008b, out of reach of the pre-2a blanket anon
-- grant. Bring them back, with their data, before the CREATE ... IF NOT EXISTS
-- below would make empty ones next to them.
DO $$
DECLARE t text;
BEGIN
    IF pg_catalog.to_regnamespace('medcea_retired_008b') IS NULL THEN
        RETURN;
    END IF;
    FOREACH t IN ARRAY ARRAY['unit_algorithm_params', 'approval', 'pending_change', 'run_release',
                             'algorithm_state_event', 'row_change', 'mqtt_service_credential', 'mqtt_service_acl'] LOOP
        IF pg_catalog.to_regclass('medcea_retired_008b.' || t) IS NOT NULL
           AND pg_catalog.to_regclass('medcea.' || t) IS NULL THEN
            EXECUTE pg_catalog.format('ALTER TABLE medcea_retired_008b.%I SET SCHEMA medcea', t);
        END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class
                    WHERE relnamespace = 'medcea_retired_008b'::regnamespace) THEN
        DROP SCHEMA medcea_retired_008b;
    END IF;
END $$;

-- ── B0. The actor store and the bootstrap functions ─────────────────────────

-- _actor_ok(): true when this session's actor table exists, false when not;
-- an error when a table of that name exists that medcea_owner does not own
-- (any role may create temporary tables: that is the spoofing attempt).
CREATE OR REPLACE FUNCTION medcea_auth._actor_ok() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE o oid;
BEGIN
    SELECT c.relowner INTO o FROM pg_catalog.pg_class c
     WHERE c.relname = 'medcea_actor' AND c.relnamespace = pg_catalog.pg_my_temp_schema();
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF o <> 'medcea_owner'::regrole THEN
        RAISE EXCEPTION 'actor table spoofed: pg_temp.medcea_actor is not owned by medcea_owner'
            USING ERRCODE = '42501';
    END IF;
    RETURN true;
END $$;

CREATE OR REPLACE FUNCTION medcea_auth._actor_store() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
BEGIN
    IF NOT medcea_auth._actor_ok() THEN
        CREATE TEMPORARY TABLE medcea_actor (
            kind      text PRIMARY KEY,         -- 'actor' | 'owner_write'
            sub       text, person text, name text, role text, source text,
            ref_kind  text, ref_id bigint
        ) ON COMMIT DELETE ROWS;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION medcea_auth._actor_put(
    p_sub text, p_person text, p_name text, p_role text, p_source text, p_ref_kind text, p_ref_id bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
BEGIN
    PERFORM medcea_auth._actor_store();
    DELETE FROM pg_temp.medcea_actor WHERE kind = 'actor';
    INSERT INTO pg_temp.medcea_actor (kind, sub, person, name, role, source, ref_kind, ref_id)
    VALUES ('actor', p_sub, p_person, p_name, p_role, p_source, p_ref_kind, p_ref_id);
END $$;

-- _owner_write(true|false): brackets an owner function's own writes (nests).
CREATE OR REPLACE FUNCTION medcea_auth._owner_write(p_on boolean) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
BEGIN
    PERFORM medcea_auth._actor_store();
    IF p_on THEN
        INSERT INTO pg_temp.medcea_actor (kind, ref_id) VALUES ('owner_write', 1)
        ON CONFLICT (kind) DO UPDATE SET ref_id = pg_temp.medcea_actor.ref_id + 1;
    ELSE
        UPDATE pg_temp.medcea_actor SET ref_id = ref_id - 1 WHERE kind = 'owner_write';
        DELETE FROM pg_temp.medcea_actor WHERE kind = 'owner_write' AND ref_id <= 0;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION medcea_auth._is_owner_write() RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
BEGIN
    -- Two statements, not one AND: a single expression is planned whole, so the
    -- temp-table reference would fail in a session that has no actor store.
    IF NOT medcea_auth._actor_ok() THEN
        RETURN false;
    END IF;
    RETURN EXISTS (SELECT 1 FROM pg_temp.medcea_actor WHERE kind = 'owner_write');
END $$;

-- Stubs of the compiled functions, created only when missing: grants.py
-- replaces each with the body compiled from the policy on every deploy.
DO $$
BEGIN
    IF pg_catalog.to_regprocedure('medcea_auth._own_role(jsonb)') IS NULL THEN
        CREATE FUNCTION medcea_auth._own_role(grp jsonb) RETURNS text
            LANGUAGE plpgsql IMMUTABLE AS $f$ BEGIN RETURN NULL; END $f$;
    END IF;
    IF pg_catalog.to_regprocedure('medcea_auth.platform_roles()') IS NULL THEN
        CREATE FUNCTION medcea_auth.platform_roles() RETURNS text[]
            LANGUAGE plpgsql IMMUTABLE AS $f$ BEGIN RETURN '{}'::text[]; END $f$;
    END IF;
    IF pg_catalog.to_regprocedure('medcea_auth._token_clients()') IS NULL THEN
        CREATE FUNCTION medcea_auth._token_clients() RETURNS text[]
            LANGUAGE plpgsql IMMUTABLE AS $f$ BEGIN RETURN '{}'::text[]; END $f$;
    END IF;
    IF pg_catalog.to_regprocedure('medcea_auth.policy_holds(text, text, text)') IS NULL THEN
        CREATE FUNCTION medcea_auth.policy_holds(p_role text, p_group text, p_level text) RETURNS text
            LANGUAGE plpgsql IMMUTABLE AS $f$ BEGIN RETURN NULL; END $f$;
    END IF;
    IF pg_catalog.to_regprocedure('medcea_auth.object_group(text)') IS NULL THEN
        CREATE FUNCTION medcea_auth.object_group(p_object text) RETURNS text
            LANGUAGE plpgsql IMMUTABLE AS $f$ BEGIN RETURN NULL; END $f$;
    END IF;
    -- IAM 2.7: never '[]' uncompiled, so an uncompiled database never calls a
    -- widening a narrowing (iam.record_decision fails instead)
    IF pg_catalog.to_regprocedure('medcea_auth.role_widening(text, text)') IS NULL THEN
        CREATE FUNCTION medcea_auth.role_widening(p_old text, p_new text) RETURNS jsonb
            LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $f$
        BEGIN
            RAISE EXCEPTION 'role_widening is not compiled: run ./apps/database/deploy.sh' USING ERRCODE = '55000';
        END $f$;
    END IF;
    IF pg_catalog.to_regprocedure('medcea_auth.pre_request()') IS NULL THEN
        CREATE FUNCTION medcea_auth.pre_request() RETURNS void LANGUAGE plpgsql AS $f$
        BEGIN
            IF pg_catalog.current_setting('medcea.iam_db_roles', true) IS DISTINCT FROM 'true' THEN RETURN; END IF;
            RAISE EXCEPTION 'pre_request() is not compiled yet (apps/database/deploy.sh)' USING ERRCODE = '28000';
        END $f$;
    END IF;
END $$;

-- request_actor(): the verified actor of this transaction, or NULLs.
--   1. the actor set_actor()/set_system_actor()/_set_internal_actor() stored;
--   2. else, only in a PostgREST session (session_user authenticator), the JWT
--      claims PostgREST verified, when they pass pre_request()'s own checks
--      (typ, azp, aud, a uuid sub, exactly one own role): source 'token';
--   3. else nothing. A service, pgAdmin or rr_admin_login setting
--      request.jwt.claims itself is never taken for a token.
CREATE OR REPLACE FUNCTION medcea_auth.request_actor(
    OUT sub text, OUT person text, OUT name text, OUT role text, OUT source text,
    OUT ref_kind text, OUT ref_id bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE
    c    jsonb;
    own  text;
BEGIN
    IF medcea_auth._actor_ok() THEN
        SELECT a.sub, a.person, a.name, a.role, a.source, a.ref_kind, a.ref_id
          INTO sub, person, name, role, source, ref_kind, ref_id
          FROM pg_temp.medcea_actor a WHERE a.kind = 'actor';
        IF FOUND THEN
            RETURN;
        END IF;
    END IF;
    IF session_user::text = 'authenticator' THEN
        BEGIN
            c := nullif(pg_catalog.current_setting('request.jwt.claims', true), '')::jsonb;
        EXCEPTION WHEN others THEN
            c := NULL;
        END;
        IF c IS NOT NULL
           AND (c ->> 'typ') = 'Bearer'
           AND (c ->> 'azp') = ANY (medcea_auth._token_clients())
           AND (c -> 'aud' = '"medcea-api"'::jsonb
                OR (pg_catalog.jsonb_typeof(c -> 'aud') = 'array' AND (c -> 'aud') ? 'medcea-api'))
           AND coalesce(c ->> 'sub', '') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
            own := medcea_auth._own_role(c -> 'groups');
            IF own IS NOT NULL THEN
                sub := c ->> 'sub'; person := c ->> 'person_id'; name := c ->> 'preferred_username';
                role := own; source := 'token';
                RETURN;
            END IF;
        END IF;
    END IF;
END $$;

-- The deploy scripts' own actors: migration:<id> and system:<what>.
CREATE OR REPLACE FUNCTION medcea_auth._set_internal_actor(p_name text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
BEGIN
    IF p_name IS NULL OR p_name !~ '^(migration|system):[a-z0-9:_-]+$' THEN
        RAISE EXCEPTION 'internal actor must be migration:<id> or system:<name>, not %', p_name
            USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._actor_put(p_name, NULL, p_name, NULL, pg_catalog.split_part(p_name, ':', 1), NULL, NULL);
END $$;

CREATE OR REPLACE FUNCTION medcea_auth.enforcing() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
    SELECT coalesce((SELECT s.value = 'true' FROM medcea.platform_setting s WHERE s.key = 'iam_db_roles'), false)
$$;

CREATE OR REPLACE FUNCTION medcea_auth.policy_refuse(p_message text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
BEGIN
    IF medcea_auth.enforcing() THEN
        RAISE EXCEPTION '%', p_message USING ERRCODE = '42501';
    END IF;
    RAISE WARNING 'IAM_DB_ROLES=false, would refuse: %', p_message;
END $$;

-- set_actor(): a service records the person whose token it verified.
CREATE OR REPLACE FUNCTION medcea_auth.set_actor(p_sub text, p_person text, p_name text, p_role text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
BEGIN
    IF p_sub IS NULL OR p_sub !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'set_actor: sub must be the uuid of a Keycloak account, not %', p_sub USING ERRCODE = '22023';
    END IF;
    IF p_role IS NULL OR NOT (p_role = ANY (medcea_auth.platform_roles())) THEN
        RAISE EXCEPTION 'set_actor: % is not a platform role', p_role USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._actor_put(p_sub, p_person, p_name, p_role, 'person via ' || session_user::text, NULL, NULL);
END $$;

-- set_system_actor('system:scheduler', 'schedule'|'run', id): a triggered run
-- acts with the person and role of whoever created the schedule (or the run,
-- falling back to its schedule). A schedule whose creator is no person
-- (migration:008, db:<login>) falls back to its last editor, but only one who
-- edited it as a verified person (source token or 'person via …') while holding
-- C on runs freely — a re-save by a production manager, never by a system
-- actor. Refused otherwise.
CREATE OR REPLACE FUNCTION medcea_auth.set_system_actor(p_name text, p_kind text, p_id bigint) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE
    v_person text; v_name text; v_role text; v_sched integer;
    s record;
BEGIN
    IF p_name IS DISTINCT FROM 'system:scheduler' THEN
        RAISE EXCEPTION 'set_system_actor: unknown system actor %', p_name USING ERRCODE = '22023';
    END IF;
    IF p_kind = 'schedule' THEN
        IF NOT EXISTS (SELECT 1 FROM medcea.schedule x WHERE x.schedule_id = p_id) THEN
            RAISE EXCEPTION 'set_system_actor: no schedule %', p_id USING ERRCODE = '22023';
        END IF;
        v_sched := p_id;
    ELSIF p_kind = 'run' THEN
        SELECT r.created_by_person, r.created_by_name, r.created_by_role, r.schedule_id
          INTO v_person, v_name, v_role, v_sched
          FROM medcea.recipe_run r WHERE r.recipe_run_id = p_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'set_system_actor: no run %', p_id USING ERRCODE = '22023';
        END IF;
    ELSE
        RAISE EXCEPTION 'set_system_actor: kind must be schedule or run, not %', p_kind USING ERRCODE = '22023';
    END IF;
    IF v_person IS NULL AND v_sched IS NOT NULL THEN
        SELECT x.created_by_person, x.created_by_name, x.created_by_role,
               x.updated_by_person, x.updated_by_name, x.updated_by_role, x.updated_by_source
          INTO s FROM medcea.schedule x WHERE x.schedule_id = v_sched;
        IF s.created_by_person IS NOT NULL THEN
            v_person := s.created_by_person; v_name := s.created_by_name; v_role := s.created_by_role;
        ELSIF s.updated_by_person IS NOT NULL
              AND (s.updated_by_source = 'token' OR s.updated_by_source LIKE 'person via %')
              AND medcea_auth.policy_holds(s.updated_by_role, 'runs', 'C') IS NOT DISTINCT FROM 'free' THEN
            v_person := s.updated_by_person; v_name := s.updated_by_name; v_role := s.updated_by_role;
        END IF;
    END IF;
    IF v_person IS NULL OR v_role IS NULL THEN
        RAISE EXCEPTION 'set_system_actor: % % has no person-attributed creator; no run is triggered from it until a person who holds C on runs re-saves it', p_kind, p_id
            USING ERRCODE = '42501';
    END IF;
    PERFORM medcea_auth._actor_put(p_name, v_person, p_name, v_role, 'system', p_kind, p_id);
END $$;

-- my_zones(): every zone of the units assigned to the person behind the request
-- (own_unit RLS on medcea.measurement); zones added to a unit later are included,
-- and so are its inactive ones (their old telemetry stays visible). The policy
-- uses the initplan form `zone_id = ANY ((SELECT my_zones())::integer[])`, like the run
-- tables' `= ANY ((SELECT my_units())::integer[])`: a bare STABLE plpgsql call in an RLS qual
-- is evaluated once per row wherever it is a filter rather than an index condition
-- (a sequential or primary-key-ordered scan of measurement). The expression change
-- renames the policy (its name hashes the expression); the bundle drops the stale one.
CREATE OR REPLACE FUNCTION medcea_auth.my_zones() RETURNS integer[]
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE
    s text := (medcea_auth.request_actor()).sub;
    v integer[];
BEGIN
    IF s IS NULL OR s !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RETURN '{}'::integer[];
    END IF;
    SELECT coalesce(pg_catalog.array_agg(cz.zone_id ORDER BY cz.zone_id), '{}') INTO v
      FROM medcea.cea_zone cz JOIN iam_policy.user_unit uu ON uu.unit_id = cz.unit_id
     WHERE uu.person_sub = s::uuid;
    RETURN v;
END $$;
REVOKE ALL ON FUNCTION medcea_auth.my_zones() FROM PUBLIC;

-- my_units(): the units assigned to the person behind the request (own_unit RLS
-- on the run tables). Both bodies are resolved when they run, so they may
-- precede B15, which creates iam_policy.user_unit.
CREATE OR REPLACE FUNCTION medcea_auth.my_units() RETURNS integer[]
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE
    s text := (medcea_auth.request_actor()).sub;
    v integer[];
BEGIN
    IF s IS NULL OR s !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RETURN '{}'::integer[];
    END IF;
    SELECT coalesce(pg_catalog.array_agg(uu.unit_id ORDER BY uu.unit_id), '{}') INTO v
      FROM iam_policy.user_unit uu WHERE uu.person_sub = s::uuid;
    RETURN v;
END $$;
REVOKE ALL ON FUNCTION medcea_auth.my_units() FROM PUBLIC;

-- The content of a row for digests and change logs: without the stamps
-- (*_by_*), timestamps (timestamp_*) and, for a digest, status, retired_at and
-- commissioning (changed only under dual control, like status; the same keys
-- _changes_since() leaves out of authorship).
CREATE OR REPLACE FUNCTION medcea_auth._content(j jsonb, p_digest boolean) RETURNS jsonb
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT coalesce(jsonb_object_agg(k, v), '{}'::jsonb) FROM jsonb_each(j) x(k, v)
     WHERE NOT (k LIKE '%\_by\_%' OR k LIKE 'timestamp\_%' OR (p_digest AND k IN ('status', 'retired_at', 'commissioning')))
$$;

-- row_digest(target, key): sha256 of a member row's content; a recipe with its
-- lines, a run with its cycles. Compared with medcea.approval.row_hash.
CREATE OR REPLACE FUNCTION medcea_auth.row_digest(p_target text, p_key jsonb) RETURNS text
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE
    rel   regclass;
    cols  text[];
    types text[];
    w     text := '';
    j     jsonb;
    i     integer;
BEGIN
    IF medcea_auth.object_group(p_target) IS NULL THEN
        RAISE EXCEPTION 'row_digest: % is not a member table of the access policy', p_target USING ERRCODE = '22023';
    END IF;
    rel := pg_catalog.to_regclass(p_target);
    IF rel IS NULL THEN
        RAISE EXCEPTION 'row_digest: no table %', p_target USING ERRCODE = '22023';
    END IF;
    SELECT pg_catalog.array_agg(a.attname::text ORDER BY k.ord),
           pg_catalog.array_agg(pg_catalog.format_type(a.atttypid, a.atttypmod) ORDER BY k.ord)
      INTO cols, types
      FROM pg_catalog.pg_index ix
      CROSS JOIN LATERAL pg_catalog.unnest(ix.indkey) WITH ORDINALITY k(attnum, ord)
      JOIN pg_catalog.pg_attribute a ON a.attrelid = ix.indrelid AND a.attnum = k.attnum
     WHERE ix.indrelid = rel AND ix.indisprimary;
    IF cols IS NULL THEN
        RAISE EXCEPTION 'row_digest: % has no primary key', p_target USING ERRCODE = '22023';
    END IF;
    IF pg_catalog.jsonb_typeof(p_key) IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_array_length(p_key) <> pg_catalog.cardinality(cols) THEN
        RAISE EXCEPTION 'row_digest: key % does not match the primary key (%) of %', p_key, cols, p_target
            USING ERRCODE = '22023';
    END IF;
    FOR i IN 1 .. pg_catalog.cardinality(cols) LOOP
        w := w || CASE WHEN i > 1 THEN ' AND ' ELSE '' END
               || pg_catalog.format('t.%I = ($1 ->> %s)::%s', cols[i], i - 1, types[i]);
    END LOOP;
    EXECUTE pg_catalog.format('SELECT pg_catalog.to_jsonb(t) FROM %s t WHERE %s', rel, w) INTO j USING p_key;
    IF j IS NULL THEN
        RETURN NULL;
    END IF;
    j := medcea_auth._content(j, true);
    IF rel = 'medcea.recipe'::regclass THEN
        j := j || pg_catalog.jsonb_build_object('lines', (
            SELECT coalesce(pg_catalog.jsonb_agg(medcea_auth._content(pg_catalog.to_jsonb(l), true)
                                                 ORDER BY l.recipe_item_seq_id), '[]'::jsonb)
              FROM medcea.recipe_line l WHERE l.recipe_id = (p_key ->> 0)::integer));
    ELSIF rel = 'medcea.recipe_run'::regclass THEN
        j := j || pg_catalog.jsonb_build_object('cycles', (
            SELECT coalesce(pg_catalog.jsonb_agg(medcea_auth._content(pg_catalog.to_jsonb(c), true)
                                                 ORDER BY c.recipe_line_cycle_run_id), '[]'::jsonb)
              FROM medcea.recipe_line_cycle_run c WHERE c.recipe_run_id = (p_key ->> 0)::integer));
    END IF;
    RETURN pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(j::text, 'UTF8')), 'hex');
END $$;

-- ── B2. The scheduler's tables (moved here from scheduler-api.py _ensure_schema) ─
DO $$
BEGIN
    IF pg_catalog.to_regclass('medcea.schedule') IS NULL THEN
        CREATE TABLE medcea.schedule (
            schedule_id      serial       PRIMARY KEY,
            unit_id          integer      NOT NULL REFERENCES medcea.cea_unit(unit_id)  ON DELETE CASCADE,
            recipe_id        integer      NOT NULL REFERENCES medcea.recipe(recipe_id)  ON DELETE CASCADE,
            cron_expression  varchar(100) NOT NULL,
            enabled          boolean      NOT NULL DEFAULT true,
            description      text,
            timestamp_cre    timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
            timestamp_upd    timestamptz
        );
        REVOKE ALL ON TABLE medcea.schedule FROM PUBLIC, anon;
        REVOKE ALL ON SEQUENCE medcea.schedule_schedule_id_seq FROM PUBLIC, anon;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.schedule'::regclass AND attname = 'algorithm_id' AND NOT attisdropped) THEN
        ALTER TABLE medcea.schedule
            ADD COLUMN IF NOT EXISTS algorithm_id     INTEGER REFERENCES medcea.control_algorithm(algorithm_id),
            ADD COLUMN IF NOT EXISTS algorithm_params JSONB DEFAULT NULL;
    END IF;
    IF pg_catalog.to_regclass('medcea.scheduler_config') IS NULL THEN
        CREATE TABLE medcea.scheduler_config (
            key   varchar(100) PRIMARY KEY,
            value text NOT NULL
        );
        REVOKE ALL ON TABLE medcea.scheduler_config FROM PUBLIC, anon;
    END IF;
END $$;
-- The scheduler used to grant itself these; PostgREST has no business with them.
REVOKE ALL ON TABLE medcea.schedule FROM authenticator;
REVOKE ALL ON SEQUENCE medcea.schedule_schedule_id_seq FROM authenticator;

-- ── B3. The unused Liquibase leftover ────────────────────────────────────────
DROP TABLE IF EXISTS medcea.databasechangeloglock;

-- ── B6 (table). Parameter sets ───────────────────────────────────────────────
-- What a schedule or an assignment runs with, approved like a recipe. Replaces
-- recipe_unit_permission.algorithm_params and schedule.algorithm_params (those
-- stay until 2.4; medcea_db_008b_data.sql copies them in). No foreign key on
-- unit_id: a parameter set is history-like and must not stop a unit's deletion.
CREATE TABLE IF NOT EXISTS medcea.unit_algorithm_params (
    params_id     integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    algorithm_id  integer NOT NULL REFERENCES medcea.control_algorithm(algorithm_id),
    unit_id       integer,
    name          varchar(120) NOT NULL,
    params        jsonb NOT NULL DEFAULT '{}' CONSTRAINT uap_params_object_chk CHECK (pg_catalog.jsonb_typeof(params) = 'object'),
    status        varchar(10) NOT NULL DEFAULT 'draft' CONSTRAINT uap_status_chk CHECK (status IN ('draft', 'approved', 'retired')),
    source        text,
    timestamp_cre timestamptz NOT NULL DEFAULT now(),
    timestamp_upd timestamptz,
    created_by_sub text, created_by_person text, created_by_name text, created_by_role varchar(40), created_by_source text,
    updated_by_sub text, updated_by_person text, updated_by_name text, updated_by_role varchar(40), updated_by_source text,
    CONSTRAINT uap_name_uk UNIQUE (name)
);
REVOKE ALL ON TABLE medcea.unit_algorithm_params FROM PUBLIC, anon, authenticator;
REVOKE ALL ON SEQUENCE medcea.unit_algorithm_params_params_id_seq FROM PUBLIC, anon, authenticator;
COMMENT ON TABLE medcea.unit_algorithm_params IS 'Approved parameter sets of a control algorithm (NULL unit_id: any unit). Schedules, assignments and runs reference one by params_id.';

-- ── B4. Attribution columns on the 14 attributed tables ─────────────────────
DO $$
DECLARE
    t     text;
    c     text;
    cols  text[] := ARRAY['created_by_sub', 'created_by_person', 'created_by_name', 'created_by_role', 'created_by_source',
                          'updated_by_sub', 'updated_by_person', 'updated_by_name', 'updated_by_role', 'updated_by_source'];
    adds  text;
BEGIN
    FOREACH t IN ARRAY ARRAY['cea_location', 'cea_unit', 'cea_zone', 'component', 'device', 'recipe', 'recipe_line',
                             'recipe_unit_permission', 'control_algorithm', 'schedule', 'scheduler_config',
                             'recipe_run', 'recipe_line_cycle_run'] LOOP
        adds := NULL;
        FOREACH c IN ARRAY cols LOOP
            IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                            WHERE attrelid = pg_catalog.to_regclass('medcea.' || t) AND attname = c AND NOT attisdropped) THEN
                adds := coalesce(adds || ', ', '') || pg_catalog.format('ADD COLUMN %I %s', c,
                            CASE WHEN c LIKE '%\_role' THEN 'varchar(40)' ELSE 'text' END);
            END IF;
        END LOOP;
        IF adds IS NOT NULL THEN
            EXECUTE pg_catalog.format('ALTER TABLE medcea.%I %s', t, adds);
        END IF;
    END LOOP;
    -- recipe_run: who executed it, which schedule triggered it, which parameter set it ran
    adds := NULL;
    FOREACH c IN ARRAY ARRAY['executed_by_sub', 'executed_by_person', 'executed_by_name', 'executed_by_role', 'executed_by_source'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                        WHERE attrelid = 'medcea.recipe_run'::regclass AND attname = c AND NOT attisdropped) THEN
            adds := coalesce(adds || ', ', '') || pg_catalog.format('ADD COLUMN %I %s', c,
                        CASE WHEN c LIKE '%\_role' THEN 'varchar(40)' ELSE 'text' END);
        END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.recipe_run'::regclass AND attname = 'schedule_id' AND NOT attisdropped) THEN
        adds := coalesce(adds || ', ', '') || 'ADD COLUMN schedule_id integer';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.recipe_run'::regclass AND attname = 'params_id' AND NOT attisdropped) THEN
        adds := coalesce(adds || ', ', '') || 'ADD COLUMN params_id integer REFERENCES medcea.unit_algorithm_params(params_id)';
    END IF;
    IF adds IS NOT NULL THEN
        EXECUTE 'ALTER TABLE medcea.recipe_run ' || adds;
    END IF;
    -- device_slot_history: who placed, moved or removed the board
    adds := NULL;
    FOREACH c IN ARRAY ARRAY['changed_by_sub', 'changed_by_person', 'changed_by_name', 'changed_by_role', 'changed_by_source'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                        WHERE attrelid = 'medcea.device_slot_history'::regclass AND attname = c AND NOT attisdropped) THEN
            adds := coalesce(adds || ', ', '') || pg_catalog.format('ADD COLUMN %I %s', c,
                        CASE WHEN c LIKE '%\_role' THEN 'varchar(40)' ELSE 'text' END);
        END IF;
    END LOOP;
    IF adds IS NOT NULL THEN
        EXECUTE 'ALTER TABLE medcea.device_slot_history ' || adds;
    END IF;
    -- the parameter set an assignment and a schedule point to
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.recipe_unit_permission'::regclass AND attname = 'params_id' AND NOT attisdropped) THEN
        ALTER TABLE medcea.recipe_unit_permission ADD COLUMN params_id integer REFERENCES medcea.unit_algorithm_params(params_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.schedule'::regclass AND attname = 'params_id' AND NOT attisdropped) THEN
        ALTER TABLE medcea.schedule ADD COLUMN params_id integer REFERENCES medcea.unit_algorithm_params(params_id);
    END IF;
END $$;

-- ── B5. Status and control columns ──────────────────────────────────────────
DO $$
DECLARE t text;
BEGIN
    -- existing recipes and algorithms were in use: they start approved (and are
    -- grandfathered once by medcea_db_008b_data.sql); new rows start as drafts
    FOREACH t IN ARRAY ARRAY['recipe', 'control_algorithm'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                        WHERE attrelid = pg_catalog.to_regclass('medcea.' || t) AND attname = 'status' AND NOT attisdropped) THEN
            EXECUTE pg_catalog.format(
                'ALTER TABLE medcea.%I ADD COLUMN status varchar(10) NOT NULL DEFAULT ''approved'' '
                'CONSTRAINT %I CHECK (status IN (''draft'', ''approved'', ''retired''))', t, t || '_status_chk');
            EXECUTE pg_catalog.format('ALTER TABLE medcea.%I ALTER COLUMN status SET DEFAULT ''draft''', t);
        END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.cea_unit'::regclass AND attname = 'commissioning' AND NOT attisdropped) THEN
        ALTER TABLE medcea.cea_unit ADD COLUMN commissioning boolean NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.schedule'::regclass AND attname = 'retired_at' AND NOT attisdropped) THEN
        ALTER TABLE medcea.schedule ADD COLUMN retired_at timestamptz;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.algorithm_state'::regclass AND attname = 'retired_at' AND NOT attisdropped) THEN
        ALTER TABLE medcea.algorithm_state ADD COLUMN retired_at timestamptz;
    END IF;
END $$;

-- ── B4 (backfill). Rows from before 008b are attributed to migration:008 ────
-- session_replication_role = replica skips stamp_actor and the guards; the
-- append-only triggers are ENABLE ALWAYS and still fire. Finds 0 rows after the
-- first deploy, because stamping is always on from then.
SET LOCAL session_replication_role = replica;
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['cea_location', 'cea_unit', 'cea_zone', 'component', 'device', 'recipe', 'recipe_line',
                             'recipe_unit_permission', 'control_algorithm', 'unit_algorithm_params', 'schedule',
                             'scheduler_config', 'recipe_run', 'recipe_line_cycle_run'] LOOP
        EXECUTE pg_catalog.format(
            'UPDATE medcea.%I SET created_by_sub = ''migration:008'', created_by_name = ''migration:008'', '
            'created_by_source = ''migration'' WHERE created_by_sub IS NULL', t);
    END LOOP;
END $$;
SET LOCAL session_replication_role = origin;

-- ── B7-B10, B12. Append-only records ────────────────────────────────────────
-- medcea.approval: every approval, review, application, release, retirement
-- and the one-time grandfathering of what was in use before 008b.
CREATE TABLE IF NOT EXISTS medcea.approval (
    approval_id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target               text NOT NULL,                 -- qualified table name
    row_key              jsonb NOT NULL,                -- the primary key values, in order
    row_hash             text NOT NULL,                 -- medcea_auth.row_digest() when approved
    group_name           text NOT NULL,
    action               text NOT NULL CONSTRAINT approval_action_chk
                         CHECK (action IN ('approve', 'review', 'apply', 'release', 'retire', 'grandfather', 'return', 'withdraw')),
    note                 text,
    author_persons       text[] NOT NULL DEFAULT '{}',
    approved_by_sub      text NOT NULL,
    approved_by_person   text,
    approved_by_name     text,
    approved_by_role     varchar(40),
    approved_by_source   text,
    session_user_name    text NOT NULL DEFAULT session_user,
    client_addr          inet DEFAULT inet_client_addr(),
    approved_at          timestamptz NOT NULL DEFAULT now(),
    last_change_id       bigint               -- the newest medcea.row_change this approval covered
);
-- last_change_id: _authors() counts the changes after it, in commit order
-- (the approver holds the row locks), not by now(), which is the transaction
-- START time and lets an edit that began before an approval and committed
-- after it fall out of every later not_own_author check.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.approval'::regclass AND attname = 'last_change_id' AND NOT attisdropped) THEN
        ALTER TABLE medcea.approval ADD COLUMN last_change_id bigint;
    END IF;
END $$;
-- 'return' (qa sends a draft or a proposal back, with a reason) and 'withdraw' (the
-- proposer takes a proposal back) close nothing an approval counts: _authors() and
-- _is_approved() read approve/review/grandfather only. Guarded: the ALTER takes the
-- table's lock, so a steady-state deploy skips it.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'medcea.approval'::regclass AND conname = 'approval_action_chk'
                      AND pg_catalog.pg_get_constraintdef(oid) LIKE '%''withdraw''%') THEN
        ALTER TABLE medcea.approval DROP CONSTRAINT IF EXISTS approval_action_chk;
        ALTER TABLE medcea.approval ADD CONSTRAINT approval_action_chk
            CHECK (action IN ('approve', 'review', 'apply', 'release', 'retire', 'grandfather', 'return', 'withdraw'));
    END IF;
END $$;
REVOKE ALL ON TABLE medcea.approval FROM PUBLIC, anon, authenticator;
REVOKE ALL ON SEQUENCE medcea.approval_approval_id_seq FROM PUBLIC, anon, authenticator;
-- Guarded: CREATE INDEX IF NOT EXISTS takes its SHARE lock before it checks
-- the name, and would hold it on every deploy until 008b commits.
DO $$
BEGIN
    IF pg_catalog.to_regclass('medcea.approval_target_idx') IS NULL THEN
        CREATE INDEX approval_target_idx ON medcea.approval (target, row_key, approved_at);
    END IF;
END $$;

-- medcea.pending_change: a blocking change waiting for approve_change(), or (applied_at)
-- a narrowing that applied at once and waits for qa's review.
CREATE TABLE IF NOT EXISTS medcea.pending_change (
    change_id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target               text NOT NULL CONSTRAINT pending_change_target_chk
                         CHECK (target IN ('medcea.scheduler_config', 'medcea.cea_unit')),
    row_key              jsonb NOT NULL,
    column_name          text NOT NULL,
    new_value            jsonb NOT NULL,
    reason               text,
    proposed_by_sub      text NOT NULL,
    proposed_by_person   text,
    proposed_by_name     text,
    proposed_by_role     varchar(40),
    proposed_by_source   text,
    proposed_at          timestamptz NOT NULL DEFAULT now(),
    applied_at           timestamptz          -- set when the change applied at once (a narrowing: commissioning off); qa reviews it after
);
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.pending_change'::regclass AND attname = 'applied_at' AND NOT attisdropped) THEN
        ALTER TABLE medcea.pending_change ADD COLUMN applied_at timestamptz;
    END IF;
END $$;
REVOKE ALL ON TABLE medcea.pending_change FROM PUBLIC, anon, authenticator;
REVOKE ALL ON SEQUENCE medcea.pending_change_change_id_seq FROM PUBLIC, anon, authenticator;
DO $$
BEGIN
    IF pg_catalog.to_regclass('medcea.pending_change_row_idx') IS NULL THEN
        CREATE INDEX pending_change_row_idx ON medcea.pending_change (target, row_key, column_name, change_id);
    END IF;
END $$;

-- medcea.run_release: the release of a completed run (one per run).
CREATE TABLE IF NOT EXISTS medcea.run_release (
    release_id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recipe_run_id        integer NOT NULL UNIQUE REFERENCES medcea.recipe_run(recipe_run_id),
    row_hash             text NOT NULL,
    note                 text,
    released_by_sub      text NOT NULL,
    released_by_person   text NOT NULL,
    released_by_name     text,
    released_by_role     varchar(40) NOT NULL,
    released_by_source   text,
    session_user_name    text NOT NULL DEFAULT session_user,
    client_addr          inet DEFAULT inet_client_addr(),
    released_at          timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON TABLE medcea.run_release FROM PUBLIC, anon, authenticator;
REVOKE ALL ON SEQUENCE medcea.run_release_release_id_seq FROM PUBLIC, anon, authenticator;

-- medcea.algorithm_state_event: every write, retirement and delete of a Q-table.
CREATE TABLE IF NOT EXISTS medcea.algorithm_state_event (
    event_id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event                text NOT NULL CONSTRAINT algorithm_state_event_chk
                         CHECK (event IN ('created', 'updated', 'retired', 'unretired', 'deleted')),
    unit_id              integer NOT NULL,
    algorithm            varchar(20) NOT NULL,
    channel              varchar(50) NOT NULL,
    recipe_run_id        integer,
    state_sha256         text NOT NULL,
    state                jsonb,               -- in full on retired and deleted; the hash otherwise
    reason               text,
    actor_sub            text NOT NULL,
    actor_person         text,
    actor_role           varchar(40),
    actor_source         text,
    at                   timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON TABLE medcea.algorithm_state_event FROM PUBLIC, anon, authenticator;
REVOKE ALL ON SEQUENCE medcea.algorithm_state_event_event_id_seq FROM PUBLIC, anon, authenticator;
DO $$
BEGIN
    IF pg_catalog.to_regclass('medcea.algorithm_state_event_key_idx') IS NULL THEN
        CREATE INDEX algorithm_state_event_key_idx ON medcea.algorithm_state_event (unit_id, algorithm, channel, at);
    END IF;
END $$;

-- medcea.row_change: every change to the 14 attributed tables (not_own_author).
CREATE TABLE IF NOT EXISTS medcea.row_change (
    change_id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target               text NOT NULL,
    row_key              jsonb NOT NULL,
    op                   char(1) NOT NULL CONSTRAINT row_change_op_chk CHECK (op IN ('I', 'U', 'D')),
    old_values           jsonb,
    new_values           jsonb,
    actor_sub            text NOT NULL,
    actor_person         text,
    actor_name           text,
    actor_role           varchar(40),
    actor_source         text,
    at                   timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON TABLE medcea.row_change FROM PUBLIC, anon, authenticator;
REVOKE ALL ON SEQUENCE medcea.row_change_change_id_seq FROM PUBLIC, anon, authenticator;
DO $$
BEGIN
    IF pg_catalog.to_regclass('medcea.row_change_row_idx') IS NULL THEN
        CREATE INDEX row_change_row_idx ON medcea.row_change (target, row_key, at);
    END IF;
END $$;

-- ── B13. MQTT: person credentials, and the serial on board credentials ──────
CREATE TABLE IF NOT EXISTS medcea.mqtt_service_credential (
    username        text PRIMARY KEY CONSTRAINT mqtt_service_credential_user_chk CHECK (username ~ '^[A-Za-z0-9._-]+$'),
    password_hash   text NOT NULL CONSTRAINT mqtt_service_credential_hash_chk
                    CHECK (password_hash ~ '^\$7\$[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'),
    person_sub      uuid,
    expires_at      timestamptz NOT NULL,
    active          boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON TABLE medcea.mqtt_service_credential FROM PUBLIC, anon, authenticator;
-- topic: <root>/<unit|+>/<zone|+>/<sense|control|control_setpoint>/# — the root's
-- shape is PROJECT_NAME's (^[a-z][a-z0-9-]{1,30}$); a trigger compares the value
-- with medcea.platform_setting.mqtt_topic_root.
CREATE TABLE IF NOT EXISTS medcea.mqtt_service_acl (
    acl_id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username        text NOT NULL REFERENCES medcea.mqtt_service_credential(username) ON DELETE CASCADE,
    access          text NOT NULL CONSTRAINT mqtt_service_acl_access_chk CHECK (access IN ('read', 'write')),
    topic           text NOT NULL CONSTRAINT mqtt_service_acl_topic_chk
                    CHECK (topic ~ '^[a-z][a-z0-9-]{1,30}/(\+|[A-Za-z0-9_-]+)/(\+|[A-Za-z0-9_-]+)/(sense|control|control_setpoint)/#$')
);
REVOKE ALL ON TABLE medcea.mqtt_service_acl FROM PUBLIC, anon, authenticator;
REVOKE ALL ON SEQUENCE medcea.mqtt_service_acl_acl_id_seq FROM PUBLIC, anon, authenticator;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.mqtt_credential'::regclass AND attname = 'serial_number' AND NOT attisdropped) THEN
        ALTER TABLE medcea.mqtt_credential ADD COLUMN serial_number text;
    END IF;
END $$;
UPDATE medcea.mqtt_credential c SET serial_number = d.serial_number
  FROM medcea.device d WHERE d.device_id = c.device_id AND c.serial_number IS NULL;

-- ── B14. measurement.zone_id, stamped at insert ─────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                    WHERE attrelid = 'medcea.measurement'::regclass AND attname = 'zone_id' AND NOT attisdropped) THEN
        ALTER TABLE medcea.measurement ADD COLUMN zone_id integer;
    END IF;
END $$;
COMMENT ON COLUMN medcea.measurement.zone_id IS 'The zone of the board that sent the row, stamped at insert by measurement_zone_trg (a later move does not move history). No foreign key; NULL for unregistered boards (cea-un-*).';

-- ── B11. Append-only enforcement ────────────────────────────────────────────
CREATE OR REPLACE FUNCTION medcea.refuse_change() RETURNS trigger
    LANGUAGE plpgsql SET search_path = medcea, pg_temp AS $$
BEGIN
    RAISE EXCEPTION '%.% is append-only: % refused', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END $$;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['approval', 'pending_change', 'run_release', 'algorithm_state_event', 'row_change',
                             'device_slot_history'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = pg_catalog.to_regclass('medcea.' || t)
                                                             AND tgname = t || '_append_only') THEN
            EXECUTE pg_catalog.format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON medcea.%I '
                                      'FOR EACH ROW EXECUTE FUNCTION medcea.refuse_change()', t || '_append_only', t);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = pg_catalog.to_regclass('medcea.' || t)
                                                             AND tgname = t || '_no_truncate') THEN
            EXECUTE pg_catalog.format('CREATE TRIGGER %I BEFORE TRUNCATE ON medcea.%I '
                                      'FOR EACH STATEMENT EXECUTE FUNCTION medcea.refuse_change()', t || '_no_truncate', t);
        END IF;
    END LOOP;
END $$;

-- ── B16. append_history (actor from request_actor) and log_export ────────────
-- The hash and history_record() are unchanged. actor_sub is a uuid column: it
-- holds the sub only when the actor is a person's account; system:, migration:
-- and db:<login> actors are named in actor_name (008a's mapping for db:).
-- From 008c on this body is iam_policy._append_history and append_history is
-- 008c's filter in front of it: re-created here only while 008c is absent, so a
-- re-run never opens the policy events to iam_svc between the two transactions.
SELECT pg_catalog.to_regprocedure('iam_policy._append_history(text,jsonb,text)') IS NULL AS b16_writer \gset
\if :b16_writer
CREATE OR REPLACE FUNCTION iam_policy.append_history(p_event text, p_payload jsonb, p_reason text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam_policy, pg_temp AS $$
DECLARE
    v_id      bigint;
    v_at      timestamptz := now();
    a         record;
    v_sub     uuid;
    v_person  text;
    v_name    text;
    v_version int;
    v_prev    text;
BEGIN
    IF coalesce(btrim(p_event), '') = '' THEN
        RAISE EXCEPTION 'append_history: event is required';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'append_history needs READ COMMITTED (is %): a transaction snapshot could miss the head',
            current_setting('transaction_isolation');
    END IF;
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        v_name := 'db:' || session_user;
    ELSIF a.sub ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        v_sub := a.sub::uuid; v_person := a.person; v_name := a.name;
    ELSE
        v_person := a.person; v_name := a.sub;
    END IF;
    p_payload := coalesce(p_payload, '{}'::jsonb);
    IF jsonb_typeof(p_payload -> 'version') = 'number' THEN
        v_version := (p_payload ->> 'version')::int;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('iam_policy.history'));
    SELECT h.hash INTO v_prev FROM iam_policy.history h ORDER BY h.event_id DESC LIMIT 1;
    v_prev := coalesce(v_prev, repeat('0', 64));
    v_id := nextval(pg_get_serial_sequence('iam_policy.history', 'event_id'));
    INSERT INTO iam_policy.history
        (event_id, at, actor_sub, actor_person, actor_name, event, version, reason, payload, prev_hash, hash)
    VALUES (v_id, v_at, v_sub, v_person, v_name, p_event, v_version, p_reason, p_payload, v_prev,
            encode(sha256(convert_to(iam_policy.history_record(
                v_id, v_at, v_sub, v_person, v_name, p_event, v_version, p_reason, p_payload, v_prev), 'UTF8')), 'hex'));
    RETURN v_id;
END $$;
\endif

-- log_export(groups, objects): one row per Database Management export (2.6).
CREATE OR REPLACE FUNCTION iam_policy.log_export(p_groups text[], p_objects text[]) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam_policy, pg_temp AS $$
DECLARE
    a      record;
    v_sub  uuid;
    v_id   bigint;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        RAISE EXCEPTION 'log_export: no actor; call medcea_auth.set_actor() first' USING ERRCODE = '42501';
    END IF;
    IF a.sub ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        v_sub := a.sub::uuid;
    END IF;
    INSERT INTO iam_policy.export_log (actor_sub, actor_person, actor_name, groups, objects)
    VALUES (v_sub, a.person, CASE WHEN v_sub IS NULL THEN a.sub ELSE a.name END, p_groups, p_objects)
    RETURNING export_id INTO v_id;
    RETURN v_id;
END $$;

-- ── B15. Zone and unit assignments are audited in the hash chain ────────────
CREATE OR REPLACE FUNCTION iam_policy.log_user_zone() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam_policy, pg_temp AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'UPDATE') THEN
        PERFORM iam_policy.append_history('zone_removed',
            jsonb_build_object('person_sub', OLD.person_sub, 'zone_id', OLD.zone_id), NULL);
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        PERFORM iam_policy.append_history('zone_assigned',
            jsonb_build_object('person_sub', NEW.person_sub, 'zone_id', NEW.zone_id), NULL);
    END IF;
    RETURN NULL;
END $$;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'iam_policy.user_zone'::regclass
                                                         AND tgname = 'user_zone_audit_trg') THEN
        CREATE TRIGGER user_zone_audit_trg AFTER INSERT OR UPDATE OR DELETE ON iam_policy.user_zone
            FOR EACH ROW EXECUTE FUNCTION iam_policy.log_user_zone();
    END IF;
END $$;

-- IAM 2.8: operators are assigned units (own_unit), every zone of a unit
-- included. user_zone above stays, unused: the history names it. Written only
-- by iam.confirm_decision() (a qa-confirmed assignment is inserted),
-- iam.refuse_decision() (a refused one in effect before the check is removed) and
-- apps/iam/units.sh (as postgres: remove, and assign --bootstrap);
-- iam_policy.propose_unit() follows in 4.3. The FK keeps the default RESTRICT: deleting a unit
-- that is still assigned fails (23503) rather than drop an assignment without
-- an account decision.
CREATE TABLE IF NOT EXISTS iam_policy.user_unit (
    person_sub  uuid,
    unit_id     int REFERENCES medcea.cea_unit,
    PRIMARY KEY (person_sub, unit_id)
);
REVOKE ALL ON iam_policy.user_unit FROM PUBLIC, anon, authenticator;
-- (composite key: no sequence; ownership: the 008b normalisation below)

CREATE OR REPLACE FUNCTION iam_policy.log_user_unit() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam_policy, pg_temp AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'UPDATE') THEN
        PERFORM iam_policy.append_history('unit_removed',
            jsonb_build_object('person_sub', OLD.person_sub, 'unit_id', OLD.unit_id), NULL);
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        PERFORM iam_policy.append_history('unit_assigned',
            jsonb_build_object('person_sub', NEW.person_sub, 'unit_id', NEW.unit_id), NULL);
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION iam_policy.log_user_unit() FROM PUBLIC;
-- ENABLE ALWAYS: an assignment is audited under session_replication_role=replica too.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'iam_policy.user_unit'::regclass
                                                         AND tgname = 'user_unit_audit_trg') THEN
        CREATE TRIGGER user_unit_audit_trg AFTER INSERT OR UPDATE OR DELETE ON iam_policy.user_unit
            FOR EACH ROW EXECUTE FUNCTION iam_policy.log_user_unit();
    END IF;
    IF (SELECT tgenabled FROM pg_catalog.pg_trigger WHERE tgrelid = 'iam_policy.user_unit'::regclass
                                                      AND tgname = 'user_unit_audit_trg') <> 'A' THEN
        ALTER TABLE iam_policy.user_unit ENABLE ALWAYS TRIGGER user_unit_audit_trg;
    END IF;
END $$;

-- ── B17. Stamping, the change log and the always-on guards ──────────────────

-- stamp_actor(): created_by_* / updated_by_* from the verified actor; client
-- values are always overwritten. Without an actor: db:<login>, or — while
-- IAM_DB_ROLES=true, for anyone but a superuser — a refusal.
CREATE OR REPLACE FUNCTION medcea.stamp_actor() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    a   record;
    ow  boolean;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        IF medcea_auth.enforcing()
           AND NOT coalesce((SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user), false) THEN
            RAISE EXCEPTION 'no actor: call set_actor() first' USING ERRCODE = '42501';
        END IF;
        a.sub := 'db:' || session_user; a.person := NULL; a.name := session_user::text; a.role := NULL; a.source := 'db';
    END IF;
    ow := medcea_auth._is_owner_write();
    IF TG_OP = 'INSERT' THEN
        NEW.created_by_sub := a.sub; NEW.created_by_person := a.person; NEW.created_by_name := a.name;
        NEW.created_by_role := a.role; NEW.created_by_source := a.source;
        NEW.updated_by_sub := a.sub; NEW.updated_by_person := a.person; NEW.updated_by_name := a.name;
        NEW.updated_by_role := a.role; NEW.updated_by_source := a.source;
        IF TG_TABLE_NAME = 'recipe_run' AND NOT ow THEN
            NEW.executed_by_sub := NULL; NEW.executed_by_person := NULL; NEW.executed_by_name := NULL;
            NEW.executed_by_role := NULL; NEW.executed_by_source := NULL;
        END IF;
        RETURN NEW;
    END IF;
    NEW.created_by_sub := OLD.created_by_sub; NEW.created_by_person := OLD.created_by_person;
    NEW.created_by_name := OLD.created_by_name; NEW.created_by_role := OLD.created_by_role;
    NEW.created_by_source := OLD.created_by_source;
    IF ow AND medcea_auth._content(to_jsonb(OLD), true) = medcea_auth._content(to_jsonb(NEW), true) THEN
        -- an owner write of status / retired_at only (approve, retire): the last
        -- editor stays the last editor
        NEW.updated_by_sub := OLD.updated_by_sub; NEW.updated_by_person := OLD.updated_by_person;
        NEW.updated_by_name := OLD.updated_by_name; NEW.updated_by_role := OLD.updated_by_role;
        NEW.updated_by_source := OLD.updated_by_source;
    ELSE
        NEW.updated_by_sub := a.sub; NEW.updated_by_person := a.person; NEW.updated_by_name := a.name;
        NEW.updated_by_role := a.role; NEW.updated_by_source := a.source;
    END IF;
    IF TG_TABLE_NAME = 'recipe_run' AND NOT ow THEN
        NEW.executed_by_sub := OLD.executed_by_sub; NEW.executed_by_person := OLD.executed_by_person;
        NEW.executed_by_name := OLD.executed_by_name; NEW.executed_by_role := OLD.executed_by_role;
        NEW.executed_by_source := OLD.executed_by_source;
    END IF;
    RETURN NEW;
END $$;

-- log_row_change(pk columns...): AFTER trigger; one medcea.row_change row per
-- change with the changed columns only (stamps and timestamps left out).
CREATE OR REPLACE FUNCTION medcea.log_row_change() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    a    record;
    o    jsonb;
    n    jsonb;
    ov   jsonb;
    nv   jsonb;
    src  jsonb;
    k    jsonb := '[]'::jsonb;
    i    integer;
BEGIN
    IF TG_OP <> 'INSERT' THEN o := medcea_auth._content(to_jsonb(OLD), false); END IF;
    IF TG_OP <> 'DELETE' THEN n := medcea_auth._content(to_jsonb(NEW), false); END IF;
    src := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
    FOR i IN 0 .. TG_NARGS - 1 LOOP
        k := k || jsonb_build_array(src -> TG_ARGV[i]);
    END LOOP;
    IF TG_OP = 'UPDATE' THEN
        SELECT jsonb_object_agg(x.key, o -> x.key), jsonb_object_agg(x.key, x.value) INTO ov, nv
          FROM jsonb_each(n) x WHERE (o -> x.key) IS DISTINCT FROM x.value;
        IF nv IS NULL THEN
            RETURN NULL;            -- nothing but stamps or timestamps changed
        END IF;
    ELSIF TG_OP = 'INSERT' THEN
        nv := n;
    ELSE
        ov := o;
    END IF;
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        a.sub := 'db:' || session_user; a.person := NULL; a.name := session_user::text; a.role := NULL; a.source := 'db';
    END IF;
    INSERT INTO medcea.row_change (target, row_key, op, old_values, new_values,
                                   actor_sub, actor_person, actor_name, actor_role, actor_source)
    VALUES (TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, k, left(TG_OP, 1), ov, nv,
            a.sub, a.person, a.name, a.role, a.source);
    RETURN NULL;
END $$;

-- guard_control_columns(): SECURITY INVOKER, so current_user is the writer
-- (medcea_owner inside an owner function). For anyone but the owner:
--   status    a new row is a draft; nobody sets 'approved' or leaves 'retired'
--             by hand; approved -> retired alone is allowed; any other content
--             change of an approved row demotes it to draft (a WARNING) — and a
--             recipe line change demotes its recipe (OLD and NEW parent);
--   control   cea_unit.commissioning, schedule.retired_at and recipe_run.params_id
--             (after insert) change only through functions (a retired schedule
--             not at all: schedule_retired_guard()); recipe_unit_permission
--             and schedule params_id too while the database setting
--             medcea.iam_db_roles is not 'true' (in enforce, assign_only and
--             start_run check what they point to).
-- It calls no function: the writer (anon, today) executes nothing in medcea.
CREATE OR REPLACE FUNCTION medcea.guard_control_columns() RETURNS trigger
    LANGUAGE plpgsql SET search_path = medcea, pg_temp AS $$
DECLARE
    changed  boolean;
    demoted  text;
    old_id   integer;
    new_id   integer;
    enforce  boolean := coalesce(current_setting('medcea.iam_db_roles', true), '') = 'true';
BEGIN
    IF current_user = 'medcea_owner' THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'recipe_line' THEN
        IF TG_OP = 'UPDATE' THEN
            changed := (SELECT jsonb_object_agg(k, v) FROM jsonb_each(to_jsonb(OLD)) x(k, v)
                         WHERE NOT (k LIKE '%\_by\_%' OR k LIKE 'timestamp\_%'))
                       IS DISTINCT FROM
                       (SELECT jsonb_object_agg(k, v) FROM jsonb_each(to_jsonb(NEW)) x(k, v)
                         WHERE NOT (k LIKE '%\_by\_%' OR k LIKE 'timestamp\_%'));
        ELSE
            changed := true;
        END IF;
        IF TG_OP <> 'INSERT' THEN old_id := OLD.recipe_id; END IF;
        IF TG_OP <> 'DELETE' THEN new_id := NEW.recipe_id; END IF;
        -- Serialise with _approve_definition(), which holds the recipe FOR
        -- UPDATE: a line edit waits for an approval in progress (and then
        -- demotes), or the approval waits for it. NO KEY UPDATE, the mode the
        -- demoting UPDATE below needs anyway, so two line writers queue
        -- instead of deadlocking on a lock upgrade; in id order for a move.
        PERFORM 1 FROM medcea.recipe r WHERE r.recipe_id IN (old_id, new_id)
         ORDER BY r.recipe_id FOR NO KEY UPDATE;
        IF changed THEN
            WITH d AS (
                UPDATE medcea.recipe r SET status = 'draft'
                 WHERE r.status = 'approved' AND r.recipe_id IN (old_id, new_id)
                RETURNING r.recipe_id)
            SELECT string_agg(recipe_id::text, ', ') INTO demoted FROM d;
            IF demoted IS NOT NULL THEN
                RAISE WARNING 'recipe % was approved and is now a draft: its lines changed after the approval', demoted;
            END IF;
        END IF;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;

    IF TG_TABLE_NAME IN ('recipe', 'control_algorithm', 'unit_algorithm_params') THEN
        IF TG_OP = 'INSERT' THEN
            IF NEW.status IS DISTINCT FROM 'draft' THEN
                RAISE EXCEPTION 'a new %.% starts as a draft; approval goes through its approval function', TG_TABLE_SCHEMA, TG_TABLE_NAME
                    USING ERRCODE = '42501';
            END IF;
        ELSE
            IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status = 'approved' THEN
                RAISE EXCEPTION '%.%: status approved is set by its approval function only', TG_TABLE_SCHEMA, TG_TABLE_NAME
                    USING ERRCODE = '42501';
            END IF;
            IF NEW.status IS DISTINCT FROM OLD.status AND OLD.status = 'retired' THEN
                RAISE EXCEPTION '%.%: a retired row stays retired; create a new draft', TG_TABLE_SCHEMA, TG_TABLE_NAME
                    USING ERRCODE = '42501';
            END IF;
            IF OLD.status = 'approved' THEN
                changed := (SELECT jsonb_object_agg(k, v) FROM jsonb_each(to_jsonb(OLD)) x(k, v)
                             WHERE NOT (k LIKE '%\_by\_%' OR k LIKE 'timestamp\_%' OR k IN ('status', 'retired_at')))
                           IS DISTINCT FROM
                           (SELECT jsonb_object_agg(k, v) FROM jsonb_each(to_jsonb(NEW)) x(k, v)
                             WHERE NOT (k LIKE '%\_by\_%' OR k LIKE 'timestamp\_%' OR k IN ('status', 'retired_at')));
                IF changed THEN
                    NEW.status := 'draft';
                    RAISE WARNING '%.% was approved and is now a draft: it changed after the approval', TG_TABLE_SCHEMA, TG_TABLE_NAME;
                END IF;
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_TABLE_NAME = 'cea_unit' THEN
        IF (TG_OP = 'INSERT' AND NEW.commissioning)
           OR (TG_OP = 'UPDATE' AND NEW.commissioning IS DISTINCT FROM OLD.commissioning) THEN
            RAISE EXCEPTION 'cea_unit.commissioning changes only through medcea.propose_commissioning() and approve_change()'
                USING ERRCODE = '42501';
        END IF;
    ELSIF TG_TABLE_NAME = 'schedule' THEN
        -- a retired schedule is never edited: schedule_retired_guard() below (its
        -- own trigger, so a reverted migration file cannot take it away)
        IF (TG_OP = 'INSERT' AND NEW.retired_at IS NOT NULL)
           OR (TG_OP = 'UPDATE' AND NEW.retired_at IS DISTINCT FROM OLD.retired_at) THEN
            RAISE EXCEPTION 'schedule.retired_at is set by a function only' USING ERRCODE = '42501';
        END IF;
        IF NOT enforce AND ((TG_OP = 'INSERT' AND NEW.params_id IS NOT NULL)
                            OR (TG_OP = 'UPDATE' AND NEW.params_id IS DISTINCT FROM OLD.params_id)) THEN
            RAISE EXCEPTION 'schedule.params_id is set by migration 008b only while IAM_DB_ROLES=false' USING ERRCODE = '42501';
        END IF;
    ELSIF TG_TABLE_NAME = 'recipe_unit_permission' THEN
        IF NOT enforce AND ((TG_OP = 'INSERT' AND NEW.params_id IS NOT NULL)
                            OR (TG_OP = 'UPDATE' AND NEW.params_id IS DISTINCT FROM OLD.params_id)) THEN
            RAISE EXCEPTION 'recipe_unit_permission.params_id is set by migration 008b only while IAM_DB_ROLES=false'
                USING ERRCODE = '42501';
        END IF;
    ELSIF TG_TABLE_NAME = 'recipe_run' THEN
        IF TG_OP = 'UPDATE' AND NEW.params_id IS DISTINCT FROM OLD.params_id THEN
            RAISE EXCEPTION 'recipe_run.params_id is fixed when the run is created' USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- log_device_slot(): migration 006's body, plus who did it.
CREATE OR REPLACE FUNCTION medcea.log_device_slot() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    ev varchar(10);
    a  record;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        a.sub := 'db:' || session_user; a.person := NULL; a.name := session_user::text; a.role := NULL; a.source := 'db';
    END IF;
    IF TG_OP = 'INSERT' THEN
        INSERT INTO medcea.device_slot_history
            (device_id, event, serial_number, to_zone_id, to_device_type, to_dns_name,
             changed_by_sub, changed_by_person, changed_by_name, changed_by_role, changed_by_source)
        VALUES (NEW.device_id, 'placed', NEW.serial_number, NEW.zone_id, NEW.device_type, NEW.dns_name,
                a.sub, a.person, a.name, a.role, a.source);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO medcea.device_slot_history
            (device_id, event, serial_number, from_zone_id, from_device_type, from_dns_name,
             changed_by_sub, changed_by_person, changed_by_name, changed_by_role, changed_by_source)
        VALUES (OLD.device_id, 'removed', OLD.serial_number, OLD.zone_id, OLD.device_type, OLD.dns_name,
                a.sub, a.person, a.name, a.role, a.source);
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
         to_zone_id, to_device_type, to_dns_name,
         changed_by_sub, changed_by_person, changed_by_name, changed_by_role, changed_by_source)
    VALUES (NEW.device_id, ev, NEW.serial_number, OLD.serial_number,
            OLD.zone_id, OLD.device_type, OLD.dns_name,
            NEW.zone_id, NEW.device_type, NEW.dns_name,
            a.sub, a.person, a.name, a.role, a.source);
    RETURN NEW;
END $$;

-- measurement.zone_id from the board's slot at insert; a client value is overwritten.
CREATE OR REPLACE FUNCTION medcea.stamp_measurement_zone() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE z integer;
BEGIN
    SELECT d.zone_id INTO z FROM medcea.device d WHERE d.serial_number = NEW.device_id;
    IF NOT FOUND THEN
        SELECT d.zone_id INTO z FROM medcea.device d WHERE d.dns_name = NEW.device_dns;
    END IF;
    NEW.zone_id := z;
    RETURN NEW;
END $$;

-- A board's credential dies with a real serial change of its device row.
CREATE OR REPLACE FUNCTION medcea.device_serial_change() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    UPDATE medcea.mqtt_credential SET active = false, updated_at = now()
     WHERE device_id = NEW.device_id AND active;
    RETURN NULL;
END $$;

-- The first segment of a person credential's topic is the platform's root.
CREATE OR REPLACE FUNCTION medcea.mqtt_service_acl_root() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE root text;
BEGIN
    SELECT s.value INTO root FROM medcea.platform_setting s WHERE s.key = 'mqtt_topic_root';
    IF root IS NULL OR split_part(NEW.topic, '/', 1) <> root THEN
        RAISE EXCEPTION 'topic % is not under the platform root %/', NEW.topic, coalesce(root, '<unset>')
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;

-- Q-tables: every write is an event (hash only), retire/delete keep the state.
CREATE OR REPLACE FUNCTION medcea.log_algorithm_state() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    a    record;
    ev   text;
    r    medcea.algorithm_state;
    run  integer;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.ref_kind = 'run' THEN run := a.ref_id; END IF;
    IF TG_OP = 'INSERT' THEN
        ev := 'created'; r := NEW;
    ELSIF TG_OP = 'DELETE' THEN
        ev := 'deleted'; r := OLD;
    ELSIF OLD.retired_at IS NULL AND NEW.retired_at IS NOT NULL THEN
        ev := 'retired'; r := NEW;
    ELSIF OLD.retired_at IS NOT NULL AND NEW.retired_at IS NULL THEN
        ev := 'unretired'; r := NEW;
    ELSIF NEW.state IS DISTINCT FROM OLD.state THEN
        ev := 'updated'; r := NEW;
    ELSE
        RETURN NULL;
    END IF;
    INSERT INTO medcea.algorithm_state_event
        (event, unit_id, algorithm, channel, recipe_run_id, state_sha256, state, reason,
         actor_sub, actor_person, actor_role, actor_source)
    VALUES (ev, r.unit_id, r.algorithm, r.channel, run,
            encode(sha256(convert_to(coalesce(r.state, '{}'::jsonb)::text, 'UTF8')), 'hex'),
            CASE WHEN ev IN ('retired', 'deleted') THEN r.state END,
            nullif(current_setting('medcea.state_reason', true), ''),
            coalesce(a.sub, 'db:' || session_user), a.person, a.role, coalesce(a.source, 'db'));
    RETURN NULL;
END $$;

-- A new Q-table state clears a retirement (logged as unretired); only the
-- owner (retire_algorithm_state) sets it.
CREATE OR REPLACE FUNCTION medcea.algorithm_state_before() RETURNS trigger
    LANGUAGE plpgsql SET search_path = medcea, pg_temp AS $$
BEGIN
    IF current_user <> 'medcea_owner' AND NEW.state IS DISTINCT FROM OLD.state THEN
        NEW.retired_at := NULL;
    END IF;
    RETURN NEW;
END $$;

-- Attach the always-on triggers (guarded: a steady-state deploy takes no lock).
DO $$
DECLARE
    t     text;
    pk    text;
    spec  text[][] := ARRAY[
        ['cea_location', 'location_id'], ['cea_unit', 'unit_id'], ['cea_zone', 'zone_id'],
        ['component', 'component_id'], ['device', 'device_id'], ['recipe', 'recipe_id'],
        ['recipe_line', 'recipe_id, recipe_item_seq_id'], ['recipe_unit_permission', 'recipe_id, unit_id'],
        ['control_algorithm', 'algorithm_id'], ['unit_algorithm_params', 'params_id'],
        ['schedule', 'schedule_id'], ['scheduler_config', 'key'], ['recipe_run', 'recipe_run_id'],
        ['recipe_line_cycle_run', 'recipe_line_cycle_run_id']];
    i     integer;
    args  text;
BEGIN
    FOR i IN 1 .. array_length(spec, 1) LOOP
        t := spec[i][1]; pk := spec[i][2];
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = pg_catalog.to_regclass('medcea.' || t)
                                                             AND tgname = 'stamp_actor_trg') THEN
            EXECUTE pg_catalog.format('CREATE TRIGGER stamp_actor_trg BEFORE INSERT OR UPDATE ON medcea.%I '
                                      'FOR EACH ROW EXECUTE FUNCTION medcea.stamp_actor()', t);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = pg_catalog.to_regclass('medcea.' || t)
                                                             AND tgname = 'row_change_trg') THEN
            SELECT string_agg(pg_catalog.quote_literal(btrim(x)), ', ') INTO args
              FROM unnest(string_to_array(pk, ',')) x;
            EXECUTE pg_catalog.format('CREATE TRIGGER row_change_trg AFTER INSERT OR UPDATE OR DELETE ON medcea.%I '
                                      'FOR EACH ROW EXECUTE FUNCTION medcea.log_row_change(%s)', t, args);
        END IF;
    END LOOP;
    FOREACH t IN ARRAY ARRAY['recipe', 'control_algorithm', 'unit_algorithm_params', 'cea_unit', 'schedule',
                             'recipe_unit_permission', 'recipe_run'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = pg_catalog.to_regclass('medcea.' || t)
                                                             AND tgname = 'status_guard_trg') THEN
            EXECUTE pg_catalog.format('CREATE TRIGGER status_guard_trg BEFORE INSERT OR UPDATE ON medcea.%I '
                                      'FOR EACH ROW EXECUTE FUNCTION medcea.guard_control_columns()', t);
        END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.recipe_line'::regclass
                                                         AND tgname = 'status_guard_trg') THEN
        CREATE TRIGGER status_guard_trg BEFORE INSERT OR UPDATE OR DELETE ON medcea.recipe_line
            FOR EACH ROW EXECUTE FUNCTION medcea.guard_control_columns();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.measurement'::regclass
                                                         AND tgname = 'measurement_zone_trg') THEN
        CREATE TRIGGER measurement_zone_trg BEFORE INSERT ON medcea.measurement
            FOR EACH ROW EXECUTE FUNCTION medcea.stamp_measurement_zone();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.device'::regclass
                                                         AND tgname = 'device_serial_change_trg') THEN
        CREATE TRIGGER device_serial_change_trg AFTER UPDATE OF serial_number ON medcea.device
            FOR EACH ROW WHEN (OLD.serial_number IS DISTINCT FROM NEW.serial_number)
            EXECUTE FUNCTION medcea.device_serial_change();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.mqtt_service_acl'::regclass
                                                         AND tgname = 'mqtt_service_acl_root_trg') THEN
        CREATE TRIGGER mqtt_service_acl_root_trg BEFORE INSERT OR UPDATE ON medcea.mqtt_service_acl
            FOR EACH ROW EXECUTE FUNCTION medcea.mqtt_service_acl_root();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.algorithm_state'::regclass
                                                         AND tgname = 'algorithm_state_event_trg') THEN
        CREATE TRIGGER algorithm_state_event_trg AFTER INSERT OR UPDATE OR DELETE ON medcea.algorithm_state
            FOR EACH ROW EXECUTE FUNCTION medcea.log_algorithm_state();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.algorithm_state'::regclass
                                                         AND tgname = 'algorithm_state_before_trg') THEN
        CREATE TRIGGER algorithm_state_before_trg BEFORE UPDATE ON medcea.algorithm_state
            FOR EACH ROW EXECUTE FUNCTION medcea.algorithm_state_before();
    END IF;
END $$;

-- schedule_retired_guard(): a retired schedule is history. Nobody but the owner
-- (retire_schedule() itself) updates it, so a scheduler that does not know about
-- retirement (the code before 2.4, after a revert) cannot re-enable one, edit it
-- or make it fire again. Its own function and trigger, never folded into
-- guard_control_columns(): the migration file before 2.4 re-creates that
-- function on every deploy and would drop the check with it; it never touches
-- this one. SECURITY INVOKER (current_user is the writer), calls no function,
-- ENABLE ALWAYS (session_replication_role does not bypass it). The full down
-- (medcea_db_migrations_down_008b.sql -v full=1) drops both.
CREATE OR REPLACE FUNCTION medcea.schedule_retired_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = medcea, pg_temp AS $$
BEGIN
    IF current_user = 'medcea_owner' THEN
        RETURN NEW;
    END IF;
    IF OLD.retired_at IS NOT NULL THEN
        RAISE EXCEPTION 'schedule % is retired', OLD.schedule_id USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.schedule'::regclass
                                                         AND tgname = 'schedule_retired_guard_trg') THEN
        CREATE TRIGGER schedule_retired_guard_trg BEFORE UPDATE ON medcea.schedule
            FOR EACH ROW EXECUTE FUNCTION medcea.schedule_retired_guard();
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.schedule'::regclass
                                                     AND tgname = 'schedule_retired_guard_trg' AND tgenabled <> 'A') THEN
        ALTER TABLE medcea.schedule ENABLE ALWAYS TRIGGER schedule_retired_guard_trg;
    END IF;
END $$;

-- Append-only triggers fire in replica mode too (session_replication_role
-- does not bypass them), including 008a's on the policy history.
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT t.tgrelid::regclass AS rel, t.tgname FROM pg_catalog.pg_trigger t
              WHERE NOT t.tgisinternal AND t.tgenabled <> 'A'
                AND (t.tgname LIKE '%\_append\_only' OR t.tgname LIKE '%\_no\_truncate')
                AND t.tgrelid IN (SELECT c.oid FROM pg_catalog.pg_class c
                                   WHERE c.relnamespace IN ('medcea'::regnamespace, 'iam_policy'::regnamespace)) LOOP
        EXECUTE pg_catalog.format('ALTER TABLE %s ENABLE ALWAYS TRIGGER %I', r.rel, r.tgname);
    END LOOP;
END $$;

-- ── B4 (listing). Schedules nobody can trigger runs from once IAM_DB_ROLES=true ─
-- The predicate is set_system_actor()'s own: no person created the schedule
-- (migration:008, or db:<login> — written without an actor, e.g. by the scheduler
-- before 2.4 or without a verified person under false) and its last editor is not
-- a verified person (source token or 'person via …') who holds C on runs freely.
-- Before grants.py has compiled policy_holds() (a first deploy) its stub answers
-- NULL, so every person-less schedule is listed: over-reporting, never under.
DO $$
DECLARE l text;
BEGIN
    SELECT string_agg(pg_catalog.format('%s (%s)', schedule_id, coalesce(created_by_sub, '?')), ', ' ORDER BY schedule_id)
      INTO l FROM medcea.schedule
     WHERE created_by_person IS NULL AND retired_at IS NULL
       AND NOT (updated_by_person IS NOT NULL
                AND (updated_by_source = 'token' OR updated_by_source LIKE 'person via %')
                AND medcea_auth.policy_holds(updated_by_role, 'runs', 'C') IS NOT DISTINCT FROM 'free');
    IF l IS NOT NULL THEN
        RAISE WARNING 'schedules with no person behind them (migration:008 or db:<login>): % — once IAM_DB_ROLES=true no run is triggered from them (set_system_actor) until a person who holds C on runs (a production manager) re-saves them', l;
    END IF;
END $$;

-- ── B18. Unit and zone codes are topic segments ─────────────────────────────
-- Added (valid at once) only when no code violates it; until then the
-- violators are listed on every deploy and stay editable, so they can be renamed.
DO $$
DECLARE l text;
BEGIN
    SELECT string_agg(pg_catalog.format('%s (unit %s)', unit_code, unit_id), ', ') INTO l
      FROM medcea.cea_unit WHERE unit_code !~ '^[A-Za-z0-9_-]+$';
    IF l IS NOT NULL THEN
        RAISE WARNING 'unit codes that cannot be MQTT topic segments (want [A-Za-z0-9_-]): % — rename them in the Units tab; cea_unit_code_chk is added once none is left', l;
    ELSIF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid = 'medcea.cea_unit'::regclass
                                                             AND conname = 'cea_unit_code_chk') THEN
        ALTER TABLE medcea.cea_unit ADD CONSTRAINT cea_unit_code_chk CHECK (unit_code ~ '^[A-Za-z0-9_-]+$');
    END IF;
    SELECT string_agg(pg_catalog.format('%s (zone %s)', zone_code, zone_id), ', ') INTO l
      FROM medcea.cea_zone WHERE zone_code !~ '^[A-Za-z0-9_-]+$';
    IF l IS NOT NULL THEN
        RAISE WARNING 'zone codes that cannot be MQTT topic segments (want [A-Za-z0-9_-]): % — rename them in the Units tab; cea_zone_code_chk is added once none is left', l;
    ELSIF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid = 'medcea.cea_zone'::regclass
                                                             AND conname = 'cea_zone_code_chk') THEN
        ALTER TABLE medcea.cea_zone ADD CONSTRAINT cea_zone_code_chk CHECK (zone_code ~ '^[A-Za-z0-9_-]+$');
    END IF;
END $$;

-- ── B19. Views run with the reader's rights (and RLS) ───────────────────────
DO $$
DECLARE v text;
BEGIN
    FOREACH v IN ARRAY ARRAY['msg_actual_points', 'msg_set_points', 'msg_controls', 'v_ap_measurements',
                             'v_sp_measurements', 'v_ct_measurements', 'run_history', 'run_watch'] LOOP
        IF pg_catalog.to_regclass('medcea.' || v) IS NOT NULL
           AND NOT coalesce((SELECT 'security_invoker=true' = ANY (c.reloptions) FROM pg_catalog.pg_class c
                              WHERE c.oid = pg_catalog.to_regclass('medcea.' || v)), false) THEN
            EXECUTE pg_catalog.format('ALTER VIEW medcea.%I SET (security_invoker = true)', v);
        END IF;
    END LOOP;
END $$;

-- ── B20. Functions: approvals, runs, proposals, credentials, enforce triggers ─

-- _changes_since(target, key): the changes to the row (a recipe: and its lines;
-- a run: and its cycles) since its last approval, review or grandfathering — or
-- since creation — oldest first. authors is false for a change of
-- status/retired_at/commissioning alone (approving, retiring, a commissioning flag
-- applied under dual control): those make nobody an author. The one copy of the
-- "since the last approval" rule: _authors() and medcea.approval_queue() read it.
-- LANGUAGE sql: its output columns share row_change's names, which a PL/pgSQL
-- body would read as ambiguous.
--
-- "Since" is commit order: change_id > the approval's last_change_id. An
-- approval from before that column (NULL) falls back to its timestamp. The
-- approval functions lock the row (and its lines or cycles) first, so every change
-- made before the approval has committed and no later one can commit before it.
CREATE OR REPLACE FUNCTION medcea_auth._changes_since(p_target text, p_key jsonb)
RETURNS TABLE (change_id bigint, target text, row_key jsonb, op text, old_values jsonb, new_values jsonb,
               actor_sub text, actor_person text, actor_name text, actor_role text, actor_source text,
               at timestamptz, authors boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
    WITH s AS (
        SELECT ap.approved_at AS since, ap.last_change_id AS since_id FROM medcea.approval ap
         WHERE ap.target = p_target AND ap.row_key = p_key AND ap.action IN ('approve', 'review', 'grandfather')
         ORDER BY ap.approval_id DESC LIMIT 1),
    m AS (
        SELECT c.* FROM medcea.row_change c
         WHERE (c.target = p_target AND c.row_key = p_key)
            OR (p_target = 'medcea.recipe' AND c.target = 'medcea.recipe_line'
                AND (c.row_key -> 0 = p_key -> 0 OR c.old_values -> 'recipe_id' = p_key -> 0
                     OR c.new_values -> 'recipe_id' = p_key -> 0))
            OR (p_target = 'medcea.recipe_run' AND c.target = 'medcea.recipe_line_cycle_run'
                AND (c.row_key ->> 0)::bigint IN (SELECT x.recipe_line_cycle_run_id FROM medcea.recipe_line_cycle_run x
                                                   WHERE x.recipe_run_id = (p_key ->> 0)::integer)))
    SELECT m.change_id, m.target, m.row_key, m.op::text, m.old_values, m.new_values,
           m.actor_sub, m.actor_person, m.actor_name, m.actor_role::text, m.actor_source, m.at,
           NOT (m.op = 'U' AND (SELECT coalesce(bool_and(k IN ('status', 'retired_at', 'commissioning')), true)
                                  FROM jsonb_object_keys(coalesce(m.new_values, '{}'::jsonb)) k))
      FROM m LEFT JOIN s ON true
     WHERE CASE WHEN s.since_id IS NOT NULL THEN m.change_id > s.since_id
                ELSE s.since IS NULL OR m.at > s.since END
     ORDER BY m.change_id
$$;

-- _authors(target, key): the persons among _changes_since()'s authors, and how
-- many of those changes have no person (other than migration:008's). last_change
-- is the newest matching row_change, authoring or not; the caller stores it in
-- approval.last_change_id.
-- An _authors() without last_change (an earlier 2a build) cannot be replaced
-- in place: its result type changes. Callers are PL/pgSQL, so nothing depends on it.
DO $$
BEGIN
    IF pg_catalog.to_regprocedure('medcea_auth._authors(text, jsonb)') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc
                        WHERE oid = pg_catalog.to_regprocedure('medcea_auth._authors(text, jsonb)')
                          AND 'last_change' = ANY (proargnames)) THEN
        DROP FUNCTION medcea_auth._authors(text, jsonb);
    END IF;
END $$;
CREATE OR REPLACE FUNCTION medcea_auth._authors(p_target text, p_key jsonb,
    OUT persons text[], OUT unattributed integer, OUT last_change bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE
    since_id  bigint;
BEGIN
    SELECT ap.last_change_id INTO since_id FROM medcea.approval ap
     WHERE ap.target = p_target AND ap.row_key = p_key AND ap.action IN ('approve', 'review', 'grandfather')
     ORDER BY ap.approval_id DESC LIMIT 1;
    SELECT coalesce(array_agg(DISTINCT ch.actor_person) FILTER (WHERE ch.actor_person IS NOT NULL), '{}'),
           count(*) FILTER (WHERE ch.actor_person IS NULL AND coalesce(ch.actor_source, '') <> 'migration')
      INTO persons, unattributed
      FROM medcea_auth._changes_since(p_target, p_key) ch WHERE ch.authors;
    SELECT max(m2.change_id) INTO last_change FROM medcea.row_change m2
     WHERE (m2.target = p_target AND m2.row_key = p_key)
        OR (p_target = 'medcea.recipe' AND m2.target = 'medcea.recipe_line'
            AND (m2.row_key -> 0 = p_key -> 0 OR m2.old_values -> 'recipe_id' = p_key -> 0
                 OR m2.new_values -> 'recipe_id' = p_key -> 0))
        OR (p_target = 'medcea.recipe_run' AND m2.target = 'medcea.recipe_line_cycle_run'
            AND (m2.row_key ->> 0)::bigint IN (SELECT x.recipe_line_cycle_run_id FROM medcea.recipe_line_cycle_run x
                                                WHERE x.recipe_run_id = (p_key ->> 0)::integer));
    last_change := greatest(last_change, since_id);
END $$;

-- _lock_row(target, key): the approval functions' row locks, taken before
-- _authors(): the row itself FOR UPDATE, and a recipe's lines or a run's
-- cycles too (an UPDATE of a line that keeps recipe_id takes no lock on the
-- recipe). A writer that had already changed them is waited for; one that
-- comes later waits for the approval, and its row_change gets a higher id.
CREATE OR REPLACE FUNCTION medcea_auth._lock_row(p_target text, p_key jsonb) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE
    col  text := CASE p_target WHEN 'medcea.cea_location' THEN 'location_id' WHEN 'medcea.cea_unit' THEN 'unit_id'
                               WHEN 'medcea.cea_zone' THEN 'zone_id' WHEN 'medcea.component' THEN 'component_id'
                               WHEN 'medcea.device' THEN 'device_id' WHEN 'medcea.recipe' THEN 'recipe_id'
                               WHEN 'medcea.control_algorithm' THEN 'algorithm_id'
                               WHEN 'medcea.unit_algorithm_params' THEN 'params_id'
                               WHEN 'medcea.recipe_run' THEN 'recipe_run_id' END;
    found_it boolean;
BEGIN
    IF col IS NULL THEN
        RAISE EXCEPTION '_lock_row: % is not an approval target', p_target USING ERRCODE = '22023';
    END IF;
    EXECUTE pg_catalog.format('SELECT true FROM %s t WHERE t.%I = ($1 ->> 0)::integer FOR UPDATE',
                              pg_catalog.to_regclass(p_target), col)
       INTO found_it USING p_key;
    IF p_target = 'medcea.recipe' THEN
        PERFORM 1 FROM medcea.recipe_line l WHERE l.recipe_id = (p_key ->> 0)::integer
         ORDER BY l.recipe_item_seq_id FOR UPDATE;
    ELSIF p_target = 'medcea.recipe_run' THEN
        PERFORM 1 FROM medcea.recipe_line_cycle_run c WHERE c.recipe_run_id = (p_key ->> 0)::integer
         ORDER BY c.recipe_line_cycle_run_id FOR UPDATE;
    END IF;
    RETURN coalesce(found_it, false);
END $$;

-- _approver(group): the actor, if it may approve on the group: a person
-- signed in through PostgREST (source token) holding A there. Never a service
-- or system actor.
CREATE OR REPLACE FUNCTION medcea_auth._approver(p_group text,
    OUT sub text, OUT person text, OUT name text, OUT role text, OUT source text)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE a record;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.source IS DISTINCT FROM 'token' THEN
        RAISE EXCEPTION 'approvals are made by a person signed in through the API, not by %', coalesce(a.source, 'an unknown actor')
            USING ERRCODE = '42501';
    END IF;
    -- IAM 4.1 (G9): a blank person_id is no person, as _person_actor already says.
    IF a.person IS NULL OR btrim(a.person) = '' THEN
        RAISE EXCEPTION 'the approver''s token carries no person_id' USING ERRCODE = '42501';
    END IF;
    IF medcea_auth.policy_holds(a.role, p_group, 'A') IS NULL THEN
        RAISE EXCEPTION 'role % holds no approval on %', a.role, p_group USING ERRCODE = '42501';
    END IF;
    sub := a.sub; person := a.person; name := a.name; role := a.role; source := a.source;
END $$;

-- _person_actor(service, group, level): a person signed in to a UI whose
-- service called set_actor (source 'person via <service>'), whose token
-- carries a non-blank person_id and whose role holds the level on the group.
-- Never a system, migration, db:<login> or PostgREST actor. The one copy of
-- this rule: _account_actor (access_svc, IAM 2.7) and the policy author
-- functions (iam_svc, IAM 4.1) call it. SECURITY INVOKER: its callers are
-- definer functions owned by medcea_owner.
CREATE OR REPLACE FUNCTION medcea_auth._person_actor(p_service text, p_group text, p_level text,
    OUT sub text, OUT person text, OUT name text, OUT role text)
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE a record;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.source IS DISTINCT FROM 'person via ' || p_service THEN
        IF p_service = 'access_svc' THEN
            RAISE EXCEPTION 'account decisions are made in the User Manager by a signed-in person, not by %',
                coalesce(a.source, 'an unknown actor') USING ERRCODE = '42501';
        END IF;
        RAISE EXCEPTION 'policy changes are made in the Policy UI by a signed-in person, not by %',
            coalesce(a.source, 'an unknown actor') USING ERRCODE = '42501';
    END IF;
    IF a.person IS NULL OR btrim(a.person) = '' THEN
        RAISE EXCEPTION 'your token carries no person_id' USING ERRCODE = '42501';
    END IF;
    IF medcea_auth.policy_holds(a.role, p_group, p_level) IS NULL THEN
        RAISE EXCEPTION 'role % holds no % on %', a.role, p_level, p_group USING ERRCODE = '42501';
    END IF;
    sub := a.sub; person := a.person; name := a.name; role := a.role;
END $$;

-- _account_actor(group, level): the actor of an account decision (IAM 2.7): a
-- person signed in to the User Manager (set_actor by access_svc, so the source
-- is 'person via access_svc'). The iam.* decision functions
-- (apps/access/access_db.sql) and medcea.revoke_person_mqtt() call it; the rule
-- itself is _person_actor's (IAM 4.1).
CREATE OR REPLACE FUNCTION medcea_auth._account_actor(p_group text, p_level text,
    OUT sub text, OUT person text, OUT name text, OUT role text)
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    SELECT p.sub, p.person, p.name, p.role INTO sub, person, name, role
      FROM medcea_auth._person_actor('access_svc', p_group, p_level) p;
END $$;

-- revoke_person_mqtt(sub, reason): every MQTT person credential of an account
-- inactive (IAM 2.7, qa_dual_control): called by access-api in the transaction
-- of a deactivation or a pure narrowing, after iam.record_decision. The broker's
-- auth sidecar drops them at its next sync (~15 s). The credentials are the MQTT
-- Explorer's (iam-api, IAM 3.5); iam.confirm_decision ends them for a confirmed
-- role change. An owner definer: access_svc holds EXECUTE only and reads no credential.
CREATE OR REPLACE FUNCTION medcea.revoke_person_mqtt(p_sub uuid, p_reason text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE n integer;
BEGIN
    PERFORM medcea_auth._account_actor('iam_users', 'K');
    IF p_sub IS NULL THEN
        RAISE EXCEPTION 'revoke_person_mqtt: the account is required' USING ERRCODE = '22023';
    END IF;
    IF coalesce(btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'revoke_person_mqtt: a reason is required' USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._owner_write(true);
    UPDATE medcea.mqtt_service_credential c SET active = false
     WHERE c.person_sub = p_sub AND c.active;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM medcea_auth._owner_write(false);
    RETURN n;
END $$;

-- _is_approved(target, key): status approved and unchanged since its last
-- approval (row_digest equals that approval's row_hash).
CREATE OR REPLACE FUNCTION medcea_auth._is_approved(p_target text, p_key jsonb) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea_auth, pg_temp AS $$
DECLARE
    st    text;
    h     text;
BEGIN
    EXECUTE pg_catalog.format('SELECT t.status FROM %s t WHERE t.%I = ($1 ->> 0)::integer',
                              pg_catalog.to_regclass(p_target),
                              CASE p_target WHEN 'medcea.recipe' THEN 'recipe_id'
                                            WHEN 'medcea.control_algorithm' THEN 'algorithm_id'
                                            WHEN 'medcea.unit_algorithm_params' THEN 'params_id' END)
       INTO st USING p_key;
    IF st IS DISTINCT FROM 'approved' THEN
        RETURN false;
    END IF;
    SELECT ap.row_hash INTO h FROM medcea.approval ap
     WHERE ap.target = p_target AND ap.row_key = p_key AND ap.action IN ('approve', 'grandfather')
     ORDER BY ap.approved_at DESC, ap.approval_id DESC LIMIT 1;
    RETURN h IS NOT NULL AND h = medcea_auth.row_digest(p_target, p_key);
END $$;

-- Shared by the three definition approvals.
CREATE OR REPLACE FUNCTION medcea._approve_definition(p_target text, p_id integer, p_group text, p_note text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    ap    record;
    au    record;
    k     jsonb := jsonb_build_array(p_id);
    st    text;
    col   text := CASE p_target WHEN 'medcea.recipe' THEN 'recipe_id'
                                WHEN 'medcea.control_algorithm' THEN 'algorithm_id'
                                WHEN 'medcea.unit_algorithm_params' THEN 'params_id' END;
    v_id  bigint;
BEGIN
    SELECT * INTO ap FROM medcea_auth._approver(p_group);
    EXECUTE format('SELECT t.status FROM %s t WHERE t.%I = $1 FOR UPDATE', p_target::regclass, col) INTO st USING p_id;
    IF st IS NULL THEN
        RAISE EXCEPTION '% % does not exist', p_target, p_id USING ERRCODE = '22023';
    END IF;
    IF st <> 'draft' THEN
        RAISE EXCEPTION '% % is %, not a draft', p_target, p_id, st USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._lock_row(p_target, k);
    SELECT * INTO au FROM medcea_auth._authors(p_target, k);
    IF ap.person = ANY (au.persons) THEN
        RAISE EXCEPTION 'not_own_author: % changed % % since its last approval', ap.person, p_target, p_id
            USING ERRCODE = '42501';
    END IF;
    IF au.unattributed > 0 THEN
        RAISE EXCEPTION 'unattributed changes: % change(s) to % % have no person; re-create it to approve it',
            au.unattributed, p_target, p_id USING ERRCODE = '42501';
    END IF;
    PERFORM medcea_auth._owner_write(true);
    EXECUTE format('UPDATE %s SET status = ''approved'' WHERE %I = $1', p_target::regclass, col) USING p_id;
    PERFORM medcea_auth._owner_write(false);
    INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note, author_persons,
                                 approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source,
                                 last_change_id)
    VALUES (p_target, k, medcea_auth.row_digest(p_target, k), p_group, 'approve', p_note, au.persons,
            ap.sub, ap.person, ap.name, ap.role, ap.source, au.last_change)
    RETURNING approval_id INTO v_id;
    RETURN v_id;
END $$;

-- approve_recipe / approve_algorithm / approve_params (id, note): the approval
-- with an optional note, recorded in approval.note. No DEFAULT on the note: a
-- default would make the 1-argument call ambiguous (PostgREST picks the overload
-- by the argument names it is sent). The 1-argument versions call these.
CREATE OR REPLACE FUNCTION medcea.approve_recipe(p_recipe_id integer, p_note text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    RETURN medcea._approve_definition('medcea.recipe', p_recipe_id, 'recipes', nullif(btrim(p_note), ''));
END $$;

CREATE OR REPLACE FUNCTION medcea.approve_algorithm(p_algorithm_id integer, p_note text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    RETURN medcea._approve_definition('medcea.control_algorithm', p_algorithm_id, 'controllers', nullif(btrim(p_note), ''));
END $$;

-- The algorithm check comes first (before the approver's own checks), as it always
-- has; approval_queue() reports algorithm_not_approved first for a parameter set too.
CREATE OR REPLACE FUNCTION medcea.approve_params(p_params_id integer, p_note text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE alg integer;
BEGIN
    SELECT algorithm_id INTO alg FROM medcea.unit_algorithm_params WHERE params_id = p_params_id;
    IF alg IS NOT NULL AND NOT medcea_auth._is_approved('medcea.control_algorithm', jsonb_build_array(alg)) THEN
        RAISE EXCEPTION 'parameter set %: its algorithm % is not approved', p_params_id, alg USING ERRCODE = '42501';
    END IF;
    RETURN medcea._approve_definition('medcea.unit_algorithm_params', p_params_id, 'controllers', nullif(btrim(p_note), ''));
END $$;

CREATE OR REPLACE FUNCTION medcea.approve_recipe(p_recipe_id integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    RETURN medcea.approve_recipe(p_recipe_id, NULL::text);
END $$;

CREATE OR REPLACE FUNCTION medcea.approve_algorithm(p_algorithm_id integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    RETURN medcea.approve_algorithm(p_algorithm_id, NULL::text);
END $$;

CREATE OR REPLACE FUNCTION medcea.approve_params(p_params_id integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    RETURN medcea.approve_params(p_params_id, NULL::text);
END $$;

-- propose_setting(key, value): a log-retention change, applied by approve_change().
-- Like a commissioning proposal, it is closed only by qa (approve_change,
-- return_change) or by its proposer (withdraw_change): while another person's
-- proposal for the key waits, a new one is refused. The proposer may replace their
-- own (the earlier one then reads 'superseded'). A per-key advisory lock
-- serialises two proposals for the same key.
CREATE OR REPLACE FUNCTION medcea.propose_setting(p_key text, p_value jsonb) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE a record; v_id bigint; waiting medcea.pending_change;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        RAISE EXCEPTION 'propose_setting: no actor' USING ERRCODE = '42501';
    END IF;
    IF a.person IS NULL THEN
        RAISE EXCEPTION 'propose_setting: your token carries no person_id' USING ERRCODE = '42501';
    END IF;
    IF p_key NOT IN ('log_compress_days', 'log_delete_days') THEN
        RAISE EXCEPTION 'propose_setting: unknown setting %', p_key USING ERRCODE = '22023';
    END IF;
    IF p_value IS NULL OR jsonb_typeof(p_value) NOT IN ('number', 'string') THEN
        RAISE EXCEPTION 'propose_setting: % must be a number', p_key USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('medcea.scheduler_config:' || p_key, 0));
    SELECT pc.* INTO waiting FROM medcea.pending_change pc
     WHERE pc.target = 'medcea.scheduler_config' AND pc.row_key = jsonb_build_array(p_key) AND pc.column_name = 'value'
     ORDER BY pc.change_id DESC LIMIT 1;
    IF waiting.change_id IS NOT NULL AND medcea._pending_open(waiting)
       AND waiting.proposed_by_person IS DISTINCT FROM a.person THEN
        RAISE EXCEPTION 'propose_setting: change % for % already waits for qa', waiting.change_id, p_key
            USING ERRCODE = '22023';
    END IF;
    INSERT INTO medcea.pending_change (target, row_key, column_name, new_value, reason,
        proposed_by_sub, proposed_by_person, proposed_by_name, proposed_by_role, proposed_by_source)
    VALUES ('medcea.scheduler_config', jsonb_build_array(p_key), 'value', p_value, NULL,
            a.sub, a.person, a.name, a.role, a.source)
    RETURNING change_id INTO v_id;
    RETURN v_id;
END $$;

-- _unit_busy(unit): a run of the unit that is running (R) or scheduled (S), the
-- running one first, or nothing. Commissioning is refused while there is one: a
-- flagged unit opens MQTT write to engineers and start_run refuses it.
CREATE OR REPLACE FUNCTION medcea._unit_busy(p_unit_id integer, OUT run_id integer, OUT run_status text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
    SELECT r.recipe_run_id, r.recipe_run_status::text FROM medcea.recipe_run r
     WHERE r.unit_id = p_unit_id AND r.recipe_run_status IN ('R', 'S')
     ORDER BY r.recipe_run_status = 'R' DESC, r.recipe_run_id LIMIT 1
$$;
REVOKE ALL ON FUNCTION medcea._unit_busy(integer) FROM PUBLIC;

-- _unit_schedulable(unit): a run is about to be scheduled (S) on the unit: a new
-- run (new_run_defaults) or F -> S (set_run_status). The unit row is read FOR
-- SHARE, as start_run reads it, so a commissioning proposal or approval in flight
-- (FOR NO KEY UPDATE) finishes first and one that follows sees this run in S
-- (_unit_busy); a flagged unit refuses it, the other half of "no flag while a run
-- is running or scheduled". A missing unit is left to the foreign key.
CREATE OR REPLACE FUNCTION medcea._unit_schedulable(p_unit_id integer) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE flagged boolean; code text;
BEGIN
    SELECT u.commissioning, u.unit_code INTO flagged, code FROM medcea.cea_unit u WHERE u.unit_id = p_unit_id FOR SHARE;
    IF flagged THEN
        PERFORM medcea_auth.policy_refuse(format('commissioning: unit %s is flagged for commissioning; schedule its run once commissioning ends',
                                                 code));
    END IF;
END $$;
REVOKE ALL ON FUNCTION medcea._unit_schedulable(integer) FROM PUBLIC;

-- propose_commissioning(unit, on, reason). On waits for a qa person other than the
-- proposer (approve_change); it is a policy refusal while the unit has a run in R
-- or S, here and again at approval. Off is a narrowing: it applies at once and
-- waits for qa's review afterwards (pending_change.applied_at; approve_change
-- records the review). A proposal that changes nothing is refused, and so is a
-- second "on" while one waits: the proposer withdraws (withdraw_change) or qa
-- returns it (return_change) — nobody replaces another person's proposal.
-- The unit row is locked (FOR NO KEY UPDATE), as approve_change locks it and
-- start_run reads the flag FOR SHARE, so a flag and a run start are serialised.
CREATE OR REPLACE FUNCTION medcea.propose_commissioning(p_unit_id integer, p_value boolean, p_reason text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE a record; v_id bigint; cur boolean; code text; busy record; waiting bigint;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        RAISE EXCEPTION 'propose_commissioning: no actor' USING ERRCODE = '42501';
    END IF;
    IF a.person IS NULL THEN
        RAISE EXCEPTION 'propose_commissioning: your token carries no person_id' USING ERRCODE = '42501';
    END IF;
    SELECT u.commissioning, u.unit_code INTO cur, code FROM medcea.cea_unit u WHERE u.unit_id = p_unit_id FOR NO KEY UPDATE;
    IF NOT FOUND OR p_value IS NULL THEN
        RAISE EXCEPTION 'propose_commissioning: no unit %', p_unit_id USING ERRCODE = '22023';
    END IF;
    IF coalesce(btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'propose_commissioning: a reason is required' USING ERRCODE = '22023';
    END IF;
    IF p_value IS NOT DISTINCT FROM coalesce(cur, false) THEN
        RAISE EXCEPTION 'propose_commissioning: unit % is already %', code, CASE WHEN p_value THEN 'on' ELSE 'off' END
            USING ERRCODE = '22023';
    END IF;
    IF p_value THEN
        SELECT pc.change_id INTO waiting FROM medcea.pending_change pc
         WHERE pc.target = 'medcea.cea_unit' AND pc.row_key = jsonb_build_array(p_unit_id) AND pc.column_name = 'commissioning'
           AND pc.applied_at IS NULL
           AND NOT EXISTS (SELECT 1 FROM medcea.approval ap WHERE ap.target = 'medcea.pending_change'
                                                              AND ap.row_key = jsonb_build_array(pc.change_id))
           AND NOT EXISTS (SELECT 1 FROM medcea.pending_change x WHERE x.target = pc.target AND x.row_key = pc.row_key
                                                                    AND x.column_name = pc.column_name AND x.change_id > pc.change_id)
         ORDER BY pc.change_id DESC LIMIT 1;
        IF waiting IS NOT NULL THEN
            RAISE EXCEPTION 'propose_commissioning: change % for unit % already waits for qa', waiting, code
                USING ERRCODE = '22023';
        END IF;
        SELECT * INTO busy FROM medcea._unit_busy(p_unit_id);
        IF busy.run_id IS NOT NULL THEN
            PERFORM medcea_auth.policy_refuse(format('commissioning: unit %s has run %s in %s; flag it when no run is running or scheduled',
                                                     code, busy.run_id, busy.run_status));
        END IF;
    END IF;
    INSERT INTO medcea.pending_change (target, row_key, column_name, new_value, reason,
        proposed_by_sub, proposed_by_person, proposed_by_name, proposed_by_role, proposed_by_source, applied_at)
    VALUES ('medcea.cea_unit', jsonb_build_array(p_unit_id), 'commissioning', to_jsonb(p_value), p_reason,
            a.sub, a.person, a.name, a.role, a.source, CASE WHEN p_value THEN NULL ELSE now() END)
    RETURNING change_id INTO v_id;
    IF NOT p_value THEN
        PERFORM set_config('medcea.commissioning_change', v_id::text, true);
        PERFORM medcea_auth._owner_write(true);
        UPDATE medcea.cea_unit SET commissioning = false WHERE unit_id = p_unit_id;
        PERFORM medcea_auth._owner_write(false);
        PERFORM set_config('medcea.commissioning_change', '', true);
    END IF;
    RETURN v_id;
END $$;

-- _pending_lock(change): approve_change, return_change and withdraw_change close a
-- pending change under this lock, so two of them never both close it. A
-- commissioning change's unit row is locked before it (the order propose takes).
CREATE OR REPLACE FUNCTION medcea._pending_lock(p_id bigint, OUT pc medcea.pending_change)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE u integer;
BEGIN
    SELECT CASE WHEN x.target = 'medcea.cea_unit' THEN (x.row_key ->> 0)::integer END INTO u
      FROM medcea.pending_change x WHERE x.change_id = p_id;
    IF u IS NOT NULL THEN
        PERFORM 1 FROM medcea.cea_unit c WHERE c.unit_id = u FOR NO KEY UPDATE;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('medcea.pending_change:' || p_id, 0));
    SELECT * INTO pc FROM medcea.pending_change x WHERE x.change_id = p_id;
END $$;
REVOKE ALL ON FUNCTION medcea._pending_lock(bigint) FROM PUBLIC;

-- _pending_open(change): no approval, return or withdrawal closed it, and (unless it
-- applied at once and only waits for its review) no later proposal replaced it.
CREATE OR REPLACE FUNCTION medcea._pending_open(pc medcea.pending_change) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
    SELECT NOT EXISTS (SELECT 1 FROM medcea.approval ap WHERE ap.target = 'medcea.pending_change'
                                                          AND ap.row_key = jsonb_build_array(pc.change_id))
       AND (pc.applied_at IS NOT NULL
            OR NOT EXISTS (SELECT 1 FROM medcea.pending_change x WHERE x.target = pc.target AND x.row_key = pc.row_key
                                                                   AND x.column_name = pc.column_name AND x.change_id > pc.change_id))
$$;
REVOKE ALL ON FUNCTION medcea._pending_open(medcea.pending_change) FROM PUBLIC;

-- approve_change(target, id, note):
--   target 'medcea.pending_change', id = change_id: approves and applies a
--     blocking change (retention: scheduler_settings; commissioning: master_data),
--     or reviews one that applied at once (commissioning off: action 'review');
--   target a master_data or devices table, id = the row's id: a review.
-- qa sends a proposal back with return_change(); its proposer withdraws it with
-- withdraw_change(); either closes it, like an approval.
CREATE OR REPLACE FUNCTION medcea.approve_change(p_target text, p_id bigint, p_note text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    pc     medcea.pending_change;
    ap     record;
    au     record;
    grp    text;
    k      jsonb;
    v_id   bigint;
    v      integer;
    cur    boolean;
    code   text;
    busy   record;
BEGIN
    IF p_target = 'medcea.pending_change' THEN
        SELECT * INTO pc FROM medcea._pending_lock(p_id);
        IF pc.change_id IS NULL THEN
            RAISE EXCEPTION 'approve_change: no pending change %', p_id USING ERRCODE = '22023';
        END IF;
        IF NOT medcea._pending_open(pc) THEN
            RAISE EXCEPTION 'approve_change: change % is no longer pending', p_id USING ERRCODE = '22023';
        END IF;
        grp := CASE pc.target WHEN 'medcea.scheduler_config' THEN 'scheduler_settings' ELSE 'master_data' END;
        SELECT * INTO ap FROM medcea_auth._approver(grp);
        IF pc.proposed_by_person IS NULL THEN
            RAISE EXCEPTION 'unattributed changes: change % has no person behind it', p_id USING ERRCODE = '42501';
        END IF;
        IF pc.proposed_by_person = ap.person THEN
            RAISE EXCEPTION 'not_own_author: % proposed change %', ap.person, p_id USING ERRCODE = '42501';
        END IF;
        IF pc.applied_at IS NOT NULL THEN
            -- applied at once (a narrowing): this is qa's review of it, nothing changes
            INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note, author_persons,
                                         approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source)
            VALUES ('medcea.pending_change', jsonb_build_array(p_id),
                    encode(sha256(convert_to(to_jsonb(pc)::text, 'UTF8')), 'hex'), grp, 'review', p_note,
                    ARRAY[pc.proposed_by_person], ap.sub, ap.person, ap.name, ap.role, ap.source)
            RETURNING approval_id INTO v_id;
            RETURN v_id;
        END IF;
        IF pc.target = 'medcea.scheduler_config' THEN
            v := CASE WHEN (pc.new_value #>> '{}') ~ '^\d{1,9}$' THEN (pc.new_value #>> '{}')::integer END;
            IF v IS NULL OR (pc.row_key ->> 0 = 'log_compress_days' AND v < 1)
                         OR (pc.row_key ->> 0 = 'log_delete_days' AND v < 30) THEN
                PERFORM medcea_auth.policy_refuse(format('retention: %s = %s is below the minimum (log_compress_days >= 1, log_delete_days >= 30)',
                                                         pc.row_key ->> 0, pc.new_value #>> '{}'));
            END IF;
            PERFORM medcea_auth._owner_write(true);
            INSERT INTO medcea.scheduler_config (key, value) VALUES (pc.row_key ->> 0, pc.new_value #>> '{}')
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
            PERFORM medcea_auth._owner_write(false);
        ELSE
            SELECT u.commissioning, u.unit_code INTO cur, code FROM medcea.cea_unit u WHERE u.unit_id = (pc.row_key ->> 0)::integer;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'approve_change: unit % no longer exists', pc.row_key ->> 0 USING ERRCODE = '22023';
            END IF;
            IF (pc.new_value #>> '{}')::boolean IS NOT DISTINCT FROM coalesce(cur, false) THEN
                RAISE EXCEPTION 'approve_change: change % changes nothing: unit % is already %', p_id, code,
                    CASE WHEN cur THEN 'on' ELSE 'off' END USING ERRCODE = '22023';
            END IF;
            IF (pc.new_value #>> '{}')::boolean THEN
                SELECT * INTO busy FROM medcea._unit_busy((pc.row_key ->> 0)::integer);
                IF busy.run_id IS NOT NULL THEN
                    PERFORM medcea_auth.policy_refuse(format('commissioning: unit %s has run %s in %s; flag it when no run is running or scheduled',
                                                             code, busy.run_id, busy.run_status));
                END IF;
            END IF;
            PERFORM set_config('medcea.commissioning_change', p_id::text, true);
            PERFORM medcea_auth._owner_write(true);
            UPDATE medcea.cea_unit SET commissioning = (pc.new_value #>> '{}')::boolean
             WHERE unit_id = (pc.row_key ->> 0)::integer;
            PERFORM medcea_auth._owner_write(false);
            PERFORM set_config('medcea.commissioning_change', '', true);
        END IF;
        INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note, author_persons,
                                     approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source)
        VALUES ('medcea.pending_change', jsonb_build_array(p_id),
                encode(sha256(convert_to(to_jsonb(pc)::text, 'UTF8')), 'hex'), grp, 'apply', p_note,
                ARRAY[pc.proposed_by_person], ap.sub, ap.person, ap.name, ap.role, ap.source)
        RETURNING approval_id INTO v_id;
        RETURN v_id;
    END IF;
    IF p_target NOT IN ('medcea.cea_location', 'medcea.cea_unit', 'medcea.cea_zone', 'medcea.component', 'medcea.device') THEN
        RAISE EXCEPTION 'approve_change: % is not reviewed by approve_change()', p_target USING ERRCODE = '22023';
    END IF;
    grp := medcea_auth.object_group(p_target);
    SELECT * INTO ap FROM medcea_auth._approver(grp);
    k := jsonb_build_array(p_id);
    IF NOT medcea_auth._lock_row(p_target, k) OR medcea_auth.row_digest(p_target, k) IS NULL THEN
        RAISE EXCEPTION 'approve_change: % % does not exist', p_target, p_id USING ERRCODE = '22023';
    END IF;
    SELECT * INTO au FROM medcea_auth._authors(p_target, k);
    IF ap.person = ANY (au.persons) THEN
        RAISE EXCEPTION 'not_own_author: % changed % % since its last review', ap.person, p_target, p_id
            USING ERRCODE = '42501';
    END IF;
    IF au.unattributed > 0 THEN
        RAISE EXCEPTION 'unattributed changes: % change(s) to % % have no person', au.unattributed, p_target, p_id
            USING ERRCODE = '42501';
    END IF;
    INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note, author_persons,
                                 approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source,
                                 last_change_id)
    VALUES (p_target, k, medcea_auth.row_digest(p_target, k), grp, 'review', p_note, au.persons,
            ap.sub, ap.person, ap.name, ap.role, ap.source, au.last_change)
    RETURNING approval_id INTO v_id;
    RETURN v_id;
END $$;

-- return_change(target, id, reason): qa sends work back, with a reason (level A on
-- the item's group, the approver rule of _approver()). A pending change
-- (target 'medcea.pending_change') is closed: it never applies, and its proposer
-- proposes again if still wanted. A draft (medcea.recipe, control_algorithm,
-- unit_algorithm_params) stays an editable draft; approval_queue() and
-- my_approvals() show it as returned until it is changed again. Recorded as
-- approval action 'return', which no approval rule counts. The proposer of a
-- change withdraws it instead (withdraw_change). A change that applied at once
-- is reviewed, not returned.
CREATE OR REPLACE FUNCTION medcea.return_change(p_target text, p_id bigint, p_reason text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    pc     medcea.pending_change;
    ap     record;
    au     record;
    grp    text;
    k      jsonb := jsonb_build_array(p_id);
    st     text;
    col    text := CASE p_target WHEN 'medcea.recipe' THEN 'recipe_id'
                                 WHEN 'medcea.control_algorithm' THEN 'algorithm_id'
                                 WHEN 'medcea.unit_algorithm_params' THEN 'params_id' END;
    v_id   bigint;
BEGIN
    IF p_target = 'medcea.pending_change' THEN
        SELECT * INTO pc FROM medcea._pending_lock(p_id);
        IF pc.change_id IS NULL THEN
            RAISE EXCEPTION 'return_change: no pending change %', p_id USING ERRCODE = '22023';
        END IF;
        grp := CASE pc.target WHEN 'medcea.scheduler_config' THEN 'scheduler_settings' ELSE 'master_data' END;
    ELSIF col IS NOT NULL THEN
        grp := medcea_auth.object_group(p_target);
    ELSE
        RAISE EXCEPTION 'return_change: % is not returned by return_change()', p_target USING ERRCODE = '22023';
    END IF;
    SELECT * INTO ap FROM medcea_auth._approver(grp);
    IF coalesce(btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'return_change: a reason is required' USING ERRCODE = '22023';
    END IF;
    IF p_target = 'medcea.pending_change' THEN
        IF NOT medcea._pending_open(pc) THEN
            RAISE EXCEPTION 'return_change: change % is no longer pending', p_id USING ERRCODE = '22023';
        END IF;
        IF pc.applied_at IS NOT NULL THEN
            RAISE EXCEPTION 'return_change: change % applied at once; review it (approve_change)', p_id USING ERRCODE = '22023';
        END IF;
        IF pc.proposed_by_person = ap.person THEN
            RAISE EXCEPTION 'not_own_author: % proposed change %; withdraw it instead', ap.person, p_id USING ERRCODE = '42501';
        END IF;
        INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note, author_persons,
                                     approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source)
        VALUES ('medcea.pending_change', k, encode(sha256(convert_to(to_jsonb(pc)::text, 'UTF8')), 'hex'), grp, 'return',
                btrim(p_reason), array_remove(ARRAY[pc.proposed_by_person], NULL), ap.sub, ap.person, ap.name, ap.role, ap.source)
        RETURNING approval_id INTO v_id;
        RETURN v_id;
    END IF;
    EXECUTE format('SELECT t.status FROM %s t WHERE t.%I = $1 FOR UPDATE', p_target::regclass, col) INTO st USING p_id::integer;
    IF st IS NULL THEN
        RAISE EXCEPTION '% % does not exist', p_target, p_id USING ERRCODE = '22023';
    END IF;
    IF st <> 'draft' THEN
        RAISE EXCEPTION '% % is %, not a draft', p_target, p_id, st USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._lock_row(p_target, k);
    SELECT * INTO au FROM medcea_auth._authors(p_target, k);
    IF EXISTS (SELECT 1 FROM medcea.approval r
                WHERE r.target = p_target AND r.row_key = k AND r.action = 'return'
                  AND r.last_change_id IS NOT DISTINCT FROM au.last_change
                  AND NOT EXISTS (SELECT 1 FROM medcea.approval x WHERE x.target = r.target AND x.row_key = r.row_key
                                                                     AND x.approval_id > r.approval_id
                                                                     AND x.action IN ('approve', 'review', 'grandfather'))) THEN
        RAISE EXCEPTION 'return_change: % % was returned and has not changed since', p_target, p_id USING ERRCODE = '22023';
    END IF;
    INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note, author_persons,
                                 approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source,
                                 last_change_id)
    VALUES (p_target, k, medcea_auth.row_digest(p_target, k), grp, 'return', btrim(p_reason), au.persons,
            ap.sub, ap.person, ap.name, ap.role, ap.source, au.last_change)
    RETURNING approval_id INTO v_id;
    RETURN v_id;
END $$;

-- withdraw_change(change, reason): the proposer takes their own waiting proposal
-- back (any role; only the person who proposed it — by person_id, whichever of
-- their accounts or services proposed it). Recorded as approval action 'withdraw'
-- with the withdrawer as approved_by_*; the reason is optional. A change that
-- applied at once cannot be withdrawn: propose the opposite.
CREATE OR REPLACE FUNCTION medcea.withdraw_change(p_id bigint, p_reason text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE a record; pc medcea.pending_change; v_id bigint;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        RAISE EXCEPTION 'withdraw_change: no actor' USING ERRCODE = '42501';
    END IF;
    IF a.person IS NULL THEN
        RAISE EXCEPTION 'withdraw_change: your token carries no person_id' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO pc FROM medcea._pending_lock(p_id);
    -- one answer for a change that does not exist and another person's: nothing
    -- here tells a caller what others proposed
    IF pc.change_id IS NULL OR pc.proposed_by_person IS DISTINCT FROM a.person THEN
        RAISE EXCEPTION 'withdraw_change: change % is not a proposal of yours', p_id USING ERRCODE = '42501';
    END IF;
    IF NOT medcea._pending_open(pc) THEN
        RAISE EXCEPTION 'withdraw_change: change % is no longer pending', p_id USING ERRCODE = '22023';
    END IF;
    IF pc.applied_at IS NOT NULL THEN
        RAISE EXCEPTION 'withdraw_change: change % applied at once; propose the opposite instead', p_id USING ERRCODE = '22023';
    END IF;
    INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note, author_persons,
                                 approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source)
    VALUES ('medcea.pending_change', jsonb_build_array(p_id), encode(sha256(convert_to(to_jsonb(pc)::text, 'UTF8')), 'hex'),
            CASE pc.target WHEN 'medcea.scheduler_config' THEN 'scheduler_settings' ELSE 'master_data' END,
            'withdraw', nullif(btrim(p_reason), ''), ARRAY[pc.proposed_by_person],
            a.sub, a.person, a.name, a.role, a.source)
    RETURNING approval_id INTO v_id;
    RETURN v_id;
END $$;

-- approval_queue(changes): what waits for qa, for the Configuration UI's Approvals
-- tab. Read-only; it writes nothing. Drafts (recipes, control algorithms,
-- parameter sets) with their content, the persons who changed them since their
-- last approval (_changes_since(), the approve functions' own rule) and, unless
-- p_changes is false (the tab's count), those changes (newest first, at most 200);
-- then the open pending changes (log settings, commissioning: state 'waiting', or
-- 'review' for one that applied at once). Rows only from the groups where the
-- caller holds R. may_approve and why_not_code/why_not are advisory, computed in the
-- approve functions' order without their locks; the database still decides at
-- approval. A draft qa returned reads state 'returned' until it changes again.
-- Last, the completed runs nobody released (kind 'run'), only for roles holding A
-- on runs and reading every unit's runs (qp): detail is the run's summary (unit,
-- recipe and parameter set with their approvals, creator, every executor,
-- attempts, cycles; no run log), authors its creator, changers and executors,
-- may_approve whether release_run() would release it (its checks, in its order;
-- a run from before 008b reads no_attribution and stays unreleased).
-- Only a person's own token (source 'token'): the services that inherit EXECUTE
-- through audit_histories R get a refusal.
CREATE OR REPLACE FUNCTION medcea.approval_queue(p_changes boolean DEFAULT true)
RETURNS TABLE (kind text, target text, id bigint, group_name text, label text, state text, detail jsonb,
               authors text[], author_names text[], unattributed integer,
               last_approval_id bigint, last_approved_at timestamptz, last_approved_by text,
               changes jsonb, changes_total integer,
               reason text, proposed_by text, proposed_at timestamptz,
               returned_at timestamptz, returned_by text, return_reason text,
               may_approve boolean, may_return boolean, why_not_code text, why_not text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
#variable_conflict use_column
DECLARE
    a     record;
    d     record;
    p     medcea.pending_change;
    la    record;
    rt    record;
    cs    record;
    b_run integer;
    b_st  text;
    rk    jsonb;
    g     text;
    cur   jsonb;
    v     integer;
    holds boolean;
    rn    record;
    ex    record;
    cy    jsonb;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.source IS DISTINCT FROM 'token' THEN
        RAISE EXCEPTION 'approval_queue: read it in the Configuration UI with your own sign-in' USING ERRCODE = '42501';
    END IF;
    FOR d IN
        SELECT 'recipe' AS d_kind, 'medcea.recipe' AS d_target, x.recipe_id::bigint AS d_id, 'recipes' AS d_group,
               x.recipe_name::text AS d_label, NULL::integer AS d_alg,
               to_jsonb(x) || jsonb_build_object('lines',
                   (SELECT coalesce(jsonb_agg(to_jsonb(l) ORDER BY l.recipe_item_seq_id), '[]'::jsonb)
                      FROM medcea.recipe_line l WHERE l.recipe_id = x.recipe_id)) AS d_detail
          FROM medcea.recipe x WHERE x.status = 'draft'
        UNION ALL
        SELECT 'algorithm', 'medcea.control_algorithm', x.algorithm_id::bigint, 'controllers', x.algorithm_code::text,
               NULL::integer, to_jsonb(x)
          FROM medcea.control_algorithm x WHERE x.status = 'draft'
        UNION ALL
        SELECT 'params', 'medcea.unit_algorithm_params', x.params_id::bigint, 'controllers', x.name::text, x.algorithm_id,
               to_jsonb(x) || jsonb_build_object('algorithm_code', ca.algorithm_code, 'unit_code', cu.unit_code)
          FROM medcea.unit_algorithm_params x
          JOIN medcea.control_algorithm ca ON ca.algorithm_id = x.algorithm_id
          LEFT JOIN medcea.cea_unit cu ON cu.unit_id = x.unit_id
         WHERE x.status = 'draft'
    LOOP
        CONTINUE WHEN medcea_auth.policy_holds(a.role, d.d_group, 'R') IS NULL;
        rk := jsonb_build_array(d.d_id);
        kind := d.d_kind; target := d.d_target; id := d.d_id; group_name := d.d_group; label := d.d_label;
        detail := d.d_detail;
        SELECT ap.approval_id, ap.approved_at, ap.approved_by_name INTO la FROM medcea.approval ap
         WHERE ap.target = d.d_target AND ap.row_key = rk AND ap.action IN ('approve', 'review', 'grandfather')
         ORDER BY ap.approval_id DESC LIMIT 1;
        last_approval_id := la.approval_id; last_approved_at := la.approved_at; last_approved_by := la.approved_by_name;
        SELECT coalesce(array_agg(DISTINCT c.actor_person) FILTER (WHERE c.authors AND c.actor_person IS NOT NULL), '{}') AS persons,
               coalesce(array_agg(DISTINCT c.actor_name) FILTER (WHERE c.authors AND c.actor_person IS NOT NULL), '{}') AS names,
               (count(*) FILTER (WHERE c.authors AND c.actor_person IS NULL AND coalesce(c.actor_source, '') <> 'migration'))::integer AS unattr,
               count(*)::integer AS total,
               max(c.change_id) FILTER (WHERE c.authors) AS last_authoring
          INTO cs FROM medcea_auth._changes_since(d.d_target, rk) c;
        authors := cs.persons; author_names := cs.names; unattributed := cs.unattr; changes_total := cs.total;
        changes := NULL;
        IF p_changes THEN
            SELECT coalesce(jsonb_agg(jsonb_build_object(
                       'change_id', c.change_id, 'target', c.target, 'row_key', c.row_key, 'op', c.op,
                       'old', c.old_values, 'new', c.new_values, 'by_name', c.actor_name, 'by_person', c.actor_person,
                       'by_role', c.actor_role, 'by_source', c.actor_source, 'at', c.at, 'authors', c.authors)
                       ORDER BY c.change_id DESC), '[]'::jsonb)
              INTO changes
              FROM (SELECT c0.* FROM medcea_auth._changes_since(d.d_target, rk) c0 ORDER BY c0.change_id DESC LIMIT 200) c;
        END IF;
        SELECT r.approval_id, r.approved_at, r.approved_by_name, r.note, r.last_change_id INTO rt FROM medcea.approval r
         WHERE r.target = d.d_target AND r.row_key = rk AND r.action = 'return'
         ORDER BY r.approval_id DESC LIMIT 1;
        IF rt.approval_id IS NOT NULL AND rt.approval_id > coalesce(la.approval_id, 0)
           AND (cs.last_authoring IS NULL OR cs.last_authoring <= coalesce(rt.last_change_id, 0)) THEN
            state := 'returned'; returned_at := rt.approved_at; returned_by := rt.approved_by_name; return_reason := rt.note;
        ELSE
            state := 'waiting'; returned_at := NULL; returned_by := NULL; return_reason := NULL;
        END IF;
        reason := NULL; proposed_by := NULL; proposed_at := NULL;
        holds := btrim(coalesce(a.person, '')) <> '' AND medcea_auth.policy_holds(a.role, d.d_group, 'A') IS NOT NULL;
        why_not_code := CASE
            WHEN d.d_alg IS NOT NULL AND NOT medcea_auth._is_approved('medcea.control_algorithm', jsonb_build_array(d.d_alg))
                THEN 'algorithm_not_approved'
            WHEN btrim(coalesce(a.person, '')) = '' THEN 'no_person'
            WHEN NOT holds THEN 'no_role'
            WHEN a.person = ANY (cs.persons) THEN 'own_author'
            WHEN cs.unattr > 0 THEN 'unattributed' END;
        why_not := CASE why_not_code
            WHEN 'algorithm_not_approved' THEN format('its control algorithm %s is not approved', d.d_alg)
            WHEN 'no_person' THEN 'your token carries no person_id'
            WHEN 'no_role' THEN format('role %s holds no approval on %s', a.role, d.d_group)
            WHEN 'own_author' THEN 'you changed it since its last approval'
            WHEN 'unattributed' THEN format('%s change(s) have no person; re-create it to approve it', cs.unattr) END;
        may_approve := why_not_code IS NULL;
        may_return := holds AND state = 'waiting';
        RETURN NEXT;
    END LOOP;
    FOR p IN SELECT x.* FROM medcea.pending_change x WHERE medcea._pending_open(x) ORDER BY x.change_id LOOP
        g := CASE p.target WHEN 'medcea.scheduler_config' THEN 'scheduler_settings' ELSE 'master_data' END;
        CONTINUE WHEN medcea_auth.policy_holds(a.role, g, 'R') IS NULL;
        b_run := NULL; b_st := NULL; cur := NULL; v := NULL;
        IF p.target = 'medcea.scheduler_config' THEN
            kind := 'setting'; label := p.row_key ->> 0;
            SELECT to_jsonb(sc.value) INTO cur FROM medcea.scheduler_config sc WHERE sc.key = p.row_key ->> 0;
            v := CASE WHEN (p.new_value #>> '{}') ~ '^\d{1,9}$' THEN (p.new_value #>> '{}')::integer END;
        ELSE
            kind := 'commissioning';
            SELECT cu.unit_code::text, to_jsonb(coalesce(cu.commissioning, false)) INTO label, cur
              FROM medcea.cea_unit cu WHERE cu.unit_id = (p.row_key ->> 0)::integer;
            IF p.applied_at IS NULL AND p.new_value = 'true'::jsonb THEN
                SELECT ub.run_id, ub.run_status INTO b_run, b_st FROM medcea._unit_busy((p.row_key ->> 0)::integer) ub;
            END IF;
        END IF;
        target := 'medcea.pending_change'; id := p.change_id; group_name := g;
        state := CASE WHEN p.applied_at IS NOT NULL THEN 'review' ELSE 'waiting' END;
        detail := jsonb_build_object('target', p.target, 'row_key', p.row_key, 'column', p.column_name,
                                     'current', cur, 'proposed', p.new_value, 'applied_at', p.applied_at,
                                     'blocking_run_id', b_run, 'blocking_run_status', b_st);
        authors := array_remove(ARRAY[p.proposed_by_person], NULL);
        author_names := array_remove(ARRAY[p.proposed_by_name], NULL);
        unattributed := CASE WHEN p.proposed_by_person IS NULL THEN 1 ELSE 0 END;
        SELECT ap.approval_id, ap.approved_at, ap.approved_by_name INTO la
          FROM medcea.approval ap JOIN medcea.pending_change y ON ap.row_key = jsonb_build_array(y.change_id)
         WHERE ap.target = 'medcea.pending_change' AND ap.action IN ('apply', 'review')
           AND y.target = p.target AND y.row_key = p.row_key AND y.column_name = p.column_name
         ORDER BY ap.approval_id DESC LIMIT 1;
        last_approval_id := la.approval_id; last_approved_at := la.approved_at; last_approved_by := la.approved_by_name;
        changes := NULL; changes_total := 0;
        reason := p.reason; proposed_by := p.proposed_by_name; proposed_at := p.proposed_at;
        returned_at := NULL; returned_by := NULL; return_reason := NULL;
        holds := btrim(coalesce(a.person, '')) <> '' AND medcea_auth.policy_holds(a.role, g, 'A') IS NOT NULL;
        why_not_code := CASE
            WHEN btrim(coalesce(a.person, '')) = '' THEN 'no_person'
            WHEN NOT holds THEN 'no_role'
            WHEN p.proposed_by_person IS NULL THEN 'unattributed'
            WHEN p.proposed_by_person = a.person THEN 'own_author'
            WHEN p.applied_at IS NOT NULL THEN NULL
            WHEN kind = 'setting' AND (v IS NULL OR (p.row_key ->> 0 = 'log_compress_days' AND v < 1)
                                                 OR (p.row_key ->> 0 = 'log_delete_days' AND v < 30)) THEN 'retention_minimum'
            WHEN kind = 'commissioning' AND p.new_value = cur THEN 'no_change'
            WHEN kind = 'commissioning' AND b_run IS NOT NULL THEN 'run_in_progress' END;
        why_not := CASE why_not_code
            WHEN 'no_person' THEN 'your token carries no person_id'
            WHEN 'no_role' THEN format('role %s holds no approval on %s', a.role, g)
            WHEN 'unattributed' THEN 'the proposal has no person behind it'
            WHEN 'own_author' THEN 'you proposed it'
            WHEN 'retention_minimum' THEN 'not a whole number of days, or below the minimum (log_compress_days >= 1, log_delete_days >= 30)'
            WHEN 'no_change' THEN 'it would change nothing'
            WHEN 'run_in_progress' THEN format('run %s is in %s on this unit', b_run, b_st) END;
        may_approve := why_not_code IS NULL;
        may_return := holds AND state = 'waiting' AND p.proposed_by_person IS DISTINCT FROM a.person;
        RETURN NEXT;
    END LOOP;
    -- a definer reads past the run tables' row security: an own_unit reader (or a
    -- role without A) gets no run row
    IF medcea_auth.policy_holds(a.role, 'runs', 'A') IS NULL
       OR medcea_auth.policy_holds(a.role, 'runs', 'R') IS DISTINCT FROM 'free' THEN
        RETURN;
    END IF;
    FOR rn IN
        SELECT x.*, cu.unit_code::text AS r_unit, rc.recipe_name::text AS r_recipe, rc.status AS r_recipe_status,
               uap.name::text AS r_params, uap.status AS r_params_status
          FROM medcea.recipe_run x
          JOIN medcea.cea_unit cu ON cu.unit_id = x.unit_id
          JOIN medcea.recipe rc ON rc.recipe_id = x.recipe_id
          LEFT JOIN medcea.unit_algorithm_params uap ON uap.params_id = x.params_id
         WHERE x.recipe_run_status = 'C'
           AND NOT EXISTS (SELECT 1 FROM medcea.run_release rl WHERE rl.recipe_run_id = x.recipe_run_id)
         ORDER BY x.recipe_run_id
    LOOP
        rk := jsonb_build_array(rn.recipe_run_id);
        kind := 'run'; target := 'medcea.recipe_run'; id := rn.recipe_run_id; group_name := 'runs';
        label := format('%s on %s', rn.r_recipe, rn.r_unit); state := 'waiting';
        -- _authors()'s rule, as for a draft (a run has no approval: every change counts)
        SELECT coalesce(array_agg(DISTINCT c.actor_person) FILTER (WHERE c.authors AND c.actor_person IS NOT NULL), '{}') AS persons,
               coalesce(array_agg(DISTINCT c.actor_name) FILTER (WHERE c.authors AND c.actor_person IS NOT NULL), '{}') AS names,
               (count(*) FILTER (WHERE c.authors AND c.actor_person IS NULL AND coalesce(c.actor_source, '') <> 'migration'))::integer AS unattr,
               count(*)::integer AS total
          INTO cs FROM medcea_auth._changes_since('medcea.recipe_run', rk) c;
        -- every attempt's executor: each start (status to R) in the run's changes
        SELECT coalesce(jsonb_agg(jsonb_build_object('by_name', c.actor_name, 'by_person', c.actor_person,
                                                     'by_role', c.actor_role, 'at', c.at) ORDER BY c.change_id), '[]'::jsonb) AS list,
               count(*)::integer AS n, coalesce(max(c.at), rn.recipe_run_start) AS last_start
          INTO ex FROM medcea.row_change c
         WHERE c.target = 'medcea.recipe_run' AND c.row_key = rk AND c.op = 'U'
           AND c.new_values ->> 'recipe_run_status' = 'R';
        SELECT jsonb_build_object('total', coalesce(sum(z.n), 0), 'by_status', coalesce(jsonb_object_agg(z.st, z.n), '{}'::jsonb))
          INTO cy
          FROM (SELECT cr.recipe_line_cycle_run_status::text AS st, count(*) AS n FROM medcea.recipe_line_cycle_run cr
                 WHERE cr.recipe_run_id = rn.recipe_run_id GROUP BY 1) z;
        -- the approvals in effect at its last start (start_run checked them then), and now
        detail := jsonb_build_object(
            'run_id', rn.recipe_run_id, 'status', rn.recipe_run_status, 'unit_id', rn.unit_id, 'unit_code', rn.r_unit,
            'start', rn.recipe_run_start, 'end', rn.recipe_run_end, 'schedule_id', rn.schedule_id,
            'recipe_id', rn.recipe_id, 'recipe_name', rn.r_recipe, 'recipe_status', rn.r_recipe_status,
            'recipe_approved_now', medcea_auth._is_approved('medcea.recipe', jsonb_build_array(rn.recipe_id)),
            'recipe_approval_id', (SELECT max(ap.approval_id) FROM medcea.approval ap
                                    WHERE ap.target = 'medcea.recipe' AND ap.row_key = jsonb_build_array(rn.recipe_id)
                                      AND ap.action IN ('approve', 'review', 'grandfather')
                                      AND ap.approved_at <= ex.last_start),
            'params_id', rn.params_id, 'params_name', rn.r_params, 'params_status', rn.r_params_status,
            'params_approved_now', CASE WHEN rn.params_id IS NOT NULL
                                        THEN medcea_auth._is_approved('medcea.unit_algorithm_params', jsonb_build_array(rn.params_id)) END,
            'params_approval_id', (SELECT max(ap.approval_id) FROM medcea.approval ap
                                    WHERE ap.target = 'medcea.unit_algorithm_params' AND ap.row_key = jsonb_build_array(rn.params_id)
                                      AND ap.action IN ('approve', 'review', 'grandfather')
                                      AND ap.approved_at <= ex.last_start),
            'created_by', rn.created_by_name, 'created_by_person', rn.created_by_person,
            'created_by_role', rn.created_by_role, 'created_at', rn.timestamp_cre,
            'executed_by', rn.executed_by_name, 'executed_by_person', rn.executed_by_person,
            'executed_by_role', rn.executed_by_role, 'executors', ex.list, 'attempts', ex.n, 'cycles', cy);
        authors := CASE WHEN rn.executed_by_person IS NULL OR rn.executed_by_person = ANY (cs.persons) THEN cs.persons
                        ELSE cs.persons || rn.executed_by_person::text END;
        author_names := CASE WHEN rn.executed_by_person IS NULL OR rn.executed_by_person = ANY (cs.persons) THEN cs.names
                             ELSE cs.names || rn.executed_by_name::text END;
        unattributed := cs.unattr; changes_total := cs.total;
        last_approval_id := NULL; last_approved_at := NULL; last_approved_by := NULL;
        changes := NULL;
        IF p_changes THEN
            SELECT coalesce(jsonb_agg(jsonb_build_object(
                       'change_id', c.change_id, 'target', c.target, 'row_key', c.row_key, 'op', c.op,
                       'old', c.old_values, 'new', c.new_values, 'by_name', c.actor_name, 'by_person', c.actor_person,
                       'by_role', c.actor_role, 'by_source', c.actor_source, 'at', c.at, 'authors', c.authors)
                       ORDER BY c.change_id DESC), '[]'::jsonb)
              INTO changes
              FROM (SELECT c0.* FROM medcea_auth._changes_since('medcea.recipe_run', rk) c0 ORDER BY c0.change_id DESC LIMIT 200) c;
        END IF;
        reason := NULL; proposed_by := NULL; proposed_at := NULL;
        returned_at := NULL; returned_by := NULL; return_reason := NULL;
        -- release_run()'s order: _approver (person), then own author or executor, then
        -- unattributed, then a run nobody recorded created or started (one from before
        -- 008b: B4 stamped it migration:008, with no row_change), whose authors are unknown
        why_not_code := CASE
            WHEN btrim(coalesce(a.person, '')) = '' THEN 'no_person'
            WHEN a.person = ANY (cs.persons) OR a.person = rn.executed_by_person THEN 'own_author'
            WHEN cs.unattr > 0 THEN 'unattributed'
            WHEN rn.created_by_person IS NULL
                 OR NOT EXISTS (SELECT 1 FROM medcea.row_change c
                                 WHERE c.target = 'medcea.recipe_run' AND c.row_key = rk AND c.op IN ('I', 'U')
                                   AND c.new_values ->> 'recipe_run_status' = 'R' AND c.actor_person IS NOT NULL)
                 THEN 'no_attribution' END;
        why_not := CASE why_not_code
            WHEN 'no_person' THEN 'your token carries no person_id'
            WHEN 'own_author' THEN 'you created, changed or executed this run'
            WHEN 'unattributed' THEN format('%s change(s) to this run have no person', cs.unattr)
            WHEN 'no_attribution' THEN 'no recorded person created or started this run (it predates attribution)' END;
        may_approve := why_not_code IS NULL;
        may_return := false;
        RETURN NEXT;
    END LOOP;
END $$;

-- my_approvals(): the caller's own work and where it stands (level R on portal:
-- every person reads only their own). Their proposals (newest 100: waiting,
-- applied, applied_review_pending, reviewed, returned, withdrawn, superseded),
-- and the drafts they changed since the last approval (waiting or returned).
-- Approvers' names and approval notes are not shown; a return's reason is (it is
-- addressed to the author). A caller without a person_id gets nothing.
CREATE OR REPLACE FUNCTION medcea.my_approvals()
RETURNS TABLE (kind text, target text, id bigint, label text, state text, detail jsonb, reason text,
               changed_at timestamptz, closed_at timestamptz, return_reason text, may_withdraw boolean)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
#variable_conflict use_column
DECLARE
    a    record;
    p    medcea.pending_change;
    d    record;
    cl   record;
    cs   record;
    rt   record;
    rk   jsonb;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.person IS NULL THEN
        RETURN;
    END IF;
    FOR p IN SELECT x.* FROM medcea.pending_change x WHERE x.proposed_by_person = a.person
              ORDER BY x.change_id DESC LIMIT 100 LOOP
        SELECT ap.action, ap.approved_at, ap.note INTO cl FROM medcea.approval ap
         WHERE ap.target = 'medcea.pending_change' AND ap.row_key = jsonb_build_array(p.change_id)
         ORDER BY ap.approval_id DESC LIMIT 1;
        kind := CASE WHEN p.target = 'medcea.scheduler_config' THEN 'setting' ELSE 'commissioning' END;
        target := 'medcea.pending_change'; id := p.change_id;
        label := CASE WHEN p.target = 'medcea.scheduler_config' THEN p.row_key ->> 0
                      ELSE (SELECT cu.unit_code::text FROM medcea.cea_unit cu WHERE cu.unit_id = (p.row_key ->> 0)::integer) END;
        state := CASE cl.action WHEN 'apply' THEN 'applied' WHEN 'review' THEN 'reviewed' WHEN 'return' THEN 'returned'
                                WHEN 'withdraw' THEN 'withdrawn'
                 ELSE CASE WHEN p.applied_at IS NOT NULL THEN 'applied_review_pending'
                           WHEN NOT medcea._pending_open(p) THEN 'superseded'
                           ELSE 'waiting' END END;
        detail := jsonb_build_object('target', p.target, 'row_key', p.row_key, 'column', p.column_name,
                                     'proposed', p.new_value, 'applied_at', p.applied_at);
        reason := p.reason; changed_at := p.proposed_at; closed_at := cl.approved_at;
        return_reason := CASE WHEN cl.action = 'return' THEN cl.note END;
        may_withdraw := state = 'waiting';
        RETURN NEXT;
    END LOOP;
    FOR d IN
        SELECT 'recipe' AS d_kind, 'medcea.recipe' AS d_target, x.recipe_id::bigint AS d_id, x.recipe_name::text AS d_label
          FROM medcea.recipe x WHERE x.status = 'draft'
        UNION ALL
        SELECT 'algorithm', 'medcea.control_algorithm', x.algorithm_id::bigint, x.algorithm_code::text
          FROM medcea.control_algorithm x WHERE x.status = 'draft'
        UNION ALL
        SELECT 'params', 'medcea.unit_algorithm_params', x.params_id::bigint, x.name::text
          FROM medcea.unit_algorithm_params x WHERE x.status = 'draft'
    LOOP
        rk := jsonb_build_array(d.d_id);
        SELECT coalesce(array_agg(DISTINCT c.actor_person) FILTER (WHERE c.authors AND c.actor_person IS NOT NULL), '{}') AS persons,
               max(c.change_id) FILTER (WHERE c.authors) AS last_authoring,
               max(c.at) FILTER (WHERE c.authors) AS last_at
          INTO cs FROM medcea_auth._changes_since(d.d_target, rk) c;
        CONTINUE WHEN NOT (a.person = ANY (cs.persons));
        SELECT r.approval_id, r.approved_at, r.note, r.last_change_id INTO rt FROM medcea.approval r
         WHERE r.target = d.d_target AND r.row_key = rk AND r.action = 'return'
           AND NOT EXISTS (SELECT 1 FROM medcea.approval x WHERE x.target = r.target AND x.row_key = r.row_key
                                                              AND x.approval_id > r.approval_id
                                                              AND x.action IN ('approve', 'review', 'grandfather'))
         ORDER BY r.approval_id DESC LIMIT 1;
        kind := d.d_kind; target := d.d_target; id := d.d_id; label := d.d_label; detail := NULL; reason := NULL;
        changed_at := cs.last_at;
        IF rt.approval_id IS NOT NULL AND (cs.last_authoring IS NULL OR cs.last_authoring <= coalesce(rt.last_change_id, 0)) THEN
            state := 'returned'; closed_at := rt.approved_at; return_reason := rt.note;
        ELSE
            state := 'waiting'; closed_at := NULL; return_reason := NULL;
        END IF;
        may_withdraw := false;
        RETURN NEXT;
    END LOOP;
END $$;

-- unit_commissioning(): every unit's commissioning flag for the Units tab (level R
-- on master_data), with the waiting "on" proposal, an "off" that applied at once
-- and waits for qa's review, the last applied change, and what the caller may do.
-- A definer function reads past the run tables' row security, so the run that
-- blocks commissioning (R or S) is returned only to roles reading every unit's
-- runs (an operator must not learn another unit's run state, as _refuse_hidden_run).
-- Proposers' names and reasons go to engineer, qa, qp and auditor (U on master_data
-- or R on audit_histories) and to the proposer; the approver's name to the
-- audit_histories readers only. Everyone else (services included) sees the flag and
-- that a proposal waits.
CREATE OR REPLACE FUNCTION medcea.unit_commissioning()
RETURNS TABLE (unit_id integer, unit_code text, commissioning boolean,
               blocking_run_id integer, blocking_run_status text,
               pending_change_id bigint, pending_value boolean, pending_reason text, pending_by text,
               pending_at timestamptz, pending_mine boolean, review_change_id bigint,
               last_change_id bigint, last_value boolean, last_changed_at timestamptz,
               last_proposed_by text, last_approved_by text,
               can_propose boolean, can_approve boolean, can_read_history boolean)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
#variable_conflict use_column
DECLARE
    a       record;
    u       record;
    pc      medcea.pending_change;
    lc      record;
    busy    record;
    person  boolean;
    sees    boolean;
    hist    boolean;
    runs    boolean;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    person := a.person IS NOT NULL AND (a.source = 'token' OR a.source LIKE 'person via %');
    hist := person AND medcea_auth.policy_holds(a.role, 'audit_histories', 'R') IS NOT NULL;
    sees := hist OR (person AND medcea_auth.policy_holds(a.role, 'master_data', 'U') IS NOT NULL);
    runs := medcea_auth.policy_holds(a.role, 'runs', 'R') IS NOT DISTINCT FROM 'free';
    can_propose := person AND medcea_auth.policy_holds(a.role, 'master_data', 'U') IS NOT NULL;
    can_approve := a.source IS NOT DISTINCT FROM 'token' AND a.person IS NOT NULL
                   AND medcea_auth.policy_holds(a.role, 'master_data', 'A') IS NOT NULL;
    can_read_history := hist;
    FOR u IN SELECT cu.unit_id AS u_id, cu.unit_code::text AS u_code, coalesce(cu.commissioning, false) AS u_flag
               FROM medcea.cea_unit cu ORDER BY cu.unit_code LOOP
        unit_id := u.u_id; unit_code := u.u_code; commissioning := u.u_flag;
        pc := NULL;
        SELECT x.* INTO pc FROM medcea.pending_change x
         WHERE x.target = 'medcea.cea_unit' AND x.row_key = jsonb_build_array(u.u_id) AND x.column_name = 'commissioning'
           AND x.applied_at IS NULL AND medcea._pending_open(x)
         ORDER BY x.change_id DESC LIMIT 1;
        pending_change_id := pc.change_id; pending_value := (pc.new_value #>> '{}')::boolean;
        pending_mine := pc.change_id IS NOT NULL AND a.person IS NOT NULL AND pc.proposed_by_person = a.person;
        pending_at := pc.proposed_at;
        pending_reason := CASE WHEN sees OR pending_mine THEN pc.reason END;
        pending_by := CASE WHEN sees OR pending_mine THEN pc.proposed_by_name END;
        SELECT max(x.change_id) INTO review_change_id FROM medcea.pending_change x
         WHERE x.target = 'medcea.cea_unit' AND x.row_key = jsonb_build_array(u.u_id) AND x.column_name = 'commissioning'
           AND x.applied_at IS NOT NULL AND medcea._pending_open(x);
        SELECT y.change_id AS c_id, (y.new_value #>> '{}')::boolean AS c_value, coalesce(ap.approved_at, y.applied_at) AS c_at,
               y.proposed_by_name AS c_by, ap.approved_by_name AS c_approver INTO lc
          FROM medcea.pending_change y
          LEFT JOIN medcea.approval ap ON ap.target = 'medcea.pending_change' AND ap.row_key = jsonb_build_array(y.change_id)
                                      AND ap.action = 'apply'
         WHERE y.target = 'medcea.cea_unit' AND y.row_key = jsonb_build_array(u.u_id) AND y.column_name = 'commissioning'
           AND (ap.approval_id IS NOT NULL OR y.applied_at IS NOT NULL)
         ORDER BY coalesce(ap.approved_at, y.applied_at) DESC, y.change_id DESC LIMIT 1;
        last_change_id := lc.c_id; last_value := lc.c_value; last_changed_at := lc.c_at;
        last_proposed_by := CASE WHEN sees THEN lc.c_by END;
        last_approved_by := CASE WHEN hist THEN lc.c_approver END;
        blocking_run_id := NULL; blocking_run_status := NULL;
        IF runs THEN
            SELECT * INTO busy FROM medcea._unit_busy(u.u_id);
            blocking_run_id := busy.run_id; blocking_run_status := busy.run_status;
        END IF;
        RETURN NEXT;
    END LOOP;
END $$;

-- log_commissioning(): every change of cea_unit.commissioning is appended to the
-- tamper-evident policy history (commissioning_enabled / commissioning_disabled),
-- like unit assignments, because the flag opens engineers' MQTT write to the
-- unit. The actor is the request's (qa applying an "on", the engineer whose "off"
-- applied at once); the change and its reason come from the pending_change the
-- function names in medcea.commissioning_change. SECURITY DEFINER (append_history
-- is the owner's); ENABLE ALWAYS, so session_replication_role does not skip it.
CREATE OR REPLACE FUNCTION medcea.log_commissioning() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE pc medcea.pending_change; cid text := nullif(current_setting('medcea.commissioning_change', true), '');
BEGIN
    IF cid ~ '^\d+$' THEN
        SELECT * INTO pc FROM medcea.pending_change x WHERE x.change_id = cid::bigint;
    END IF;
    PERFORM iam_policy.append_history(
        CASE WHEN NEW.commissioning THEN 'commissioning_enabled' ELSE 'commissioning_disabled' END,
        jsonb_build_object('unit_id', NEW.unit_id, 'unit_code', NEW.unit_code, 'change_id', pc.change_id,
                           'proposed_by_person', pc.proposed_by_person, 'proposed_by_role', pc.proposed_by_role,
                           'applied_at_once', pc.applied_at IS NOT NULL),
        pc.reason);
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION medcea.log_commissioning() FROM PUBLIC;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.cea_unit'::regclass
                                                         AND tgname = 'commissioning_history_trg') THEN
        CREATE TRIGGER commissioning_history_trg AFTER UPDATE OF commissioning ON medcea.cea_unit
            FOR EACH ROW WHEN (OLD.commissioning IS DISTINCT FROM NEW.commissioning)
            EXECUTE FUNCTION medcea.log_commissioning();
    END IF;
    IF (SELECT tgenabled FROM pg_catalog.pg_trigger WHERE tgrelid = 'medcea.cea_unit'::regclass
                                                      AND tgname = 'commissioning_history_trg') <> 'A' THEN
        ALTER TABLE medcea.cea_unit ENABLE ALWAYS TRIGGER commissioning_history_trg;
    END IF;
END $$;

-- H9: a run's parameter set belongs to its unit (or any unit) and runs the
-- algorithm the run was planned with: its schedule's (the schedule's set's
-- algorithm, else schedule.algorithm_id) when it was triggered by a schedule
-- that names one, else the recipe's assignment on that unit. Structural.
CREATE OR REPLACE FUNCTION medcea._check_run_params(p_unit integer, p_recipe integer, p_params integer, p_schedule integer)
RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE s medcea.unit_algorithm_params; alg integer; src text := 'the recipe is assigned to this unit with';
BEGIN
    IF p_params IS NULL THEN
        RETURN;
    END IF;
    SELECT * INTO s FROM medcea.unit_algorithm_params WHERE params_id = p_params;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no parameter set %', p_params USING ERRCODE = '22023';
    END IF;
    IF s.unit_id IS NOT NULL AND s.unit_id <> p_unit THEN
        RAISE EXCEPTION 'parameter set % belongs to unit %, not %', p_params, s.unit_id, p_unit USING ERRCODE = '22023';
    END IF;
    IF p_schedule IS NOT NULL THEN
        SELECT coalesce(ss.algorithm_id, sc.algorithm_id) INTO alg
          FROM medcea.schedule sc
          LEFT JOIN medcea.unit_algorithm_params ss ON ss.params_id = sc.params_id
         WHERE sc.schedule_id = p_schedule;
        src := 'its schedule runs';
    END IF;
    IF alg IS NULL THEN
        SELECT coalesce(us.algorithm_id, p.algorithm_id) INTO alg
          FROM medcea.recipe_unit_permission p
          LEFT JOIN medcea.unit_algorithm_params us ON us.params_id = p.params_id
         WHERE p.recipe_id = p_recipe AND p.unit_id = p_unit;
        src := 'the recipe is assigned to this unit with';
    END IF;
    IF alg IS NOT NULL AND alg <> s.algorithm_id THEN
        RAISE EXCEPTION 'parameter set % is for algorithm %, but % algorithm %',
            p_params, s.algorithm_id, src, alg USING ERRCODE = '22023';
    END IF;
END $$;
REVOKE ALL ON FUNCTION medcea._check_run_params(integer, integer, integer, integer) FROM PUBLIC;

-- _refuse_hidden_run(): the one answer an operator (O under assigned_run) gets for
-- a run outside their units AND for a run that does not exist, so start_run and
-- set_run_status (SECURITY DEFINER, past the RLS) cannot be used to list other
-- units' runs, their status, or whether a unit is running. Policy.
CREATE OR REPLACE FUNCTION medcea._refuse_hidden_run(p_run_id integer) RETURNS void
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    PERFORM medcea_auth.policy_refuse(format('assigned_run: run %s is not one of your units'' runs', p_run_id));
END $$;
REVOKE ALL ON FUNCTION medcea._refuse_hidden_run(integer) FROM PUBLIC;

-- assigned_run: an operator executes only a run another person prepared while
-- holding C on runs freely, in one of the operator's units. Policy.
CREATE OR REPLACE FUNCTION medcea._check_assigned_run(r medcea.recipe_run, p_sub text, p_person text, p_role text) RETURNS void
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE how text := medcea_auth.policy_holds(p_role, 'runs', 'O');
BEGIN
    IF how IS NULL THEN
        PERFORM medcea_auth.policy_refuse(format('role %s holds no O on runs', coalesce(p_role, '<none>')));
        RETURN;
    END IF;
    IF how <> 'assigned_run' THEN
        RETURN;
    END IF;
    -- the unit first: the run tables' RLS hides other units' runs from an operator,
    -- so nothing about such a run (its creator, status, unit) may decide the answer
    IF p_sub IS NULL OR p_sub !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR NOT EXISTS (SELECT 1 FROM iam_policy.user_unit u
                       WHERE u.unit_id = r.unit_id AND u.person_sub = p_sub::uuid) THEN
        PERFORM medcea._refuse_hidden_run(r.recipe_run_id);
    END IF;
    IF r.created_by_person IS NOT DISTINCT FROM p_person THEN
        PERFORM medcea_auth.policy_refuse(format('assigned_run: run %s was created by the same person', r.recipe_run_id));
    END IF;
    IF medcea_auth.policy_holds(r.created_by_role, 'runs', 'C') IS DISTINCT FROM 'free' THEN
        PERFORM medcea_auth.policy_refuse(format('assigned_run: run %s was not prepared by a role that creates runs', r.recipe_run_id));
    END IF;
END $$;

-- start_run(run): S -> R, as the executor. Level O.
CREATE OR REPLACE FUNCTION medcea.start_run(p_run_id integer) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    a  record;
    r  medcea.recipe_run;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        RAISE EXCEPTION 'start_run: no actor' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO r FROM medcea.recipe_run WHERE recipe_run_id = p_run_id FOR UPDATE;
    IF NOT FOUND THEN
        IF medcea_auth.policy_holds(a.role, 'runs', 'O') IS NOT DISTINCT FROM 'assigned_run' THEN
            PERFORM medcea._refuse_hidden_run(p_run_id);   -- same answer as another unit's run
        END IF;
        RAISE EXCEPTION 'start_run: no run %', p_run_id USING ERRCODE = '22023';
    END IF;
    -- policy before structure: assigned_run (the unit first) precedes every
    -- status, transition, running-run and parameter check
    PERFORM medcea._check_assigned_run(r, a.sub, a.person, a.role);
    IF r.recipe_run_status <> 'S' THEN
        RAISE EXCEPTION 'start_run: run % is %, not S', p_run_id, r.recipe_run_status USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM medcea.recipe_run x WHERE x.unit_id = r.unit_id AND x.recipe_run_status = 'R'
                                                   AND x.recipe_run_id <> p_run_id) THEN
        RAISE EXCEPTION 'start_run: unit % already has a running run', r.unit_id USING ERRCODE = '22023';
    END IF;
    PERFORM medcea._check_run_params(r.unit_id, r.recipe_id, r.params_id, r.schedule_id);
    -- FOR SHARE: waits for a commissioning change in flight on the unit (propose and
    -- approve_change lock its row FOR NO KEY UPDATE), and holds one off until this
    -- run is R, which they then see (_unit_busy)
    PERFORM 1 FROM medcea.cea_unit u WHERE u.unit_id = r.unit_id FOR SHARE;
    IF (SELECT u.commissioning FROM medcea.cea_unit u WHERE u.unit_id = r.unit_id) THEN
        PERFORM medcea_auth.policy_refuse(format('commissioning: unit %s is flagged for commissioning', r.unit_id));
    END IF;
    IF NOT medcea_auth._is_approved('medcea.recipe', jsonb_build_array(r.recipe_id)) THEN
        PERFORM medcea_auth.policy_refuse(format('recipe %s is not approved, or changed since its approval', r.recipe_id));
    END IF;
    IF r.params_id IS NULL THEN
        PERFORM medcea_auth.policy_refuse(format('run %s has no approved parameter set', p_run_id));
    ELSIF NOT medcea_auth._is_approved('medcea.unit_algorithm_params', jsonb_build_array(r.params_id)) THEN
        PERFORM medcea_auth.policy_refuse(format('parameter set %s is not approved, or changed since its approval', r.params_id));
    END IF;
    PERFORM medcea_auth._owner_write(true);
    UPDATE medcea.recipe_run SET recipe_run_status = 'R', timestamp_upd = now(),
           executed_by_sub = a.sub, executed_by_person = a.person, executed_by_name = a.name,
           executed_by_role = a.role, executed_by_source = a.source
     WHERE recipe_run_id = p_run_id;
    PERFORM medcea_auth._owner_write(false);
END $$;

-- set_run_status(run, status): S -> F, R -> F (ends it), F -> S. Level O.
CREATE OR REPLACE FUNCTION medcea.set_run_status(p_run_id integer, p_status text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    a  record;
    r  medcea.recipe_run;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        RAISE EXCEPTION 'set_run_status: no actor' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO r FROM medcea.recipe_run WHERE recipe_run_id = p_run_id FOR UPDATE;
    IF NOT FOUND THEN
        IF medcea_auth.policy_holds(a.role, 'runs', 'O') IS NOT DISTINCT FROM 'assigned_run' THEN
            PERFORM medcea._refuse_hidden_run(p_run_id);   -- same answer as another unit's run
        END IF;
        RAISE EXCEPTION 'set_run_status: no run %', p_run_id USING ERRCODE = '22023';
    END IF;
    -- policy before structure: assigned_run (the unit first) precedes every
    -- status, transition, running-run and parameter check
    PERFORM medcea._check_assigned_run(r, a.sub, a.person, a.role);
    IF NOT ((r.recipe_run_status, p_status) IN (('S', 'F'), ('R', 'F'), ('F', 'S'))) THEN
        RAISE EXCEPTION 'set_run_status: % -> % is not a transition', r.recipe_run_status, p_status USING ERRCODE = '22023';
    END IF;
    IF p_status = 'S' THEN
        PERFORM medcea._unit_schedulable(r.unit_id);
    END IF;
    PERFORM medcea_auth._owner_write(true);
    UPDATE medcea.recipe_run SET recipe_run_status = p_status, timestamp_upd = now(),
           recipe_run_end = CASE WHEN p_status = 'F' THEN now() WHEN p_status = 'S' THEN NULL ELSE recipe_run_end END
     WHERE recipe_run_id = p_run_id;
    PERFORM medcea_auth._owner_write(false);
END $$;

-- finish_run(run, C|F): the runner ends a running run. Service only.
CREATE OR REPLACE FUNCTION medcea.finish_run(p_run_id integer, p_status text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE a record; st text;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        RAISE EXCEPTION 'finish_run: no actor' USING ERRCODE = '42501';
    END IF;
    IF p_status NOT IN ('C', 'F') THEN
        RAISE EXCEPTION 'finish_run: status must be C or F' USING ERRCODE = '22023';
    END IF;
    SELECT recipe_run_status INTO st FROM medcea.recipe_run WHERE recipe_run_id = p_run_id FOR UPDATE;
    IF st IS DISTINCT FROM 'R' THEN
        RAISE EXCEPTION 'finish_run: run % is %, not R', p_run_id, coalesce(st, 'missing') USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._owner_write(true);
    UPDATE medcea.recipe_run SET recipe_run_status = p_status, recipe_run_end = now(), timestamp_upd = now()
     WHERE recipe_run_id = p_run_id;
    PERFORM medcea_auth._owner_write(false);
END $$;

-- retire_schedule(schedule): the schedule stops firing and is kept (a schedule
-- is never deleted). Its last row stays as it was: schedule_retired_guard()
-- refuses any later edit of a retired schedule. Level U on schedules (checked:
-- a policy refusal, a WARNING while IAM_DB_ROLES=false).
CREATE OR REPLACE FUNCTION medcea.retire_schedule(p_schedule_id integer) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE a record; v_retired timestamptz;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        RAISE EXCEPTION 'retire_schedule: no actor' USING ERRCODE = '42501';
    END IF;
    SELECT s.retired_at INTO v_retired FROM medcea.schedule s WHERE s.schedule_id = p_schedule_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'retire_schedule: no schedule %', p_schedule_id USING ERRCODE = '22023';
    END IF;
    IF v_retired IS NOT NULL THEN
        RAISE EXCEPTION 'retire_schedule: schedule % is already retired', p_schedule_id USING ERRCODE = '22023';
    END IF;
    -- the actor's role must hold U on schedules (a person, or the creator a
    -- system actor acts for); an internal actor has no role: a WARNING while
    -- false, refused while true
    IF medcea_auth.policy_holds(a.role, 'schedules', 'U') IS NULL THEN
        PERFORM medcea_auth.policy_refuse(format('retire_schedule: role %s holds no U on schedules', coalesce(a.role, '<none>')));
    END IF;
    PERFORM medcea_auth._owner_write(true);
    UPDATE medcea.schedule SET retired_at = now(), enabled = false, timestamp_upd = now()
     WHERE schedule_id = p_schedule_id;
    PERFORM medcea_auth._owner_write(false);
END $$;

-- record_cycle(run, cycle): insert or close one cycle of a running run.
-- cycle = {recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num, status,
--          start?, end?, run_params?}. A completed cycle (C) is never reopened.
-- Service only.
CREATE OR REPLACE FUNCTION medcea.record_cycle(p_run_id integer, p_cycle jsonb) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE a record; st text; v_id integer; cst text;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        RAISE EXCEPTION 'record_cycle: no actor' USING ERRCODE = '42501';
    END IF;
    SELECT recipe_run_status INTO st FROM medcea.recipe_run WHERE recipe_run_id = p_run_id;
    IF st IS DISTINCT FROM 'R' THEN
        RAISE EXCEPTION 'record_cycle: run % is %, not R', p_run_id, coalesce(st, 'missing') USING ERRCODE = '22023';
    END IF;
    IF jsonb_typeof(p_cycle) IS DISTINCT FROM 'object' OR p_cycle ->> 'recipe_id' IS NULL
       OR p_cycle ->> 'recipe_item_seq_id' IS NULL OR p_cycle ->> 'recipe_item_seq_cycle_num' IS NULL
       OR p_cycle ->> 'status' IS NULL THEN
        RAISE EXCEPTION 'record_cycle: recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num and status are required'
            USING ERRCODE = '22023';
    END IF;
    -- the existing cycle, locked: a completed one stays completed
    SELECT c.recipe_line_cycle_run_status INTO cst FROM medcea.recipe_line_cycle_run c
     WHERE c.recipe_run_id = p_run_id AND c.recipe_id = (p_cycle ->> 'recipe_id')::integer
       AND c.recipe_item_seq_id = (p_cycle ->> 'recipe_item_seq_id')::integer
       AND c.recipe_item_seq_cycle_num = (p_cycle ->> 'recipe_item_seq_cycle_num')::integer
       FOR UPDATE;
    IF cst = 'C' THEN
        RAISE EXCEPTION 'record_cycle: cycle % of line % of run % is complete', p_cycle ->> 'recipe_item_seq_cycle_num',
            p_cycle ->> 'recipe_item_seq_id', p_run_id USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._owner_write(true);
    INSERT INTO medcea.recipe_line_cycle_run AS c
        (recipe_run_id, recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num,
         recipe_line_seq_cycle_run_start, recipe_line_seq_cycle_run_end, recipe_line_cycle_run_status, run_params)
    VALUES (p_run_id, (p_cycle ->> 'recipe_id')::integer, (p_cycle ->> 'recipe_item_seq_id')::integer,
            (p_cycle ->> 'recipe_item_seq_cycle_num')::integer,
            coalesce((p_cycle ->> 'start')::timestamptz, now()), (p_cycle ->> 'end')::timestamptz,
            p_cycle ->> 'status', (p_cycle -> 'run_params')::json)
    ON CONFLICT (recipe_run_id, recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num) DO UPDATE
       SET recipe_line_seq_cycle_run_end = coalesce(EXCLUDED.recipe_line_seq_cycle_run_end, c.recipe_line_seq_cycle_run_end),
           recipe_line_cycle_run_status = EXCLUDED.recipe_line_cycle_run_status,
           run_params = coalesce(EXCLUDED.run_params, c.run_params),
           timestamp_upd = now()
    RETURNING recipe_line_cycle_run_id INTO v_id;
    PERFORM medcea_auth._owner_write(false);
    RETURN v_id;
END $$;

-- release_run(run, note): qp releases a completed run nobody it authored or
-- executed (any attempt), whose creator and a start are recorded persons, with an optional note (run_release.note and
-- approval.note). Level A. No DEFAULT on the note, as approve_recipe(id, note):
-- the 1-argument version calls this one. approval_queue() mirrors these checks.
CREATE OR REPLACE FUNCTION medcea.release_run(p_run_id integer, p_note text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    ap   record;
    au   record;
    st   text;
    k    jsonb := jsonb_build_array(p_run_id);
    h    text;
    nt   text := nullif(btrim(p_note), '');
    v_id bigint;
BEGIN
    SELECT * INTO ap FROM medcea_auth._approver('runs');
    SELECT recipe_run_status INTO st FROM medcea.recipe_run WHERE recipe_run_id = p_run_id FOR UPDATE;
    IF st IS DISTINCT FROM 'C' THEN
        RAISE EXCEPTION 'release_run: run % is %, not completed', p_run_id, coalesce(st, 'missing') USING ERRCODE = '22023';
    END IF;
    -- after the run's lock: a release committed meanwhile is seen here
    IF EXISTS (SELECT 1 FROM medcea.run_release rl WHERE rl.recipe_run_id = p_run_id) THEN
        RAISE EXCEPTION 'release_run: run % is already released', p_run_id USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._lock_row('medcea.recipe_run', k);
    SELECT * INTO au FROM medcea_auth._authors('medcea.recipe_run', k);
    IF ap.person = ANY (au.persons)
       OR EXISTS (SELECT 1 FROM medcea.recipe_run r WHERE r.recipe_run_id = p_run_id AND r.executed_by_person = ap.person) THEN
        RAISE EXCEPTION 'not_own_author: % created, changed or executed run %', ap.person, p_run_id USING ERRCODE = '42501';
    END IF;
    IF au.unattributed > 0 THEN
        RAISE EXCEPTION 'unattributed changes: % change(s) to run % have no person', au.unattributed, p_run_id
            USING ERRCODE = '42501';
    END IF;
    -- a run from before 008b (created migration:008, no row_change) has no known creator
    -- or executor, so not_own_author proves nothing: it is never released
    IF EXISTS (SELECT 1 FROM medcea.recipe_run r WHERE r.recipe_run_id = p_run_id AND r.created_by_person IS NULL)
       OR NOT EXISTS (SELECT 1 FROM medcea.row_change c
                       WHERE c.target = 'medcea.recipe_run' AND c.row_key = k AND c.op IN ('I', 'U')
                         AND c.new_values ->> 'recipe_run_status' = 'R' AND c.actor_person IS NOT NULL) THEN
        RAISE EXCEPTION 'no attributed history: no recorded person created or started run %', p_run_id
            USING ERRCODE = '42501';
    END IF;
    h := medcea_auth.row_digest('medcea.recipe_run', k);
    INSERT INTO medcea.run_release (recipe_run_id, row_hash, note, released_by_sub, released_by_person, released_by_name,
                                    released_by_role, released_by_source)
    VALUES (p_run_id, h, nt, ap.sub, ap.person, ap.name, ap.role, ap.source);
    INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note, author_persons,
                                 approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source,
                                 last_change_id)
    VALUES ('medcea.recipe_run', k, h, 'runs', 'release', nt, au.persons, ap.sub, ap.person, ap.name, ap.role, ap.source,
            au.last_change)
    RETURNING approval_id INTO v_id;
    RETURN v_id;
END $$;

CREATE OR REPLACE FUNCTION medcea.release_run(p_run_id integer) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    RETURN medcea.release_run(p_run_id, NULL::text);
END $$;

-- retire_algorithm_state(unit, algorithm, reason): the next run starts cold.
-- Nothing is deleted; the event keeps the full state. Level A.
CREATE OR REPLACE FUNCTION medcea.retire_algorithm_state(p_unit_id integer, p_algorithm text, p_reason text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    ap  record;
    s   record;
    n   integer := 0;
BEGIN
    SELECT * INTO ap FROM medcea_auth._approver('controllers_state');
    IF coalesce(btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'retire_algorithm_state: a reason is required' USING ERRCODE = '22023';
    END IF;
    PERFORM set_config('medcea.state_reason', p_reason, true);
    FOR s IN SELECT * FROM medcea.algorithm_state
              WHERE unit_id = p_unit_id AND algorithm = p_algorithm AND retired_at IS NULL FOR UPDATE LOOP
        UPDATE medcea.algorithm_state SET retired_at = now()
         WHERE unit_id = s.unit_id AND algorithm = s.algorithm AND channel = s.channel;
        INSERT INTO medcea.approval (target, row_key, row_hash, group_name, action, note,
                                     approved_by_sub, approved_by_person, approved_by_name, approved_by_role, approved_by_source)
        VALUES ('medcea.algorithm_state', jsonb_build_array(s.unit_id, s.algorithm, s.channel),
                encode(sha256(convert_to(coalesce(s.state, '{}'::jsonb)::text, 'UTF8')), 'hex'),
                'controllers_state', 'retire', p_reason, ap.sub, ap.person, ap.name, ap.role, ap.source);
        n := n + 1;
    END LOOP;
    PERFORM set_config('medcea.state_reason', '', true);
    RETURN n;
END $$;

-- register_mqtt_credential v2 (device id, the board's serial, the hash): user,
-- role and topic come from the device row and platform_setting. Every refusal
-- is structural. EXECUTE: the holders of C on devices (grants.py).
CREATE OR REPLACE FUNCTION medcea.register_mqtt_credential(p_device_id integer, p_serial text, p_hash text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE
    d     record;
    root  text;
    cur   medcea.mqtt_credential;
BEGIN
    IF p_hash IS NULL OR p_hash !~ '^\$7\$[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$' THEN
        RAISE EXCEPTION 'register_mqtt_credential: the hash must be a mosquitto $7$ hash, not a password' USING ERRCODE = '22023';
    END IF;
    SELECT dv.device_id, dv.serial_number, dv.dns_name, dv.device_type, dv.is_active, u.unit_code, z.zone_code
      INTO d
      FROM medcea.device dv
      JOIN medcea.cea_zone z ON z.zone_id = dv.zone_id
      JOIN medcea.cea_unit u ON u.unit_id = z.unit_id
     WHERE dv.device_id = p_device_id
       FOR UPDATE OF dv;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'register_mqtt_credential: device % does not exist or has no slot', p_device_id USING ERRCODE = '22023';
    END IF;
    IF d.is_active IS DISTINCT FROM 'Y' THEN
        RAISE EXCEPTION 'register_mqtt_credential: device % is inactive', p_device_id USING ERRCODE = '22023';
    END IF;
    IF p_serial IS NULL OR p_serial IS DISTINCT FROM d.serial_number THEN
        RAISE EXCEPTION 'register_mqtt_credential: serial % is not device %''s board', p_serial, p_device_id USING ERRCODE = '42501';
    END IF;
    IF upper(d.device_type) NOT IN ('SENSE', 'CONTROL') THEN
        RAISE EXCEPTION 'register_mqtt_credential: device % is a %, not SENSE or CONTROL', p_device_id, d.device_type
            USING ERRCODE = '22023';
    END IF;
    IF d.unit_code !~ '^[A-Za-z0-9_-]+$' OR d.zone_code !~ '^[A-Za-z0-9_-]+$' THEN
        RAISE EXCEPTION 'register_mqtt_credential: unit % / zone % cannot be a topic segment; rename it', d.unit_code, d.zone_code
            USING ERRCODE = '22023';
    END IF;
    IF d.dns_name ~ '[:\s]' OR d.dns_name = '' THEN
        RAISE EXCEPTION 'register_mqtt_credential: device name % cannot be a broker user', d.dns_name USING ERRCODE = '22023';
    END IF;
    SELECT s.value INTO root FROM medcea.platform_setting s WHERE s.key = 'mqtt_topic_root';
    IF root IS NULL THEN
        RAISE EXCEPTION 'register_mqtt_credential: mqtt_topic_root is not set (apps/database/deploy.sh)' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO cur FROM medcea.mqtt_credential WHERE device_id = p_device_id;
    IF FOUND AND cur.active AND cur.serial_number IS DISTINCT FROM p_serial THEN
        RAISE EXCEPTION 'register_mqtt_credential: device % has an active credential of another board', p_device_id
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM medcea.mqtt_credential c WHERE c.username = d.dns_name AND c.device_id <> p_device_id AND c.active) THEN
        RAISE EXCEPTION 'register_mqtt_credential: % is the active credential of another device', d.dns_name USING ERRCODE = '42501';
    END IF;
    DELETE FROM medcea.mqtt_credential WHERE device_id = p_device_id AND username <> d.dns_name;
    DELETE FROM medcea.mqtt_credential WHERE username = d.dns_name AND device_id <> p_device_id;
    INSERT INTO medcea.mqtt_credential (username, password_hash, device_id, role, topic_base, serial_number)
    VALUES (d.dns_name, p_hash, p_device_id, upper(d.device_type), root || '/' || d.unit_code || '/' || d.zone_code, p_serial)
    ON CONFLICT (username) DO UPDATE
       SET password_hash = EXCLUDED.password_hash, device_id = EXCLUDED.device_id, role = EXCLUDED.role,
           topic_base = EXCLUDED.topic_base, serial_number = EXCLUDED.serial_number, active = true, updated_at = now();
    RETURN d.dns_name;
END $$;

-- v1 (migration 007), same signature: also records the board's serial.
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
    INSERT INTO medcea.mqtt_credential (username, password_hash, device_id, role, topic_base, serial_number)
    VALUES (p_username, p_password_hash, p_device_id, upper(p_role), p_topic_base,
            (SELECT d.serial_number FROM medcea.device d WHERE d.device_id = p_device_id))
    ON CONFLICT (username) DO UPDATE
       SET password_hash = EXCLUDED.password_hash, device_id = EXCLUDED.device_id,
           role = EXCLUDED.role, topic_base = EXCLUDED.topic_base, serial_number = EXCLUDED.serial_number,
           active = true, updated_at = now();
END $$;

-- ── The enforce trigger functions (attached by medcea_db_migrations_008b_enforce.sql) ─

-- draft_only: only a draft is edited (approved -> retired alone excepted); a
-- recipe line only while its recipe (OLD and NEW) is a draft. INVOKER.
CREATE OR REPLACE FUNCTION medcea.reject_non_draft_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = medcea, pg_temp AS $$
DECLARE
    changed boolean;
    old_id  integer;
    new_id  integer;
BEGIN
    IF current_user = 'medcea_owner' THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'recipe_line' THEN
        IF TG_OP <> 'INSERT' THEN old_id := OLD.recipe_id; END IF;
        IF TG_OP <> 'DELETE' THEN new_id := NEW.recipe_id; END IF;
        -- The parent's status is read under a lock (the same mode as
        -- guard_control_columns, which fires after this trigger), so an
        -- approval cannot commit between this check and the line's write.
        PERFORM 1 FROM medcea.recipe r WHERE r.recipe_id IN (old_id, new_id)
         ORDER BY r.recipe_id FOR NO KEY UPDATE;
        IF EXISTS (SELECT 1 FROM medcea.recipe r WHERE r.status <> 'draft' AND r.recipe_id IN (old_id, new_id)) THEN
            RAISE EXCEPTION 'draft_only: the recipe of this line is not a draft; a change starts a new draft'
                USING ERRCODE = '42501';
        END IF;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF OLD.status = 'draft' THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'approved' AND NEW.status = 'retired' THEN
        changed := (SELECT jsonb_object_agg(k, v) FROM jsonb_each(to_jsonb(OLD)) x(k, v)
                     WHERE NOT (k LIKE '%\_by\_%' OR k LIKE 'timestamp\_%' OR k IN ('status', 'retired_at')))
                   IS DISTINCT FROM
                   (SELECT jsonb_object_agg(k, v) FROM jsonb_each(to_jsonb(NEW)) x(k, v)
                     WHERE NOT (k LIKE '%\_by\_%' OR k LIKE 'timestamp\_%' OR k IN ('status', 'retired_at')));
        IF NOT changed THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION 'draft_only: %.% is %, not a draft; a change starts a new draft', TG_TABLE_SCHEMA, TG_TABLE_NAME, OLD.status
        USING ERRCODE = '42501';
END $$;

-- Regulated records: insert_too (cycles: owner only), no_owner (telemetry:
-- nobody changes or deletes a row), default (runs: owner only). INVOKER.
CREATE OR REPLACE FUNCTION medcea.immutable_row() RETURNS trigger
    LANGUAGE plpgsql SET search_path = medcea, pg_temp AS $$
DECLARE variant text := coalesce(TG_ARGV[0], 'owner_exempt');
BEGIN
    IF variant <> 'no_owner' AND current_user = 'medcea_owner' THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '%.% is a regulated record: % refused (use its functions)', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = '42501';
END $$;

-- A new run is scheduled (S), executed by nobody yet, with a parameter set of
-- its unit and algorithm.
CREATE OR REPLACE FUNCTION medcea.new_run_defaults() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    PERFORM medcea._unit_schedulable(NEW.unit_id);
    NEW.recipe_run_status := 'S';
    NEW.executed_by_sub := NULL; NEW.executed_by_person := NULL; NEW.executed_by_name := NULL;
    NEW.executed_by_role := NULL; NEW.executed_by_source := NULL;
    PERFORM medcea._check_run_params(NEW.unit_id, NEW.recipe_id, NEW.params_id, NEW.schedule_id);
    RETURN NEW;
END $$;

-- The 3-argument _check_run_params of the first 2a build: both callers above
-- now pass the run's schedule.
DROP FUNCTION IF EXISTS medcea._check_run_params(integer, integer, integer);

-- Q-tables: the owner may do anything; svc_scheduler may change state and
-- updated_at only (a state write clears retired_at through
-- algorithm_state_before_trg, which fires first); nobody else. INVOKER.
CREATE OR REPLACE FUNCTION medcea.algorithm_state_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = medcea, pg_temp AS $$
BEGIN
    IF current_user = 'medcea_owner' THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'algorithm_state: retire it (retire_algorithm_state), never delete it' USING ERRCODE = '42501';
    END IF;
    IF current_user = 'svc_scheduler'
       AND (to_jsonb(NEW) - 'state' - 'updated_at' - 'retired_at') = (to_jsonb(OLD) - 'state' - 'updated_at' - 'retired_at')
       AND (NEW.retired_at IS NOT DISTINCT FROM OLD.retired_at
            OR (NEW.state IS DISTINCT FROM OLD.state AND NEW.retired_at IS NULL)) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'algorithm_state: only the scheduler''s state writes are allowed' USING ERRCODE = '42501';
END $$;

-- assign_only: an allowed assignment points to an approved, unchanged recipe
-- and parameter set (of that unit). Every caller.
CREATE OR REPLACE FUNCTION medcea.assign_only() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
BEGIN
    IF NEW.allowed IS NOT TRUE THEN
        RETURN NEW;                    -- withdrawing an assignment is always possible
    END IF;
    IF NOT medcea_auth._is_approved('medcea.recipe', jsonb_build_array(NEW.recipe_id)) THEN
        PERFORM medcea_auth.policy_refuse(format('assign_only: recipe %s is not approved, or changed since', NEW.recipe_id));
    END IF;
    IF NEW.params_id IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM medcea.unit_algorithm_params s WHERE s.params_id = NEW.params_id
                      AND s.unit_id IS NOT NULL AND s.unit_id <> NEW.unit_id) THEN
            RAISE EXCEPTION 'parameter set % belongs to another unit', NEW.params_id USING ERRCODE = '22023';
        END IF;
        IF NOT medcea_auth._is_approved('medcea.unit_algorithm_params', jsonb_build_array(NEW.params_id)) THEN
            PERFORM medcea_auth.policy_refuse(format('assign_only: parameter set %s is not approved, or changed since', NEW.params_id));
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- existing_slot: a role holding devices C only under existing_slot registers a
-- board only into a slot that already has a device row (inactive or replaced).
CREATE OR REPLACE FUNCTION medcea.existing_slot() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = medcea, pg_temp AS $$
DECLARE a record;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF medcea_auth.policy_holds(a.role, 'devices', 'C') IS DISTINCT FROM 'existing_slot' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.zone_id IS NOT DISTINCT FROM OLD.zone_id
       AND NEW.device_type IS NOT DISTINCT FROM OLD.device_type THEN
        RETURN NEW;                    -- re-onboarding in place
    END IF;
    IF NOT EXISTS (SELECT 1 FROM medcea.device d
                    WHERE d.zone_id = NEW.zone_id AND d.device_type = NEW.device_type
                      AND d.device_id IS DISTINCT FROM NEW.device_id
                      AND d.is_active IS DISTINCT FROM 'Y') THEN
        PERFORM medcea_auth.policy_refuse(format('existing_slot: zone %s has no %s slot to re-onboard into; a new slot is an engineer''s change',
                                                 NEW.zone_id, NEW.device_type));
    END IF;
    RETURN NEW;
END $$;

-- ── Ownership: every object in medcea, medcea_auth, iam_policy is medcea_owner's
-- (the same normalisation as medcea_db_owner.sql, here so this transaction's
-- definer functions never meet a table their owner cannot read).
DO $$
DECLARE
    r       record;
    v_owner oid := 'medcea_owner'::regrole;
    schemas oid[] := ARRAY(SELECT oid FROM pg_catalog.pg_namespace
                            WHERE nspname IN ('medcea', 'medcea_auth', 'iam_policy'));
BEGIN
    FOR r IN SELECT nspname FROM pg_catalog.pg_namespace
              WHERE oid = ANY (schemas) AND nspowner <> v_owner LOOP
        EXECUTE pg_catalog.format('ALTER SCHEMA %I OWNER TO medcea_owner', r.nspname);
    END LOOP;
    -- Relations; a sequence owned by a column follows its table (ALTER TABLE
    -- recurses to it, and refuses to change it alone).
    FOR r IN SELECT c.oid::regclass AS rel, c.relkind FROM pg_catalog.pg_class c
              WHERE c.relnamespace = ANY (schemas) AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                AND c.relowner <> v_owner
                AND NOT (c.relkind = 'S' AND EXISTS (
                         SELECT 1 FROM pg_catalog.pg_depend d
                          WHERE d.objid = c.oid AND d.classid = 'pg_catalog.pg_class'::regclass
                            AND d.refclassid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i')))
              ORDER BY c.relkind = 'S', c.oid LOOP
        EXECUTE pg_catalog.format('ALTER %s %s OWNER TO medcea_owner',
            CASE r.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'S' THEN 'SEQUENCE'
                           WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END, r.rel);
    END LOOP;
    FOR r IN SELECT p.oid::regprocedure AS f, p.prokind FROM pg_catalog.pg_proc p
              WHERE p.pronamespace = ANY (schemas) AND p.proowner <> v_owner LOOP
        EXECUTE pg_catalog.format('ALTER %s %s OWNER TO medcea_owner',
            CASE r.prokind WHEN 'p' THEN 'PROCEDURE' WHEN 'a' THEN 'AGGREGATE' ELSE 'FUNCTION' END, r.f);
    END LOOP;
    -- Domains and standalone types (not a table's row type, not an array type).
    FOR r IN SELECT t.oid::regtype AS typ, t.typtype FROM pg_catalog.pg_type t
              WHERE t.typnamespace = ANY (schemas) AND t.typowner <> v_owner
                AND t.typtype IN ('d', 'e', 'r', 'c') AND t.typelem = 0
                AND (t.typrelid = 0 OR (SELECT c.relkind FROM pg_catalog.pg_class c WHERE c.oid = t.typrelid) = 'c') LOOP
        EXECUTE pg_catalog.format('ALTER %s %s OWNER TO medcea_owner',
            CASE r.typtype WHEN 'd' THEN 'DOMAIN' ELSE 'TYPE' END, r.typ);
    END LOOP;
END $$;

-- The two sequences the original dump left unowned: OWNED BY ties them to
-- their column (and so to the table's owner and grants).
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES ('medcea.cea_zone_zone_id_seq', 'medcea.cea_zone', 'zone_id'),
                                   ('medcea.recipe_recipe_id_seq', 'medcea.recipe', 'recipe_id')) v(seq, tab, col) LOOP
        IF pg_catalog.to_regclass(r.seq) IS NOT NULL AND pg_catalog.to_regclass(r.tab) IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                            WHERE d.objid = pg_catalog.to_regclass(r.seq) AND d.classid = 'pg_catalog.pg_class'::regclass
                              AND d.refclassid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i')) THEN
            IF (SELECT relowner FROM pg_catalog.pg_class WHERE oid = pg_catalog.to_regclass(r.seq)) <> 'medcea_owner'::regrole THEN
                EXECUTE pg_catalog.format('ALTER SEQUENCE %s OWNER TO medcea_owner', pg_catalog.to_regclass(r.seq));
            END IF;
            EXECUTE pg_catalog.format('ALTER SEQUENCE %s OWNED BY %s.%I', pg_catalog.to_regclass(r.seq),
                                      pg_catalog.to_regclass(r.tab), r.col);
        END IF;
    END LOOP;
END $$;

-- ── B21. Ownership, PUBLIC and the tail ─────────────────────────────────────
DO $$
DECLARE f regprocedure;
BEGIN
    FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
              WHERE p.pronamespace IN ('medcea'::regnamespace, 'medcea_auth'::regnamespace, 'iam_policy'::regnamespace) LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        IF (SELECT proowner FROM pg_catalog.pg_proc WHERE oid = f) <> 'medcea_owner'::regrole THEN
            EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO medcea_owner', f);
        END IF;
    END LOOP;
    -- schema iam (apps/access/access_db.sql): every function loses PUBLIC EXECUTE
    -- (trigger firing never checks it; the decision functions are granted by the
    -- compiled policy). Its ownership is medcea_db_owner.sql's (IAM 2.7), not
    -- 008b's: 008b does not depend on the access component.
    IF pg_catalog.to_regnamespace('iam') IS NOT NULL THEN
        FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
                  WHERE p.pronamespace = 'iam'::regnamespace LOOP
            EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        END LOOP;
    END IF;
END $$;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE medcea_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

COMMENT ON TABLE medcea.approval IS 'Append-only approvals: approve, review, apply, release, retire and the one-time grandfather of definitions in use before 008b; return (qa sends work back) and withdraw (the proposer takes a proposal back), which no approval rule counts. Written by the approval functions only.';
COMMENT ON TABLE medcea.row_change IS 'Append-only log of every change to the 14 attributed tables, with the verified actor; not_own_author reads it.';
COMMENT ON TABLE medcea.pending_change IS 'Append-only blocking changes (log retention, commissioning) waiting for approve_change(), or (applied_at) a commissioning off that applied at once and waits for qa''s review; closed by an approval row (apply, review, return, withdraw).';
COMMENT ON TABLE medcea.run_release IS 'Append-only release of completed runs by a person who neither created, changed nor executed them.';
COMMENT ON TABLE medcea.algorithm_state_event IS 'Append-only events of the controller state (Q-tables): writes as hashes, retirement and deletion with the full state.';

NOTIFY pgrst, 'reload schema';

INSERT INTO medcea.platform_setting (key, value) VALUES ('008b:last_nonce', :'deploy_nonce')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

COMMIT;

-- ── Migration 008c: the access policy's versions (IAM Phase 4, slice 4.1) ───
-- (Design phase4-design-v3 §2 and §14.2.) Every database object Phase 4 needs:
-- the version table's new columns, the per-level entry table, the accepted
-- skeletons, the host-computed diffs, the approvals' signed tokens, the freeze
-- trigger and the functions of the policy's state machine. NOTHING CALLS THEM
-- in 4.1: iam-api, apply.sh and the Policy UI arrive in 4.2a–4.5, and no row is
-- written here.
--
-- Its own transaction, after 008b's, with the same deploy nonce, which
-- lib-db-apply.sh reads back as 008c:last_nonce. Re-run on every database
-- deploy, so it writes no row (once version 1 exists the freeze trigger would
-- refuse one) and every ALTER TABLE is guarded by a catalog check: a steady-state
-- re-run takes no ACCESS EXCLUSIVE or SHARE lock on any table.
--
-- Who writes what:
--   * iam_policy.version, entry, waiver, skeleton, version_diff and
--     approval_evidence are written only by the definer functions below, which
--     run as medcea_owner and open with iam_policy._begin(), which sets the
--     transaction-local marker iam_policy.transition = '<function>:<v>:<txid>'.
--     The freeze trigger (SECURITY INVOKER, ENABLE ALWAYS) refuses any write
--     without that marker or by another role, any DELETE (but a draft's
--     entries, replaced by save_entry) and TRUNCATE, keeps a version on the
--     edges of its state machine and records every status change itself
--     (status_changed in the hash chain).
--   * Authors (draft, edit, submit, withdraw) act through iam-api as iam_svc,
--     with set_actor (medcea_auth._person_actor('iam_svc', ...)).
--   * qa approves, returns, confirms and disputes with their own token through
--     PostgREST, on the wrappers medcea.*_policy (schema medcea is the one
--     PostgREST exposes), which only a token of the policy host's client may
--     call (pre_request's only_rpc block and medcea_auth._rpc_client, both
--     compiled by grants.py). The signed token is kept as evidence.
--   * apply.sh (4.2a on) builds, applies, reverts and records as postgres
--     through the owner-only functions, actor system:apply.
-- Refusals: 42501 who may not, 22023 a wrong state, 23505 a race, 55000 a
-- missing component (the access deploy's iam._changed_since).

BEGIN;
SET LOCAL lock_timeout = '5s';

-- 1. A down file (medcea_db_migrations_down_008c.sql) may have parked three
--    tables in schema iam_policy_retired_008c: bring them back, with their rows.
DO $$
DECLARE t text;
BEGIN
    IF pg_catalog.to_regnamespace('iam_policy_retired_008c') IS NULL THEN
        RETURN;
    END IF;
    FOREACH t IN ARRAY ARRAY['skeleton', 'version_diff', 'approval_evidence'] LOOP
        IF pg_catalog.to_regclass('iam_policy_retired_008c.' || t) IS NOT NULL
           AND pg_catalog.to_regclass('iam_policy.' || t) IS NULL THEN
            EXECUTE pg_catalog.format('ALTER TABLE iam_policy_retired_008c.%I SET SCHEMA iam_policy', t);
        END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class
                    WHERE relnamespace = 'iam_policy_retired_008c'::regnamespace) THEN
        DROP SCHEMA iam_policy_retired_008c;
    END IF;
END $$;

-- 2. iam_policy.entry, one row per level. 008a's shape (levels char(1)[],
--    applies_to) cannot hold {R: own_unit, O: assigned_run}; nothing ever wrote
--    it, so the old shape is dropped while empty, and refused otherwise. The
--    guard tests the column, never the rows, once the new shape exists.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                WHERE attrelid = pg_catalog.to_regclass('iam_policy.entry') AND attname = 'levels' AND NOT attisdropped) THEN
        IF EXISTS (SELECT 1 FROM iam_policy.entry) THEN
            RAISE EXCEPTION 'iam_policy.entry has rows in the pre-008c shape: nothing writes them before 008c; restore from backup or move them away'
                USING ERRCODE = '55000';
        END IF;
        DROP TABLE iam_policy.entry;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS iam_policy.entry (
    version          int NOT NULL REFERENCES iam_policy.version,
    role             text NOT NULL REFERENCES iam_policy.role,
    group_code       text NOT NULL REFERENCES iam_policy.resource_group,
    level            char(1) NOT NULL CHECK (level IN ('R', 'X', 'C', 'U', 'A', 'O', 'K', 'D')),
    constraint_name  text,             -- NULL = unconstrained at this level
    PRIMARY KEY (version, role, group_code, level)
);

-- 3. Added columns, each only when pg_attribute lacks it (no lock otherwise).
--    resource_group.retired: _sync_skeleton marks a group that left the skeleton,
--    as role.retired (008a) does for a role.
DO $$
DECLARE c text[];
BEGIN
    FOREACH c SLICE 1 IN ARRAY ARRAY[
        ['waiver', 'objects', $t$text[] NOT NULL DEFAULT '{}'$t$],
        ['resource_group', 'retired', 'boolean NOT NULL DEFAULT false'],
        ['version', 'kind', $t$text NOT NULL DEFAULT 'change'$t$],
        ['version', 'based_on', 'integer'],
        ['version', 'rollback_of', 'integer'],
        ['version', 'groups', 'text[]'],
        ['version', 'roles', 'text[]'],
        ['version', 'created_by_person', 'text'],
        ['version', 'created_by_name', 'text'],
        ['version', 'created_at', 'timestamptz NOT NULL DEFAULT now()'],
        ['version', 'submitted_by_sub', 'uuid'],
        ['version', 'submitted_by_name', 'text'],
        ['version', 'submitted_at', 'timestamptz'],
        ['version', 'approved_by_name', 'text'],
        ['version', 'approval_note', 'text'],
        ['version', 'approved_iat', 'double precision'],
        ['version', 'returned_at', 'timestamptz'],
        ['version', 'return_note', 'text'],
        ['version', 'withdrawn_at', 'timestamptz'],
        ['version', 'withdrawn_by_sub', 'uuid'],
        ['version', 'withdrawn_by', 'text'],
        ['version', 'superseded_at', 'timestamptz'],
        ['version', 'confirmed_by_sub', 'uuid'],
        ['version', 'confirm_note', 'text'],
        ['version', 'disputed_at', 'timestamptz'],
        ['version', 'disputed_by_person', 'text'],
        ['version', 'dispute_note', 'text'],
        ['version', 'entries_digest', 'text'],
        ['version', 'skeleton_digest', 'text'],
        ['version', 'approved_skeleton_digest', 'text'],
        ['version', 'diff_digest', 'text'],
        ['version', 'artefact_digests', 'jsonb'],
        ['version', 'claimed_by_os', 'text'],
        ['version', 'claimed_by_person', 'text'],
        ['version', 'claimed_by_sub', 'uuid'],
        ['version', 'apply_log', 'text'],
        ['version', 'apply_log_sha256', 'text']] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute
                        WHERE attrelid = pg_catalog.to_regclass('iam_policy.' || c[1]) AND attname = c[2] AND NOT attisdropped) THEN
            EXECUTE pg_catalog.format('ALTER TABLE iam_policy.%I ADD COLUMN %I %s', c[1], c[2], c[3]);
        END IF;
    END LOOP;
END $$;

-- 4. New tables. Owner-written through the functions below only.
CREATE TABLE IF NOT EXISTS iam_policy.skeleton (
    digest               text PRIMARY KEY,      -- sha256 of the canonical skeleton (compiler/source.py)
    body                 jsonb NOT NULL,
    git_commit           text,
    compiler_digest      text,
    accepted_at          timestamptz,           -- NULL: proposed (a skeleton version), never accepted
    accepted_event       bigint,                -- iam_policy.history event_id of skeleton_accepted
    reviewed_by_version  int                    -- the skeleton version qa approved, if any
);
CREATE TABLE IF NOT EXISTS iam_policy.version_diff (
    version      int PRIMARY KEY REFERENCES iam_policy.version,
    diff         jsonb NOT NULL,
    diff_digest  text NOT NULL,
    computed_on  text NOT NULL CHECK (computed_on = 'host')
);
CREATE TABLE IF NOT EXISTS iam_policy.approval_evidence (
    version      int REFERENCES iam_policy.version,
    history_id   bigint,
    event        text NOT NULL,
    jws          text NOT NULL,
    claims       jsonb NOT NULL,
    recorded_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (version, history_id)
);
REVOKE ALL ON iam_policy.entry, iam_policy.skeleton, iam_policy.version_diff, iam_policy.approval_evidence
    FROM PUBLIC, anon, authenticator;

-- 5. iam_policy.version: named CHECKs, replaced only when pg_get_constraintdef()
--    differs from the wanted text (deparsed from a temporary copy of the table,
--    so the comparison never depends on how PostgreSQL prints an expression);
--    foreign keys and the one-open index added only when their name is missing.
DO $$
DECLARE r record; want text; have text;
BEGIN
    CREATE TEMPORARY TABLE iam_008c_shape (LIKE iam_policy.version) ON COMMIT DROP;
    FOR r IN SELECT * FROM (VALUES
        ('version_status_check', $c$status IN ('draft', 'submitted', 'approved', 'applied', 'superseded', 'withdrawn')$c$),
        ('version_kind_check', $c$kind IN ('bootstrap', 'change', 'skeleton', 'rollback')$c$),
        ('version_rollback_check', $c$(kind = 'rollback') = (rollback_of IS NOT NULL)$c$),
        ('version_built_check', $c$kind NOT IN ('bootstrap', 'rollback') OR status IN ('draft', 'applied', 'superseded', 'withdrawn')$c$)
    ) v(name, expr) LOOP
        EXECUTE pg_catalog.format('ALTER TABLE pg_temp.iam_008c_shape ADD CONSTRAINT %I CHECK (%s)', r.name, r.expr);
        SELECT pg_catalog.pg_get_constraintdef(c.oid) INTO want FROM pg_catalog.pg_constraint c
         WHERE c.conrelid = 'pg_temp.iam_008c_shape'::regclass AND c.conname = r.name;
        have := NULL;
        SELECT pg_catalog.pg_get_constraintdef(c.oid) INTO have FROM pg_catalog.pg_constraint c
         WHERE c.conrelid = 'iam_policy.version'::regclass AND c.conname = r.name;
        IF have IS DISTINCT FROM want THEN
            EXECUTE pg_catalog.format('ALTER TABLE iam_policy.version DROP CONSTRAINT IF EXISTS %I', r.name);
            EXECUTE pg_catalog.format('ALTER TABLE iam_policy.version ADD CONSTRAINT %I CHECK (%s)', r.name, r.expr);
        END IF;
    END LOOP;
    DROP TABLE pg_temp.iam_008c_shape;
    FOR r IN SELECT * FROM (VALUES
        ('version_based_on_fkey', 'FOREIGN KEY (based_on) REFERENCES iam_policy.version (version)'),
        ('version_rollback_of_fkey', 'FOREIGN KEY (rollback_of) REFERENCES iam_policy.version (version)'),
        ('version_skeleton_digest_fkey', 'FOREIGN KEY (skeleton_digest) REFERENCES iam_policy.skeleton (digest)'),
        ('version_approved_skeleton_fkey', 'FOREIGN KEY (approved_skeleton_digest) REFERENCES iam_policy.skeleton (digest)')
    ) v(name, def) LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint c
                        WHERE c.conrelid = 'iam_policy.version'::regclass AND c.conname = r.name) THEN
            EXECUTE pg_catalog.format('ALTER TABLE iam_policy.version ADD CONSTRAINT %I %s', r.name, r.def);
        END IF;
    END LOOP;
    -- one change or skeleton version in flight; bootstrap and rollback versions are
    -- built and applied in one transaction and never count
    IF pg_catalog.to_regclass('iam_policy.one_open') IS NULL THEN
        CREATE UNIQUE INDEX one_open ON iam_policy.version ((true))
            WHERE status IN ('draft', 'submitted', 'approved') AND kind IN ('change', 'skeleton');
    END IF;
END $$;

-- 6. Functions. Every one SET search_path = pg_catalog, pg_temp, with qualified
--    names. Owner-only unless the policy grants EXECUTE (defaults.yaml: the
--    iam_policy group's members and infrastructure_functions).

-- The hash chain's writer (008b B16's body, unchanged) is owner-only from 008c on:
-- iam_policy._append_history. iam_policy.append_history, which iam_svc may
-- execute (iam-api's mqtt_credential_issued; defaults.yaml), is a filter in
-- front of it that refuses every event the policy's versions are read from
-- (new_draft's guard, _authors, audit_versions, the health rules): those are
-- written only by the functions below, through _append_history. A definer
-- function cannot tell its caller (current_user is medcea_owner either way), so
-- the line is the function, not the caller.
CREATE OR REPLACE FUNCTION iam_policy._append_history(p_event text, p_payload jsonb, p_reason text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam_policy, pg_temp AS $$
DECLARE
    v_id      bigint;
    v_at      timestamptz := now();
    a         record;
    v_sub     uuid;
    v_person  text;
    v_name    text;
    v_version int;
    v_prev    text;
BEGIN
    IF coalesce(btrim(p_event), '') = '' THEN
        RAISE EXCEPTION '_append_history: event is required';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION '_append_history needs READ COMMITTED (is %): a transaction snapshot could miss the head',
            current_setting('transaction_isolation');
    END IF;
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        v_name := 'db:' || session_user;
    ELSIF a.sub ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        v_sub := a.sub::uuid; v_person := a.person; v_name := a.name;
    ELSE
        v_person := a.person; v_name := a.sub;
    END IF;
    p_payload := coalesce(p_payload, '{}'::jsonb);
    IF jsonb_typeof(p_payload -> 'version') = 'number' THEN
        v_version := (p_payload ->> 'version')::int;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('iam_policy.history'));
    SELECT h.hash INTO v_prev FROM iam_policy.history h ORDER BY h.event_id DESC LIMIT 1;
    v_prev := coalesce(v_prev, repeat('0', 64));
    v_id := nextval(pg_get_serial_sequence('iam_policy.history', 'event_id'));
    INSERT INTO iam_policy.history
        (event_id, at, actor_sub, actor_person, actor_name, event, version, reason, payload, prev_hash, hash)
    VALUES (v_id, v_at, v_sub, v_person, v_name, p_event, v_version, p_reason, p_payload, v_prev,
            encode(sha256(convert_to(iam_policy.history_record(
                v_id, v_at, v_sub, v_person, v_name, p_event, v_version, p_reason, p_payload, v_prev), 'UTF8')), 'hex'));
    RETURN v_id;
END $$;
CREATE OR REPLACE FUNCTION iam_policy.append_history(p_event text, p_payload jsonb, p_reason text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    e text := pg_catalog.lower(p_event);
BEGIN
    -- IAM 4.2a (critique sec-11): compared case-insensitively, with the prefixes of
    -- every apply.sh and deploy event, so no near-copy of a policy event name passes
    IF e IN ('draft_created', 'entry_saved', 'submitted', 'approved', 'returned', 'withdrawn',
             'confirmed', 'disputed', 'status_changed', 'apply_started', 'applied', 'partial_apply',
             'bootstrap_applied', 'apply_reverted', 'break_glass_seen', 'break_glass_ended', 'apply_deferred',
             'account_seeded')
       OR e LIKE 'waiver\_%' OR e LIKE 'skeleton\_%' OR e LIKE 'break\_glass\_%' OR e LIKE 'apply\_%'
       OR e LIKE 'bootstrap\_%' OR e LIKE 'policy\_%' THEN
        RAISE EXCEPTION 'append_history: % is a policy version event, written only by the policy functions', p_event
            USING ERRCODE = '42501';
    END IF;
    -- iam-api's one event (iam-api.py): iam_svc appends nothing else
    IF session_user = 'iam_svc' AND p_event IS DISTINCT FROM 'mqtt_credential_issued' THEN
        RAISE EXCEPTION 'append_history: iam_svc writes only mqtt_credential_issued' USING ERRCODE = '42501';
    END IF;
    -- only the policy functions file an event under a version
    RETURN iam_policy._append_history(p_event, p_payload - 'version', p_reason);
END $$;

-- The compiled medcea_auth._rpc_client(text) (grants.py, database deploy step 4a)
-- replaces this stub, created only when missing: before the first compile no
-- wrapper accepts any client.
DO $$
BEGIN
    IF pg_catalog.to_regprocedure('medcea_auth._rpc_client(text)') IS NULL THEN
        CREATE FUNCTION medcea_auth._rpc_client(p_function text) RETURNS text
            LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $f$ SELECT NULL::text $f$;
    END IF;
END $$;

-- _begin(function, version): marks this transaction's writes as the named
-- policy function's. SECURITY INVOKER on purpose: called from a definer
-- function it sees medcea_owner, called by anyone else it refuses.
CREATE OR REPLACE FUNCTION iam_policy._begin(p_function text, p_version integer) RETURNS void
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF current_user <> 'medcea_owner' THEN
        RAISE EXCEPTION 'iam_policy._begin: only the policy functions (medcea_owner) write the policy, not %', current_user
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_catalog.set_config('iam_policy.transition',
        p_function || ':' || coalesce(p_version::text, '') || ':' || pg_catalog.txid_current()::text, true);
END $$;

-- _edge_ok(from, to, kind, function): the version state machine (design §2.3).
-- from NULL is the INSERT; function NULL asks only whether the edge exists
-- (audit_versions, for events recorded without one).
CREATE OR REPLACE FUNCTION iam_policy._edge_ok(p_from text, p_to text, p_kind text, p_function text) RETURNS boolean
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM (VALUES
        (NULL::text,   'draft',      '{change}'::text[],                          '{new_draft}'::text[]),
        (NULL,         'draft',      '{bootstrap,rollback}',                      '{_build_version}'),
        (NULL,         'submitted',  '{skeleton}',                                '{_propose_skeleton}'),
        ('draft',      'submitted',  '{change}',                                  '{submit}'),
        ('draft',      'withdrawn',  '{change}',                                  '{withdraw,_withdraw_open}'),
        ('submitted',  'draft',      '{change}',                                  '{return_version}'),
        ('submitted',  'withdrawn',  '{skeleton}',                                '{return_version}'),
        ('submitted',  'approved',   '{change,skeleton}',                         '{approve}'),
        ('submitted',  'withdrawn',  '{change,skeleton}',                         '{withdraw,_withdraw_open}'),
        ('approved',   'withdrawn',  '{change,skeleton}',                         '{withdraw,_withdraw_open}'),
        ('approved',   'applied',    '{change,skeleton}',                         '{_mark_applied}'),
        ('draft',      'applied',    '{bootstrap,rollback}',                      '{_mark_applied}'),
        ('applied',    'superseded', '{change,skeleton,bootstrap,rollback}',      '{_mark_applied}'),
        ('applied',    'approved',   '{change,skeleton}',                         '{_mark_reverted}'),
        ('superseded', 'applied',    '{change,skeleton,bootstrap,rollback}',      '{_mark_reverted}'),
        ('applied',    'withdrawn',  '{bootstrap,rollback}',                      '{_mark_reverted}')
    ) e(f, t, kinds, fns)
     WHERE e.f IS NOT DISTINCT FROM p_from AND e.t = p_to AND p_kind = ANY (e.kinds)
       AND (p_function IS NULL OR p_function = ANY (e.fns)))
$$;

-- _accepted(): the digest of the skeleton this host accepted last, or NULL.
CREATE OR REPLACE FUNCTION iam_policy._accepted() RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT s.digest FROM iam_policy.skeleton s WHERE s.accepted_at IS NOT NULL
     ORDER BY s.accepted_at DESC, s.accepted_event DESC NULLS LAST LIMIT 1
$$;

-- freeze_policy(): see the header. SECURITY INVOKER, so current_user is the
-- writer: medcea_owner inside a definer function, anyone else otherwise.
CREATE OR REPLACE FUNCTION iam_policy.freeze_policy() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    m        text := pg_catalog.current_setting('iam_policy.transition', true);
    fn       text;
    st       text;
    changed  text[];
    allowed  text[];
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'iam_policy.% cannot be truncated', TG_TABLE_NAME USING ERRCODE = '42501';
    END IF;
    fn := pg_catalog.split_part(coalesce(m, ''), ':', 1);
    IF current_user <> 'medcea_owner' OR coalesce(m, '') = ''
       OR pg_catalog.split_part(m, ':', 3) IS DISTINCT FROM pg_catalog.txid_current()::text THEN
        RAISE EXCEPTION 'iam_policy.% is written only by the policy functions (% refused)', TG_TABLE_NAME, TG_OP
            USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN
        -- a draft's cell is replaced (save_entry), nothing else is ever deleted
        IF TG_TABLE_NAME IN ('entry', 'waiver') AND fn IN ('save_entry', 'save_waiver', 'drop_waiver')
           AND (SELECT v.status FROM iam_policy.version v WHERE v.version = OLD.version) = 'draft' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'iam_policy.% rows are never deleted', TG_TABLE_NAME USING ERRCODE = '42501';
    END IF;
    IF TG_TABLE_NAME IN ('entry', 'waiver') THEN
        IF TG_OP = 'UPDATE' AND NEW.version IS DISTINCT FROM OLD.version THEN
            RAISE EXCEPTION 'iam_policy.% rows never move to another version', TG_TABLE_NAME USING ERRCODE = '22023';
        END IF;
        SELECT v.status INTO st FROM iam_policy.version v WHERE v.version = NEW.version;
        IF st = 'draft' OR (TG_OP = 'INSERT' AND fn = '_propose_skeleton' AND st = 'submitted') THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'version % is %: its entries and waivers are frozen', NEW.version, coalesce(st, 'missing')
            USING ERRCODE = '22023';
    ELSIF TG_TABLE_NAME = 'skeleton' THEN
        IF TG_OP = 'INSERT' AND fn IN ('_accept_skeleton', '_propose_skeleton') THEN
            RETURN NEW;
        END IF;
        IF TG_OP = 'UPDATE' AND fn = '_accept_skeleton' AND NEW.digest = OLD.digest AND NEW.body = OLD.body
           AND NEW.git_commit IS NOT DISTINCT FROM OLD.git_commit
           AND NEW.compiler_digest IS NOT DISTINCT FROM OLD.compiler_digest THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'iam_policy.skeleton: a skeleton never changes (% by %)', TG_OP, fn USING ERRCODE = '42501';
    ELSIF TG_TABLE_NAME = 'version_diff' THEN
        IF TG_OP = 'INSERT' AND fn = '_propose_skeleton' THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'iam_policy.version_diff: a stored diff never changes' USING ERRCODE = '42501';
    ELSIF TG_TABLE_NAME = 'approval_evidence' THEN
        IF TG_OP = 'INSERT' AND fn IN ('approve', 'return_version', 'confirm_applied', 'dispute_applied') THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'iam_policy.approval_evidence is append-only' USING ERRCODE = '42501';
    END IF;
    -- iam_policy.version: one edge per statement, only that edge's columns
    IF TG_OP = 'INSERT' THEN
        IF NOT iam_policy._edge_ok(NULL, NEW.status, NEW.kind, fn) THEN
            RAISE EXCEPTION 'a % version cannot start as % (by %)', NEW.kind, NEW.status, fn USING ERRCODE = '22023';
        END IF;
        PERFORM iam_policy._append_history('status_changed',
            pg_catalog.jsonb_build_object('version', NEW.version, 'from', NULL, 'to', NEW.status, 'kind', NEW.kind,
                                          'by_function', fn), NULL);
        RETURN NEW;
    END IF;
    SELECT coalesce(pg_catalog.array_agg(n.key ORDER BY n.key), '{}') INTO changed
      FROM pg_catalog.jsonb_each(pg_catalog.to_jsonb(NEW)) n
     WHERE n.value IS DISTINCT FROM pg_catalog.to_jsonb(OLD) -> n.key;
    allowed := CASE fn
        WHEN 'save_entry'       THEN '{checker_verdict,checker_digest}'
        WHEN 'submit'           THEN '{status,submitted_by_sub,submitted_by_person,submitted_by_name,submitted_at,skeleton_digest,entries_digest}'
        WHEN 'withdraw'         THEN '{status,withdrawn_at,withdrawn_by_sub,withdrawn_by}'
        WHEN '_withdraw_open'   THEN '{status,withdrawn_at,withdrawn_by_sub,withdrawn_by}'
        WHEN 'return_version'   THEN '{status,returned_at,return_note,withdrawn_at,withdrawn_by_sub,withdrawn_by}'
        WHEN 'approve'          THEN '{status,approved_by_person,approved_by_sub,approved_by_name,approved_at,approval_note,approved_iat,diff_digest,approved_skeleton_digest}'
        WHEN 'confirm_applied'  THEN '{confirmed_by_person,confirmed_by_sub,confirmed_at,confirm_note}'
        WHEN 'dispute_applied'  THEN '{disputed_at,disputed_by_person,dispute_note}'
        WHEN '_build_version'   THEN '{entries_digest}'
        WHEN '_propose_skeleton' THEN '{entries_digest}'
        WHEN '_mark_applied'    THEN '{status,applied_at,superseded_at,artefact_digests,claimed_by_os,claimed_by_person,claimed_by_sub,apply_log,apply_log_sha256}'
        WHEN '_mark_reverted'   THEN '{status,applied_at,superseded_at,withdrawn_at,withdrawn_by}'
        ELSE '{}' END::text[];
    IF NOT changed <@ allowed THEN
        RAISE EXCEPTION 'version %: % may not change %', NEW.version, fn, pg_catalog.array_to_string(changed, ', ')
            USING ERRCODE = '42501';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF NOT iam_policy._edge_ok(OLD.status, NEW.status, NEW.kind, fn) THEN
            RAISE EXCEPTION 'version % (%): % -> % is not a transition % makes', NEW.version, NEW.kind, OLD.status, NEW.status, fn
                USING ERRCODE = '22023';
        END IF;
        PERFORM iam_policy._append_history('status_changed',
            pg_catalog.jsonb_build_object('version', NEW.version, 'from', OLD.status, 'to', NEW.status, 'kind', NEW.kind,
                                          'by_function', fn), NULL);
    END IF;
    RETURN NEW;
END $$;

-- _changed_since(sub, person, iat): iam._changed_since (apps/access/access_db.sql)
-- when the access component is installed; 55000 otherwise, so 008c applies
-- without schema iam and a policy change without it fails closed.
CREATE OR REPLACE FUNCTION iam_policy._changed_since(p_sub text, p_person text, p_iat double precision) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r boolean;
BEGIN
    IF pg_catalog.to_regprocedure('iam._changed_since(text,text,double precision)') IS NULL THEN
        RAISE EXCEPTION 'policy changes need the access component: run ./apps/access/deploy.sh' USING ERRCODE = '55000';
    END IF;
    EXECUTE 'SELECT iam._changed_since($1, $2, $3)' INTO r USING p_sub, p_person, p_iat;
    RETURN coalesce(r, true);
END $$;

-- _authors(v): the actors of the version's draft_created, entry_saved,
-- waiver_saved, waiver_dropped and submitted events; for a skeleton version
-- also the claimed --by person (design §1.2).
CREATE OR REPLACE FUNCTION iam_policy._authors(p_version integer) RETURNS TABLE (sub text, person text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT DISTINCT h.actor_sub::text, h.actor_person FROM iam_policy.history h
     WHERE h.version = p_version
       AND h.event IN ('draft_created', 'entry_saved', 'waiver_saved', 'waiver_dropped', 'submitted')
       AND (h.actor_sub IS NOT NULL OR h.actor_person IS NOT NULL)
    UNION
    SELECT v.created_by_sub::text, v.created_by_person FROM iam_policy.version v
     WHERE v.version = p_version AND v.kind = 'skeleton'
       AND (v.created_by_sub IS NOT NULL OR v.created_by_person IS NOT NULL)
$$;

-- entries_digest(v): sha256 of the canonical jsonb text of {kind, groups, roles,
-- entries, waivers}: entries [role, group, level, constraint] ordered by role,
-- group, level (bytewise), waivers every column but version, ordered by id.
-- compiler/source.py entries_digest() reproduces it (fixture probe P2).
CREATE OR REPLACE FUNCTION iam_policy.entries_digest(p_version integer) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.jsonb_build_object(
        'kind', v.kind, 'groups', pg_catalog.to_jsonb(v.groups), 'roles', pg_catalog.to_jsonb(v.roles),
        'entries', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(e.role, e.group_code, e.level::text, e.constraint_name)
                                                  ORDER BY e.role COLLATE "C", e.group_code COLLATE "C", e.level::text COLLATE "C")
                               FROM iam_policy.entry e WHERE e.version = v.version), '[]'::jsonb),
        'waivers', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(w) - 'version' ORDER BY w.id COLLATE "C")
                               FROM iam_policy.waiver w WHERE w.version = v.version), '[]'::jsonb)
    )::text, 'UTF8')), 'hex')
      FROM iam_policy.version v WHERE v.version = p_version
$$;

-- _put_rows(v, entries, waivers): a new version's rows from jsonb
-- ([{role, group_code, level, constraint_name}], [{id, invariant, subject,
-- group_code (or group), target, levels, review_by, rationale, controls, objects}]),
-- the shapes of compiler/source.py entries_and_waivers(). Its callers hold the marker.
CREATE OR REPLACE FUNCTION iam_policy._put_rows(p_version integer, p_entries jsonb, p_waivers jsonb) RETURNS void
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF pg_catalog.jsonb_typeof(coalesce(p_entries, '[]')) <> 'array' OR pg_catalog.jsonb_typeof(coalesce(p_waivers, '[]')) <> 'array' THEN
        RAISE EXCEPTION 'entries and waivers must be JSON arrays' USING ERRCODE = '22023';
    END IF;
    INSERT INTO iam_policy.entry (version, role, group_code, level, constraint_name)
    SELECT p_version, e ->> 'role', e ->> 'group_code', e ->> 'level', nullif(e ->> 'constraint_name', '')
      FROM pg_catalog.jsonb_array_elements(coalesce(p_entries, '[]')) e;
    INSERT INTO iam_policy.waiver (version, id, invariant, subject, group_code, target, levels, review_by,
                                   rationale, controls, objects)
    SELECT p_version, w ->> 'id', w ->> 'invariant', w ->> 'subject', coalesce(w ->> 'group_code', w ->> 'group'),
           w ->> 'target',
           ARRAY(SELECT pg_catalog.jsonb_array_elements_text(coalesce(w -> 'levels', '[]')))::char(1)[],
           (w ->> 'review_by')::date, w ->> 'rationale', w ->> 'controls',
           ARRAY(SELECT pg_catalog.jsonb_array_elements_text(coalesce(w -> 'objects', '[]')))
      FROM pg_catalog.jsonb_array_elements(coalesce(p_waivers, '[]')) w;
END $$;

-- _evidence(v, event): the signed token behind this request (PostgREST's
-- request headers, Authorization: the raw JWS) after checking that its payload
-- is the verified claims' (sub, iat, jti, azp). Returns {source, sub, iat, jti,
-- azp, jws_sha256, jws}; the caller appends its event without `jws` and stores
-- the row in iam_policy.approval_evidence with that event's id. The signature
-- is checked by apply.sh against the realm keys, not here.
CREATE OR REPLACE FUNCTION iam_policy._evidence(p_version integer, p_event text) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c    jsonb;
    h    text;
    jws  text;
    b    text;
    pl   jsonb;
BEGIN
    c := nullif(pg_catalog.current_setting('request.jwt.claims', true), '')::jsonb;
    BEGIN
        h := nullif(pg_catalog.current_setting('request.headers', true), '')::json ->> 'authorization';
    EXCEPTION WHEN others THEN
        h := NULL;
    END;
    IF c IS NULL OR h IS NULL OR h !~* '^bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$' THEN
        RAISE EXCEPTION 'version %: % needs the signed token as evidence: use the Policy UI', p_version, p_event
            USING ERRCODE = '42501';
    END IF;
    jws := pg_catalog.substr(h, 8);
    b := pg_catalog.translate(pg_catalog.split_part(jws, '.', 2), '-_', '+/');
    b := b || pg_catalog.repeat('=', (4 - pg_catalog.length(b) % 4) % 4);
    BEGIN
        pl := pg_catalog.convert_from(pg_catalog.decode(b, 'base64'), 'UTF8')::jsonb;
    EXCEPTION WHEN others THEN
        pl := NULL;
    END;
    IF pl IS NULL OR pg_catalog.jsonb_typeof(pl) <> 'object'
       OR (pl ->> 'sub') IS DISTINCT FROM (c ->> 'sub') OR (pl ->> 'iat') IS DISTINCT FROM (c ->> 'iat')
       OR (pl ->> 'jti') IS DISTINCT FROM (c ->> 'jti') OR (pl ->> 'azp') IS DISTINCT FROM (c ->> 'azp')
       OR (c ->> 'sub') IS NULL OR (c ->> 'iat') IS NULL THEN
        RAISE EXCEPTION 'version %: the token sent is not the one verified for this request', p_version
            USING ERRCODE = '42501';
    END IF;
    RETURN pg_catalog.jsonb_build_object('source', 'token', 'sub', c ->> 'sub', 'iat', c -> 'iat', 'jti', c ->> 'jti',
        'azp', c ->> 'azp', 'jws_sha256', pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(jws, 'UTF8')), 'hex'),
        'jws', jws);
END $$;

-- ── author functions (iam-api as iam_svc, set_actor from the verified token) ──

-- new_draft(from, reason, iat, cells, waivers): a change version as a draft,
-- from the applied version, the factory defaults iam-api passes, or version N.
-- Keys of the accepted skeleton the base does not cover get the proposed cells.
CREATE OR REPLACE FUNCTION iam_policy.new_draft(p_from text, p_reason text, p_iat double precision,
    p_cells jsonb, p_waivers jsonb) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a        record;
    applied  integer;
    base     integer;
    open_v   integer;
    last_ev  text;
    v        integer;
    skel     text;
    sgroups  text[];
    sroles   text[];
    bgroups  text[];
    broles   text[];
    ents     jsonb;
    wvs      jsonb;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('new_draft', NULL);
    SELECT * INTO a FROM medcea_auth._person_actor('iam_svc', 'iam_policy', 'C');
    IF iam_policy._changed_since(a.sub, a.person, p_iat) THEN
        RAISE EXCEPTION 'your access changed since you signed in: reload the page' USING ERRCODE = '42501';
    END IF;
    IF coalesce(pg_catalog.btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'a reason is required' USING ERRCODE = '22023';
    END IF;
    SELECT x.version INTO applied FROM iam_policy.version x WHERE x.status = 'applied';
    IF applied IS NULL THEN
        RAISE EXCEPTION 'no policy version is applied yet: the host operator runs ./apps/iam/apply.sh --bootstrap first'
            USING ERRCODE = '22023';
    END IF;
    SELECT h.event INTO last_ev FROM iam_policy.history h WHERE h.version = applied
       AND h.event <> 'status_changed' ORDER BY h.event_id DESC LIMIT 1;
    IF last_ev IN ('apply_started', 'partial_apply') THEN
        RAISE EXCEPTION 'version % is being applied (%): wait for apply.sh, or have the host operator run ./apps/iam/apply.sh --resume',
            applied, last_ev USING ERRCODE = '22023';
    END IF;
    SELECT x.version INTO open_v FROM iam_policy.version x
     WHERE x.status IN ('draft', 'submitted', 'approved') AND x.kind IN ('change', 'skeleton');
    IF open_v IS NOT NULL THEN
        RAISE EXCEPTION 'version % is still open: take it through or withdraw it first', open_v USING ERRCODE = '23505';
    END IF;
    skel := iam_policy._accepted();
    SELECT ARRAY(SELECT k FROM pg_catalog.jsonb_object_keys(s.body -> 'resource_groups') k ORDER BY k COLLATE "C"),
           ARRAY(SELECT k FROM pg_catalog.jsonb_object_keys(s.body -> 'roles') k ORDER BY k COLLATE "C")
      INTO sgroups, sroles FROM iam_policy.skeleton s WHERE s.digest = skel;
    IF p_from = 'applied' OR p_from ~ '^[0-9]+$' THEN
        base := CASE WHEN p_from = 'applied' THEN applied ELSE p_from::integer END;
        IF NOT EXISTS (SELECT 1 FROM iam_policy.version x WHERE x.version = base) THEN
            RAISE EXCEPTION 'no policy version %', base USING ERRCODE = '22023';
        END IF;
        SELECT x.groups, x.roles INTO bgroups, broles FROM iam_policy.version x WHERE x.version = base;
        SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('role', e.role, 'group_code', e.group_code,
                   'level', e.level::text, 'constraint_name', e.constraint_name)), '[]')
          INTO ents FROM iam_policy.entry e WHERE e.version = base;
        SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(w) - 'version'), '[]')
          INTO wvs FROM iam_policy.waiver w WHERE w.version = base;
        -- keys the base does not cover (a group or role git added since) get the proposed cells
        SELECT ents || coalesce(pg_catalog.jsonb_agg(c), '[]') INTO ents
          FROM pg_catalog.jsonb_array_elements(coalesce(p_cells, '[]')) c
         WHERE NOT ((c ->> 'group_code') = ANY (coalesce(bgroups, '{}')) AND (c ->> 'role') = ANY (coalesce(broles, '{}')))
           AND (c ->> 'group_code') = ANY (coalesce(sgroups, '{}')) AND (c ->> 'role') = ANY (coalesce(sroles, '{}'));
    ELSIF p_from = 'defaults' THEN
        ents := coalesce(p_cells, '[]');
        wvs := coalesce(p_waivers, '[]');
    ELSE
        RAISE EXCEPTION 'a draft starts from applied, defaults or a version number, not %', p_from USING ERRCODE = '22023';
    END IF;
    SELECT coalesce(max(x.version), 0) + 1 INTO v FROM iam_policy.version x;
    INSERT INTO iam_policy.version (version, status, kind, reason, based_on, groups, roles,
                                    created_by_sub, created_by_person, created_by_name)
    VALUES (v, 'draft', 'change', p_reason, applied, sgroups, sroles, a.sub::uuid, a.person, a.name);
    PERFORM iam_policy._put_rows(v, ents, wvs);
    PERFORM iam_policy._append_history('draft_created',
        pg_catalog.jsonb_build_object('version', v, 'base', base, 'from', p_from), p_reason);
    RETURN v;
END $$;

-- save_entry(v, role, group, levels, reason, verdict, iat): replaces one cell of a
-- draft; p_levels {"R": null, "O": "assigned_run"} ({} = N); p_verdict {ok,
-- errors[], checker_digest} is iam-api's checker run, advisory here and
-- required ok by submit().
CREATE OR REPLACE FUNCTION iam_policy.save_entry(p_version integer, p_role text, p_group text, p_levels jsonb,
    p_reason text, p_verdict jsonb, p_iat double precision) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a       record;
    v       iam_policy.version;
    v_before  jsonb;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('save_entry', p_version);
    SELECT * INTO a FROM medcea_auth._person_actor('iam_svc', 'iam_policy', 'U');
    IF iam_policy._changed_since(a.sub, a.person, p_iat) THEN
        RAISE EXCEPTION 'your access changed since you signed in: reload the page' USING ERRCODE = '42501';
    END IF;
    IF coalesce(pg_catalog.btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'a reason is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version FOR UPDATE;
    IF NOT FOUND OR v.status <> 'draft' OR v.kind <> 'change' THEN
        RAISE EXCEPTION 'version % is not a draft', p_version USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM iam_policy.role r WHERE r.code = p_role AND NOT r.retired)
       OR NOT EXISTS (SELECT 1 FROM iam_policy.resource_group g WHERE g.code = p_group AND NOT g.retired) THEN
        RAISE EXCEPTION 'no role % or group % in the accepted skeleton', p_role, p_group USING ERRCODE = '22023';
    END IF;
    IF pg_catalog.jsonb_typeof(p_levels) IS DISTINCT FROM 'object'
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_each(p_levels) l
                   WHERE l.key NOT IN ('R', 'X', 'C', 'U', 'A', 'O', 'K', 'D')
                      OR pg_catalog.jsonb_typeof(l.value) NOT IN ('null', 'string')) THEN
        RAISE EXCEPTION 'levels must be an object {level: constraint or null}' USING ERRCODE = '22023';
    END IF;
    SELECT coalesce(pg_catalog.jsonb_object_agg(e.level::text, e.constraint_name), '{}') INTO v_before
      FROM iam_policy.entry e WHERE e.version = p_version AND e.role = p_role AND e.group_code = p_group;
    DELETE FROM iam_policy.entry e WHERE e.version = p_version AND e.role = p_role AND e.group_code = p_group;
    INSERT INTO iam_policy.entry (version, role, group_code, level, constraint_name)
    SELECT p_version, p_role, p_group, l.key, nullif(l.value #>> '{}', '') FROM pg_catalog.jsonb_each(p_levels) l;
    UPDATE iam_policy.version x SET checker_verdict = coalesce((p_verdict ->> 'ok')::boolean, false),
                                    checker_digest = p_verdict ->> 'checker_digest'
     WHERE x.version = p_version;
    PERFORM iam_policy._append_history('entry_saved',
        pg_catalog.jsonb_build_object('version', p_version, 'role', p_role, 'group', p_group, 'before', v_before,
                                      'after', p_levels, 'verdict_ok', coalesce((p_verdict ->> 'ok')::boolean, false)),
        p_reason);
END $$;

-- submit(v, reason, iat): draft -> submitted; stores the accepted skeleton and
-- the entries digest qa will approve; returns the digest.
CREATE OR REPLACE FUNCTION iam_policy.submit(p_version integer, p_reason text, p_iat double precision) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a     record;
    v     iam_policy.version;
    d     text;
    skel  text;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('submit', p_version);
    SELECT * INTO a FROM medcea_auth._person_actor('iam_svc', 'iam_policy', 'U');
    IF iam_policy._changed_since(a.sub, a.person, p_iat) THEN
        RAISE EXCEPTION 'your access changed since you signed in: reload the page' USING ERRCODE = '42501';
    END IF;
    IF coalesce(pg_catalog.btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'a reason is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version FOR UPDATE;
    IF NOT FOUND OR v.status <> 'draft' OR v.kind <> 'change' THEN
        RAISE EXCEPTION 'version % is not a draft', p_version USING ERRCODE = '22023';
    END IF;
    IF v.checker_verdict IS NOT TRUE THEN
        RAISE EXCEPTION 'version % does not pass the checker: fix the errors it lists first', p_version USING ERRCODE = '22023';
    END IF;
    skel := iam_policy._accepted();
    IF skel IS NULL THEN
        RAISE EXCEPTION 'this host has accepted no platform skeleton yet' USING ERRCODE = '22023';
    END IF;
    d := iam_policy.entries_digest(p_version);
    UPDATE iam_policy.version x SET status = 'submitted', submitted_by_sub = a.sub::uuid, submitted_by_person = a.person,
           submitted_by_name = a.name, submitted_at = pg_catalog.now(), skeleton_digest = skel, entries_digest = d
     WHERE x.version = p_version;
    PERFORM iam_policy._append_history('submitted',
        pg_catalog.jsonb_build_object('version', p_version, 'entries_digest', d), p_reason);
    RETURN d;
END $$;

-- withdraw(v, reason, iat): an admin (U on iam_policy) takes an open version back;
-- withdrawing grants nothing, so it is not limited to the authors.
CREATE OR REPLACE FUNCTION iam_policy.withdraw(p_version integer, p_reason text, p_iat double precision) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a  record;
    v  iam_policy.version;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('withdraw', p_version);
    SELECT * INTO a FROM medcea_auth._person_actor('iam_svc', 'iam_policy', 'U');
    IF iam_policy._changed_since(a.sub, a.person, p_iat) THEN
        RAISE EXCEPTION 'your access changed since you signed in: reload the page' USING ERRCODE = '42501';
    END IF;
    IF coalesce(pg_catalog.btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'a reason is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version FOR UPDATE;
    IF NOT FOUND OR v.kind NOT IN ('change', 'skeleton') OR v.status NOT IN ('draft', 'submitted', 'approved')
       OR (v.kind = 'skeleton' AND v.status = 'draft') THEN
        RAISE EXCEPTION 'version % is not open', p_version USING ERRCODE = '22023';
    END IF;
    UPDATE iam_policy.version x SET status = 'withdrawn', withdrawn_at = pg_catalog.now(),
           withdrawn_by_sub = a.sub::uuid, withdrawn_by = a.person
     WHERE x.version = p_version;
    PERFORM iam_policy._append_history('withdrawn', pg_catalog.jsonb_build_object('version', p_version), p_reason);
END $$;

-- ── qa functions (the person's own token through PostgREST; owner only, called
--    by the medcea.*_policy wrappers) ─────────────────────────────────────────

-- _qa(rpc): the approver and the verified claims; the token must be the policy
-- host's (the client whose only_rpc names the wrapper).
CREATE OR REPLACE FUNCTION iam_policy._qa(p_rpc text, OUT sub text, OUT person text, OUT name text, OUT role text,
    OUT source text, OUT claims jsonb)
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE a record; want text;
BEGIN
    SELECT * INTO a FROM medcea_auth._approver('iam_policy');
    claims := nullif(pg_catalog.current_setting('request.jwt.claims', true), '')::jsonb;
    want := medcea_auth._rpc_client(p_rpc);
    IF want IS NULL OR (claims ->> 'azp') IS DISTINCT FROM want THEN
        RAISE EXCEPTION 'approve access-policy versions in the Policy UI' USING ERRCODE = '42501';
    END IF;
    IF iam_policy._changed_since(a.sub, a.person, (claims ->> 'iat')::double precision) THEN
        RAISE EXCEPTION 'your access changed since you signed in: reload the page' USING ERRCODE = '42501';
    END IF;
    sub := a.sub; person := a.person; name := a.name; role := a.role; source := a.source;
END $$;

-- approve(v, note, entries_digest, diff_digest, skeleton_digest): submitted ->
-- approved; binds the entries, the diff qa saw and the skeleton it was computed on.
-- Refused while a policy break-glass is open (4.4); a skeleton version also needs
-- its proposal not stale, the attestation in the note and no role the approver
-- holds (with what it includes) gaining reach in the stored diff (4.4, §14.7.1).
CREATE OR REPLACE FUNCTION iam_policy.approve(p_version integer, p_note text, p_entries_digest text,
    p_diff_digest text, p_skeleton_digest text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a        record;
    v        iam_policy.version;
    applied  integer;
    d        text;
    want     text;
    ev       jsonb;
    hid      bigint;
    bg_ev    bigint;
    bg_open  text;
    acc      text;
    s_from   text;
    wide     text;
    attest   constant text := 'I did not run apply.sh --propose-skeleton for this version.';
BEGIN
    SELECT * INTO a FROM iam_policy._qa('approve_policy');
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('approve', p_version);
    IF coalesce(pg_catalog.btrim(p_note), '') = '' THEN
        RAISE EXCEPTION 'a note is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version FOR UPDATE;
    IF NOT FOUND OR v.status <> 'submitted' THEN
        RAISE EXCEPTION 'version % is not submitted', p_version USING ERRCODE = '22023';
    END IF;
    SELECT x.version INTO applied FROM iam_policy.version x WHERE x.status = 'applied';
    IF applied IS NULL THEN
        RAISE EXCEPTION 'no policy version is applied' USING ERRCODE = '22023';
    END IF;
    IF v.based_on IS DISTINCT FROM applied THEN
        RAISE EXCEPTION 'version % was drafted on version %, but version % is applied now: return it', p_version, v.based_on, applied
            USING ERRCODE = '22023';
    END IF;
    -- a policy break-glass still open (4.4, §3.5): a break_glass_seen of source file
    -- with a component no break_glass_ended has closed; the predicate of
    -- policy_db_state's break_glass_open (infra/lib-policy-source.sh), inline because a
    -- helper would be a new skeleton member
    SELECT min(b.event_id), pg_catalog.string_agg(b.component, ', ' ORDER BY b.component COLLATE "C")
      INTO bg_ev, bg_open
      FROM (SELECT min(h.event_id) AS event_id, bc.value AS component
              FROM iam_policy.history h
             CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(CASE WHEN pg_catalog.jsonb_typeof(h.payload -> 'components') = 'array'
                                                                          THEN h.payload -> 'components' ELSE '[]' END) AS bc(value)
             WHERE h.event = 'break_glass_seen' AND h.payload ->> 'source' = 'file'
               AND NOT EXISTS (SELECT 1 FROM iam_policy.history e
                                WHERE e.event = 'break_glass_ended'
                                  AND e.payload ->> 'since_event' = h.event_id::text
                                  AND e.payload ->> 'component' = bc.value)
             GROUP BY bc.value) b;
    IF bg_ev IS NOT NULL THEN
        RAISE EXCEPTION 'a policy break-glass is open (event %): approvals wait until a normal deploy of % ends it', bg_ev, bg_open
            USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_policy._authors(p_version) au WHERE au.sub = a.sub OR au.person = a.person) THEN
        RAISE EXCEPTION 'you are an author of version %: another qa person approves it', p_version USING ERRCODE = '42501';
    END IF;
    d := iam_policy.entries_digest(p_version);
    IF d IS DISTINCT FROM v.entries_digest OR d IS DISTINCT FROM p_entries_digest THEN
        RAISE EXCEPTION 'version % changed since you opened it: reload the page', p_version USING ERRCODE = '22023';
    END IF;
    want := CASE WHEN v.kind = 'skeleton' THEN v.skeleton_digest ELSE iam_policy._accepted() END;
    IF want IS NULL OR p_skeleton_digest IS DISTINCT FROM want THEN
        RAISE EXCEPTION 'the Policy service shows another platform skeleton than this host accepted: run ./apps/iam/deploy.sh, then reload'
            USING ERRCODE = '22023';
    END IF;
    IF coalesce(p_diff_digest, '') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'the approval names no diff digest' USING ERRCODE = '22023';
    END IF;
    IF v.kind = 'skeleton' AND p_diff_digest IS DISTINCT FROM (SELECT x.diff_digest FROM iam_policy.version_diff x WHERE x.version = p_version) THEN
        RAISE EXCEPTION 'the diff you saw is not the one the host stored for version %: reload the page', p_version
            USING ERRCODE = '22023';
    END IF;
    IF v.kind = 'skeleton' THEN
        -- stale: a deploy accepted another (narrowing) skeleton since the proposal
        acc := iam_policy._accepted();
        SELECT x.diff -> 'skeleton' ->> 'from' INTO s_from FROM iam_policy.version_diff x WHERE x.version = p_version;
        IF s_from IS DISTINCT FROM acc THEN
            RAISE EXCEPTION 'version % was proposed against skeleton %, the accepted one is now %: return it and propose again',
                p_version, pg_catalog.left(s_from, 12), pg_catalog.left(acc, 12) USING ERRCODE = '22023';
        END IF;
        -- the maker is only the claimed --by (_propose_skeleton): qa attests, as confirm_applied
        IF pg_catalog.left(coalesce(p_note, ''), pg_catalog.length(attest)) IS DISTINCT FROM attest
           OR pg_catalog.btrim(pg_catalog.substr(p_note, pg_catalog.length(attest) + 1)) = '' THEN
            RAISE EXCEPTION 'approving a skeleton version needs the attestation "I did not run apply.sh --propose-skeleton for this version."'
                USING ERRCODE = '22023';
        END IF;
        -- the approver's own role, or one it includes, gains reach: not theirs to approve
        WITH RECURSIVE held(role_code) AS (
            SELECT a.role
            UNION
            SELECT i.role_code FROM held hr JOIN iam_policy.role r ON r.code = hr.role_code
             CROSS JOIN LATERAL pg_catalog.unnest(r.includes) AS i(role_code))
        SELECT hr.role_code INTO wide FROM held hr, iam_policy.version_diff x
         WHERE x.version = p_version
           AND pg_catalog.jsonb_typeof(x.diff -> 'roles' -> hr.role_code -> 'added') = 'array'
           AND pg_catalog.jsonb_array_length(x.diff -> 'roles' -> hr.role_code -> 'added') > 0
         ORDER BY hr.role_code COLLATE "C" LIMIT 1;
        IF wide IS NOT NULL THEN
            RAISE EXCEPTION 'version % widens role %, which you hold: you may not approve it', p_version, wide
                USING ERRCODE = '42501';
        END IF;
    END IF;
    ev := iam_policy._evidence(p_version, 'approved');
    UPDATE iam_policy.version x SET status = 'approved', approved_by_person = a.person, approved_by_sub = a.sub::uuid,
           approved_by_name = a.name, approved_at = pg_catalog.now(), approval_note = p_note,
           approved_iat = (a.claims ->> 'iat')::double precision, diff_digest = p_diff_digest,
           approved_skeleton_digest = p_skeleton_digest
     WHERE x.version = p_version;
    hid := iam_policy._append_history('approved', pg_catalog.jsonb_build_object(
        'version', p_version, 'source', a.source, 'role', a.role, 'person', a.person, 'sub', a.sub,
        'iat', ev -> 'iat', 'jti', ev ->> 'jti', 'azp', ev ->> 'azp', 'entries_digest', d,
        'diff_digest', p_diff_digest, 'skeleton_digest', p_skeleton_digest, 'jws_sha256', ev ->> 'jws_sha256'), p_note);
    INSERT INTO iam_policy.approval_evidence (version, history_id, event, jws, claims)
    VALUES (p_version, hid, 'approved', ev ->> 'jws', a.claims);
END $$;

-- return_version(v, note): qa sends a submitted version back (a change to its
-- draft, a skeleton version to withdrawn: git changes and a new proposal follow).
CREATE OR REPLACE FUNCTION iam_policy.return_version(p_version integer, p_note text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a    record;
    v    iam_policy.version;
    ev   jsonb;
    hid  bigint;
BEGIN
    SELECT * INTO a FROM iam_policy._qa('return_policy');
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('return_version', p_version);
    IF coalesce(pg_catalog.btrim(p_note), '') = '' THEN
        RAISE EXCEPTION 'a note is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version FOR UPDATE;
    IF NOT FOUND OR v.status <> 'submitted' THEN
        RAISE EXCEPTION 'version % is not submitted', p_version USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_policy._authors(p_version) au WHERE au.sub = a.sub OR au.person = a.person) THEN
        RAISE EXCEPTION 'you are an author of version %: another qa person returns it', p_version USING ERRCODE = '42501';
    END IF;
    ev := iam_policy._evidence(p_version, 'returned');
    IF v.kind = 'skeleton' THEN
        UPDATE iam_policy.version x SET status = 'withdrawn', returned_at = pg_catalog.now(), return_note = p_note,
               withdrawn_at = pg_catalog.now(), withdrawn_by_sub = a.sub::uuid, withdrawn_by = a.person
         WHERE x.version = p_version;
    ELSE
        UPDATE iam_policy.version x SET status = 'draft', returned_at = pg_catalog.now(), return_note = p_note
         WHERE x.version = p_version;
    END IF;
    hid := iam_policy._append_history('returned', pg_catalog.jsonb_build_object(
        'version', p_version, 'source', a.source, 'role', a.role, 'person', a.person, 'sub', a.sub,
        'iat', ev -> 'iat', 'jti', ev ->> 'jti', 'azp', ev ->> 'azp', 'jws_sha256', ev ->> 'jws_sha256'), p_note);
    INSERT INTO iam_policy.approval_evidence (version, history_id, event, jws, claims)
    VALUES (p_version, hid, 'returned', ev ->> 'jws', a.claims);
END $$;

-- confirm_applied(v, note, attest): qa confirms a bootstrap or rollback version
-- (applied at once by apply.sh); not by the person who claimed to run apply.sh.
CREATE OR REPLACE FUNCTION iam_policy.confirm_applied(p_version integer, p_note text, p_attest text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a    record;
    v    iam_policy.version;
    ev   jsonb;
    hid  bigint;
BEGIN
    SELECT * INTO a FROM iam_policy._qa('confirm_policy');
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('confirm_applied', p_version);
    IF coalesce(pg_catalog.btrim(p_note), '') = '' THEN
        RAISE EXCEPTION 'a note is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version FOR UPDATE;
    IF NOT FOUND OR v.kind NOT IN ('bootstrap', 'rollback') OR v.status NOT IN ('applied', 'superseded') THEN
        RAISE EXCEPTION 'version % is no applied bootstrap or rollback version', p_version USING ERRCODE = '22023';
    END IF;
    IF v.confirmed_at IS NOT NULL OR v.disputed_at IS NOT NULL THEN
        RAISE EXCEPTION 'version % is already % ', p_version, CASE WHEN v.confirmed_at IS NOT NULL THEN 'confirmed' ELSE 'disputed' END
            USING ERRCODE = '22023';
    END IF;
    IF v.claimed_by_person IS NOT NULL AND v.claimed_by_person = a.person THEN
        RAISE EXCEPTION 'apply.sh recorded you as running version %: another qa person confirms it', p_version
            USING ERRCODE = '42501';
    END IF;
    IF p_attest IS DISTINCT FROM 'I did not run apply.sh for this version.' THEN
        RAISE EXCEPTION 'confirming needs the attestation "I did not run apply.sh for this version."' USING ERRCODE = '22023';
    END IF;
    ev := iam_policy._evidence(p_version, 'confirmed');
    UPDATE iam_policy.version x SET confirmed_by_person = a.person, confirmed_by_sub = a.sub::uuid,
           confirmed_at = pg_catalog.now(), confirm_note = p_note
     WHERE x.version = p_version;
    hid := iam_policy._append_history('confirmed', pg_catalog.jsonb_build_object(
        'version', p_version, 'source', a.source, 'role', a.role, 'person', a.person, 'sub', a.sub, 'attest', p_attest,
        'iat', ev -> 'iat', 'jti', ev ->> 'jti', 'azp', ev ->> 'azp', 'jws_sha256', ev ->> 'jws_sha256'), p_note);
    INSERT INTO iam_policy.approval_evidence (version, history_id, event, jws, claims)
    VALUES (p_version, hid, 'confirmed', ev ->> 'jws', a.claims);
END $$;

-- dispute_applied(v, note): qa disputes a bootstrap or rollback version not yet
-- confirmed (health FAILs until a later version replaces it).
CREATE OR REPLACE FUNCTION iam_policy.dispute_applied(p_version integer, p_note text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a    record;
    v    iam_policy.version;
    ev   jsonb;
    hid  bigint;
BEGIN
    SELECT * INTO a FROM iam_policy._qa('dispute_policy');
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('dispute_applied', p_version);
    IF coalesce(pg_catalog.btrim(p_note), '') = '' THEN
        RAISE EXCEPTION 'a note is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version FOR UPDATE;
    IF NOT FOUND OR v.kind NOT IN ('bootstrap', 'rollback') OR v.status NOT IN ('applied', 'superseded', 'withdrawn') THEN
        RAISE EXCEPTION 'version % is no applied bootstrap or rollback version', p_version USING ERRCODE = '22023';
    END IF;
    IF v.confirmed_at IS NOT NULL OR v.disputed_at IS NOT NULL THEN
        RAISE EXCEPTION 'version % is already %', p_version, CASE WHEN v.confirmed_at IS NOT NULL THEN 'confirmed' ELSE 'disputed' END
            USING ERRCODE = '22023';
    END IF;
    ev := iam_policy._evidence(p_version, 'disputed');
    UPDATE iam_policy.version x SET disputed_at = pg_catalog.now(), disputed_by_person = a.person, dispute_note = p_note
     WHERE x.version = p_version;
    hid := iam_policy._append_history('disputed', pg_catalog.jsonb_build_object(
        'version', p_version, 'source', a.source, 'role', a.role, 'person', a.person, 'sub', a.sub,
        'iat', ev -> 'iat', 'jti', ev ->> 'jti', 'azp', ev ->> 'azp', 'jws_sha256', ev ->> 'jws_sha256'), p_note);
    INSERT INTO iam_policy.approval_evidence (version, history_id, event, jws, claims)
    VALUES (p_version, hid, 'disputed', ev ->> 'jws', a.claims);
END $$;

-- ── read functions (R on iam_policy) ─────────────────────────────────────────

-- why_not(v): approve()'s checks for the actor of this transaction, read-only.
-- The token and client checks are reported as needs_token_path (iam-api asks
-- as iam_svc with set_actor; the approval itself goes through PostgREST).
CREATE OR REPLACE FUNCTION iam_policy.why_not(p_version integer)
    RETURNS TABLE (may_approve boolean, why_not_code text, needs_token_path boolean)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    a        record;
    c        jsonb;
    v        iam_policy.version;
    applied  integer;
    code     text;
    bg       boolean;
    stale    boolean := false;
    wide     boolean := false;
BEGIN
    SELECT * INTO a FROM medcea_auth.request_actor();
    c := CASE WHEN a.source = 'token' THEN nullif(pg_catalog.current_setting('request.jwt.claims', true), '')::jsonb END;
    needs_token_path := a.source IS DISTINCT FROM 'token'
        OR (c ->> 'azp') IS DISTINCT FROM medcea_auth._rpc_client('approve_policy')
        OR medcea_auth._rpc_client('approve_policy') IS NULL;
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version;
    SELECT x.version INTO applied FROM iam_policy.version x WHERE x.status = 'applied';
    -- approve()'s 4.4 checks, the same predicates (break-glass: lib-policy-source.sh's)
    bg := EXISTS (SELECT 1 FROM iam_policy.history h
                  CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(CASE WHEN pg_catalog.jsonb_typeof(h.payload -> 'components') = 'array'
                                                                               THEN h.payload -> 'components' ELSE '[]' END) AS bc(value)
                  WHERE h.event = 'break_glass_seen' AND h.payload ->> 'source' = 'file'
                    AND NOT EXISTS (SELECT 1 FROM iam_policy.history e
                                     WHERE e.event = 'break_glass_ended'
                                       AND e.payload ->> 'since_event' = h.event_id::text
                                       AND e.payload ->> 'component' = bc.value));
    IF v.kind = 'skeleton' THEN
        stale := (SELECT x.diff -> 'skeleton' ->> 'from' FROM iam_policy.version_diff x WHERE x.version = p_version)
                 IS DISTINCT FROM iam_policy._accepted();
        WITH RECURSIVE held(role_code) AS (
            SELECT a.role
            UNION
            SELECT i.role_code FROM held hr JOIN iam_policy.role r ON r.code = hr.role_code
             CROSS JOIN LATERAL pg_catalog.unnest(r.includes) AS i(role_code))
        SELECT EXISTS (SELECT 1 FROM held hr, iam_policy.version_diff x
                        WHERE x.version = p_version
                          AND pg_catalog.jsonb_typeof(x.diff -> 'roles' -> hr.role_code -> 'added') = 'array'
                          AND pg_catalog.jsonb_array_length(x.diff -> 'roles' -> hr.role_code -> 'added') > 0) INTO wide;
    END IF;
    code := CASE
        WHEN a.sub IS NULL THEN 'no_token'
        WHEN coalesce(pg_catalog.btrim(a.person), '') = '' THEN 'no_person'
        WHEN medcea_auth.policy_holds(a.role, 'iam_policy', 'A') IS NULL THEN 'not_approver'
        WHEN c IS NOT NULL AND iam_policy._changed_since(a.sub, a.person, (c ->> 'iat')::double precision) THEN 'changed_since'
        WHEN v.version IS NULL THEN 'no_version'
        WHEN v.status <> 'submitted' THEN 'not_submitted'
        WHEN applied IS NULL THEN 'no_applied'
        WHEN v.based_on IS DISTINCT FROM applied THEN 'stale_base'
        WHEN bg THEN 'break_glass_open'
        WHEN stale THEN 'stale_skeleton'
        WHEN wide THEN 'own_widening'
        WHEN EXISTS (SELECT 1 FROM iam_policy._authors(p_version) au WHERE au.sub = a.sub OR au.person = a.person) THEN 'own_author'
        WHEN iam_policy.entries_digest(p_version) IS DISTINCT FROM v.entries_digest THEN 'entries_changed'
        END;
    may_approve := code IS NULL;
    why_not_code := code;
    RETURN NEXT;
END $$;

-- audit_versions(): read-only; one row per finding (health iampolicy and the
-- History tab, from 4.2a/4.3). No row: every version's history is consistent.
CREATE OR REPLACE FUNCTION iam_policy.audit_versions() RETURNS TABLE (version integer, finding text, detail jsonb)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v    record;
    ch   record;
    ap   jsonb;
    evs  text[];
    ok   boolean;
BEGIN
    SELECT vc.ok INTO ok FROM iam_policy.verify_chain() vc;
    IF NOT ok THEN
        version := NULL; finding := 'chain';
        detail := (SELECT pg_catalog.to_jsonb(vc) FROM iam_policy.verify_chain() vc);
        RETURN NEXT;
    END IF;
    FOR ch IN SELECT DISTINCT h.version FROM iam_policy.history h
               WHERE h.version IS NOT NULL AND NOT EXISTS (SELECT 1 FROM iam_policy.version x WHERE x.version = h.version)
                 AND h.event IN ('draft_created', 'entry_saved', 'waiver_saved', 'waiver_dropped', 'submitted', 'approved',
                                 'returned', 'withdrawn', 'apply_started', 'applied', 'partial_apply', 'bootstrap_applied',
                                 'apply_reverted', 'confirmed', 'disputed', 'status_changed') LOOP
        version := ch.version; finding := 'unknown_version'; detail := NULL; RETURN NEXT;
    END LOOP;
    FOR ch IN SELECT h.version, h.payload, h.event_id FROM iam_policy.history h
               WHERE h.event = 'status_changed' AND h.version IS NOT NULL
                 AND NOT iam_policy._edge_ok(h.payload ->> 'from', h.payload ->> 'to',
                                             coalesce(h.payload ->> 'kind', (SELECT x.kind FROM iam_policy.version x WHERE x.version = h.version)),
                                             h.payload ->> 'by_function') LOOP
        version := ch.version; finding := 'bad_transition';
        detail := ch.payload || pg_catalog.jsonb_build_object('event_id', ch.event_id); RETURN NEXT;
    END LOOP;
    FOR v IN SELECT * FROM iam_policy.version x ORDER BY x.version LOOP
        SELECT pg_catalog.array_agg(h.event ORDER BY h.event_id) INTO evs FROM iam_policy.history h
         WHERE h.version = v.version AND h.event <> 'status_changed';
        evs := coalesce(evs, '{}');
        IF v.status IN ('applied', 'superseded') AND v.kind IN ('change', 'skeleton') THEN
            IF NOT coalesce(pg_catalog.array_position(evs, 'approved') IS NOT NULL
                    AND pg_catalog.array_position(evs, 'submitted') < pg_catalog.array_position(evs, 'approved')
                    AND pg_catalog.array_position(evs, 'apply_started', pg_catalog.array_position(evs, 'approved')) IS NOT NULL
                    AND pg_catalog.array_position(evs, 'applied', pg_catalog.array_position(evs, 'approved')) IS NOT NULL
                    AND (v.kind = 'skeleton' OR evs[1] = 'draft_created'), false) THEN
                version := v.version; finding := 'sequence'; detail := pg_catalog.to_jsonb(evs); RETURN NEXT;
            END IF;
        ELSIF v.status IN ('applied', 'superseded') AND v.kind IN ('bootstrap', 'rollback') THEN
            IF NOT coalesce(pg_catalog.array_position(evs, 'apply_started') IS NOT NULL
                    AND (pg_catalog.array_position(evs, 'applied', pg_catalog.array_position(evs, 'apply_started')) IS NOT NULL
                         OR pg_catalog.array_position(evs, 'bootstrap_applied', pg_catalog.array_position(evs, 'apply_started')) IS NOT NULL), false) THEN
                version := v.version; finding := 'sequence'; detail := pg_catalog.to_jsonb(evs); RETURN NEXT;
            END IF;
        END IF;
        IF v.approved_at IS NOT NULL THEN
            IF EXISTS (SELECT 1 FROM iam_policy._authors(v.version) au
                        WHERE au.sub = v.approved_by_sub::text OR au.person = v.approved_by_person) THEN
                version := v.version; finding := 'approver_is_author'; detail := NULL; RETURN NEXT;
            END IF;
            SELECT h.payload INTO ap FROM iam_policy.history h
             WHERE h.version = v.version AND h.event = 'approved' ORDER BY h.event_id DESC LIMIT 1;
            IF ap IS NULL OR (ap ->> 'diff_digest') IS DISTINCT FROM v.diff_digest
               OR (ap ->> 'skeleton_digest') IS DISTINCT FROM v.approved_skeleton_digest
               OR (ap ->> 'entries_digest') IS DISTINCT FROM iam_policy.entries_digest(v.version) THEN
                version := v.version; finding := 'approval_mismatch';
                detail := pg_catalog.jsonb_build_object('approved', ap, 'diff_digest', v.diff_digest,
                    'skeleton_digest', v.approved_skeleton_digest, 'entries_digest', iam_policy.entries_digest(v.version));
                RETURN NEXT;
            END IF;
        END IF;
    END LOOP;
END $$;

-- ── owner-only functions (apply.sh as postgres, actor system:apply; 4.2a on) ──

-- _system_as(allowed): the policy's system actors (IAM 4.2a). With no actor set it
-- sets allowed[1]; an actor in the list is accepted; anything else is 42501. Returns
-- the actor. SECURITY INVOKER: called from the owner functions only.
CREATE OR REPLACE FUNCTION iam_policy._system_as(p_allowed text[]) RETURNS text
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE a record;
BEGIN
    IF p_allowed IS NULL OR pg_catalog.cardinality(p_allowed) = 0 THEN
        RAISE EXCEPTION '_system_as needs the allowed actors' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO a FROM medcea_auth.request_actor();
    IF a.sub IS NULL THEN
        PERFORM medcea_auth._set_internal_actor(p_allowed[1]);
        RETURN p_allowed[1];
    ELSIF a.sub = ANY (p_allowed) THEN
        RETURN a.sub;
    END IF;
    RAISE EXCEPTION 'the policy is built and applied by % (apply.sh, or a deploy''s skeleton gate and records), not by %',
        pg_catalog.array_to_string(p_allowed, ' or '), a.sub USING ERRCODE = '42501';
END $$;

-- _system(): the actor of apply.sh's bundle, system:apply, unless one is set.
CREATE OR REPLACE FUNCTION iam_policy._system() RETURNS void
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM iam_policy._system_as(ARRAY['system:apply']);
END $$;

-- _sync_skeleton(body, commit): role and resource_group follow the skeleton's
-- keys (the entries' foreign keys need them): upserted, and a key that left it
-- marked retired. member and effective_route are not synced in Phase 4.
CREATE OR REPLACE FUNCTION iam_policy._sync_skeleton(p_body jsonb, p_commit text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    nr       integer;
    ng       integer;
    v_retired  jsonb;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._system_as(ARRAY['system:apply', 'system:deploy']);
    IF pg_catalog.jsonb_typeof(p_body -> 'roles') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(p_body -> 'resource_groups') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'a skeleton names roles and resource_groups' USING ERRCODE = '22023';
    END IF;
    INSERT INTO iam_policy.role AS r (code, db_role, includes, retired)
    SELECT k, coalesce(d ->> 'db_role', 'rr_' || k),
           ARRAY(SELECT pg_catalog.jsonb_array_elements_text(coalesce(d -> 'includes', '[]'))), false
      FROM pg_catalog.jsonb_each(p_body -> 'roles') x(k, d)
    ON CONFLICT (code) DO UPDATE SET db_role = EXCLUDED.db_role, includes = EXCLUDED.includes, retired = false;
    GET DIAGNOSTICS nr = ROW_COUNT;
    INSERT INTO iam_policy.resource_group AS g (code, data_class, retired)
    SELECT k, d ->> 'class', false FROM pg_catalog.jsonb_each(p_body -> 'resource_groups') x(k, d)
    ON CONFLICT (code) DO UPDATE SET data_class = EXCLUDED.data_class, retired = false;
    GET DIAGNOSTICS ng = ROW_COUNT;
    WITH r AS (UPDATE iam_policy.role x SET retired = true
                WHERE NOT x.retired AND NOT (p_body -> 'roles') ? x.code RETURNING 'role:' || x.code AS k),
         g AS (UPDATE iam_policy.resource_group x SET retired = true
                WHERE NOT x.retired AND NOT (p_body -> 'resource_groups') ? x.code RETURNING 'group:' || x.code AS k)
    SELECT coalesce(pg_catalog.jsonb_agg(k ORDER BY k), '[]') INTO v_retired FROM (SELECT k FROM r UNION ALL SELECT k FROM g) z;
    PERFORM iam_policy._append_history('skeleton_synced', pg_catalog.jsonb_build_object(
        'version', (SELECT x.version FROM iam_policy.version x WHERE x.status = 'applied'),
        'roles', nr, 'groups', ng, 'retired', v_retired, 'commit', p_commit), NULL);
END $$;

-- _accept_skeleton(digest, body, commit, compiler_digest, summary): the host's
-- skeleton gate (system:deploy, IAM 4.2a) or apply.sh (system:apply) accepts a
-- skeleton: inserted if new, made the accepted one; the event names the digest it
-- replaced ('from', null for the first). summary {narrowed, unchanged, reviewed_by_version}.
CREATE OR REPLACE FUNCTION iam_policy._accept_skeleton(p_digest text, p_body jsonb, p_commit text,
    p_compiler_digest text, p_summary jsonb) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    hid  bigint;
    rv   integer := (p_summary ->> 'reviewed_by_version')::integer;
    v_from text;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('_accept_skeleton', rv);
    PERFORM iam_policy._system_as(ARRAY['system:apply', 'system:deploy']);
    IF coalesce(p_digest, '') !~ '^[0-9a-f]{64}$' OR p_body IS NULL THEN
        RAISE EXCEPTION 'a skeleton needs its sha256 digest and its body' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_policy.skeleton s WHERE s.digest = p_digest AND s.body <> p_body) THEN
        RAISE EXCEPTION 'skeleton % is stored with another body' , p_digest USING ERRCODE = '22023';
    END IF;
    -- what it replaces (critique sec-12): health recomputes every accept from its two bodies
    SELECT s.digest INTO v_from FROM iam_policy.skeleton s WHERE s.accepted_at IS NOT NULL
     ORDER BY s.accepted_at DESC, s.digest LIMIT 1;
    INSERT INTO iam_policy.skeleton (digest, body, git_commit, compiler_digest)
    VALUES (p_digest, p_body, p_commit, p_compiler_digest) ON CONFLICT (digest) DO NOTHING;
    hid := iam_policy._append_history('skeleton_accepted', pg_catalog.jsonb_build_object(
        'version', (SELECT x.version FROM iam_policy.version x WHERE x.status = 'applied'),
        'digest', p_digest, 'from', v_from, 'commit', p_commit, 'narrowed', p_summary -> 'narrowed', 'unchanged', p_summary -> 'unchanged',
        'reviewed_by_version', rv), NULL);
    UPDATE iam_policy.skeleton s SET accepted_at = pg_catalog.clock_timestamp(), accepted_event = hid,
           reviewed_by_version = coalesce(rv, s.reviewed_by_version)
     WHERE s.digest = p_digest;
END $$;

-- _propose_skeleton(...): apply.sh --propose-skeleton (4.4): a git skeleton that
-- adds reach becomes a submitted skeleton version with the applied entries and
-- the host-computed diff qa will see byte for byte. It does not hash p_diff
-- itself: apply.sh computed p_diff_digest over source.canonical(p_diff), and
-- iam-api re-checks it before serving the diff. created_by_name is the fixed text
-- 'apply.sh --by (claimed)'; the --by username and the OS user are in the reason.
CREATE OR REPLACE FUNCTION iam_policy._propose_skeleton(p_digest text, p_body jsonb, p_commit text, p_diff jsonb,
    p_diff_digest text, p_by_sub uuid, p_by_person text, p_reason text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    applied  integer;
    open_v   integer;
    v        integer;
    ents     jsonb;
    wvs      jsonb;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    SELECT coalesce(max(x.version), 0) + 1 INTO v FROM iam_policy.version x;
    PERFORM iam_policy._begin('_propose_skeleton', v);
    PERFORM iam_policy._system();
    IF coalesce(pg_catalog.btrim(p_reason), '') = '' OR coalesce(pg_catalog.btrim(p_by_person), '') = '' OR p_by_sub IS NULL THEN
        RAISE EXCEPTION 'a skeleton proposal needs a reason and the proposer (--by)' USING ERRCODE = '22023';
    END IF;
    IF coalesce(p_digest, '') !~ '^[0-9a-f]{64}$' OR coalesce(p_diff_digest, '') !~ '^[0-9a-f]{64}$' OR p_diff IS NULL THEN
        RAISE EXCEPTION 'a skeleton proposal needs the skeleton digest, the diff and its digest' USING ERRCODE = '22023';
    END IF;
    SELECT x.version INTO applied FROM iam_policy.version x WHERE x.status = 'applied';
    IF applied IS NULL THEN
        RAISE EXCEPTION 'no policy version is applied' USING ERRCODE = '22023';
    END IF;
    SELECT x.version INTO open_v FROM iam_policy.version x
     WHERE x.status IN ('draft', 'submitted', 'approved') AND x.kind IN ('change', 'skeleton');
    IF open_v IS NOT NULL THEN
        RAISE EXCEPTION 'version % is still open: take it through or withdraw it first', open_v USING ERRCODE = '23505';
    END IF;
    IF p_digest IS NOT DISTINCT FROM iam_policy._accepted() THEN
        RAISE EXCEPTION 'nothing to approve: this skeleton is the accepted one' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_policy.skeleton s WHERE s.digest = p_digest AND s.body <> p_body) THEN
        RAISE EXCEPTION 'skeleton % is stored with another body', p_digest USING ERRCODE = '22023';
    END IF;
    INSERT INTO iam_policy.skeleton (digest, body, git_commit) VALUES (p_digest, p_body, p_commit)
    ON CONFLICT (digest) DO NOTHING;
    INSERT INTO iam_policy.version (version, status, kind, reason, based_on, groups, roles, skeleton_digest,
                                    created_by_sub, created_by_person, created_by_name,
                                    submitted_by_sub, submitted_by_person, submitted_by_name, submitted_at)
    VALUES (v, 'submitted', 'skeleton', p_reason, applied,
            ARRAY(SELECT k FROM pg_catalog.jsonb_object_keys(p_body -> 'resource_groups') k ORDER BY k COLLATE "C"),
            ARRAY(SELECT k FROM pg_catalog.jsonb_object_keys(p_body -> 'roles') k ORDER BY k COLLATE "C"),
            p_digest, p_by_sub, p_by_person, 'apply.sh --by (claimed)', p_by_sub, p_by_person, 'apply.sh --by (claimed)',
            pg_catalog.now());
    SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('role', e.role, 'group_code', e.group_code,
               'level', e.level::text, 'constraint_name', e.constraint_name)), '[]')
      INTO ents FROM iam_policy.entry e WHERE e.version = applied;
    SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(w) - 'version'), '[]')
      INTO wvs FROM iam_policy.waiver w WHERE w.version = applied;
    PERFORM iam_policy._put_rows(v, ents, wvs);
    UPDATE iam_policy.version x SET entries_digest = iam_policy.entries_digest(v) WHERE x.version = v;
    INSERT INTO iam_policy.version_diff (version, diff, diff_digest, computed_on) VALUES (v, p_diff, p_diff_digest, 'host');
    PERFORM iam_policy._append_history('submitted', pg_catalog.jsonb_build_object(
        'version', v, 'kind', 'skeleton', 'skeleton_digest', p_digest, 'diff_digest', p_diff_digest, 'commit', p_commit,
        'claimed_by', pg_catalog.jsonb_build_object('sub', p_by_sub, 'person', p_by_person),
        'entries_digest', (SELECT x.entries_digest FROM iam_policy.version x WHERE x.version = v)), p_reason);
    RETURN v;
END $$;

-- _build_version(kind, entries, waivers, based_on, rollback_of, reason): a
-- bootstrap or rollback version as a draft with its rows, inside apply.sh's
-- bundle, which applies it (_mark_applied) in the same transaction. Bootstrap
-- only on an empty table; a rollback only to a version once approved and
-- applied (now superseded) or a confirmed bootstrap or rollback (OA-c).
CREATE OR REPLACE FUNCTION iam_policy._build_version(p_kind text, p_entries jsonb, p_waivers jsonb,
    p_based_on integer, p_rollback_of integer, p_reason text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v     integer;
    t     iam_policy.version;
    skel  text;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    SELECT coalesce(max(x.version), 0) + 1 INTO v FROM iam_policy.version x;
    PERFORM iam_policy._begin('_build_version', v);
    PERFORM iam_policy._system();
    IF coalesce(pg_catalog.btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'a reason is required' USING ERRCODE = '22023';
    END IF;
    IF p_kind = 'bootstrap' THEN
        IF EXISTS (SELECT 1 FROM iam_policy.version) THEN
            RAISE EXCEPTION 'policy versions exist: --bootstrap is only for an empty table' USING ERRCODE = '22023';
        END IF;
        IF p_based_on IS NOT NULL OR p_rollback_of IS NOT NULL THEN
            RAISE EXCEPTION 'a bootstrap version has no base' USING ERRCODE = '22023';
        END IF;
    ELSIF p_kind = 'rollback' THEN
        SELECT * INTO t FROM iam_policy.version x WHERE x.version = p_rollback_of;
        IF NOT FOUND OR t.status <> 'superseded'
           OR (t.kind IN ('bootstrap', 'rollback') AND (t.confirmed_at IS NULL OR t.disputed_at IS NOT NULL)) THEN
            RAISE EXCEPTION 'version % cannot be rolled back to: only an approved version once applied, or a confirmed bootstrap or rollback',
                p_rollback_of USING ERRCODE = '22023';
        END IF;
        IF p_based_on IS DISTINCT FROM (SELECT x.version FROM iam_policy.version x WHERE x.status = 'applied') THEN
            RAISE EXCEPTION 'a rollback is based on the applied version' USING ERRCODE = '22023';
        END IF;
    ELSE
        RAISE EXCEPTION '_build_version builds bootstrap or rollback versions, not %', p_kind USING ERRCODE = '22023';
    END IF;
    skel := iam_policy._accepted();
    IF skel IS NULL THEN
        RAISE EXCEPTION 'accept the platform skeleton first (_accept_skeleton)' USING ERRCODE = '22023';
    END IF;
    INSERT INTO iam_policy.version (version, status, kind, reason, based_on, rollback_of, groups, roles, skeleton_digest,
                                    created_by_name)
    SELECT v, 'draft', p_kind, p_reason, p_based_on, p_rollback_of,
           ARRAY(SELECT k FROM pg_catalog.jsonb_object_keys(s.body -> 'resource_groups') k ORDER BY k COLLATE "C"),
           ARRAY(SELECT k FROM pg_catalog.jsonb_object_keys(s.body -> 'roles') k ORDER BY k COLLATE "C"),
           skel, 'system:apply'
      FROM iam_policy.skeleton s WHERE s.digest = skel;
    PERFORM iam_policy._put_rows(v, p_entries, p_waivers);
    UPDATE iam_policy.version x SET entries_digest = iam_policy.entries_digest(v) WHERE x.version = v;
    PERFORM iam_policy._append_history('draft_created', pg_catalog.jsonb_build_object(
        'version', v, 'kind', p_kind, 'rollback_of', p_rollback_of,
        'entries_digest', (SELECT x.entries_digest FROM iam_policy.version x WHERE x.version = v)), p_reason);
    RETURN v;
END $$;

-- _mark_applied(v, digests, os_user, by_sub, by_person, log): approved (or a
-- bootstrap/rollback draft) -> applied, the previous applied -> superseded.
-- Re-reads the status and the entries digest FOR UPDATE (F-16).
CREATE OR REPLACE FUNCTION iam_policy._mark_applied(p_version integer, p_digests jsonb, p_os_user text,
    p_by_sub uuid, p_by_person text, p_log_path text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v     iam_policy.version;
    prev  integer;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('_mark_applied', p_version);
    PERFORM iam_policy._system();
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no policy version %', p_version USING ERRCODE = '22023';
    END IF;
    IF NOT ((v.kind IN ('change', 'skeleton') AND v.status = 'approved')
            OR (v.kind IN ('bootstrap', 'rollback') AND v.status = 'draft')) THEN
        RAISE EXCEPTION 'version % (%) is %: nothing to apply', p_version, v.kind, v.status USING ERRCODE = '22023';
    END IF;
    IF iam_policy.entries_digest(p_version) IS DISTINCT FROM v.entries_digest THEN
        RAISE EXCEPTION 'version %: its entries are not the ones approved', p_version USING ERRCODE = '22023';
    END IF;
    SELECT x.version INTO prev FROM iam_policy.version x WHERE x.status = 'applied' FOR UPDATE;
    IF v.kind IN ('change', 'skeleton') AND v.based_on IS DISTINCT FROM prev THEN
        RAISE EXCEPTION 'version % was approved on version %, but version % is applied', p_version, v.based_on, prev
            USING ERRCODE = '22023';
    END IF;
    IF prev IS NOT NULL THEN
        UPDATE iam_policy.version x SET status = 'superseded', superseded_at = pg_catalog.now() WHERE x.version = prev;
    END IF;
    UPDATE iam_policy.version x SET status = 'applied', applied_at = pg_catalog.now(), artefact_digests = p_digests,
           claimed_by_os = p_os_user, claimed_by_sub = p_by_sub, claimed_by_person = p_by_person, apply_log = p_log_path
     WHERE x.version = p_version;
    PERFORM iam_policy._append_history('apply_started', pg_catalog.jsonb_build_object(
        'version', p_version, 'kind', v.kind, 'previous', prev, 'db_digests', p_digests, 'commit', p_digests ->> 'git_commit',
        'skeleton_digest', iam_policy._accepted(), 'compiler_digest', p_digests ->> 'compiler_digest'), NULL);
END $$;

-- _mark_reverted(v, prev, why): a failed apply puts the previous version back
-- (a full revert only): a change or skeleton version returns to approved, a
-- bootstrap or rollback version is withdrawn (never an "approved" phantom).
CREATE OR REPLACE FUNCTION iam_policy._mark_reverted(p_version integer, p_prev integer, p_why text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v  iam_policy.version;
    n  bigint;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    PERFORM iam_policy._begin('_mark_reverted', p_version);
    PERFORM iam_policy._system();
    IF coalesce(pg_catalog.btrim(p_why), '') = '' THEN
        RAISE EXCEPTION 'a reason is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v FROM iam_policy.version x WHERE x.version = p_version FOR UPDATE;
    IF NOT FOUND OR v.status <> 'applied' THEN
        RAISE EXCEPTION 'version % is not the applied one', p_version USING ERRCODE = '22023';
    END IF;
    IF p_prev IS NOT NULL AND NOT EXISTS (SELECT 1 FROM iam_policy.version x WHERE x.version = p_prev AND x.status = 'superseded') THEN
        RAISE EXCEPTION 'version % is not superseded: nothing to put back', p_prev USING ERRCODE = '22023';
    END IF;
    IF v.kind IN ('change', 'skeleton') THEN
        UPDATE iam_policy.version x SET status = 'approved', applied_at = NULL WHERE x.version = p_version;
    ELSE
        UPDATE iam_policy.version x SET status = 'withdrawn', withdrawn_at = pg_catalog.now(), withdrawn_by = 'system:apply'
         WHERE x.version = p_version;
    END IF;
    IF p_prev IS NOT NULL THEN
        UPDATE iam_policy.version x SET status = 'applied', superseded_at = NULL WHERE x.version = p_prev;
    END IF;
    IF pg_catalog.to_regclass('iam.account_decision') IS NOT NULL AND v.applied_at IS NOT NULL THEN
        EXECUTE 'SELECT count(*) FROM iam.account_decision d WHERE d.made_at >= $1' INTO n USING v.applied_at;
    END IF;
    PERFORM iam_policy._append_history('apply_reverted', pg_catalog.jsonb_build_object(
        'version', p_version, 'prev', p_prev, 'decisions_in_window', n), p_why);
END $$;

-- _withdraw_open(reason): apply.sh withdraws an open change or skeleton version
-- (a rollback, §6.6), as system:apply. Returns its number, or NULL.
CREATE OR REPLACE FUNCTION iam_policy._withdraw_open(p_reason text) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v integer;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version'));
    SELECT x.version INTO v FROM iam_policy.version x
     WHERE x.status IN ('draft', 'submitted', 'approved') AND x.kind IN ('change', 'skeleton') FOR UPDATE;
    PERFORM iam_policy._begin('_withdraw_open', v);
    PERFORM iam_policy._system();
    IF coalesce(pg_catalog.btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'a reason is required' USING ERRCODE = '22023';
    END IF;
    IF v IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE iam_policy.version x SET status = 'withdrawn', withdrawn_at = pg_catalog.now(), withdrawn_by = 'system:apply'
     WHERE x.version = v;
    PERFORM iam_policy._append_history('withdrawn', pg_catalog.jsonb_build_object('version', v, 'by', 'system:apply'), p_reason);
    RETURN v;
END $$;

-- _record(event, payload): apply.sh's and the deploys' own events (IAM 4.2a).
--   applied, partial_apply, bootstrap_applied, apply_deferred: system:apply only,
--     and the payload names its version (a number);
--   break_glass_seen, break_glass_ended, account_seeded: system:apply or
--     system:deploy; a payload without a version key is filed under the applied
--     version (JSON null when none). break_glass_seen with source 'file' (a policy
--     override) needs a number version and a reason. account_seeded needs
--     username, sub, fact and fact_id = the sha256 of its canonical content
--     (jsonb text of fact, username, sub, role, person_id; source.pg_jsonb_text in
--     Python) and is idempotent per content: the same fact_id returns the event
--     already recorded and appends nothing.
CREATE OR REPLACE FUNCTION iam_policy._record(p_event text, p_payload jsonb) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_fid  text;
    v_id   bigint;
BEGIN
    IF p_event IN ('applied', 'partial_apply', 'bootstrap_applied', 'apply_deferred') THEN
        PERFORM iam_policy._system_as(ARRAY['system:apply']);
    ELSIF p_event IN ('break_glass_seen', 'break_glass_ended', 'account_seeded') THEN
        PERFORM iam_policy._system_as(ARRAY['system:apply', 'system:deploy']);
    ELSE
        RAISE EXCEPTION '_record: % is not an apply.sh or deploy event', p_event USING ERRCODE = '22023';
    END IF;
    IF pg_catalog.jsonb_typeof(p_payload) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION '_record: the % payload must be an object', p_event USING ERRCODE = '22023';
    END IF;
    IF p_event IN ('applied', 'partial_apply', 'bootstrap_applied', 'apply_deferred') THEN
        IF pg_catalog.jsonb_typeof(p_payload -> 'version') IS DISTINCT FROM 'number' THEN
            RAISE EXCEPTION '_record: the % payload must name its version', p_event USING ERRCODE = '22023';
        END IF;
    ELSIF NOT p_payload ? 'version' THEN
        p_payload := p_payload || pg_catalog.jsonb_build_object('version',
            (SELECT x.version FROM iam_policy.version x WHERE x.status = 'applied'));
    ELSIF pg_catalog.jsonb_typeof(p_payload -> 'version') NOT IN ('number', 'null') THEN
        RAISE EXCEPTION '_record: the % payload''s version must be a number or null', p_event USING ERRCODE = '22023';
    END IF;
    IF p_event = 'break_glass_seen' AND p_payload ->> 'source' = 'file' THEN
        IF pg_catalog.jsonb_typeof(p_payload -> 'version') IS DISTINCT FROM 'number' THEN
            RAISE EXCEPTION '_record: a policy break-glass (source file) needs an applied version' USING ERRCODE = '22023';
        END IF;
        IF coalesce(pg_catalog.btrim(p_payload ->> 'reason'), '') = '' THEN
            RAISE EXCEPTION '_record: a policy break-glass (source file) needs its reason' USING ERRCODE = '22023';
        END IF;
    END IF;
    IF p_event = 'account_seeded' THEN
        IF coalesce(pg_catalog.btrim(p_payload ->> 'username'), '') = '' OR coalesce(pg_catalog.btrim(p_payload ->> 'sub'), '') = ''
           OR coalesce(p_payload ->> 'fact', '') NOT IN ('created', 'person_id_set', 'observed') THEN
            RAISE EXCEPTION '_record: an account_seeded fact names its username, sub and fact (created, person_id_set, observed)'
                USING ERRCODE = '22023';
        END IF;
        v_fid := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.jsonb_build_object(
                     'fact', p_payload -> 'fact', 'username', p_payload -> 'username', 'sub', p_payload -> 'sub',
                     'role', p_payload -> 'role', 'person_id', p_payload -> 'person_id')::text, 'UTF8')), 'hex');
        IF coalesce(p_payload ->> 'fact_id', '') !~ '^[0-9a-f]{64}$' OR p_payload ->> 'fact_id' <> v_fid THEN
            RAISE EXCEPTION '_record: fact_id is not the content hash of this account_seeded fact' USING ERRCODE = '22023';
        END IF;
        PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.account_seeded'));
        SELECT h.event_id INTO v_id FROM iam_policy.history h
         WHERE h.event = 'account_seeded' AND h.payload ->> 'fact_id' = v_fid ORDER BY h.event_id LIMIT 1;
        IF v_id IS NOT NULL THEN
            RETURN v_id;
        END IF;
    END IF;
    RETURN iam_policy._append_history(p_event, p_payload, p_payload ->> 'reason');
END $$;

-- ── the PostgREST wrappers (schema medcea; level A of iam_policy) ───────────
-- PL/pgSQL on purpose: medcea_auth._rpc_client is compiled after the migrations
-- (lib-db-apply.sh step 4a), and a plpgsql body is resolved only when it runs.
CREATE OR REPLACE FUNCTION medcea.approve_policy(p_version integer, p_note text, p_entries_digest text,
    p_diff_digest text, p_skeleton_digest text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM iam_policy.approve(p_version, p_note, p_entries_digest, p_diff_digest, p_skeleton_digest);
END $$;
CREATE OR REPLACE FUNCTION medcea.return_policy(p_version integer, p_note text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM iam_policy.return_version(p_version, p_note);
END $$;
CREATE OR REPLACE FUNCTION medcea.confirm_policy(p_version integer, p_note text, p_attest text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM iam_policy.confirm_applied(p_version, p_note, p_attest);
END $$;
CREATE OR REPLACE FUNCTION medcea.dispute_policy(p_version integer, p_note text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM iam_policy.dispute_applied(p_version, p_note);
END $$;

-- 7. The freeze trigger on the six tables: created only when missing (never
--    CREATE OR REPLACE TRIGGER, which would reset it to ORIGIN mode), and
--    ENABLE ALWAYS only where it is not already (session_replication_role =
--    replica does not bypass it).
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['version', 'entry', 'waiver', 'skeleton', 'version_diff', 'approval_evidence'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = pg_catalog.to_regclass('iam_policy.' || t)
                                                             AND tgname = 'freeze_policy_trg') THEN
            EXECUTE pg_catalog.format('CREATE TRIGGER freeze_policy_trg BEFORE INSERT OR UPDATE OR DELETE ON iam_policy.%I '
                                      'FOR EACH ROW EXECUTE FUNCTION iam_policy.freeze_policy()', t);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = pg_catalog.to_regclass('iam_policy.' || t)
                                                             AND tgname = 'freeze_policy_truncate_trg') THEN
            EXECUTE pg_catalog.format('CREATE TRIGGER freeze_policy_truncate_trg BEFORE TRUNCATE ON iam_policy.%I '
                                      'FOR EACH STATEMENT EXECUTE FUNCTION iam_policy.freeze_policy()', t);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = pg_catalog.to_regclass('iam_policy.' || t)
                    AND tgname IN ('freeze_policy_trg', 'freeze_policy_truncate_trg') AND tgenabled <> 'A') THEN
            EXECUTE pg_catalog.format('ALTER TABLE iam_policy.%I ENABLE ALWAYS TRIGGER freeze_policy_trg', t);
            EXECUTE pg_catalog.format('ALTER TABLE iam_policy.%I ENABLE ALWAYS TRIGGER freeze_policy_truncate_trg', t);
        END IF;
    END LOOP;
END $$;

-- 8. Ownership: 008b's loop (B21) ran before 008c in this file, so 008c owns its
--    own: every function in iam_policy, the four wrappers and the _rpc_client stub
--    to medcea_owner, nothing executable by PUBLIC; the new tables to medcea_owner.
DO $$
DECLARE f regprocedure; t text;
BEGIN
    FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
              WHERE p.pronamespace = 'iam_policy'::regnamespace
                 OR p.oid IN (pg_catalog.to_regprocedure('medcea.approve_policy(integer,text,text,text,text)'),
                              pg_catalog.to_regprocedure('medcea.return_policy(integer,text)'),
                              pg_catalog.to_regprocedure('medcea.confirm_policy(integer,text,text)'),
                              pg_catalog.to_regprocedure('medcea.dispute_policy(integer,text)'),
                              pg_catalog.to_regprocedure('medcea_auth._rpc_client(text)')) LOOP
        IF (SELECT proowner FROM pg_catalog.pg_proc WHERE oid = f) <> 'medcea_owner'::regrole THEN
            EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO medcea_owner', f);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p, pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
                    WHERE p.oid = f AND a.grantee = 0) THEN
            EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        END IF;
    END LOOP;
    FOREACH t IN ARRAY ARRAY['entry', 'skeleton', 'version_diff', 'approval_evidence'] LOOP
        IF (SELECT relowner FROM pg_catalog.pg_class WHERE oid = pg_catalog.to_regclass('iam_policy.' || t)) <> 'medcea_owner'::regrole THEN
            EXECUTE pg_catalog.format('ALTER TABLE iam_policy.%I OWNER TO medcea_owner', t);
        END IF;
    END LOOP;
END $$;

COMMENT ON TABLE iam_policy.skeleton IS 'Accepted (accepted_at set) and proposed platform skeletons by digest: everything of the policy but matrix, waivers and policy_version. Written by the host only (apply.sh, the deploys'' skeleton gate; IAM Phase 4).';
COMMENT ON TABLE iam_policy.version_diff IS 'The host-computed diff of a skeleton version, served to qa byte for byte; its digest is what qa approves (IAM Phase 4).';
COMMENT ON TABLE iam_policy.approval_evidence IS 'The signed tokens (JWS) behind each approve, return, confirm and dispute of a policy version, with their claims; owner only; apply.sh verifies the signature (IAM Phase 4).';
COMMENT ON TABLE iam_policy.entry IS 'One row per (version, role, group, level): the matrix of a policy version; constraint_name NULL = unconstrained (IAM Phase 4).';

NOTIFY pgrst, 'reload schema';

INSERT INTO medcea.platform_setting (key, value) VALUES ('008c:last_nonce', :'deploy_nonce')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

COMMIT;
