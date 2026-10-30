-- apps/access/access_db.sql — self-service access requests and account decisions
-- (applied by deploy.sh)
--
-- Run as postgres, in ONE transaction:  psql -1 -v ON_ERROR_STOP=1 -v access_pw=<password> -f access_db.sql
-- Idempotent: every statement is CREATE ... IF NOT EXISTS / OR REPLACE. No BEGIN/COMMIT
-- here: -1 makes a failure part-way leave nothing applied, and the triggers this
-- file replaces (CREATE OR REPLACE TRIGGER, then ENABLE ALWAYS) are never missing
-- or in ORIGIN mode in between.
--
-- Schema iam, not medcea: PostgREST exposes medcea to anon with full DML, and
-- these rows hold e-mail addresses and business justifications. Nothing here is
-- reachable through the config API.
--
-- Since IAM 2.7 schema iam belongs to medcea_owner (apps/database/medcea_db_owner.sql
-- normalises it on every database deploy) and its grants, access_svc's included,
-- are compiled from the access policy (apps/iam/compiler/grants.py) by the database
-- deploy. This file holds no GRANT or REVOKE but CONNECT and PUBLIC's EXECUTE:
-- everything it adds is unreachable until the next database deploy, which
-- apps/access/deploy.sh runs itself when access_svc lacks its grants. Function
-- bodies are late-bound, so the file applies before medcea_auth and iam_policy
-- exist (a fresh install deploys access before database).
--
-- The access service connects as access_svc, which may read and update requests
-- but never DELETE them, and may only read the histories. The histories are
-- written by SECURITY DEFINER triggers and the decision functions, and refuse
-- UPDATE, DELETE and TRUNCATE for everyone (Compliance Plane rule,
-- docs/architecture.md). Account decisions are written only by the iam.*
-- decision functions below (SECURITY DEFINER, medcea_owner).

CREATE SCHEMA IF NOT EXISTS iam;

CREATE TABLE IF NOT EXISTS iam.access_request (
    request_id        BIGSERIAL PRIMARY KEY,
    keycloak_user_id  VARCHAR(64),
    username          VARCHAR(255) NOT NULL,
    email             VARCHAR(255) NOT NULL,
    first_name        VARCHAR(255) NOT NULL,
    last_name         VARCHAR(255) NOT NULL,
    organisation      VARCHAR(255),
    requested_role    VARCHAR(32)  NOT NULL
                      CHECK (requested_role IN ('operator', 'qa', 'admin', 'auditor')),
    justification     TEXT         NOT NULL,
    status            VARCHAR(16)  NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'approved', 'rejected')),
    granted_role      VARCHAR(32)
                      CHECK (granted_role IN ('operator', 'qa', 'admin', 'auditor')),
    decided_by        VARCHAR(255),
    decided_at        TIMESTAMP WITH TIME ZONE,
    admin_notes       TEXT,
    created_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CHECK ((status = 'pending')  = (decided_at IS NULL)),
    CHECK ((status = 'approved') = (granted_role IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS access_request_status_idx ON iam.access_request (status, created_at);
-- One open request per person: a second form for the same address is refused
-- until the first is decided.
CREATE UNIQUE INDEX IF NOT EXISTS access_request_pending_email_uq
    ON iam.access_request (lower(email)) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS iam.access_request_history (
    event_id        BIGSERIAL PRIMARY KEY,
    request_id      BIGINT       NOT NULL,
    event           VARCHAR(16)  NOT NULL
                    CHECK (event IN ('submitted', 'approved', 'reassigned', 'rejected')),
    username        VARCHAR(255) NOT NULL,
    requested_role  VARCHAR(32)  NOT NULL,
    granted_role    VARCHAR(32),
    actor           VARCHAR(255) NOT NULL,
    notes           TEXT,
    occurred_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS access_request_history_req_idx
    ON iam.access_request_history (request_id, occurred_at);

CREATE OR REPLACE FUNCTION iam.log_access_request() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE ev varchar(16);
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO iam.access_request_history (request_id, event, username, requested_role, actor, notes)
        VALUES (NEW.request_id, 'submitted', NEW.username, NEW.requested_role, NEW.username, NEW.justification);
        RETURN NEW;
    END IF;
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NEW;                       -- e.g. keycloak_user_id filled in
    END IF;
    IF NEW.status = 'rejected' THEN
        ev := 'rejected';
    ELSIF NEW.granted_role IS DISTINCT FROM NEW.requested_role THEN
        ev := 'reassigned';
    ELSE
        ev := 'approved';
    END IF;
    INSERT INTO iam.access_request_history
        (request_id, event, username, requested_role, granted_role, actor, notes)
    VALUES (NEW.request_id, ev, NEW.username, NEW.requested_role, NEW.granted_role,
            coalesce(NEW.decided_by, current_user), NEW.admin_notes);
    RETURN NEW;
END $$;

CREATE OR REPLACE TRIGGER access_request_history_trg
    AFTER INSERT OR UPDATE ON iam.access_request
    FOR EACH ROW EXECUTE FUNCTION iam.log_access_request();
ALTER TABLE iam.access_request ENABLE ALWAYS TRIGGER access_request_history_trg;

-- A decision is final: a request leaves 'pending' once and never changes again.
CREATE OR REPLACE FUNCTION iam.freeze_decided_request() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status <> 'pending' THEN
        RAISE EXCEPTION 'access request % is already %', OLD.request_id, OLD.status;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE TRIGGER access_request_freeze_trg
    BEFORE UPDATE ON iam.access_request
    FOR EACH ROW EXECUTE FUNCTION iam.freeze_decided_request();
ALTER TABLE iam.access_request ENABLE ALWAYS TRIGGER access_request_freeze_trg;

COMMENT ON TABLE iam.access_request IS 'Self-service access requests (apps/access). Decided once: pending -> approved | rejected. Since IAM 2.7 an approved request''s account stays disabled until a qa person confirms its grant (iam.account_decision.request_id).';
COMMENT ON TABLE iam.access_request_history IS 'Append-only log of access requests and decisions. Written by trigger access_request_history_trg only; UPDATE, DELETE and TRUNCATE refused for everyone.';

-- ── E-mail: the message actually sent with each decision ────────────────────
-- The approver edits the pre-filled template before sending; what went out is
-- part of the decision record, written in the same UPDATE (so frozen with it).
ALTER TABLE iam.access_request ADD COLUMN IF NOT EXISTS email_subject TEXT;
ALTER TABLE iam.access_request ADD COLUMN IF NOT EXISTS email_body    TEXT;

-- ── The eleven platform roles of the access policy ──────────────────────────
-- (apps/iam/policy/defaults.yaml). The table accepts all of them; which ones
-- the service offers is ROLES in access-api.py. Re-created rather than altered:
-- the original CHECKs are inline, so an existing install keeps the old list.
ALTER TABLE iam.access_request DROP CONSTRAINT IF EXISTS access_request_requested_role_check;
ALTER TABLE iam.access_request ADD CONSTRAINT access_request_requested_role_check
    CHECK (requested_role IN ('operator', 'production_manager', 'maintenance', 'qc', 'qa', 'qp',
                              'engineer', 'bio_scientist', 'control_scientist', 'admin', 'auditor'));
ALTER TABLE iam.access_request DROP CONSTRAINT IF EXISTS access_request_granted_role_check;
ALTER TABLE iam.access_request ADD CONSTRAINT access_request_granted_role_check
    CHECK (granted_role IN ('operator', 'production_manager', 'maintenance', 'qc', 'qa', 'qp',
                            'engineer', 'bio_scientist', 'control_scientist', 'admin', 'auditor'));

-- ── E-mail settings and templates, managed in the User Manager ──────────────
-- One row. smtp_pass is the Gmail app password: readable by access_svc (it has
-- to log in with it) and never returned by the API.
CREATE TABLE IF NOT EXISTS iam.mail_settings (
    id            SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    smtp_host     VARCHAR(255) NOT NULL DEFAULT 'smtp.gmail.com',
    smtp_port     INTEGER      NOT NULL DEFAULT 587 CHECK (smtp_port BETWEEN 1 AND 65535),
    smtp_user     VARCHAR(255) NOT NULL DEFAULT '',
    smtp_pass     VARCHAR(255) NOT NULL DEFAULT '',
    from_name     VARCHAR(255) NOT NULL DEFAULT 'MedCEA Platform',
    notify_emails TEXT         NOT NULL DEFAULT '',
    updated_by    VARCHAR(255),
    updated_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
INSERT INTO iam.mail_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- An edited template; absent, or is_default, = the default file in apps/access/templates/.
CREATE TABLE IF NOT EXISTS iam.mail_template (
    name        VARCHAR(32) PRIMARY KEY
                CHECK (name IN ('new-request', 'approved', 'reassigned', 'rejected')),
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    updated_by  VARCHAR(255) NOT NULL,
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
-- IAM 2.7: "reset to default" is an UPDATE that sets is_default (and the default
-- text), not a DELETE: nobody holds DELETE in schema iam. A row with is_default
-- is read as "use the file", so a changed default file still applies after a reset;
-- saving a template sets it back to false.
ALTER TABLE iam.mail_template ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;

-- Who changed the mail configuration, and what — never the password itself.
CREATE TABLE IF NOT EXISTS iam.config_history (
    event_id     BIGSERIAL PRIMARY KEY,
    item         VARCHAR(64)  NOT NULL,
    action       VARCHAR(16)  NOT NULL,
    detail       TEXT,
    actor        VARCHAR(255) NOT NULL,
    occurred_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION iam.log_mail_config() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE changed text[] := '{}';
BEGIN
    IF TG_TABLE_NAME = 'mail_settings' THEN
        IF NEW.smtp_host     IS DISTINCT FROM OLD.smtp_host     THEN changed := changed || ('smtp_host=' || NEW.smtp_host); END IF;
        IF NEW.smtp_port     IS DISTINCT FROM OLD.smtp_port     THEN changed := changed || ('smtp_port=' || NEW.smtp_port); END IF;
        IF NEW.smtp_user     IS DISTINCT FROM OLD.smtp_user     THEN changed := changed || ('smtp_user=' || NEW.smtp_user); END IF;
        IF NEW.smtp_pass     IS DISTINCT FROM OLD.smtp_pass     THEN changed := changed || 'smtp_pass changed'::text; END IF;
        IF NEW.from_name     IS DISTINCT FROM OLD.from_name     THEN changed := changed || ('from_name=' || NEW.from_name); END IF;
        IF NEW.notify_emails IS DISTINCT FROM OLD.notify_emails THEN changed := changed || ('notify_emails=' || NEW.notify_emails); END IF;
        IF array_length(changed, 1) IS NULL THEN RETURN NEW; END IF;
        INSERT INTO iam.config_history (item, action, detail, actor)
        VALUES ('mail_settings', 'updated', array_to_string(changed, '; '), coalesce(NEW.updated_by, current_user));
        RETURN NEW;
    END IF;
    -- unreachable since IAM 2.7 (nobody holds DELETE); kept so a superuser's delete is logged
    IF TG_OP = 'DELETE' THEN
        INSERT INTO iam.config_history (item, action, detail, actor)
        VALUES ('template:' || OLD.name, 'reset', 'row deleted: back to the default file', current_user);
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.is_default AND NOT OLD.is_default THEN
        INSERT INTO iam.config_history (item, action, detail, actor)
        VALUES ('template:' || NEW.name, 'reset', 'back to the default text', NEW.updated_by);
        RETURN NEW;
    END IF;
    INSERT INTO iam.config_history (item, action, detail, actor)
    VALUES ('template:' || NEW.name, lower(TG_OP), 'Subject: ' || NEW.subject, NEW.updated_by);
    RETURN NEW;
END $$;

CREATE OR REPLACE TRIGGER mail_settings_history_trg AFTER UPDATE ON iam.mail_settings
    FOR EACH ROW EXECUTE FUNCTION iam.log_mail_config();
ALTER TABLE iam.mail_settings ENABLE ALWAYS TRIGGER mail_settings_history_trg;
CREATE OR REPLACE TRIGGER mail_template_history_trg AFTER INSERT OR UPDATE OR DELETE ON iam.mail_template
    FOR EACH ROW EXECUTE FUNCTION iam.log_mail_config();
ALTER TABLE iam.mail_template ENABLE ALWAYS TRIGGER mail_template_history_trg;

-- ── Mail settings waiting for qa (IAM 2.7, qa_dual_control, kind mail_settings) ─
-- An admin's change of the e-mail account is staged here, never in mail_settings:
-- whoever controls the realm's SMTP account can read password-reset links, so it
-- waits for a qa person. iam.confirm_decision moves the row into mail_settings
-- (the access service then pushes it to the realm); withdraw and refuse delete it.
-- One row. The service inserts it right after iam.record_decision('mail_settings'),
-- in the same transaction; what qa confirms is what was staged: a staged row
-- never changes (withdraw and stage again).
CREATE TABLE IF NOT EXISTS iam.mail_settings_pending
    (LIKE iam.mail_settings INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES);
ALTER TABLE iam.mail_settings_pending ADD COLUMN IF NOT EXISTS decision_id BIGINT NOT NULL;

CREATE OR REPLACE FUNCTION iam.stage_mail_settings() RETURNS trigger
    LANGUAGE plpgsql SET search_path = iam, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'iam.mail_settings_pending: staged settings do not change; withdraw decision #% and stage again',
            OLD.decision_id USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM iam.account_decision d
                    WHERE d.decision_id = NEW.decision_id AND d.kind = 'mail_settings' AND d.status = 'pending_qa') THEN
        RAISE EXCEPTION 'iam.mail_settings_pending: decision #% is not a mail_settings decision waiting for qa',
            NEW.decision_id USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN NEW;
END $$;
CREATE OR REPLACE TRIGGER mail_settings_pending_stage_trg BEFORE INSERT OR UPDATE ON iam.mail_settings_pending
    FOR EACH ROW EXECUTE FUNCTION iam.stage_mail_settings();
ALTER TABLE iam.mail_settings_pending ENABLE ALWAYS TRIGGER mail_settings_pending_stage_trg;
COMMENT ON TABLE iam.mail_settings_pending IS 'A mail settings change waiting for qa (account decision kind mail_settings). Moved to iam.mail_settings by iam.confirm_decision, deleted by withdraw_decision or refuse_decision; never updated.';

-- ── Account history: activation, deactivation, role changes (User Manager → Users)
-- Every change of a Keycloak account's enabled flag made from the User Manager:
-- who, whose account, which way, and why. Nobody may change or remove a row (the
-- Compliance Plane rule); the deactivation itself lives in Keycloak, this is its
-- record.
CREATE TABLE IF NOT EXISTS iam.user_status_history (
    event_id          BIGSERIAL PRIMARY KEY,
    keycloak_user_id  VARCHAR(64)  NOT NULL,
    username          VARCHAR(255) NOT NULL,
    action            VARCHAR(16)  NOT NULL CHECK (action IN ('deactivated', 'activated')),
    reason            TEXT,
    actor             VARCHAR(255) NOT NULL,
    occurred_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CHECK (action = 'activated' OR coalesce(btrim(reason), '') <> '')
);
CREATE INDEX IF NOT EXISTS user_status_history_user_idx
    ON iam.user_status_history (keycloak_user_id, occurred_at);
-- Role changes are part of the same account history (who gave whom which role,
-- from what, and why). Added in place so an existing table upgrades.
ALTER TABLE iam.user_status_history ADD COLUMN IF NOT EXISTS from_role VARCHAR(64);
ALTER TABLE iam.user_status_history ADD COLUMN IF NOT EXISTS to_role   VARCHAR(32);
ALTER TABLE iam.user_status_history DROP CONSTRAINT IF EXISTS user_status_history_action_check;
ALTER TABLE iam.user_status_history ADD CONSTRAINT user_status_history_action_check
    CHECK (action IN ('deactivated', 'activated', 'role_changed'));
-- IAM 2.7: who acted, as a person, and which account decision the row carries out.
-- No new action values on purpose (a reverted access_db.sql re-adds the CHECK
-- above): a confirmed grant is 'activated' with to_role set; a person_id change
-- writes no row here (its decision is its record).
ALTER TABLE iam.user_status_history ADD COLUMN IF NOT EXISTS actor_sub    VARCHAR(64);
ALTER TABLE iam.user_status_history ADD COLUMN IF NOT EXISTS actor_person TEXT;
ALTER TABLE iam.user_status_history ADD COLUMN IF NOT EXISTS decision_id  BIGINT;   -- iam.account_decision
COMMENT ON TABLE iam.user_status_history IS 'Append-only account history from the User Manager (apps/access): deactivated, activated, role_changed (from_role -> to_role). Deactivations and role changes need a reason. Since IAM 2.7 written by the decision functions only, with the actor as a person and the decision it carries out.';

-- ── Service role ─────────────────────────────────────────────────────────────
-- The role shell and its password only. Its grants, CONNECT aside, are compiled
-- from the access policy (svc_access) by apps/database/deploy.sh (IAM 2.7).
SELECT 'CREATE ROLE access_svc LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'access_svc') \gexec
ALTER ROLE access_svc LOGIN PASSWORD :'access_pw';
DO $$
BEGIN
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO access_svc', current_database());
END $$;

-- ── Account decisions and access reviews (codeplan IAM plan 3.7, 3.10) ──────
-- account_decision: every grant, role change, unit assignment or removal
-- (zone_* kept for old rows), person_id change, (de)activation and mail settings
-- change an administrator makes. A widening (qa_dual_control) waits as
-- pending_qa until a qa person who is neither the maker nor the subject confirms
-- or refuses it, or until it is withdrawn; a narrowing acts at once (applied) and
-- is reviewed afterwards. What was decided never changes; only the confirmation,
-- review or withdrawal is added, once, by the decision functions. No DELETE, for
-- anyone.
CREATE TABLE IF NOT EXISTS iam.account_decision (
    decision_id        BIGSERIAL PRIMARY KEY,
    kind               VARCHAR(16)  NOT NULL
                       CHECK (kind IN ('grant', 'role_change', 'zone_assign', 'zone_remove',
                                       'person_id', 'deactivate', 'activate')),
    keycloak_user_id   VARCHAR(64)  NOT NULL,
    username           VARCHAR(255) NOT NULL,
    subject_person     TEXT,
    from_role          VARCHAR(32),
    to_role            VARCHAR(32),
    zone_id            INTEGER,           -- medcea.cea_zone, another schema: no FK
    new_person_id      TEXT,
    widens             BOOLEAN      NOT NULL,
    status             VARCHAR(16)  NOT NULL
                       CHECK (status IN ('pending_qa', 'confirmed', 'refused', 'applied', 'reviewed')),
    reason             TEXT         NOT NULL CHECK (btrim(reason) <> ''),
    made_by_sub        VARCHAR(64),       -- NULL for system:deploy (bootstrap)
    made_by_person     TEXT,
    made_by_name       VARCHAR(255) NOT NULL,
    made_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    checked_by_sub     VARCHAR(64),       -- the qa person who confirmed, refused or reviewed
    checked_by_person  TEXT,
    checked_by_name    VARCHAR(255),
    checked_at         TIMESTAMP WITH TIME ZONE,
    check_note         TEXT,
    CHECK (widens = (status IN ('pending_qa', 'confirmed', 'refused'))),
    CHECK ((checked_at IS NULL) = (status IN ('pending_qa', 'applied'))),
    CHECK ((checked_at IS NULL) = (checked_by_name IS NULL)),
    CHECK (checked_at IS NOT NULL OR (checked_by_sub IS NULL AND checked_by_person IS NULL AND check_note IS NULL)),
    CHECK (checked_by_person IS NULL OR checked_by_person IS DISTINCT FROM made_by_person),
    CHECK (checked_by_person IS NULL OR checked_by_person IS DISTINCT FROM subject_person)
);
CREATE INDEX IF NOT EXISTS account_decision_status_idx ON iam.account_decision (status, made_at);
CREATE INDEX IF NOT EXISTS account_decision_user_idx ON iam.account_decision (keycloak_user_id, made_at);

-- Unit assignments (IAM 2.8): operators are assigned units (iam_policy.user_unit),
-- not zones. Re-created rather than altered, like the role CHECKs above: the
-- original kind CHECK is inline. apps/iam/units.sh writes a unit_assign as
-- pending_qa and nothing else: iam.confirm_decision inserts the iam_policy.user_unit
-- row, and a refusal applies nothing. unit_remove rows are applied (the row is
-- deleted at once). Rows already in effect while pending — made before the
-- assignment waited for qa, by units.sh assign --bootstrap (no other qa account),
-- or by apps/access/unit_backfill.sql — are confirmed as they are (the insert is a
-- no-op), and when iam.refuse_decision refuses one it DELETEs the user_unit row in
-- the same transaction — but only if that decision is the latest unit_* decision
-- for its (keycloak_user_id, unit_id): after assign, remove, assign the older
-- pending row must not remove the current assignment, which has its own. A waiting
-- assignment is withdrawn by units.sh remove.
-- IAM 2.7 adds kind mail_settings (one per realm: keycloak_user_id 'realm').
ALTER TABLE iam.account_decision ADD COLUMN IF NOT EXISTS unit_id INTEGER;   -- medcea.cea_unit, another schema: no FK
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_kind_check;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_kind_check
    CHECK (kind IN ('grant', 'role_change', 'zone_assign', 'zone_remove', 'unit_assign', 'unit_remove',
                    'person_id', 'deactivate', 'activate', 'mail_settings'));
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_unit_chk;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_unit_chk
    CHECK (kind NOT IN ('unit_assign', 'unit_remove') OR unit_id IS NOT NULL);

-- IAM 2.7: which (group, level) pairs a role change adds (medcea_auth.role_widening,
-- compiled from the matrix; '[]' otherwise — also for a person_id or mail_settings
-- decision, which waits for qa all the same); the access request a grant carries
-- out; and a withdrawal by the maker or another admin (status 'withdrawn').
-- freeze_record() leaves widening and request_id out of the columns a close may
-- set, so they are frozen with the rest.
ALTER TABLE iam.account_decision ADD COLUMN IF NOT EXISTS widening            JSONB NOT NULL DEFAULT '[]';
ALTER TABLE iam.account_decision ADD COLUMN IF NOT EXISTS request_id          BIGINT;   -- iam.access_request
ALTER TABLE iam.account_decision ADD COLUMN IF NOT EXISTS withdrawn_by_sub    VARCHAR(64);
ALTER TABLE iam.account_decision ADD COLUMN IF NOT EXISTS withdrawn_by_person TEXT;
ALTER TABLE iam.account_decision ADD COLUMN IF NOT EXISTS withdrawn_by_name   VARCHAR(255);
ALTER TABLE iam.account_decision ADD COLUMN IF NOT EXISTS withdrawn_at        TIMESTAMP WITH TIME ZONE;
ALTER TABLE iam.account_decision ADD COLUMN IF NOT EXISTS withdraw_reason     TEXT;
COMMENT ON COLUMN iam.account_decision.widening IS 'The (group, level) pairs the change adds, as [[group, level], ...] from medcea_auth.role_widening(). Empty for a person_id or mail_settings decision, which waits for qa all the same (widens = true).';
COMMENT ON COLUMN iam.account_decision.request_id IS 'The access request a grant carries out (iam.access_request); the confirm screen and the approval e-mail read it.';

-- The inline status CHECKs gain 'withdrawn'. The two that compare status with
-- widens and checked_at have generated names, so they are found by definition
-- and replaced by named ones; the reverted access_db.sql never touches them.
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT c.conname FROM pg_catalog.pg_constraint c
              WHERE c.conrelid = 'iam.account_decision'::regclass AND c.contype = 'c'
                AND c.conname NOT LIKE 'account\_decision\_%\_chk'
                AND (pg_catalog.pg_get_constraintdef(c.oid) ~ '^CHECK \(+widens = '
                     OR pg_catalog.pg_get_constraintdef(c.oid) ~ '^CHECK \(+checked_at IS NULL\) = \(+status\)') LOOP
        EXECUTE pg_catalog.format('ALTER TABLE iam.account_decision DROP CONSTRAINT %I', r.conname);
    END LOOP;
END $$;
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_status_check;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_status_check
    CHECK (status IN ('pending_qa', 'confirmed', 'refused', 'applied', 'reviewed', 'withdrawn'));
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_widens_chk;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_widens_chk
    CHECK (widens = (status IN ('pending_qa', 'confirmed', 'refused', 'withdrawn')));
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_checked_chk;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_checked_chk
    CHECK ((checked_at IS NULL) = (status IN ('pending_qa', 'applied', 'withdrawn')));
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_withdrawn_chk;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_withdrawn_chk
    CHECK ((withdrawn_at IS NULL) = (status <> 'withdrawn')
           AND (withdrawn_at IS NULL) = (withdrawn_by_name IS NULL)
           AND (withdrawn_at IS NOT NULL OR (withdrawn_by_sub IS NULL AND withdrawn_by_person IS NULL
                                             AND withdraw_reason IS NULL))
           AND (withdrawn_at IS NULL OR coalesce(btrim(withdraw_reason), '') <> ''));
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_request_chk;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_request_chk
    CHECK (request_id IS NULL OR kind = 'grant');
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_widening_chk;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_widening_chk
    CHECK (pg_catalog.jsonb_typeof(widening) = 'array');
-- One open decision per account (unit decisions apart): the backstop of
-- record_decision's check, which runs under the per-account lock.
CREATE UNIQUE INDEX IF NOT EXISTS account_decision_one_open_uq ON iam.account_decision (keycloak_user_id)
    WHERE status = 'pending_qa' AND kind NOT IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove');
CREATE INDEX IF NOT EXISTS account_decision_unit_idx ON iam.account_decision (keycloak_user_id, unit_id, decision_id)
    WHERE unit_id IS NOT NULL;

-- access_review: the quarterly snapshot of accounts, roles, persons, units,
-- last logins, pending decisions, waivers and enforcement switches, signed off
-- by a qa person. The snapshot is frozen at creation; sign-off is added once.
CREATE TABLE IF NOT EXISTS iam.access_review (
    review_id            BIGSERIAL PRIMARY KEY,
    period               VARCHAR(16)  NOT NULL UNIQUE,   -- e.g. 2026-Q4
    snapshot             JSONB        NOT NULL,
    created_by           VARCHAR(255) NOT NULL,
    created_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    signed_off_by_sub    VARCHAR(64),
    signed_off_by_person TEXT,
    signed_off_by_name   VARCHAR(255),
    signed_off_at        TIMESTAMP WITH TIME ZONE,
    sign_off_note        TEXT,
    CHECK ((signed_off_at IS NULL) = (signed_off_by_name IS NULL)),
    CHECK (signed_off_at IS NOT NULL OR (signed_off_by_sub IS NULL AND signed_off_by_person IS NULL AND sign_off_note IS NULL))
);
-- IAM 2.7: the creator as a person (iam.create_review)
ALTER TABLE iam.access_review ADD COLUMN IF NOT EXISTS created_by_sub    VARCHAR(64);
ALTER TABLE iam.access_review ADD COLUMN IF NOT EXISTS created_by_person TEXT;

-- What a decision or a review says is final; the check / sign-off / withdrawal
-- columns are filled once, from their empty state, all in the one UPDATE that
-- sets checked_at, withdrawn_at or signed_off_at — so the person recorded is
-- the one who closed it, not a value left by an earlier write. Only the
-- decision functions close a record (IAM 2.7): this trigger is SECURITY INVOKER,
-- so inside a SECURITY DEFINER function current_user is its owner, medcea_owner.
-- No DELETE or TRUNCATE.
CREATE OR REPLACE FUNCTION iam.freeze_record() RETURNS trigger
    LANGUAGE plpgsql SET search_path = iam, pg_temp AS $$
DECLARE
    is_decision boolean := TG_TABLE_NAME = 'account_decision';
    added text[] := CASE WHEN is_decision
        THEN ARRAY['status', 'checked_by_sub', 'checked_by_person', 'checked_by_name', 'checked_at', 'check_note',
                   'withdrawn_by_sub', 'withdrawn_by_person', 'withdrawn_by_name', 'withdrawn_at', 'withdraw_reason']
        ELSE ARRAY['signed_off_by_sub', 'signed_off_by_person', 'signed_off_by_name',
                   'signed_off_at', 'sign_off_note'] END;
    closers text[] := CASE WHEN is_decision THEN ARRAY['checked_at', 'withdrawn_at'] ELSE ARRAY['signed_off_at'] END;
    o jsonb := to_jsonb(OLD);
    n jsonb := to_jsonb(NEW);
    c text;
    done boolean := false;
    closes boolean := false;
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'iam.% is append-only: % refused', TG_TABLE_NAME, TG_OP
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    FOREACH c IN ARRAY closers LOOP
        done := done OR (o ->> c) IS NOT NULL;
        closes := closes OR (n ->> c) IS NOT NULL;
    END LOOP;
    IF done THEN
        RAISE EXCEPTION 'iam.% row is final', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (n - added) IS DISTINCT FROM (o - added) THEN
        RAISE EXCEPTION 'iam.%: only the check, sign-off or withdrawal may be added', TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT closes AND n IS DISTINCT FROM o THEN
        RAISE EXCEPTION 'iam.%: the check, sign-off or withdrawal is added in one update, with %', TG_TABLE_NAME,
            array_to_string(closers, ' or ') USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF current_user <> 'medcea_owner' THEN
        RAISE EXCEPTION 'iam.%: only iam.confirm_decision, refuse_decision, review_decision, withdraw_decision, record_decision or sign_off_review close a record', TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE TRIGGER account_decision_freeze_trg BEFORE UPDATE OR DELETE ON iam.account_decision
    FOR EACH ROW EXECUTE FUNCTION iam.freeze_record();
ALTER TABLE iam.account_decision ENABLE ALWAYS TRIGGER account_decision_freeze_trg;
CREATE OR REPLACE TRIGGER account_decision_truncate_trg BEFORE TRUNCATE ON iam.account_decision
    FOR EACH STATEMENT EXECUTE FUNCTION iam.freeze_record();
ALTER TABLE iam.account_decision ENABLE ALWAYS TRIGGER account_decision_truncate_trg;
CREATE OR REPLACE TRIGGER access_review_freeze_trg BEFORE UPDATE OR DELETE ON iam.access_review
    FOR EACH ROW EXECUTE FUNCTION iam.freeze_record();
ALTER TABLE iam.access_review ENABLE ALWAYS TRIGGER access_review_freeze_trg;
CREATE OR REPLACE TRIGGER access_review_truncate_trg BEFORE TRUNCATE ON iam.access_review
    FOR EACH STATEMENT EXECUTE FUNCTION iam.freeze_record();
ALTER TABLE iam.access_review ENABLE ALWAYS TRIGGER access_review_truncate_trg;

COMMENT ON TABLE iam.account_decision IS 'Account decisions (grant, role change, units, person_id, (de)activation, mail settings): pending_qa -> confirmed | refused | withdrawn for a widening, applied -> reviewed otherwise. Written by the iam.* decision functions only; final once closed; no DELETE.';
COMMENT ON TABLE iam.access_review IS 'Quarterly access review snapshots (iam.create_review), signed off once by a qa person (iam.sign_off_review). Append-only.';

-- ── The three histories refuse change for everyone (IAM 2.7) ────────────────
-- Not only by grant: UPDATE, DELETE and TRUNCATE are refused by trigger, for the
-- owner and the superuser too, and ENABLE ALWAYS (session_replication_role=replica
-- does not bypass them). Their writers only INSERT.
CREATE OR REPLACE FUNCTION iam.refuse_change() RETURNS trigger
    LANGUAGE plpgsql SET search_path = iam, pg_temp AS $$
BEGIN
    RAISE EXCEPTION '%.% is append-only: % refused', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE OR REPLACE TRIGGER user_status_history_append_only BEFORE UPDATE OR DELETE ON iam.user_status_history
    FOR EACH ROW EXECUTE FUNCTION iam.refuse_change();
ALTER TABLE iam.user_status_history ENABLE ALWAYS TRIGGER user_status_history_append_only;
CREATE OR REPLACE TRIGGER user_status_history_no_truncate BEFORE TRUNCATE ON iam.user_status_history
    FOR EACH STATEMENT EXECUTE FUNCTION iam.refuse_change();
ALTER TABLE iam.user_status_history ENABLE ALWAYS TRIGGER user_status_history_no_truncate;
CREATE OR REPLACE TRIGGER access_request_history_append_only BEFORE UPDATE OR DELETE ON iam.access_request_history
    FOR EACH ROW EXECUTE FUNCTION iam.refuse_change();
ALTER TABLE iam.access_request_history ENABLE ALWAYS TRIGGER access_request_history_append_only;
CREATE OR REPLACE TRIGGER access_request_history_no_truncate BEFORE TRUNCATE ON iam.access_request_history
    FOR EACH STATEMENT EXECUTE FUNCTION iam.refuse_change();
ALTER TABLE iam.access_request_history ENABLE ALWAYS TRIGGER access_request_history_no_truncate;
CREATE OR REPLACE TRIGGER config_history_append_only BEFORE UPDATE OR DELETE ON iam.config_history
    FOR EACH ROW EXECUTE FUNCTION iam.refuse_change();
ALTER TABLE iam.config_history ENABLE ALWAYS TRIGGER config_history_append_only;
CREATE OR REPLACE TRIGGER config_history_no_truncate BEFORE TRUNCATE ON iam.config_history
    FOR EACH STATEMENT EXECUTE FUNCTION iam.refuse_change();
ALTER TABLE iam.config_history ENABLE ALWAYS TRIGGER config_history_no_truncate;

-- ── Back from a rollback (apps/access/rollback-2.7.sql) ─────────────────────
-- The rollback parks the mail_settings decisions in schema iam_retired_27 (no
-- grants), because the reverted file's kind CHECK does not know the kind. Now
-- that the CHECK above does again, they come back with their data and ids.
DO $$
DECLARE
    cols text;
    n    bigint;
BEGIN
    IF pg_catalog.to_regclass('iam_retired_27.account_decision') IS NULL THEN
        RETURN;
    END IF;
    SELECT string_agg(pg_catalog.quote_ident(a.attname), ', ' ORDER BY a.attnum) INTO cols
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = 'iam_retired_27.account_decision'::regclass AND a.attnum > 0 AND NOT a.attisdropped
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute b
                    WHERE b.attrelid = 'iam.account_decision'::regclass AND b.attname = a.attname AND NOT b.attisdropped);
    EXECUTE pg_catalog.format(
        'INSERT INTO iam.account_decision (%s) SELECT %s FROM iam_retired_27.account_decision r '
        'WHERE NOT EXISTS (SELECT 1 FROM iam.account_decision x WHERE x.decision_id = r.decision_id)', cols, cols);
    GET DIAGNOSTICS n = ROW_COUNT;
    -- a staged mail settings row parked with its decision (its trigger checks the
    -- decision is back and still waiting)
    IF pg_catalog.to_regclass('iam_retired_27.mail_settings_pending') IS NOT NULL THEN
        INSERT INTO iam.mail_settings_pending (id, smtp_host, smtp_port, smtp_user, smtp_pass, from_name,
                                               notify_emails, updated_by, updated_at, decision_id)
        SELECT r.id, r.smtp_host, r.smtp_port, r.smtp_user, r.smtp_pass, r.from_name,
               r.notify_emails, r.updated_by, r.updated_at, r.decision_id
          FROM iam_retired_27.mail_settings_pending r
         WHERE NOT EXISTS (SELECT 1 FROM iam.mail_settings_pending x);
        DROP TABLE iam_retired_27.mail_settings_pending;
    END IF;
    DROP TABLE iam_retired_27.account_decision;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE relnamespace = 'iam_retired_27'::regnamespace) THEN
        DROP SCHEMA iam_retired_27;
    END IF;
    IF n > 0 AND pg_catalog.to_regprocedure('iam_policy.append_history(text, jsonb, text)') IS NOT NULL THEN
        PERFORM medcea_auth._set_internal_actor('system:deploy');
        PERFORM iam_policy.append_history('account_decisions_restored', jsonb_build_object('count', n),
                                          'apps/access/access_db.sql (IAM 2.7) after rollback-2.7.sql');
    END IF;
    RAISE WARNING 'IAM 2.7: % mail_settings decision(s) parked by rollback-2.7.sql are back in iam.account_decision', n;
END $$;

-- ══ The decision functions (IAM 2.7) ════════════════════════════════════════
-- SECURITY DEFINER, owned by medcea_owner once the database deploy has
-- normalised schema iam; PUBLIC holds no EXECUTE (end of file) and access_svc
-- gets it from the compiled policy (service_only: svc_access). The actor comes
-- from medcea_auth.set_actor(), which access-api calls first in the same
-- transaction with the person of the verified token; medcea_auth._account_actor()
-- (apps/database/medcea_db_migrations.sql) is the one who-may rule: a person via
-- access_svc, with a person_id, whose role holds the level on the group.
--
-- Locks, always in this order: the account, pg_advisory_xact_lock(
-- hashtext('iam.account'), hashtext(keycloak_user_id)); for a change of the
-- admin/qa person sets (grant, role_change, activate, person_id) the I17 lock,
-- hashtext('iam.i17'); for a unit decision the (user, unit) lock,
-- hashtext('iam.user_unit'), hashtext(keycloak_user_id || ':' || unit_id), the
-- same key apps/iam/units.sql takes; then the row FOR UPDATE.
--
-- Refusals of who may act are structural, 42501 in both IAM_DB_ROLES modes (never
-- policy_refuse); a decision in the wrong state, or a bad argument, is 22023.

-- _check_rules: rules 4-7 of the checker (spec 2.5) for one decision, after
-- _account_actor(group, 'A'): the checker is neither the maker nor the subject,
-- by account and by person; the maker and the subject are attributed (a
-- bootstrap unit row without a subject person is compared by account only, and
-- a units.sh row — without a maker, or with --by's unverified one — is confirmed
-- only with the attestation). Returns the
-- check note to store. Called by confirm, refuse and review only.
CREATE OR REPLACE FUNCTION iam._check_rules(p_decision bigint, p_note text, p_confirm boolean,
    OUT sub text, OUT person text, OUT name text, OUT role text, OUT note text)
    LANGUAGE plpgsql SET search_path = iam, pg_temp AS $$
DECLARE
    d       record;
    a       record;
    attest  constant text := 'attest: I did not run units.sh for this assignment.';
    unitish boolean;
BEGIN
    SELECT * INTO d FROM iam.account_decision x WHERE x.decision_id = p_decision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no decision #%', p_decision USING ERRCODE = '22023';
    END IF;
    unitish := d.kind IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove');
    SELECT * INTO a FROM medcea_auth._account_actor(CASE WHEN unitish THEN 'zones' ELSE 'iam_users' END, 'A');
    -- 4. not the maker or the subject, by account
    IF lower(a.sub) = lower(d.made_by_sub) THEN
        RAISE EXCEPTION 'not_own_author: you made this decision' USING ERRCODE = '42501';
    END IF;
    IF lower(a.sub) = lower(d.keycloak_user_id) THEN
        RAISE EXCEPTION 'not_own_author: you are its subject' USING ERRCODE = '42501';
    END IF;
    -- 5. not the maker or the subject, by person
    IF a.person = d.made_by_person THEN
        RAISE EXCEPTION 'not_own_author: same person as the maker' USING ERRCODE = '42501';
    END IF;
    IF a.person = d.subject_person THEN
        RAISE EXCEPTION 'not_own_author: same person as the subject' USING ERRCODE = '42501';
    END IF;
    IF a.person = d.new_person_id THEN
        RAISE EXCEPTION 'not_own_author: same person as the new person_id' USING ERRCODE = '42501';
    END IF;
    -- 6. the maker is attributed; a units.sh row needs the attestation: one without a
    -- maker (bootstrap), and one whose maker is units.sh's --by, which names an account
    -- without proving the person running the script holds it
    IF d.made_by_person IS NULL AND d.made_by_name NOT LIKE 'system:%' THEN
        RAISE EXCEPTION 'unattributed maker' USING ERRCODE = '42501';
    END IF;
    note := nullif(btrim(coalesce(p_note, '')), '');
    IF p_confirm AND (d.made_by_sub IS NULL OR (unitish AND d.made_by_name LIKE 'system:deploy%'))
       AND left(coalesce(note, ''), length(attest)) IS DISTINCT FROM attest THEN
        RAISE EXCEPTION 'units.sh row: confirming needs the attestation' USING ERRCODE = '42501';
    END IF;
    -- 7. the subject is attributed, but for a bootstrap unit row (compared by account above)
    IF d.subject_person IS NULL THEN
        IF d.kind IN ('unit_assign', 'unit_remove') AND d.made_by_name LIKE 'system:deploy%' THEN
            note := coalesce(note, '') || ' [subject has no person_id: compared by account]';
            note := btrim(note);
        ELSE
            RAISE EXCEPTION 'the subject has no person_id' USING ERRCODE = '42501';
        END IF;
    END IF;
    sub := a.sub; person := a.person; name := a.name; role := a.role;
END $$;

-- record_decision: an admin's proposal (K on iam_users). Pending_qa when it
-- widens — a grant, any activation, a role change
-- role_widening() says adds a pair, a person_id or mail_settings change — else
-- applied, with its user_status_history row. Keycloak is the service's: untouched
-- while pending, changed by access-api in the same transaction when applied. One
-- open (pending_qa) decision per account, unit decisions apart; a deactivation is
-- always allowed and withdraws the account's open ones (returned in withdrawn).
-- p_from_role: the account's one own platform role, NULL for none or several (a
-- role change from several is then a widening from none). A grant needs the
-- pending access request it carries out (p_request_id) and records the account
-- as its own person (new_person_id = the account); a subject without a person_id
-- is recorded as its own account, the person_id it gets on first enable.
CREATE OR REPLACE FUNCTION iam.record_decision(p_kind text, p_user text, p_username text, p_subject_person text,
    p_from_role text, p_to_role text, p_new_person_id text, p_reason text, p_request_id bigint)
RETURNS TABLE (decision_id bigint, status text, widening jsonb, withdrawn bigint[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
#variable_conflict use_column
DECLARE
    a          record;
    v_user     text := lower(p_user);
    v_name     text := p_username;
    v_subject  text := nullif(btrim(coalesce(p_subject_person, '')), '');
    v_from     text := p_from_role;
    v_to       text := p_to_role;
    v_newp     text;
    v_w        jsonb := '[]'::jsonb;
    v_widens   boolean;
    v_status   text;
    v_id       bigint;
    v_open     bigint;
    v_wd       bigint[] := '{}';
    v_action   text;
BEGIN
    SELECT * INTO a FROM medcea_auth._account_actor('iam_users', 'K');
    IF p_kind IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove') THEN
        RAISE EXCEPTION 'units are assigned with apps/iam/units.sh until IAM 4.3' USING ERRCODE = '22023';
    END IF;
    IF p_kind IS NULL OR p_kind NOT IN ('grant', 'role_change', 'activate', 'deactivate', 'person_id', 'mail_settings') THEN
        RAISE EXCEPTION 'record_decision: unknown kind %', p_kind USING ERRCODE = '22023';
    END IF;
    IF coalesce(btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'a reason is required' USING ERRCODE = '22023';
    END IF;
    IF p_kind = 'mail_settings' THEN
        IF v_from IS NOT NULL OR v_to IS NOT NULL OR p_new_person_id IS NOT NULL THEN
            RAISE EXCEPTION 'a mail_settings decision names no role or person' USING ERRCODE = '22023';
        END IF;
        v_user := 'realm'; v_name := 'realm mail settings'; v_subject := 'realm';
    ELSE
        IF v_user IS NULL OR v_user !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
            RAISE EXCEPTION 'record_decision: the account must be a Keycloak user id, not %', p_user USING ERRCODE = '22023';
        END IF;
        IF coalesce(btrim(v_name), '') = '' THEN
            RAISE EXCEPTION 'record_decision: the username is required' USING ERRCODE = '22023';
        END IF;
        IF v_user = lower(a.sub) THEN
            RAISE EXCEPTION 'not_own_author: you cannot decide on your own account' USING ERRCODE = '42501';
        END IF;
        v_subject := coalesce(v_subject, v_user);
    END IF;
    IF (v_from IS NOT NULL AND NOT (v_from = ANY (medcea_auth.platform_roles())))
       OR (v_to IS NOT NULL AND NOT (v_to = ANY (medcea_auth.platform_roles()))) THEN
        RAISE EXCEPTION 'record_decision: % -> % is not a change between platform roles', v_from, v_to USING ERRCODE = '22023';
    END IF;
    IF p_request_id IS NOT NULL AND p_kind <> 'grant' THEN
        RAISE EXCEPTION 'record_decision: only a grant carries out an access request' USING ERRCODE = '22023';
    END IF;
    CASE p_kind
    WHEN 'grant' THEN
        IF v_to IS NULL OR v_from IS NOT NULL THEN
            RAISE EXCEPTION 'a grant gives one role to an account that holds none' USING ERRCODE = '22023';
        END IF;
        IF p_request_id IS NULL OR NOT EXISTS (
               SELECT 1 FROM iam.access_request r
                WHERE r.request_id = p_request_id AND lower(r.keycloak_user_id) = v_user AND r.status = 'pending') THEN
            RAISE EXCEPTION 'a grant carries out a pending access request of the same account (request #%)', p_request_id
                USING ERRCODE = '22023';
        END IF;
        v_newp := v_user;
    WHEN 'role_change' THEN
        IF v_to IS NULL THEN
            RAISE EXCEPTION 'a role change needs the new role' USING ERRCODE = '22023';
        END IF;
        IF v_to = v_from THEN
            RAISE EXCEPTION 'the account already holds %', v_to USING ERRCODE = '22023';
        END IF;
    WHEN 'activate' THEN
        IF v_to IS NOT NULL AND v_to IS DISTINCT FROM v_from THEN
            RAISE EXCEPTION 'an activation restores the role the account holds (%), not %', v_from, v_to USING ERRCODE = '22023';
        END IF;
        v_to := v_from;
    WHEN 'person_id' THEN
        v_newp := nullif(btrim(coalesce(p_new_person_id, '')), '');
        IF v_newp IS NULL OR v_newp !~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}$' THEN
            RAISE EXCEPTION 'a person_id is 1-64 characters [A-Za-z0-9._:@-], starting with a letter or digit' USING ERRCODE = '22023';
        END IF;
        IF v_newp = v_subject THEN
            RAISE EXCEPTION 'the account''s person_id is already %', v_newp USING ERRCODE = '22023';
        END IF;
        v_from := NULL; v_to := NULL;
    WHEN 'deactivate' THEN
        v_to := NULL;
    ELSE
        NULL;
    END CASE;

    PERFORM pg_advisory_xact_lock(hashtext('iam.account'), hashtext(v_user));
    IF p_kind IN ('grant', 'role_change', 'activate', 'person_id') THEN
        PERFORM pg_advisory_xact_lock(hashtext('iam.i17'));
    END IF;
    IF p_kind <> 'deactivate' THEN
        SELECT x.decision_id INTO v_open FROM iam.account_decision x
         WHERE x.keycloak_user_id = v_user AND x.status = 'pending_qa'
           AND x.kind NOT IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove')
         ORDER BY x.decision_id LIMIT 1;
        IF FOUND THEN
            RAISE EXCEPTION 'decision #% is waiting for qa', v_open USING ERRCODE = '22023';
        END IF;
    END IF;

    v_w := CASE p_kind
        WHEN 'grant'       THEN medcea_auth.role_widening(NULL, v_to)
        WHEN 'role_change' THEN medcea_auth.role_widening(v_from, v_to)
        WHEN 'activate'    THEN CASE WHEN v_from IS NULL THEN '[]'::jsonb ELSE medcea_auth.role_widening(NULL, v_from) END
        ELSE '[]'::jsonb END;
    IF v_w IS NULL OR pg_catalog.jsonb_typeof(v_w) <> 'array' THEN
        RAISE EXCEPTION 'role_widening(%, %) answered %, not a list', v_from, v_to, v_w;
    END IF;
    -- Every activation waits: an enabled account reaches the hosts not gated by role
    -- yet (Grafana, until IAM 3.1) even with no platform role.
    v_widens := v_w <> '[]'::jsonb OR p_kind IN ('grant', 'activate', 'person_id', 'mail_settings');
    v_status := CASE WHEN v_widens THEN 'pending_qa' ELSE 'applied' END;

    PERFORM medcea_auth._owner_write(true);
    INSERT INTO iam.account_decision AS x (kind, keycloak_user_id, username, subject_person, from_role, to_role,
                                      new_person_id, widens, widening, status, reason, request_id,
                                      made_by_sub, made_by_person, made_by_name)
    VALUES (p_kind, v_user, v_name, v_subject, v_from, v_to, v_newp, v_widens, v_w, v_status, p_reason,
            p_request_id, a.sub, a.person, a.name)
    RETURNING x.decision_id INTO v_id;
    IF p_kind = 'deactivate' THEN
        WITH w AS (
            UPDATE iam.account_decision x
               SET status = 'withdrawn', withdrawn_by_sub = a.sub, withdrawn_by_person = a.person,
                   withdrawn_by_name = a.name, withdrawn_at = now(),
                   withdraw_reason = 'withdrawn by deactivation #' || v_id
             WHERE x.keycloak_user_id = v_user AND x.status = 'pending_qa' AND x.decision_id <> v_id
               AND x.kind NOT IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove')
            RETURNING x.decision_id)
        SELECT coalesce(array_agg(w.decision_id ORDER BY w.decision_id), '{}') INTO v_wd FROM w;
    END IF;
    IF v_status = 'applied' THEN
        v_action := CASE p_kind WHEN 'role_change' THEN 'role_changed' WHEN 'activate' THEN 'activated'
                                WHEN 'deactivate' THEN 'deactivated' END;
        INSERT INTO iam.user_status_history (keycloak_user_id, username, action, reason, from_role, to_role,
                                             actor, actor_sub, actor_person, decision_id)
        VALUES (v_user, v_name, v_action, p_reason,
                CASE WHEN p_kind = 'role_change' THEN v_from END, CASE WHEN p_kind = 'role_change' THEN v_to END,
                a.name, a.sub, a.person, v_id);
    END IF;
    PERFORM medcea_auth._owner_write(false);

    decision_id := v_id; status := v_status; widening := v_w; withdrawn := v_wd;
    RETURN NEXT;
END $$;

-- withdraw_decision: the maker, or any admin, takes back a waiting non-unit
-- decision (K on iam_users); no Keycloak effect. A unit assignment is undone
-- with apps/iam/units.sh remove instead.
CREATE OR REPLACE FUNCTION iam.withdraw_decision(p_decision integer, p_reason text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    a       record;
    d       record;
    v_user  text;
BEGIN
    SELECT * INTO a FROM medcea_auth._account_actor('iam_users', 'K');
    IF coalesce(btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION 'a reason is required' USING ERRCODE = '22023';
    END IF;
    SELECT x.keycloak_user_id INTO v_user FROM iam.account_decision x WHERE x.decision_id = p_decision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no decision #%', p_decision USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('iam.account'), hashtext(v_user));
    SELECT * INTO d FROM iam.account_decision x WHERE x.decision_id = p_decision FOR UPDATE;
    IF d.kind IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove') THEN
        RAISE EXCEPTION 'decision #% is a unit decision: undo it with apps/iam/units.sh remove', p_decision
            USING ERRCODE = '22023';
    END IF;
    IF d.status <> 'pending_qa' THEN
        RAISE EXCEPTION 'decision #% is already %', p_decision, d.status USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._owner_write(true);
    UPDATE iam.account_decision x
       SET status = 'withdrawn', withdrawn_by_sub = a.sub, withdrawn_by_person = a.person,
           withdrawn_by_name = a.name, withdrawn_at = now(), withdraw_reason = p_reason
     WHERE x.decision_id = p_decision;
    IF d.kind = 'mail_settings' THEN
        DELETE FROM iam.mail_settings_pending p WHERE p.decision_id = p_decision;
    END IF;
    PERFORM medcea_auth._owner_write(false);
    RETURN d.decision_id;
END $$;

-- _lock_decision: the closing functions' locks (account, I17, unit) and the row
-- FOR UPDATE, in the one order every writer takes them.
CREATE OR REPLACE FUNCTION iam._lock_decision(p_decision bigint) RETURNS iam.account_decision
    LANGUAGE plpgsql SET search_path = iam, pg_temp AS $$
DECLARE
    d iam.account_decision;
BEGIN
    SELECT * INTO d FROM iam.account_decision x WHERE x.decision_id = p_decision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no decision #%', p_decision USING ERRCODE = '22023';
    END IF;
    -- keycloak_user_id, kind and unit_id never change (freeze_record): safe to lock by them
    PERFORM pg_advisory_xact_lock(hashtext('iam.account'), hashtext(d.keycloak_user_id));
    IF d.kind IN ('grant', 'role_change', 'activate', 'person_id') THEN
        PERFORM pg_advisory_xact_lock(hashtext('iam.i17'));
    END IF;
    IF d.kind IN ('unit_assign', 'unit_remove') THEN
        PERFORM pg_advisory_xact_lock(hashtext('iam.user_unit'), hashtext(d.keycloak_user_id || ':' || d.unit_id));
    END IF;
    SELECT * INTO d FROM iam.account_decision x WHERE x.decision_id = p_decision FOR UPDATE;
    RETURN d;
END $$;

-- _later_unit_decision: the newest unit decision for the same (user, unit) made
-- after this one, or NULL — "later" exactly as apps/iam/units.sh list reads it.
CREATE OR REPLACE FUNCTION iam._later_unit_decision(p_decision bigint) RETURNS bigint
    LANGUAGE sql STABLE SET search_path = iam, pg_temp AS $$
    SELECT max(l.decision_id) FROM iam.account_decision d JOIN iam.account_decision l
        ON l.keycloak_user_id = d.keycloak_user_id AND l.unit_id = d.unit_id
       AND l.kind IN ('unit_assign', 'unit_remove') AND l.decision_id > d.decision_id
     WHERE d.decision_id = p_decision
$$;

-- confirm_decision: a qa person applies a waiting decision (A on iam_users, or on
-- zones for a unit decision). Closes the row and writes its user_status_history
-- (grant, role_change, activate) in this transaction; access-api then makes the
-- Keycloak change inside it and commits only if that succeeded. A mail_settings
-- decision moves the staged account into iam.mail_settings (access-api pushes it
-- to the realm). A unit_assign takes effect here: the iam_policy.user_unit row is
-- inserted (its trigger chains unit_assigned with the qa person as the actor,
-- whom access-api set with set_actor), unless the row is already there — a row in
-- effect before the check (bootstrap, backfill, or made before assignments waited
-- for qa), for which the insert is a no-op. A unit deleted meanwhile is 22023:
-- refuse the decision. Either way the chain gets account_decision_confirmed.
CREATE OR REPLACE FUNCTION iam.confirm_decision(p_decision integer, p_note text)
RETURNS TABLE (decision_id bigint, kind text, keycloak_user_id text, username text, from_role text,
               to_role text, new_person_id text, unit_id integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
#variable_conflict use_column
DECLARE
    d       iam.account_decision;
    c       record;
    v_later bigint;
BEGIN
    d := iam._lock_decision(p_decision);
    IF d.status <> 'pending_qa' THEN
        RAISE EXCEPTION 'decision #% is already %', p_decision, d.status USING ERRCODE = '22023';
    END IF;
    IF d.kind IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove') THEN
        v_later := iam._later_unit_decision(d.decision_id);
        IF v_later IS NOT NULL THEN
            RAISE EXCEPTION 'decision #% was superseded by #%: refuse or review it instead', p_decision, v_later
                USING ERRCODE = '22023';
        END IF;
    ELSE
        SELECT max(l.decision_id) INTO v_later FROM iam.account_decision l
         WHERE l.keycloak_user_id = d.keycloak_user_id AND l.decision_id > d.decision_id
           AND l.kind NOT IN ('unit_assign', 'unit_remove', 'zone_assign', 'zone_remove');
        IF v_later IS NOT NULL THEN
            RAISE EXCEPTION 'decision #% was superseded by #%', p_decision, v_later USING ERRCODE = '22023';
        END IF;
    END IF;
    SELECT * INTO c FROM iam._check_rules(d.decision_id, p_note, true);

    PERFORM medcea_auth._owner_write(true);
    UPDATE iam.account_decision x
       SET status = 'confirmed', checked_by_sub = c.sub, checked_by_person = c.person,
           checked_by_name = c.name, checked_at = now(), check_note = c.note
     WHERE x.decision_id = d.decision_id;
    IF d.kind IN ('grant', 'role_change', 'activate') THEN
        INSERT INTO iam.user_status_history (keycloak_user_id, username, action, reason, from_role, to_role,
                                             actor, actor_sub, actor_person, decision_id)
        VALUES (d.keycloak_user_id, d.username, CASE d.kind WHEN 'role_change' THEN 'role_changed' ELSE 'activated' END,
                d.reason, d.from_role, d.to_role, c.name, c.sub, c.person, d.decision_id);
    ELSIF d.kind = 'mail_settings' THEN
        UPDATE iam.mail_settings m
           SET smtp_host = p.smtp_host, smtp_port = p.smtp_port, smtp_user = p.smtp_user, smtp_pass = p.smtp_pass,
               from_name = p.from_name, notify_emails = p.notify_emails, updated_by = c.name, updated_at = now()
          FROM iam.mail_settings_pending p
         WHERE m.id = 1 AND p.decision_id = d.decision_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'the mail settings staged with decision #% are missing: refuse it and stage them again', d.decision_id
                USING ERRCODE = '22023';
        END IF;
        DELETE FROM iam.mail_settings_pending p WHERE p.decision_id = d.decision_id;
    ELSIF d.kind = 'unit_assign' THEN
        BEGIN
            INSERT INTO iam_policy.user_unit (person_sub, unit_id)
            VALUES (d.keycloak_user_id::uuid, d.unit_id) ON CONFLICT DO NOTHING;
        EXCEPTION WHEN foreign_key_violation THEN
            RAISE EXCEPTION 'unit % no longer exists: refuse decision #%', d.unit_id, d.decision_id
                USING ERRCODE = '22023';
        END;
    END IF;
    PERFORM medcea_auth._owner_write(false);
    IF d.kind IN ('unit_assign', 'unit_remove') THEN
        PERFORM iam_policy.append_history('account_decision_confirmed',
            jsonb_build_object('decision_id', d.decision_id, 'kind', d.kind,
                               'keycloak_user_id', d.keycloak_user_id, 'unit_id', d.unit_id), c.note);
    END IF;

    RETURN QUERY SELECT d.decision_id, d.kind::text, d.keycloak_user_id::text, d.username::text,
                        d.from_role::text, d.to_role::text, d.new_person_id, d.unit_id;
END $$;

-- refuse_decision: a qa person refuses a waiting decision (note required). No
-- Keycloak change is undone here: nothing was applied, and access-api's
-- reconcile makes Keycloak match (a refused grant deletes the account). A
-- unit_assign waiting for qa is not in effect: nothing to remove (removed =
-- false). One that is (bootstrap, backfill, or made before assignments waited for
-- qa) is removed — only while it is the latest unit decision for its (user, unit);
-- the user_unit trigger appends unit_removed to the chain with the qa person as
-- actor. The chain gets account_decision_refused either way. A mail_settings
-- decision's staged row is deleted.
CREATE OR REPLACE FUNCTION iam.refuse_decision(p_decision integer, p_note text)
RETURNS TABLE (decision_id bigint, kind text, keycloak_user_id text, unit_id integer, removed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
#variable_conflict use_column
DECLARE
    d         iam.account_decision;
    c         record;
    v_removed boolean := false;
BEGIN
    IF coalesce(btrim(p_note), '') = '' THEN
        RAISE EXCEPTION 'a note is required to refuse a decision' USING ERRCODE = '22023';
    END IF;
    d := iam._lock_decision(p_decision);
    IF d.status <> 'pending_qa' THEN
        RAISE EXCEPTION 'decision #% is already %', p_decision, d.status USING ERRCODE = '22023';
    END IF;
    SELECT * INTO c FROM iam._check_rules(d.decision_id, p_note, false);

    PERFORM medcea_auth._owner_write(true);
    UPDATE iam.account_decision x
       SET status = 'refused', checked_by_sub = c.sub, checked_by_person = c.person,
           checked_by_name = c.name, checked_at = now(), check_note = c.note
     WHERE x.decision_id = d.decision_id;
    IF d.kind = 'unit_assign' AND iam._later_unit_decision(d.decision_id) IS NULL THEN
        DELETE FROM iam_policy.user_unit uu
         WHERE uu.person_sub = d.keycloak_user_id::uuid AND uu.unit_id = d.unit_id;
        v_removed := FOUND;
    ELSIF d.kind = 'mail_settings' THEN
        DELETE FROM iam.mail_settings_pending p WHERE p.decision_id = d.decision_id;
    END IF;
    PERFORM medcea_auth._owner_write(false);
    IF d.kind IN ('unit_assign', 'unit_remove') THEN
        PERFORM iam_policy.append_history('account_decision_refused',
            jsonb_build_object('decision_id', d.decision_id, 'kind', d.kind, 'keycloak_user_id', d.keycloak_user_id,
                               'unit_id', d.unit_id, 'removed', v_removed), c.note);
    END IF;

    RETURN QUERY SELECT d.decision_id, d.kind::text, d.keycloak_user_id::text, d.unit_id, v_removed;
END $$;

-- review_decision: a qa person reviews a decision that acted at once (applied ->
-- reviewed). Same who-may rules as confirm; no Keycloak effect; note optional.
CREATE OR REPLACE FUNCTION iam.review_decision(p_decision integer, p_note text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    d  iam.account_decision;
    c  record;
BEGIN
    d := iam._lock_decision(p_decision);
    IF d.status <> 'applied' THEN
        RAISE EXCEPTION 'decision #% is %: only an applied decision is reviewed', p_decision, d.status
            USING ERRCODE = '22023';
    END IF;
    SELECT * INTO c FROM iam._check_rules(d.decision_id, p_note, false);
    PERFORM medcea_auth._owner_write(true);
    UPDATE iam.account_decision x
       SET status = 'reviewed', checked_by_sub = c.sub, checked_by_person = c.person,
           checked_by_name = c.name, checked_at = now(), check_note = c.note
     WHERE x.decision_id = d.decision_id;
    PERFORM medcea_auth._owner_write(false);
    IF d.kind IN ('unit_assign', 'unit_remove') THEN
        PERFORM iam_policy.append_history('account_decision_reviewed',
            jsonb_build_object('decision_id', d.decision_id, 'kind', d.kind,
                               'keycloak_user_id', d.keycloak_user_id, 'unit_id', d.unit_id), c.note);
    END IF;
    RETURN d.decision_id;
END $$;

-- create_review: this quarter's access review (C on audit_histories: qa). The
-- service's part of the snapshot (accounts, last logins, policy, waivers,
-- switches as of deploy-infra) is p_snapshot; the database adds what it holds
-- itself, over any key of the same name, so the service cannot misreport it.
CREATE OR REPLACE FUNCTION iam.create_review(p_snapshot jsonb) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    a         record;
    v_period  text := to_char(now() AT TIME ZONE 'UTC', 'YYYY-"Q"Q');
    v_prev    timestamptz;
    v_exists  bigint;
    v_snap    jsonb;
    v_id      bigint;
BEGIN
    SELECT * INTO a FROM medcea_auth._account_actor('audit_histories', 'C');
    IF p_snapshot IS NULL OR pg_catalog.jsonb_typeof(p_snapshot) <> 'object' THEN
        RAISE EXCEPTION 'create_review: the snapshot is a JSON object' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('iam.access_review'));
    SELECT r.review_id INTO v_exists FROM iam.access_review r WHERE r.period = v_period;
    IF FOUND THEN
        RAISE EXCEPTION 'the review of % exists (#%)', v_period, v_exists USING ERRCODE = '23505';
    END IF;
    SELECT max(r.created_at) INTO v_prev FROM iam.access_review r;
    v_snap := p_snapshot || jsonb_build_object(
        'period', v_period,
        'database_at', now(),
        'units', coalesce((
            SELECT jsonb_agg(jsonb_build_object('person_sub', uu.person_sub, 'unit_id', uu.unit_id,
                                                'unit_code', u.unit_code) ORDER BY uu.person_sub, uu.unit_id)
              FROM iam_policy.user_unit uu LEFT JOIN medcea.cea_unit u ON u.unit_id = uu.unit_id), '[]'::jsonb),
        'pending_decisions', coalesce((
            SELECT jsonb_agg(jsonb_build_object('decision_id', d.decision_id, 'kind', d.kind, 'username', d.username,
                                                'unit_id', d.unit_id, 'made_by_name', d.made_by_name,
                                                'made_at', d.made_at) ORDER BY d.decision_id)
              FROM iam.account_decision d WHERE d.status = 'pending_qa'), '[]'::jsonb),
        'previous_review_at', v_prev,
        'decisions_since', coalesce((
            SELECT jsonb_agg(jsonb_build_object('decision_id', d.decision_id, 'kind', d.kind, 'status', d.status,
                                                'username', d.username, 'made_by_name', d.made_by_name,
                                                'made_at', d.made_at, 'checked_by_name', d.checked_by_name,
                                                'withdrawn_by_name', d.withdrawn_by_name) ORDER BY d.decision_id)
              FROM iam.account_decision d WHERE v_prev IS NULL OR d.made_at > v_prev), '[]'::jsonb),
        'iam_db_roles', medcea_auth.enforcing(),
        'service_logins', coalesce((
            SELECT jsonb_object_agg(r.rolname, r.rolcanlogin ORDER BY r.rolname) FROM pg_catalog.pg_roles r
             WHERE r.rolname LIKE 'svc\_%' OR r.rolname IN ('iam_svc', 'rr_admin_login')), '{}'::jsonb),
        'policy_chain', (SELECT to_jsonb(v) FROM iam_policy.verify_chain() v));
    PERFORM medcea_auth._owner_write(true);
    INSERT INTO iam.access_review (period, snapshot, created_by, created_by_sub, created_by_person)
    VALUES (v_period, v_snap, a.name, a.sub, a.person)
    RETURNING review_id INTO v_id;
    PERFORM medcea_auth._owner_write(false);
    RETURN v_id;
END $$;

-- sign_off_review: a qa person signs a review off, once (C on audit_histories).
-- The creator may sign it off: with one qa person a "different person" rule
-- would deadlock (a known single-person control, spec Q5 / R11).
CREATE OR REPLACE FUNCTION iam.sign_off_review(p_review integer, p_note text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    a  record;
    r  record;
BEGIN
    SELECT * INTO a FROM medcea_auth._account_actor('audit_histories', 'C');
    SELECT * INTO r FROM iam.access_review x WHERE x.review_id = p_review FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no review #%', p_review USING ERRCODE = '22023';
    END IF;
    IF r.signed_off_at IS NOT NULL THEN
        RAISE EXCEPTION 'review #% is already signed off', p_review USING ERRCODE = '22023';
    END IF;
    PERFORM medcea_auth._owner_write(true);
    UPDATE iam.access_review x
       SET signed_off_by_sub = a.sub, signed_off_by_person = a.person, signed_off_by_name = a.name,
           signed_off_at = now(), sign_off_note = nullif(btrim(coalesce(p_note, '')), '')
     WHERE x.review_id = p_review;
    PERFORM medcea_auth._owner_write(false);
    RETURN r.review_id;
END $$;

-- Nobody but the owner executes anything in iam by default: trigger functions
-- need no EXECUTE to fire, and the decision functions are granted by the
-- compiled policy (apps/database/deploy.sh). The helpers (_check_rules,
-- _lock_decision, _later_unit_decision) are SECURITY INVOKER and owner-only:
-- only the definer functions above, running as medcea_owner, call them.
DO $$
DECLARE f regprocedure;
BEGIN
    FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p WHERE p.pronamespace = 'iam'::regnamespace LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
END $$;
