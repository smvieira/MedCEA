-- apps/access/access_db.sql — self-service access requests (applied by deploy.sh)
--
-- Run as postgres with:  psql -v access_pw=<password> -f access_db.sql
-- Idempotent: every statement is CREATE ... IF NOT EXISTS / OR REPLACE.
--
-- Schema iam, not medcea: PostgREST exposes medcea to anon with full DML, and
-- these rows hold e-mail addresses and business justifications. Nothing here is
-- reachable through the config API.
--
-- The access service connects as access_svc, which may read and update requests
-- but never DELETE them, and may only read the history. The history is written
-- by a SECURITY DEFINER trigger, so it is append-only to the service, the same
-- way medcea.device_slot_history is (Compliance Plane rule, docs/architecture.md).

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

DROP TRIGGER IF EXISTS access_request_history_trg ON iam.access_request;
CREATE TRIGGER access_request_history_trg
    AFTER INSERT OR UPDATE ON iam.access_request
    FOR EACH ROW EXECUTE FUNCTION iam.log_access_request();

-- A decision is final: a request leaves 'pending' once and never changes again.
CREATE OR REPLACE FUNCTION iam.freeze_decided_request() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status <> 'pending' THEN
        RAISE EXCEPTION 'access request % is already %', OLD.request_id, OLD.status;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS access_request_freeze_trg ON iam.access_request;
CREATE TRIGGER access_request_freeze_trg
    BEFORE UPDATE ON iam.access_request
    FOR EACH ROW EXECUTE FUNCTION iam.freeze_decided_request();

COMMENT ON TABLE iam.access_request IS 'Self-service access requests (apps/access). Decided once: pending -> approved | rejected.';
COMMENT ON TABLE iam.access_request_history IS 'Append-only log of access requests and decisions. Written by trigger access_request_history_trg only; read-only to access_svc.';

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

-- An edited template; absent = the default file in apps/access/templates/.
CREATE TABLE IF NOT EXISTS iam.mail_template (
    name        VARCHAR(32) PRIMARY KEY
                CHECK (name IN ('new-request', 'approved', 'reassigned', 'rejected')),
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    updated_by  VARCHAR(255) NOT NULL,
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

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
    IF TG_OP = 'DELETE' THEN
        INSERT INTO iam.config_history (item, action, detail, actor)
        VALUES ('template:' || OLD.name, 'reset', 'back to the default file', coalesce(current_setting('iam.actor', true), current_user));
        RETURN OLD;
    END IF;
    INSERT INTO iam.config_history (item, action, detail, actor)
    VALUES ('template:' || NEW.name, lower(TG_OP), 'Subject: ' || NEW.subject, NEW.updated_by);
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS mail_settings_history_trg ON iam.mail_settings;
CREATE TRIGGER mail_settings_history_trg AFTER UPDATE ON iam.mail_settings
    FOR EACH ROW EXECUTE FUNCTION iam.log_mail_config();
DROP TRIGGER IF EXISTS mail_template_history_trg ON iam.mail_template;
CREATE TRIGGER mail_template_history_trg AFTER INSERT OR UPDATE OR DELETE ON iam.mail_template
    FOR EACH ROW EXECUTE FUNCTION iam.log_mail_config();

-- ── Account history: activation, deactivation, role changes (User Manager → Users)
-- Every change of a Keycloak account's enabled flag made from the User Manager:
-- who, whose account, which way, and why. access_svc may append and read, never
-- change or remove (the Compliance Plane rule); the deactivation itself lives in
-- Keycloak, this is its record.
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
COMMENT ON TABLE iam.user_status_history IS 'Append-only account history from the User Manager (apps/access): deactivated, activated, role_changed (from_role -> to_role). Deactivations and role changes need a reason.';

-- ── Service role ─────────────────────────────────────────────────────────────
SELECT 'CREATE ROLE access_svc LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'access_svc') \gexec
ALTER ROLE access_svc LOGIN PASSWORD :'access_pw';

GRANT CONNECT ON DATABASE medcea_db TO access_svc;
GRANT USAGE ON SCHEMA iam TO access_svc;
GRANT SELECT, INSERT, UPDATE ON iam.access_request TO access_svc;
GRANT USAGE, SELECT ON SEQUENCE iam.access_request_request_id_seq TO access_svc;
GRANT SELECT ON iam.access_request_history TO access_svc;
REVOKE DELETE, TRUNCATE ON iam.access_request FROM access_svc;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON iam.access_request_history FROM access_svc;
GRANT SELECT, UPDATE ON iam.mail_settings TO access_svc;
-- DELETE here is "reset to default"; the trigger logs it.
GRANT SELECT, INSERT, UPDATE, DELETE ON iam.mail_template TO access_svc;
GRANT SELECT ON iam.config_history TO access_svc;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON iam.config_history FROM access_svc;
GRANT SELECT, INSERT ON iam.user_status_history TO access_svc;
GRANT USAGE, SELECT ON SEQUENCE iam.user_status_history_event_id_seq TO access_svc;
REVOKE UPDATE, DELETE, TRUNCATE ON iam.user_status_history FROM access_svc;

-- ── Account decisions and access reviews (codeplan IAM plan 3.7, 3.10) ──────
-- Created in Phase 1 so later phases can record into them; nothing writes them
-- yet. Phase 2.7 adds their writers (the User Manager's decisions, qa's
-- confirm screen, iam.confirm_decision(), iam.sign_off_review()).
--
-- account_decision: every grant, role change, unit assignment or removal
-- (zone_* kept for old rows), person_id change and (de)activation an
-- administrator makes. A widening
-- (qa_dual_control) waits as pending_qa until a qa person who is neither the
-- maker nor the subject confirms or refuses it; a narrowing acts at once
-- (applied) and is reviewed afterwards. What was decided never changes; only
-- the confirmation or review is added, once. No DELETE, for anyone.
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
-- original kind CHECK is inline. Bootstrap exception (like the policy's
-- --bootstrap): apps/iam/units.sh writes unit_assign rows as pending_qa while the
-- assignment is already in effect, and unit_remove rows as applied. When 2.7's
-- confirm_decision refuses a unit_assign, it must DELETE the iam_policy.user_unit
-- row in the same transaction — but only if that decision is the latest unit_*
-- decision for its (keycloak_user_id, unit_id): after assign, remove, assign the
-- older pending row must not remove the current assignment, which has its own.
ALTER TABLE iam.account_decision ADD COLUMN IF NOT EXISTS unit_id INTEGER;   -- medcea.cea_unit, another schema: no FK
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_kind_check;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_kind_check
    CHECK (kind IN ('grant', 'role_change', 'zone_assign', 'zone_remove', 'unit_assign', 'unit_remove',
                    'person_id', 'deactivate', 'activate'));
ALTER TABLE iam.account_decision DROP CONSTRAINT IF EXISTS account_decision_unit_chk;
ALTER TABLE iam.account_decision ADD CONSTRAINT account_decision_unit_chk
    CHECK (kind NOT IN ('unit_assign', 'unit_remove') OR unit_id IS NOT NULL);

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

-- What a decision or a review says is final; the check / sign-off columns are
-- filled once, from their empty state, all in the one UPDATE that sets
-- checked_at / signed_off_at — so the person recorded as checker is the one who
-- closed it, not a value left by an earlier write. No DELETE or TRUNCATE.
CREATE OR REPLACE FUNCTION iam.freeze_record() RETURNS trigger
    LANGUAGE plpgsql SET search_path = iam, pg_temp AS $$
DECLARE
    added text[] := CASE TG_TABLE_NAME
        WHEN 'account_decision' THEN ARRAY['status', 'checked_by_sub', 'checked_by_person',
                                           'checked_by_name', 'checked_at', 'check_note']
        ELSE ARRAY['signed_off_by_sub', 'signed_off_by_person', 'signed_off_by_name',
                   'signed_off_at', 'sign_off_note'] END;
    closer text := CASE TG_TABLE_NAME WHEN 'account_decision' THEN 'checked_at' ELSE 'signed_off_at' END;
    done boolean := to_jsonb(OLD) ->> closer IS NOT NULL;
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'iam.% is append-only: % refused', TG_TABLE_NAME, TG_OP
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF done THEN
        RAISE EXCEPTION 'iam.% row is final', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (to_jsonb(NEW) - added) IS DISTINCT FROM (to_jsonb(OLD) - added) THEN
        RAISE EXCEPTION 'iam.%: only the check or sign-off may be added', TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF to_jsonb(NEW) ->> closer IS NULL AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'iam.%: the check or sign-off is added in one update, with %', TG_TABLE_NAME, closer
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS account_decision_freeze_trg ON iam.account_decision;
CREATE TRIGGER account_decision_freeze_trg BEFORE UPDATE OR DELETE ON iam.account_decision
    FOR EACH ROW EXECUTE FUNCTION iam.freeze_record();
DROP TRIGGER IF EXISTS account_decision_truncate_trg ON iam.account_decision;
CREATE TRIGGER account_decision_truncate_trg BEFORE TRUNCATE ON iam.account_decision
    FOR EACH STATEMENT EXECUTE FUNCTION iam.freeze_record();
DROP TRIGGER IF EXISTS access_review_freeze_trg ON iam.access_review;
CREATE TRIGGER access_review_freeze_trg BEFORE UPDATE OR DELETE ON iam.access_review
    FOR EACH ROW EXECUTE FUNCTION iam.freeze_record();
DROP TRIGGER IF EXISTS access_review_truncate_trg ON iam.access_review;
CREATE TRIGGER access_review_truncate_trg BEFORE TRUNCATE ON iam.access_review
    FOR EACH STATEMENT EXECUTE FUNCTION iam.freeze_record();

COMMENT ON TABLE iam.account_decision IS 'Account decisions (grant, role change, units, person_id, (de)activation): pending_qa -> confirmed | refused for a widening, applied -> reviewed otherwise. Final once checked; no DELETE.';
COMMENT ON TABLE iam.access_review IS 'Quarterly access review snapshots, signed off once by a qa person. Append-only.';

-- Read-only to the service until Phase 2.7 gives it its writers.
GRANT SELECT ON iam.account_decision, iam.access_review TO access_svc;
