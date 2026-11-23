-- apps/research/db/agent_trace.sql — the agent trace of medcea_research (research sandbox
-- Phase 4a, stage 2; codeplan/rs4-design.md section 3.3 as revised by R8, R9, R11, R31, R32).
--
-- Run by apps/research/deploy.sh as postgres in pod research-postgresql-0, connected to
-- medcea_research, SQL on stdin, after db/lake_api.sql and before the passwords and
-- db/grants.sql (which grants what is created here; db/assert_grants.sql checks it):
--     psql -X -U postgres -d medcea_research -v ON_ERROR_STOP=1 -f - < agent_trace.sql
-- Re-run safe: the role is created only when missing and restated every run, tables are
-- IF NOT EXISTS, every function CREATE OR REPLACE.
--
-- Role rs_session (cluster-wide, research PostgreSQL only): LOGIN NOINHERIT, CONNECTION
-- LIMIT 5, statement_timeout 10s. research-session logs in as it. EXECUTE on the eight
-- writers/readers below and nothing else: no table privilege. Its password is set by
-- deploy.sh as a SCRAM verifier (RS_SESSION_DB_PASS), never here.
--
-- Everything is owned by rs_owner; every function is SECURITY DEFINER with
-- search_path = pg_catalog, pg_temp and no EXECUTE for PUBLIC. Every table is
-- append-only (UPDATE, DELETE and TRUNCATE refused, ENABLE ALWAYS, for the owner too).
--
-- Who may write which event (R8). The writer is append_event(port, ...): the PORT is
-- the caller's identity, never a body field, and an event outside the port's list is
-- refused and recorded as trace_refused (once per session):
--   person  research-session's own routes: session_minted, claim_exchanged,
--           claim_reused, gate_decided, proposal_decided, session_revoked
--   agent   (agent port 8101) turn_request, turn_response (only while the session's
--           backend is 'scripted'), tool_call, tool_result, checkpoint, proposal, stop;
--           the token's sha256 must equal the session's (R9)
--   server  (server port 8102) tool_result, gate_pending, sim_started, sim_finished,
--           replay_result, turn_request, turn_response (the last two only for the
--           model-gateway and only while the backend is 'local'); the actor is the
--           server's declared name, checked against the event
-- After a revocation or expiry only the person port, and on the server port
-- sim_finished and replay_result, may append (R9); never the agent.
-- Payloads carry digests and small fields only (<= 16 KiB); content goes to blob
-- (<= 1 MiB); a session's bytes (payloads + blobs it referenced) are capped (R31).
--
-- The chain: one hash chain over all sessions. hash = sha256(event_record(...)), the
-- canonical jsonb text in UTC as iam_policy.history_record; genesis prev_hash is 64
-- zeros; the writer takes an advisory lock and READ COMMITTED only. sup_* are copied
-- from the session row, never from a parameter. Person data in this schema: sup_sub,
-- sup_person, sup_username (never exposed through lake_api).

SET client_min_messages = warning;

-- ── Role ──────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rs_session') THEN
        CREATE ROLE rs_session LOGIN NOINHERIT;
    END IF;
END $$;
ALTER ROLE rs_session LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    CONNECTION LIMIT 5;
ALTER ROLE rs_session SET statement_timeout = '10s';

SET ROLE rs_owner;

-- ── Tables ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_trace.session (
    sid            text PRIMARY KEY CHECK (sid ~ '^[A-Za-z0-9_-]{22}$'),
    kid            text NOT NULL,
    token_sha256   text NOT NULL UNIQUE CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    claim_sha256   text NOT NULL UNIQUE CHECK (claim_sha256 ~ '^[0-9a-f]{64}$'),
    sup_sub        uuid NOT NULL,
    sup_person     text NOT NULL CHECK (sup_person <> ''),
    sup_role       text NOT NULL,
    sup_username   text NOT NULL,
    profile        text NOT NULL,
    profile_sha256 text NOT NULL CHECK (profile_sha256 ~ '^[0-9a-f]{64}$'),
    tools          text[] NOT NULL,
    budget         jsonb NOT NULL CHECK (jsonb_typeof(budget) = 'object'),
    backend        text NOT NULL CONSTRAINT session_backend_check CHECK (backend ~ '^[a-z][a-z0-9-]{0,30}$'),
    code_commit    text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    exp            timestamptz NOT NULL,
    CONSTRAINT session_exp_chk CHECK (exp > created_at AND exp <= created_at + interval '8 hours')
);
-- research Phase 4d: backend is 'scripted' or the name of a model endpoint (apps/research-model/endpoints.yaml;
-- 'local' is the model on this host). A database created before keeps its older CHECK until this runs.
ALTER TABLE agent_trace.session DROP CONSTRAINT IF EXISTS session_backend_check;
ALTER TABLE agent_trace.session ADD CONSTRAINT session_backend_check CHECK (backend ~ '^[a-z][a-z0-9-]{0,30}$');
CREATE TABLE IF NOT EXISTS agent_trace.revocation (
    sid     text PRIMARY KEY REFERENCES agent_trace.session (sid),
    at      timestamptz NOT NULL DEFAULT now(),
    reason  text NOT NULL,
    by_sub  uuid
);
CREATE TABLE IF NOT EXISTS agent_trace.claim_use (
    sid   text PRIMARY KEY REFERENCES agent_trace.session (sid),
    at    timestamptz NOT NULL DEFAULT now(),
    peer  inet
);
CREATE TABLE IF NOT EXISTS agent_trace.expect (
    sid   text PRIMARY KEY REFERENCES agent_trace.session (sid),
    at    timestamptz NOT NULL DEFAULT now(),
    peer  inet NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_trace.blob (
    sha256      text PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    media       text NOT NULL,
    bytes       bytea NOT NULL CHECK (octet_length(bytes) <= 1048576),
    created_at  timestamptz NOT NULL DEFAULT now()
);
-- which session referenced which blob (a blob is content-addressed and shared)
CREATE TABLE IF NOT EXISTS agent_trace.blob_ref (
    sid     text NOT NULL REFERENCES agent_trace.session (sid),
    sha256  text NOT NULL REFERENCES agent_trace.blob (sha256),
    bytes   integer NOT NULL,
    at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sid, sha256)
);
CREATE TABLE IF NOT EXISTS agent_trace.state (
    sid     text NOT NULL REFERENCES agent_trace.session (sid),
    seq     integer NOT NULL,
    at      timestamptz NOT NULL DEFAULT now(),
    sha256  text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    state   jsonb NOT NULL,
    PRIMARY KEY (sid, seq)
);
CREATE TABLE IF NOT EXISTS agent_trace.event (
    event_id     bigint PRIMARY KEY,
    at           timestamptz NOT NULL,
    sid          text NOT NULL REFERENCES agent_trace.session (sid),
    sup_sub      uuid NOT NULL,
    sup_person   text NOT NULL,
    sup_role     text NOT NULL,
    actor        text NOT NULL,
    event        text NOT NULL,
    payload      jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 16384),
    prev_hash    text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    hash         text NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS event_sid_idx ON agent_trace.event (sid, event_id);
CREATE SEQUENCE IF NOT EXISTS agent_trace.event_event_id_seq;

-- ── Append-only, for the owner too ────────────────────────────────────────────
CREATE OR REPLACE FUNCTION agent_trace.refuse_change() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION '%.% is append-only: % refused', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END $$;
REVOKE ALL ON FUNCTION agent_trace.refuse_change() FROM PUBLIC;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['agent_trace.session', 'agent_trace.revocation', 'agent_trace.claim_use',
                             'agent_trace.expect', 'agent_trace.blob', 'agent_trace.blob_ref', 'agent_trace.state',
                             'agent_trace.event'] LOOP
        EXECUTE pg_catalog.format('CREATE OR REPLACE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON %s '
                                  'FOR EACH ROW EXECUTE FUNCTION agent_trace.refuse_change()', t);
        EXECUTE pg_catalog.format('CREATE OR REPLACE TRIGGER append_only_truncate BEFORE TRUNCATE ON %s '
                                  'FOR EACH STATEMENT EXECUTE FUNCTION agent_trace.refuse_change()', t);
        EXECUTE pg_catalog.format('ALTER TABLE %s ENABLE ALWAYS TRIGGER append_only_row', t);
        EXECUTE pg_catalog.format('ALTER TABLE %s ENABLE ALWAYS TRIGGER append_only_truncate', t);
    END LOOP;
END $$;

-- ── The canonical text a trace event is hashed over ───────────────────────────
CREATE OR REPLACE FUNCTION agent_trace.event_record(
    p_event_id bigint, p_at timestamptz, p_sid text, p_sup_sub uuid, p_sup_person text, p_sup_role text,
    p_actor text, p_event text, p_payload jsonb, p_prev_hash text)
    RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.jsonb_build_object(
        'event_id', p_event_id,
        'at', pg_catalog.to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'sid', p_sid, 'sup_sub', p_sup_sub, 'sup_person', p_sup_person, 'sup_role', p_sup_role,
        'actor', p_actor, 'event', p_event, 'payload', p_payload, 'prev_hash', p_prev_hash)::text
$$;
REVOKE ALL ON FUNCTION agent_trace.event_record(bigint, timestamptz, text, uuid, text, text, text, text, jsonb, text)
    FROM PUBLIC;

-- ── Per-port allow-lists (R8) ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION agent_trace._port_events(p_port text) RETURNS text[]
    LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE p_port
        WHEN 'person' THEN ARRAY['session_minted', 'claim_exchanged', 'claim_reused', 'gate_decided',
                                 'proposal_decided', 'session_revoked']
        WHEN 'agent'  THEN ARRAY['turn_request', 'turn_response', 'tool_call', 'tool_result', 'checkpoint',
                                 'proposal', 'stop']
        WHEN 'server' THEN ARRAY['tool_result', 'gate_pending', 'sim_started', 'sim_finished', 'replay_result',
                                 'turn_request', 'turn_response']
    END
$$;
REVOKE ALL ON FUNCTION agent_trace._port_events(text) FROM PUBLIC;

-- ── Internals ─────────────────────────────────────────────────────────────────
-- A session is active iff it has no revocation and exp > now().
CREATE OR REPLACE FUNCTION agent_trace._active(p_sid text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM agent_trace.session s
                    WHERE s.sid = p_sid AND s.exp > pg_catalog.now()
                      AND NOT EXISTS (SELECT 1 FROM agent_trace.revocation r WHERE r.sid = s.sid))
$$;
REVOKE ALL ON FUNCTION agent_trace._active(text) FROM PUBLIC;

-- The one place a row enters agent_trace.event: advisory lock, READ COMMITTED only,
-- head read after the lock is held, sup_* copied from the session.
CREATE OR REPLACE FUNCTION agent_trace._append(p_sid text, p_actor text, p_event text, p_payload jsonb)
    RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    s       agent_trace.session%ROWTYPE;
    v_id    bigint;
    v_at    timestamptz := pg_catalog.clock_timestamp();
    v_prev  text;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'agent_trace needs READ COMMITTED (is %): a transaction snapshot could miss the head',
            pg_catalog.current_setting('transaction_isolation');
    END IF;
    p_payload := coalesce(p_payload, '{}'::jsonb);
    SELECT * INTO s FROM agent_trace.session WHERE sid = p_sid;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent_trace: no session %', p_sid USING ERRCODE = '22023';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('medcea_research.agent_trace'));
    SELECT e.hash INTO v_prev FROM agent_trace.event e ORDER BY e.event_id DESC LIMIT 1;
    v_prev := coalesce(v_prev, pg_catalog.repeat('0', 64));
    v_id := pg_catalog.nextval('agent_trace.event_event_id_seq');
    INSERT INTO agent_trace.event (event_id, at, sid, sup_sub, sup_person, sup_role, actor, event, payload,
                                   prev_hash, hash)
    VALUES (v_id, v_at, p_sid, s.sup_sub, s.sup_person, s.sup_role, p_actor, p_event, p_payload, v_prev,
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(agent_trace.event_record(
                v_id, v_at, p_sid, s.sup_sub, s.sup_person, s.sup_role, p_actor, p_event, p_payload, v_prev),
                'UTF8')), 'hex'));
    RETURN v_id;
END $$;
REVOKE ALL ON FUNCTION agent_trace._append(text, text, text, jsonb) FROM PUBLIC;

-- Bytes a session has used: its event payloads plus the blobs it referenced (R31).
CREATE OR REPLACE FUNCTION agent_trace._bytes(p_sid text) RETURNS bigint
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT (SELECT coalesce(pg_catalog.sum(pg_catalog.octet_length(e.payload::text)), 0)
              FROM agent_trace.event e WHERE e.sid = p_sid)
         + (SELECT coalesce(pg_catalog.sum(b.bytes), 0) FROM agent_trace.blob_ref b WHERE b.sid = p_sid)
$$;
REVOKE ALL ON FUNCTION agent_trace._bytes(text) FROM PUBLIC;

-- A refusal is recorded once per session (trace_refused), then counted by nobody: a
-- flood cannot fill the chain.
CREATE OR REPLACE FUNCTION agent_trace._refuse(p_sid text, p_port text, p_event text, p_why text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM agent_trace.session WHERE sid = p_sid)
       AND NOT EXISTS (SELECT 1 FROM agent_trace.event e WHERE e.sid = p_sid AND e.event = 'trace_refused') THEN
        PERFORM agent_trace._append(p_sid, 'research-session', 'trace_refused',
                                    pg_catalog.jsonb_build_object('port', p_port, 'event', pg_catalog.left(p_event, 40),
                                                                  'why', pg_catalog.left(p_why, 200)));
    END IF;
    RETURN p_why;
END $$;
REVOKE ALL ON FUNCTION agent_trace._refuse(text, text, text, text) FROM PUBLIC;

-- ── Writers (EXECUTE for rs_session) ──────────────────────────────────────────
-- open_session: inserts the session and its session_minted event. A third active
-- session of one person is refused (max_active 2, R10).
CREATE OR REPLACE FUNCTION agent_trace.open_session(
    p_sid text, p_kid text, p_token_sha256 text, p_claim_sha256 text, p_sup_sub uuid, p_sup_person text,
    p_sup_role text, p_sup_username text, p_profile text, p_profile_sha256 text, p_tools text[],
    p_budget jsonb, p_backend text, p_code_commit text, p_exp timestamptz)
    RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('medcea_research.agent_trace.mint'));
    IF (SELECT pg_catalog.count(*) FROM agent_trace.session s
         WHERE s.sup_person = p_sup_person AND agent_trace._active(s.sid)) >= 2 THEN
        RAISE EXCEPTION 'agent_trace: person already has 2 active sessions (max_active)' USING ERRCODE = '53400';
    END IF;
    INSERT INTO agent_trace.session (sid, kid, token_sha256, claim_sha256, sup_sub, sup_person, sup_role,
                                     sup_username, profile, profile_sha256, tools, budget, backend, code_commit,
                                     created_at, exp)
    VALUES (p_sid, p_kid, p_token_sha256, p_claim_sha256, p_sup_sub, p_sup_person, p_sup_role, p_sup_username,
            p_profile, p_profile_sha256, p_tools, p_budget, p_backend, p_code_commit, pg_catalog.now(), p_exp);
    RETURN agent_trace._append(p_sid, 'research-session', 'session_minted',
        pg_catalog.jsonb_build_object('profile', p_profile, 'profile_sha256', p_profile_sha256, 'backend', p_backend,
                                      'code_commit', p_code_commit, 'kid', p_kid, 'exp', p_exp));
END $$;
REVOKE ALL ON FUNCTION agent_trace.open_session(text, text, text, text, uuid, text, text, text, text, text, text[],
    jsonb, text, text, timestamptz) FROM PUBLIC;

-- append_event: THE writer. The port decides who is calling; an event outside the
-- port's list, a session that is not active (but for R9's exceptions), a token that is
-- not the session's, a payload over 16 KiB or a session over its byte budget is
-- refused: event_id NULL and the reason in `refused`, the refusal recorded once.
-- An unknown port or session is an exception (a bug, not a refusal).
CREATE OR REPLACE FUNCTION agent_trace.append_event(
    p_port text, p_sid text, p_actor text, p_event text, p_payload jsonb, p_token_sha256 text DEFAULT NULL)
    RETURNS TABLE (event_id bigint, refused text) LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    s       agent_trace.session%ROWTYPE;
    v_act   boolean;
    v_why   text;
    v_cap   bigint;
BEGIN
    IF p_port IS NULL OR agent_trace._port_events(p_port) IS NULL THEN
        RAISE EXCEPTION 'agent_trace: unknown port %', p_port USING ERRCODE = '22023';
    END IF;
    SELECT * INTO s FROM agent_trace.session x WHERE x.sid = p_sid;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent_trace: no session %', p_sid USING ERRCODE = '22023';
    END IF;
    p_payload := coalesce(p_payload, '{}'::jsonb);
    v_act := agent_trace._active(p_sid);

    IF p_event IS NULL OR NOT (p_event = ANY (agent_trace._port_events(p_port))) THEN
        v_why := 'the ' || p_port || ' port may not write ' || coalesce(pg_catalog.left(p_event, 40), 'NULL');
    ELSIF pg_catalog.jsonb_typeof(p_payload) <> 'object' THEN
        v_why := 'the payload is not an object';
    ELSIF pg_catalog.octet_length(p_payload::text) > 16384 THEN
        v_why := 'the payload is over 16 KiB: put the content in a blob';
    ELSIF p_port = 'agent' AND p_token_sha256 IS DISTINCT FROM s.token_sha256 THEN
        v_why := 'the token is not the session''s';
    ELSIF p_port = 'agent' AND p_event = 'turn_response' AND s.backend <> 'scripted' THEN
        v_why := 'turn_response from the agent port is for a scripted backend only';
    ELSIF p_port = 'server' AND p_event IN ('turn_request', 'turn_response')
          AND (p_actor <> 'model-gateway' OR s.backend = 'scripted') THEN
        v_why := p_event || ' on the server port is the model-gateway''s, for a model backend only';
    ELSIF p_port = 'server' AND NOT (
            (p_event = 'tool_result' AND p_actor IN ('mcp-sim', 'mcp-lake'))
         OR (p_event IN ('gate_pending', 'sim_started', 'sim_finished') AND p_actor = 'mcp-sim')
         OR (p_event = 'sim_finished' AND p_actor = 'orchestrator')
         OR (p_event = 'replay_result' AND p_actor IN ('orchestrator', 'research-session'))
         OR (p_event IN ('turn_request', 'turn_response') AND p_actor = 'model-gateway')) THEN
        v_why := 'the server ' || coalesce(pg_catalog.left(p_actor, 40), 'NULL') || ' may not write ' || p_event;
    ELSIF NOT v_act AND NOT (p_port = 'person' OR (p_port = 'server' AND p_event IN ('sim_finished', 'replay_result'))) THEN
        v_why := 'the session is revoked or expired';
    ELSE
        v_cap := coalesce((s.budget ->> 'trace_bytes')::bigint, 209715200);
        IF p_port <> 'person' AND agent_trace._bytes(p_sid) + pg_catalog.octet_length(p_payload::text) > v_cap THEN
            v_why := 'the session is over its trace byte budget';
        END IF;
    END IF;

    IF v_why IS NOT NULL THEN
        RETURN QUERY SELECT NULL::bigint, agent_trace._refuse(p_sid, p_port, p_event, v_why);
        RETURN;
    END IF;
    -- the actor comes from the port; on the server port it is the server's declared name (checked above)
    RETURN QUERY SELECT agent_trace._append(p_sid,
        CASE p_port WHEN 'person' THEN 'research-session' WHEN 'agent' THEN 'agent' ELSE p_actor END,
        p_event, p_payload), NULL::text;
END $$;
REVOKE ALL ON FUNCTION agent_trace.append_event(text, text, text, text, jsonb, text) FROM PUBLIC;

-- put_blob: content-addressed (sha256 computed here), <= 1 MiB, counted against the
-- session's bytes. Returns the sha256, or NULL with the refusal recorded.
CREATE OR REPLACE FUNCTION agent_trace.put_blob(p_sid text, p_media text, p_bytes bytea) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    s      agent_trace.session%ROWTYPE;
    v_sha  text;
BEGIN
    SELECT * INTO s FROM agent_trace.session x WHERE x.sid = p_sid;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent_trace: no session %', p_sid USING ERRCODE = '22023';
    END IF;
    IF p_bytes IS NULL OR pg_catalog.octet_length(p_bytes) > 1048576 THEN
        PERFORM agent_trace._refuse(p_sid, 'blob', 'put_blob', 'a blob is over 1 MiB');
        RETURN NULL;
    END IF;
    IF NOT agent_trace._active(p_sid) THEN
        PERFORM agent_trace._refuse(p_sid, 'blob', 'put_blob', 'the session is revoked or expired');
        RETURN NULL;
    END IF;
    v_sha := pg_catalog.encode(pg_catalog.sha256(p_bytes), 'hex');
    IF agent_trace._bytes(p_sid) + pg_catalog.octet_length(p_bytes)
         > coalesce((s.budget ->> 'trace_bytes')::bigint, 209715200) THEN
        PERFORM agent_trace._refuse(p_sid, 'blob', 'put_blob', 'the session is over its trace byte budget');
        RETURN NULL;
    END IF;
    INSERT INTO agent_trace.blob (sha256, media, bytes) VALUES (v_sha, p_media, p_bytes) ON CONFLICT DO NOTHING;
    INSERT INTO agent_trace.blob_ref (sid, sha256, bytes) VALUES (p_sid, v_sha, pg_catalog.octet_length(p_bytes))
        ON CONFLICT DO NOTHING;
    RETURN v_sha;
END $$;
REVOKE ALL ON FUNCTION agent_trace.put_blob(text, text, bytea) FROM PUBLIC;

-- checkpoint: the AH.7 state, one row per seq, and its event (digest only).
CREATE OR REPLACE FUNCTION agent_trace.checkpoint(p_sid text, p_state jsonb) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_seq  integer;
    v_sha  text;
BEGIN
    IF NOT agent_trace._active(p_sid) THEN
        PERFORM agent_trace._refuse(p_sid, 'agent', 'checkpoint', 'the session is revoked or expired');
        RETURN NULL;
    END IF;
    IF p_state IS NULL OR pg_catalog.jsonb_typeof(p_state) <> 'object' OR pg_catalog.octet_length(p_state::text) > 1048576 THEN
        PERFORM agent_trace._refuse(p_sid, 'agent', 'checkpoint', 'the state is not an object or is over 1 MiB');
        RETURN NULL;
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('medcea_research.agent_trace.state'));
    SELECT coalesce(pg_catalog.max(x.seq), 0) + 1 INTO v_seq FROM agent_trace.state x WHERE x.sid = p_sid;
    v_sha := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_state::text, 'UTF8')), 'hex');
    INSERT INTO agent_trace.state (sid, seq, sha256, state) VALUES (p_sid, v_seq, v_sha, p_state);
    PERFORM agent_trace._append(p_sid, 'agent', 'checkpoint', pg_catalog.jsonb_build_object('seq', v_seq, 'sha256', v_sha));
    RETURN v_seq;
END $$;
REVOKE ALL ON FUNCTION agent_trace.checkpoint(text, jsonb) FROM PUBLIC;

-- revoke: idempotent; true when this call revoked it.
CREATE OR REPLACE FUNCTION agent_trace.revoke(p_sid text, p_reason text, p_by_sub uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM agent_trace.session WHERE sid = p_sid) THEN
        RAISE EXCEPTION 'agent_trace: no session %', p_sid USING ERRCODE = '22023';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('medcea_research.agent_trace.revoke'));
    IF EXISTS (SELECT 1 FROM agent_trace.revocation WHERE sid = p_sid) THEN
        RETURN false;
    END IF;
    INSERT INTO agent_trace.revocation (sid, reason, by_sub)
        VALUES (p_sid, pg_catalog.left(coalesce(p_reason, 'unspecified'), 200), p_by_sub);
    PERFORM agent_trace._append(p_sid, 'research-session', 'session_revoked',
        pg_catalog.jsonb_build_object('reason', pg_catalog.left(coalesce(p_reason, 'unspecified'), 200)));
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION agent_trace.revoke(text, text, uuid) FROM PUBLIC;

-- use_claim: the one-time exchange. The second use is refused and revokes the session.
CREATE OR REPLACE FUNCTION agent_trace.use_claim(p_sid text, p_peer inet) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_n integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM agent_trace.session WHERE sid = p_sid) THEN
        RAISE EXCEPTION 'agent_trace: no session %', p_sid USING ERRCODE = '22023';
    END IF;
    IF NOT agent_trace._active(p_sid) THEN
        RETURN false;
    END IF;
    INSERT INTO agent_trace.claim_use (sid, peer) VALUES (p_sid, p_peer) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n = 0 THEN
        PERFORM agent_trace._append(p_sid, 'research-session', 'claim_reused',
                                    pg_catalog.jsonb_build_object('peer', pg_catalog.host(p_peer)));
        PERFORM agent_trace.revoke(p_sid, 'claim_reused', NULL);
        RETURN false;
    END IF;
    PERFORM agent_trace._append(p_sid, 'research-session', 'claim_exchanged',
                                pg_catalog.jsonb_build_object('peer', pg_catalog.host(p_peer)));
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION agent_trace.use_claim(text, inet) FROM PUBLIC;

-- ── Readers (EXECUTE for rs_session) ──────────────────────────────────────────
-- session_status: active, revocation, exp, backend, the budget and what the events say
-- was spent (turns from turn_request, tokens from turn_response's usage (both backends
-- record them there; a top-level count is still read), cpu_hours from
-- sim_finished, trace_bytes).
CREATE OR REPLACE FUNCTION agent_trace.session_status(p_sid text)
    RETURNS TABLE (active boolean, revoked boolean, exp timestamptz, backend text, budget jsonb, spent jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT agent_trace._active(s.sid),
           EXISTS (SELECT 1 FROM agent_trace.revocation r WHERE r.sid = s.sid),
           s.exp, s.backend, s.budget,
           pg_catalog.jsonb_build_object(
             'turns', (SELECT pg_catalog.count(*) FROM agent_trace.event e WHERE e.sid = s.sid AND e.event = 'turn_request'),
             'prompt_tokens', (SELECT coalesce(pg_catalog.sum(CASE WHEN pg_catalog.jsonb_typeof(coalesce(e.payload -> 'usage', e.payload) -> 'prompt_tokens') = 'number'
                                      THEN (coalesce(e.payload -> 'usage', e.payload) ->> 'prompt_tokens')::numeric END), 0)
                                 FROM agent_trace.event e WHERE e.sid = s.sid AND e.event = 'turn_response'),
             'output_tokens', (SELECT coalesce(pg_catalog.sum(CASE WHEN pg_catalog.jsonb_typeof(coalesce(e.payload -> 'usage', e.payload) -> 'output_tokens') = 'number'
                                      THEN (coalesce(e.payload -> 'usage', e.payload) ->> 'output_tokens')::numeric END), 0)
                                 FROM agent_trace.event e WHERE e.sid = s.sid AND e.event = 'turn_response'),
             'cpu_hours', (SELECT coalesce(pg_catalog.sum(CASE WHEN pg_catalog.jsonb_typeof(e.payload -> 'cpu_hours') = 'number'
                                      THEN (e.payload ->> 'cpu_hours')::numeric END), 0)
                                 FROM agent_trace.event e WHERE e.sid = s.sid AND e.event = 'sim_finished'),
             'trace_bytes', agent_trace._bytes(s.sid))
      FROM agent_trace.session s WHERE s.sid = p_sid
$$;
REVOKE ALL ON FUNCTION agent_trace.session_status(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION agent_trace.events(p_sid text, p_after bigint DEFAULT 0)
    RETURNS TABLE (event_id bigint, at timestamptz, actor text, event text, payload jsonb, prev_hash text, hash text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT e.event_id, e.at, e.actor, e.event, e.payload, e.prev_hash, e.hash
      FROM agent_trace.event e
     WHERE e.sid = p_sid AND e.event_id > coalesce(p_after, 0)
     ORDER BY e.event_id LIMIT 1000
$$;
REVOKE ALL ON FUNCTION agent_trace.events(text, bigint) FROM PUBLIC;

-- set_expect: the orchestrator registers the pod IP a session's claim may come from (once;
-- the same IP again is fine). 'ok' | 'claimed' (the claim is used) | 'conflict' (another IP).
CREATE OR REPLACE FUNCTION agent_trace.set_expect(p_sid text, p_peer inet) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_n integer;
    v_old inet;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM agent_trace.session WHERE sid = p_sid) THEN
        RAISE EXCEPTION 'agent_trace: no session %', p_sid USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM agent_trace.claim_use WHERE sid = p_sid) THEN
        RETURN 'claimed';
    END IF;
    INSERT INTO agent_trace.expect (sid, peer) VALUES (p_sid, p_peer) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n = 1 THEN
        RETURN 'ok';
    END IF;
    SELECT peer INTO v_old FROM agent_trace.expect WHERE sid = p_sid;
    RETURN CASE WHEN v_old = p_peer THEN 'ok' ELSE 'conflict' END;
END $$;
REVOKE ALL ON FUNCTION agent_trace.set_expect(text, inet) FROM PUBLIC;

-- session_state: what research-session needs to judge a token or a claim (hashes only, never a token).
CREATE OR REPLACE FUNCTION agent_trace.session_state(p_sid text)
    RETURNS TABLE (token_sha256 text, claim_sha256 text, created_at bigint, exp bigint, sup_sub uuid,
                   sup_person text, sup_role text, sup_username text, profile text, profile_sha256 text,
                   tools text[], budget jsonb, backend text, expect text, claimed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT s.token_sha256, s.claim_sha256, pg_catalog.date_part('epoch', s.created_at)::bigint,
           pg_catalog.date_part('epoch', s.exp)::bigint, s.sup_sub, s.sup_person, s.sup_role, s.sup_username,
           s.profile, s.profile_sha256, s.tools, s.budget, s.backend,
           (SELECT pg_catalog.host(x.peer) FROM agent_trace.expect x WHERE x.sid = s.sid),
           EXISTS (SELECT 1 FROM agent_trace.claim_use c WHERE c.sid = s.sid)
      FROM agent_trace.session s WHERE s.sid = p_sid
$$;
REVOKE ALL ON FUNCTION agent_trace.session_state(text) FROM PUBLIC;

-- active_sessions: the sids still active, for the revoke-all at service start (R10).
CREATE OR REPLACE FUNCTION agent_trace.active_sessions() RETURNS TABLE (sid text, sup_person text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT s.sid, s.sup_person FROM agent_trace.session s WHERE agent_trace._active(s.sid)
     ORDER BY s.created_at LIMIT 1000
$$;
REVOKE ALL ON FUNCTION agent_trace.active_sessions() FROM PUBLIC;

-- ── No grant: health runs these as postgres ───────────────────────────────────
-- verify_chain(): recomputes every hash and every prev_hash link, oldest first. Does not
-- detect a tail cut off by a superuser (the anchors do: backup MANIFEST, live anchor).
CREATE OR REPLACE FUNCTION agent_trace.verify_chain()
    RETURNS TABLE (ok boolean, events bigint, first_bad_event bigint, detail text, head text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r       record;
    v_prev  text := pg_catalog.repeat('0', 64);
    v_n     bigint := 0;
BEGIN
    FOR r IN SELECT * FROM agent_trace.event e ORDER BY e.event_id LOOP
        v_n := v_n + 1;
        IF r.prev_hash <> v_prev THEN
            RETURN QUERY SELECT false, v_n, r.event_id, 'prev_hash does not follow the previous event', v_prev;
            RETURN;
        END IF;
        IF r.hash <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(agent_trace.event_record(
               r.event_id, r.at, r.sid, r.sup_sub, r.sup_person, r.sup_role, r.actor, r.event, r.payload,
               r.prev_hash), 'UTF8')), 'hex') THEN
            RETURN QUERY SELECT false, v_n, r.event_id, 'hash does not match the row', v_prev;
            RETURN;
        END IF;
        v_prev := r.hash;
    END LOOP;
    RETURN QUERY SELECT true, v_n, NULL::bigint, NULL::text, CASE WHEN v_n = 0 THEN NULL ELSE v_prev END;
END $$;
REVOKE ALL ON FUNCTION agent_trace.verify_chain() FROM PUBLIC;

CREATE OR REPLACE FUNCTION agent_trace.head() RETURNS TABLE (event_id bigint, hash text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT e.event_id, e.hash FROM agent_trace.event e ORDER BY e.event_id DESC LIMIT 1
$$;
REVOKE ALL ON FUNCTION agent_trace.head() FROM PUBLIC;

RESET ROLE;
