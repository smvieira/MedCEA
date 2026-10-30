-- medcea_db_owner.sql — every object in medcea, medcea_auth, iam_policy and iam
-- is owned by medcea_owner (IAM plan 3.6). Run by apps/database/lib-db-apply.sh
-- (step 4) in one transaction as postgres, after the DDL and the migrations;
-- migration 008b runs the same normalisation inside its own transaction so its
-- SECURITY DEFINER functions (owned by medcea_owner) never meet a table they
-- cannot read. Idempotent: only objects whose owner differs are altered, so the
-- first deploy takes the ACCESS EXCLUSIVE locks and later deploys take none.
--
-- Schema iam (apps/access/access_db.sql) since IAM 2.7, when it exists: its
-- tables, sequences and functions, the trigger functions included, so the
-- decision functions are SECURITY DEFINER as medcea_owner and freeze_record()'s
-- owner rule holds. 008b's own copy of this normalisation leaves iam out on
-- purpose: 008b must not depend on the access component, and this file runs
-- after it on every deploy. A later CREATE OR REPLACE by the access deploy (as
-- postgres) keeps the owner; a function it adds is postgres's until the next
-- database deploy, and holds no grant until then either.
-- medcea_owner is NOLOGIN and has no members: nobody acts as the owner except
-- through its SECURITY DEFINER functions and the migrations (SET ROLE, postgres).

SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
    r       record;
    v_owner oid := 'medcea_owner'::regrole;
    schemas oid[] := ARRAY(SELECT oid FROM pg_catalog.pg_namespace
                            WHERE nspname IN ('medcea', 'medcea_auth', 'iam_policy', 'iam'));
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
