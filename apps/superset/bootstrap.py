"""apps/superset/bootstrap.py — the data connection and roles Superset needs, as code.

Run by the init Job (k8s/superset-init.yaml) after `superset db upgrade` and
`superset init`, inside the app context:

    python /app/pythonpath/bootstrap.py

1. The connection "MedCEA" (fixed uuid DB_UUID, so a dashboard bundle can name it)
   to the platform database as svc_superset, read-only by its role; the URI is built
   here from the environment (MEDCEA_DATA_DB_PASS is a secretKeyRef of Secret
   db-svc-superset), never passed as an argument (`superset set-database-uri` would
   put the password in argv). Its flags are stated, not defaulted, and read back after
   the commit: DML, CTAS, CVAS, file upload, async and impersonation off, exposed in
   SQL Lab. Its sessions are read-only transactions with a statement timeout too, a
   second fence behind the role's grants (the role is the control: DML-off is a
   parser check, CVE-2026-23984).
2. Role "MedCEA Viewer" holds exactly database_access on that connection: what Gamma
   (viewers: qp, qc, production_manager) needs to see its charts. Builders get Alpha +
   sql_lab from `superset init`.
3. Nobody holds Admin, and the Public role holds nothing.

Never creates a user (people are created at their first Keycloak sign-in) and never
prints a password. Exit 0 done, 1 refused or not as stated.
"""
import json
import os
import sys
import uuid
from urllib.parse import quote

DB_NAME = "MedCEA"
DB_UUID = "51fcabb4-6cd4-598e-8013-26d95b9172e1"  # uuid5(URL, https://medcea/superset/database/MedCEA)
DB_USER = "svc_superset"
VIEWER_ROLE = "MedCEA Viewer"

FLAGS = {
    "expose_in_sqllab": True,
    "allow_run_async": False,
    "allow_file_upload": False,
    "allow_ctas": False,
    "allow_cvas": False,
    "allow_dml": False,
    "impersonate_user": False,
    "select_as_create_table_as": False,
    "force_ctas_schema": None,
    "is_managed_externally": True,
}
EXTRA = {
    "metadata_params": {},
    "engine_params": {"connect_args": {
        "application_name": "superset",
        "options": "-c default_transaction_read_only=on -c statement_timeout=60000",
    }},
    "metadata_cache_timeout": {},
    "schemas_allowed_for_file_upload": [],
}


class Refused(Exception):
    pass


def data_uri(env):
    """The connection's URI from the environment; Refused unless it is svc_superset."""
    user = env.get("MEDCEA_DATA_DB_USER", "")
    if user != DB_USER:
        raise Refused("the data connection must log in as %s, not %r" % (DB_USER, user or "nothing"))
    pw = env.get("MEDCEA_DATA_DB_PASS", "")
    if not pw:
        raise Refused("MEDCEA_DATA_DB_PASS is empty")
    return "postgresql+psycopg2://%s:%s@rdbms-postgresql.%s.svc.cluster.local:5432/%s" % (
        DB_USER, quote(pw, safe=""), env["MEDCEA_NAMESPACE"], env["MEDCEA_DATA_DB_NAME"])


def apply_flags(database):
    for k, v in FLAGS.items():
        setattr(database, k, v)
    database.extra = json.dumps(EXTRA, sort_keys=True)
    database.verbose_name = "MedCEA (read-only, %s)" % DB_USER


def flag_problems(database):
    """What differs from FLAGS/EXTRA after the commit (empty: as stated)."""
    out = []
    for k, v in FLAGS.items():
        if getattr(database, k, object()) != v:
            out.append("%s is %r, not %r" % (k, getattr(database, k, None), v))
    try:
        if json.loads(database.extra or "{}") != EXTRA:
            out.append("extra differs")
    except ValueError:
        out.append("extra is not JSON")
    if str(database.uuid) != DB_UUID:
        out.append("uuid is %s, not %s" % (database.uuid, DB_UUID))
    return out


def ensure_connection(session, database_cls, uri):
    """Create or update the row; Refused when a row of that name has another uuid."""
    database = session.query(database_cls).filter_by(database_name=DB_NAME).first()
    if database is None:
        database = database_cls(database_name=DB_NAME, uuid=uuid.UUID(DB_UUID))
        session.add(database)
    elif str(database.uuid) != DB_UUID:
        raise Refused("a connection named %s with another uuid exists (made by hand?): "
                      "delete it in Superset, then deploy again" % DB_NAME)
    database.set_sqlalchemy_uri(uri)  # the password goes to the encrypted column
    apply_flags(database)
    return database


def _pv(pv):
    return (pv.permission.name, pv.view_menu.name)


def ensure_viewer_role(sm, database):
    """VIEWER_ROLE holds exactly database_access on the connection."""
    role = sm.add_role(VIEWER_ROLE)
    if role is None:
        raise Refused("cannot create role %s" % VIEWER_ROLE)
    want = ("database_access", database.perm)
    pv = sm.add_permission_view_menu(*want)
    if pv is None:
        raise Refused("cannot create the permission %s on %s" % want)
    for other in list(role.permissions):
        if _pv(other) != want:
            sm.del_permission_role(role, other)
    if want not in {_pv(p) for p in role.permissions}:
        sm.add_permission_role(role, pv)
    role = sm.find_role(VIEWER_ROLE)
    have = {_pv(p) for p in role.permissions}
    if have != {want}:
        raise Refused("role %s holds %s, not only %s" % (VIEWER_ROLE, sorted(have), want))


def strip_admins_and_public(sm):
    """Nobody holds Admin; the Public role holds nothing. Returns the usernames changed."""
    changed = []
    for user in sm.get_all_users() or []:
        if any(r.name == "Admin" for r in user.roles):
            user.roles = [r for r in user.roles if r.name != "Admin"]
            if sm.update_user(user) is False:
                raise Refused("cannot take Admin from %s" % user.username)
            changed.append(user.username)
    public = sm.find_role("Public")
    if public is not None:
        for p in list(public.permissions):
            sm.del_permission_role(public, p)
        if sm.find_role("Public").permissions:
            raise Refused("the Public role still holds permissions")
    return changed


def main():
    from superset.app import create_app

    app = create_app()
    with app.app_context():
        from superset import db, security_manager
        from superset.models.core import Database

        try:
            database = ensure_connection(db.session, Database, data_uri(os.environ))
            db.session.commit()
            db.session.refresh(database)
            problems = flag_problems(database)
            if problems:
                raise Refused("connection %s is not as stated: %s" % (DB_NAME, "; ".join(problems)))
            ensure_viewer_role(security_manager, database)
            for name in strip_admins_and_public(security_manager):
                print("bootstrap: took the Admin role from %s" % name)
        except Refused as e:
            db.session.rollback()
            print("bootstrap: REFUSED: %s" % e, file=sys.stderr)
            return 1
        print("bootstrap: connection %s (%s, read-only) and role %s are as stated"
              % (DB_NAME, DB_USER, VIEWER_ROLE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
