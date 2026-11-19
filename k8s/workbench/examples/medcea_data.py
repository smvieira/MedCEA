"""medcea_data — read MedCEA data from a notebook.

    import medcea_data as md          # on PYTHONPATH in every server (medcea-examples/)
    md.connect()                      # works wherever your server runs (see below)
    md.units(); md.zones()            # pandas DataFrames
    md.measurements("UNIT01", "ZONE01", tag="air_temperature", minutes=60)

Two modes, chosen by the pod's environment (md.mode()):

"lake" (MEDCEA_LAKE is set: the workbench runs in the research zone, research sandbox
Phase 2b). The notebook reads the person-free snapshots the platform exports every night
into the research database, through the snapshot reader lake-api: no sign-in, no token,
nothing about any person. connect() pins the newest snapshot for this kernel and prints
its provenance; every reading then comes from that snapshot (use_snapshot(n) pins another,
use_snapshot(n, expect=<lineage>) refuses one whose lineage is not the one you recorded).
`minutes` counts back from the snapshot's cut, not from now: the newest data is up to a
day old. Held-out ranges (holds()) never reach the lake. units() and zones() carry codes,
not the platform's ids or descriptions. provenance(df) says which snapshot a result came
from, the lineage that binds it (checked here against snapshots()), the query and a
sha256 of the raw answer: put it next to any figure you keep.

"platform" (otherwise: the workbench on the platform, IAM 3.2b). The notebook signs you
in with a device code (RFC 8628) on the public Keycloak client `workbench-notebook`: no
secret and no password is in this pod or in any file. Your tokens live only in this
kernel's memory — never on disk, never in an environment variable — are refreshed while
you work, and are gone when the kernel stops (restart the kernel or call sign_out() to
drop them sooner). Every request goes to config-api (PostgREST) with your own token, so
the database runs it as your platform role with its row security: you read exactly what
your role may read, nothing more, and the database refuses the rest. A notebook sign-in
only reads: the database refuses any write or approval made with it, whatever your role
may do in the Config UI. The notebook reaches only Keycloak and config-api among the
platform's services, and only while the platform verifies tokens (IAM_POSTGREST_JWT and
IAM_DB_ROLES true). Telemetry is regulated data: keep it on the platform.

In both modes cell outputs are stripped when you commit a notebook to git (nbstripout);
do not paste values into code or text cells.

The pod's environment names the endpoints (set by infra/deploy-workbench.sh):
  MEDCEA_LAKE       http://lake-api.<research namespace>.svc.cluster.local:3000   (lake)
  MEDCEA_KEYCLOAK   http://keycloak.<namespace>.svc.cluster.local/realms/<realm>  (platform)
  MEDCEA_API        http://config-api.<namespace>.svc.cluster.local:3000          (platform)
  MEDCEA_CLIENT_ID  workbench-notebook                                            (platform)
Standard library only, except pandas for the DataFrames (in the workbench image).
"""
import base64
import datetime
import hashlib
import json
import os
import threading
import time
import warnings
import urllib.error
import urllib.parse
import urllib.request

AUDIENCE = "medcea-api"
# For display only (whoami); the database decides from the verified token.
PLATFORM_ROLES = ("operator", "production_manager", "maintenance", "qc", "qa", "qp",
                  "engineer", "bio_scientist", "control_scientist", "admin", "auditor")
REFRESH_MARGIN = 60          # refresh when the access token has less than this left (s)
TIMEOUT = 20
# sensor: the reading's instance (sht45_1, scd30, ...); "default" for a board flashed
# before sensor ids existed. Two sensors of one tag are two series: group or filter by it.
MEASUREMENT_COLUMNS = ("measure_timestamp", "unit_code", "zone_code", "tag", "value", "unit_of_measurement",
                       "sensor")
# What a network failure looks like: a connection refused or timed out is the workbench's
# NetworkPolicy (the hop is open only while the platform verifies tokens).
NET_ERRORS = (OSError,)
# PostgREST's own answers about the token (invalid, missing, expired): a refresh can help.
# A permission refusal (42501) also comes back as 401 (config-api runs every token as
# anon until the database picks your role), and signing in again never helps it.
JWT_ERRORS = ("PGRST301", "PGRST302", "PGRST303")


class SignInError(Exception):
    """The sign-in failed or has ended; the message says what to do."""


class AccessError(Exception):
    """config-api refused or could not answer; the message says why and what to do."""

    def __init__(self, msg, status=None, code=None):
        super().__init__(msg)
        self.status, self.code = status, code


def _claims(tok):
    """A token's payload, unverified: for display and a sanity check only. The token came
    back on this kernel's own request to Keycloak; config-api verifies the signature."""
    try:
        part = (tok or "").split(".")[1]
        part += "=" * (-len(part) % 4)
        c = json.loads(base64.urlsafe_b64decode(part).decode("utf-8", "replace"))
        return c if isinstance(c, dict) else {}
    except (ValueError, IndexError):
        return {}


def _q(v):
    """Percent-encode one query value. PostgREST does not strip quotes, so a value is never
    wrapped in them; '+' in a timestamp must not reach it as a space."""
    return urllib.parse.quote(str(v), safe=",()")


def query_string(params):
    return "&".join(f"{k}={_q(v)}" for k, v in params)


def units_query():
    return "cea_unit", [("select", "unit_id,unit_code,description,is_active"), ("order", "unit_code.asc")]


def zones_query():
    return "cea_zone", [("select", "zone_id,unit_id,zone_code,zone_description,is_active"),
                        ("order", "unit_id.asc,zone_code.asc")]


def measurement_query(unit, zone, tag="air_temperature", minutes=60, now=None, limit=50000, sensor=None):
    """(path, params) for one unit, zone and tag over the last `minutes`, newest first, at
    most `limit` rows (so a window that holds more keeps its latest readings; measurements()
    sorts them oldest first and warns). Reads the view v_ap_measurements (actual points),
    which the database filters by your role's row security like the table under it.
    One row per reading: `sensor` names the instance (`default` for a board not yet
    re-onboarded); group or filter by it (sensor="sht45_1"), or two sensors mix."""
    if not unit or not zone or not tag:
        raise ValueError("unit, zone and tag are required")
    minutes = float(minutes)
    if minutes <= 0:
        raise ValueError("minutes must be positive")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    since = (now - datetime.timedelta(minutes=minutes)).isoformat(timespec="seconds")
    return "v_ap_measurements", [
        ("select", ",".join(MEASUREMENT_COLUMNS)),
        ("unit_code", f"eq.{unit}"), ("zone_code", f"eq.{zone}"), ("tag", f"eq.{tag}"),
        *([("sensor", f"eq.{sensor}")] if sensor else []),
        ("measure_timestamp", f"gte.{since}"),
        ("order", "measure_timestamp.desc"), ("limit", str(int(limit))),
    ]


def _refusal(status, body):
    """AccessError for a config-api answer that is not 200, in words a scientist can act on."""
    code = body.get("code") if isinstance(body, dict) else None
    msg = (body.get("message") if isinstance(body, dict) else None) or ""
    if status == 500 and code == "PGRST300":
        return AccessError("config-api does not verify tokens yet (IAM_POSTGREST_JWT=false); ask an "
                           "administrator", status, code)
    if code == "42703" and "sensor" in msg:   # the views gained sensor in migration 010
        return AccessError("the platform database is older than this notebook helper (no sensor column); "
                           "ask an administrator to run ./apps/database/deploy.sh", status, code)
    if code == "42501":   # 401 or 403: PostgREST picks by the token's role, not the refusal
        return AccessError("your role may not read this (%s)" % msg, status, code)
    if status == 401:
        return AccessError("config-api did not accept your sign-in (%s); run sign_in() again" % (msg or code),
                           status, code)
    if status == 403 and "may not use the API" in msg:
        return AccessError("the database does not accept notebook sign-ins yet; ask an administrator to "
                           "run ./apps/database/deploy.sh", status, code)
    if status == 403:
        return AccessError("refused: %s" % (msg or code or "forbidden"), status, code)
    return AccessError("config-api answered %d %s" % (status, msg or code or ""), status, code)


def _jwt_refused(body):
    """True when a 401 is about the token itself, which a refresh may cure."""
    if not isinstance(body, dict):
        return False
    return body.get("code") in JWT_ERRORS or "jwt" in str(body.get("message") or "").lower()


class Session:
    """One person's sign-in and their requests to config-api. Tokens are attributes of
    this object only; repr never shows them."""

    def __init__(self, keycloak=None, api=None, client_id=None, clock=time.time, sleep=time.sleep,
                 show=None):
        self.keycloak = (keycloak or os.environ.get("MEDCEA_KEYCLOAK") or "").rstrip("/")
        self.api = (api or os.environ.get("MEDCEA_API") or "").rstrip("/")
        self.client_id = client_id or os.environ.get("MEDCEA_CLIENT_ID") or "workbench-notebook"
        self._clock, self._sleep, self._show = clock, sleep, show or _show
        self._lock = threading.RLock()
        self._wipe()

    def __repr__(self):
        who = self.user or "not signed in"
        return "<medcea_data.Session %s%s>" % (who, " (%s)" % self.role if self.role else "")

    def _wipe(self):
        self._access = self._refresh = ""
        self._access_exp = self._refresh_exp = 0.0
        self.user = self.role = None

    # ---------------------------------------------------------------- Keycloak ----
    def _post(self, path, data):
        if not self.keycloak:
            raise SignInError("MEDCEA_KEYCLOAK is not set: this server was started before the workbench "
                              "could read platform data; stop and start it (File > Hub Control Panel)")
        req = urllib.request.Request(self.keycloak + path, data=urllib.parse.urlencode(data).encode(),
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
            e.close()
        try:
            body = json.loads(raw.decode("utf-8", "replace")) if raw.strip() else {}
        except ValueError:
            body = {}
        return status, (body if isinstance(body, dict) else {})

    def _store(self, tok, now):
        self._access = tok.get("access_token") or ""
        self._access_exp = now + int(tok.get("expires_in") or 0)
        # A new refresh token replaces the old one only when one comes back (rotation on or off).
        if tok.get("refresh_token"):
            self._refresh = tok["refresh_token"]
            ttl = int(tok.get("refresh_expires_in") or 0)
            self._refresh_exp = now + (ttl or 10 ** 9)
        c = _claims(self._access)
        why = None
        if c.get("azp") != self.client_id:
            why = "azp %s" % self.client_id
        elif AUDIENCE not in (c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")]):
            why = "the %s audience" % AUDIENCE
        elif not c.get("groups"):
            why = "a groups claim (no platform role?)"
        if why:
            self._wipe()
            raise SignInError("the sign-in token lacks %s; ask an administrator to run ./deploy-infra.sh" % why)
        self.user = c.get("preferred_username") or c.get("sub")
        self.role = next((g for g in c.get("groups") or [] if g in PLATFORM_ROLES), None)

    def sign_in(self):
        """Sign in with a device code: shows a link and a code, waits until you confirm in
        the browser (up to the code's lifetime, about 10 minutes)."""
        try:
            status, body = self._post("/protocol/openid-connect/auth/device",
                                      {"client_id": self.client_id, "scope": "openid"})
        except NET_ERRORS as e:
            raise SignInError("cannot reach Keycloak (%s); the workbench opens it only while the platform "
                              "verifies tokens; ask an administrator" % (getattr(e, "reason", None) or e))
        if status != 200 or not body.get("device_code"):
            raise SignInError("Keycloak refused the sign-in (%s %s); ask an administrator to run "
                              "./deploy-infra.sh" % (body.get("error") or status, body.get("error_description") or ""))
        expires = int(body.get("expires_in") or 600)
        self._show(body.get("verification_uri_complete") or body.get("verification_uri"),
                   body.get("verification_uri"), body.get("user_code"), expires)
        interval = max(1, int(body.get("interval") or 5))
        deadline = self._clock() + expires
        while True:
            self._sleep(interval)
            if self._clock() >= deadline:
                raise SignInError("the code expired before the sign-in was finished; run sign_in() again")
            try:
                status, tok = self._post("/protocol/openid-connect/token", {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": body["device_code"], "client_id": self.client_id})
            except NET_ERRORS:
                continue
            if status == 200 and tok.get("access_token"):
                break
            err = tok.get("error")
            if status >= 500 or not err or err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            if err == "access_denied":
                raise SignInError("the sign-in was denied in the browser; run sign_in() to try again")
            if err == "expired_token":
                raise SignInError("the code expired before the sign-in was finished; run sign_in() again")
            raise SignInError("Keycloak refused the sign-in: %s %s" % (err, tok.get("error_description") or ""))
        with self._lock:
            self._store(tok, self._clock())
        return self.user

    def sign_out(self):
        """Forget the tokens (they are only in this kernel's memory). Your Keycloak session
        in the browser is not ended."""
        with self._lock:
            self._wipe()

    def token(self):
        """A valid access token, refreshed when it has less than a minute left. Never print
        it: notebook outputs end up in files."""
        with self._lock:
            now = self._clock()
            if not self._access and not self._refresh:
                raise SignInError("not signed in: run sign_in() first")
            if self._access and self._access_exp - now >= REFRESH_MARGIN:
                return self._access
            if not self._refresh or self._refresh_exp <= now:
                self._wipe()
                raise SignInError("your sign-in has ended; run sign_in() again")
            try:
                status, tok = self._post("/protocol/openid-connect/token", {
                    "grant_type": "refresh_token", "refresh_token": self._refresh, "client_id": self.client_id})
            except NET_ERRORS as e:
                if self._access and self._access_exp - now > 5:
                    return self._access
                raise SignInError("cannot reach Keycloak to refresh your sign-in (%s)"
                                  % (getattr(e, "reason", None) or e))
            if status == 200 and tok.get("access_token"):
                self._store(tok, now)
                return self._access
            # invalid_grant: the Keycloak session ended (signed out, idle, deactivated)
            self._wipe()
            raise SignInError("your sign-in has ended (%s); run sign_in() again"
                              % (tok.get("error_description") or tok.get("error") or status))

    # -------------------------------------------------------------- config-api ----
    def get(self, path, params=()):
        """GET config-api /<path>?<params> with your token; the decoded JSON rows."""
        if not self.api:
            raise AccessError("MEDCEA_API is not set: stop and start your server (File > Hub Control Panel)")
        url = "%s/%s%s" % (self.api, path.lstrip("/"), ("?" + query_string(params)) if params else "")
        for attempt in (1, 2):
            req = urllib.request.Request(url, headers={"Authorization": "Bearer " + self.token(),
                                                       "Accept": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                    return json.loads(r.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                raw = e.read()
                e.close()
                try:
                    body = json.loads(raw.decode("utf-8", "replace")) if raw.strip() else {}
                except ValueError:
                    body = {}
                if e.code == 401 and attempt == 1 and self._refresh and _jwt_refused(body):
                    with self._lock:
                        self._access_exp = 0.0   # force a refresh, then try once more
                    continue
                raise _refusal(e.code, body) from None
            except NET_ERRORS as e:
                raise AccessError("cannot reach config-api (%s); the workbench opens it only while the "
                                  "platform verifies tokens; ask an administrator"
                                  % (getattr(e, "reason", None) or e)) from None
        raise AccessError("config-api refused the refreshed sign-in; run sign_in() again", 401)

    def units(self):
        import pandas as pd
        return pd.DataFrame(self.get(*units_query()),
                            columns=["unit_id", "unit_code", "description", "is_active"])

    def zones(self):
        import pandas as pd
        zones = pd.DataFrame(self.get(*zones_query()),
                             columns=["zone_id", "unit_id", "zone_code", "zone_description", "is_active"])
        units = self.units()[["unit_id", "unit_code"]]
        return zones.merge(units, on="unit_id", how="left")[
            ["unit_code", "zone_code", "zone_description", "is_active", "unit_id", "zone_id"]]

    def measurements(self, unit, zone, tag="air_temperature", minutes=60, limit=50000, sensor=None):
        import pandas as pd
        rows = self.get(*measurement_query(unit, zone, tag, minutes, limit=limit, sensor=sensor))
        df = pd.DataFrame(rows, columns=list(MEASUREMENT_COLUMNS))
        df["measure_timestamp"] = pd.to_datetime(df["measure_timestamp"], utc=True)
        df["value"] = pd.to_numeric(df["value"])
        df = df.sort_values("measure_timestamp", kind="stable").reset_index(drop=True)
        # The server returned the newest `limit` rows: older ones in the window are left out.
        df.attrs["truncated"] = len(rows) >= int(limit)
        if df.attrs["truncated"]:
            warnings.warn("only the latest %d readings of the last %s minutes: the window holds more. "
                          "Shorten MINUTES or raise limit= to see all of it" % (int(limit), minutes), stacklevel=2)
        return df


def _show(link, uri, code, expires):
    text = ("Sign in to read platform data: open %s and confirm the code %s (valid %d minutes). "
            "This cell waits until you have." % (link, code, max(1, expires // 60)))
    try:
        from IPython.display import HTML, display
        import html
        display(HTML('<p>Sign in to read platform data: open <a href="%s" target="_blank">%s</a> '
                     'and confirm the code <b>%s</b> (valid %d minutes). This cell waits until you have.</p>'
                     % (html.escape(link, quote=True), html.escape(uri or link), html.escape(code or ""),
                        max(1, expires // 60))))
    except ImportError:
        print(text, flush=True)


# ------------------------------------------------------------------ the lake ----
# Research sandbox Phase 2b: the snapshot reader lake-api (PostgREST over schema lake_api
# of the research database), read without identity.
LAKE_MEASUREMENT_COLUMNS = MEASUREMENT_COLUMNS + ("ingested_at", "snapshot_id")
LAKE_UNREACHABLE = "the lake reader is not reachable (./apps/lake-api/deploy.sh)"
MAX_LIMIT = 50000


def mode():
    """'lake' when the workbench runs in the research zone (MEDCEA_LAKE is set), else
    'platform'."""
    return "lake" if (os.environ.get("MEDCEA_LAKE") or "").strip() else "platform"


def lineage_chain(snapshots):
    """{snapshot_id: lineage} recomputed from snapshots() rows, with the database's rule:
    L_0 = '', L_N = sha256_hex(L_{N-1} + '\n' + digests['measurement']), in id order."""
    out, prev = {}, ""
    for row in sorted(snapshots, key=lambda r: int(r["snapshot_id"])):
        md = (row.get("digests") or {}).get("measurement") or ""
        prev = hashlib.sha256((prev + "\n" + md).encode("utf-8")).hexdigest()
        out[int(row["snapshot_id"])] = prev
    return out


def _ts(v):
    """A PostgREST timestamp (ISO 8601) as an aware datetime."""
    if isinstance(v, datetime.datetime):
        return v if v.tzinfo else v.replace(tzinfo=datetime.timezone.utc)
    t = str(v).strip().replace(" ", "T", 1)
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    # Python before 3.11 takes only 0, 3 or 6 fraction digits, and "+00" without minutes
    head, sep, frac = t.partition(".")
    if sep:
        n = 0
        while n < len(frac) and frac[n].isdigit():
            n += 1
        digits, zone = frac[:n], frac[n:]
        t = head + "." + (digits + "000000")[:6] + zone
    if "T" in t and len(t) >= 3 and t[-3] in "+-" and t[-2:].isdigit():
        t += ":00"
    d = datetime.datetime.fromisoformat(t)
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def _iso(d):
    return _ts(d).isoformat()


class LakeSession:
    """Reads the research lake's snapshots through lake-api, for this kernel. One
    snapshot is pinned (connect() or use_snapshot()); everything read comes from it."""

    def __init__(self, lake=None):
        self.lake = (lake or os.environ.get("MEDCEA_LAKE") or "").rstrip("/")
        self.user = os.environ.get("JUPYTERHUB_USER") or None
        self.role = None
        self._pinned = None
        self._warned = set()

    def __repr__(self):
        pin = "snapshot %s" % self._pinned["snapshot_id"] if self._pinned else "no snapshot pinned"
        return "<medcea_data.LakeSession %s, %s>" % (self.user or "?", pin)

    def _warn_once(self, key, text):
        if key not in self._warned:
            self._warned.add(key)
            warnings.warn(text, stacklevel=3)

    # ------------------------------------------------------------ requests ----
    def rpc(self, fn, params=()):
        """GET lake-api /rpc/<fn>?<params>: (decoded rows, the raw answer's bytes)."""
        if not self.lake:
            raise AccessError("MEDCEA_LAKE is not set: stop and start your server (File > Hub Control Panel)")
        params = [(k, v) for k, v in params if v is not None]
        url = "%s/rpc/%s%s" % (self.lake, fn, ("?" + query_string(params)) if params else "")
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            body_raw = e.read()
            e.close()
            try:
                body = json.loads(body_raw.decode("utf-8", "replace")) if body_raw.strip() else {}
            except ValueError:
                body = {}
            code = body.get("code") if isinstance(body, dict) else None
            msg = (body.get("message") if isinstance(body, dict) else None) or ""
            if code == "22023":
                raise AccessError(msg or "refused", e.code, code) from None
            if code == "57014":
                raise AccessError("the lake reader stopped the query after 30 s: ask for a shorter window "
                                  "(minutes=, start=/end=) or one tag", e.code, code) from None
            raise AccessError("the lake reader answered %d %s" % (e.code, msg or code or ""), e.code, code) from None
        except NET_ERRORS:
            raise AccessError(LAKE_UNREACHABLE) from None
        try:
            return json.loads(raw.decode("utf-8")), raw
        except ValueError:
            raise AccessError("the lake reader answered something that is not JSON") from None

    # ------------------------------------------------------------ snapshots ----
    def _snapshot_rows(self):
        rows, _ = self.rpc("snapshots")
        if not isinstance(rows, list):
            raise AccessError("the lake reader answered something that is not a list of snapshots")
        chain = lineage_chain(rows)
        for r in rows:
            r["lineage_verified"] = chain.get(int(r["snapshot_id"])) == r.get("lineage")
        return rows

    def snapshots(self):
        """Every snapshot (oldest first): id, cut, previous cut, created, contract version,
        row counts and digests per set, lineage, and whether the lineage recomputes here."""
        import pandas as pd
        rows = self._snapshot_rows()
        cols = ["snapshot_id", "cut_at", "previous_cut_at", "created_at", "contract_version", "rows", "digests",
                "lineage", "lineage_verified"]
        df = pd.DataFrame(rows, columns=cols)
        for c in ("cut_at", "previous_cut_at", "created_at"):
            df[c] = pd.to_datetime(df[c], utc=True)
        return df

    def snapshot(self, n=None):
        """One snapshot's metadata as a dict: n, or the pinned one (resolved once)."""
        if n is None:
            return dict(self._current())
        return dict(self._find(n))

    def _find(self, n, rows=None):
        rows = self._snapshot_rows() if rows is None else rows
        for r in rows:
            if int(r["snapshot_id"]) == int(n):
                return r
        raise AccessError("no snapshot %s in the lake (snapshots() lists them)" % n)

    def use_snapshot(self, n, expect=None):
        """Pin snapshot n for this kernel. expect: the lineage you recorded with an earlier
        result; a different one is refused (snapshot ids restart if the research database is
        ever rebuilt, so an id alone does not name the same data)."""
        doc = self._find(n)
        if not doc.get("lineage_verified"):
            raise AccessError("snapshot %s's lineage does not recompute from the snapshot list: ask an "
                              "administrator to run ./health-check.sh (Research lake reader)" % n)
        if expect is not None and str(expect).strip().lower() != str(doc.get("lineage")):
            raise AccessError("snapshot %s has lineage %s, not the %s you expected: it is not the same data"
                              % (n, doc.get("lineage"), expect))
        self._pinned = doc
        return dict(doc)

    def _current(self):
        if self._pinned is None:
            rows = self._snapshot_rows()
            if not rows:
                raise AccessError("the lake holds no snapshot yet: the nightly export has not run "
                                  "(./apps/research-export/deploy.sh)")
            newest = max(rows, key=lambda r: int(r["snapshot_id"]))
            if not newest.get("lineage_verified"):
                raise AccessError("the newest snapshot's lineage does not recompute: ask an administrator to "
                                  "run ./health-check.sh (Research lake reader)")
            self._pinned = newest
        return self._pinned

    def connect(self):
        """Pin the newest snapshot (unless one is pinned) and print its provenance line."""
        doc = self._current()
        print("Snapshot %s, cut %s (contract %s), lineage %s (%s). Data up to the cut; held-out ranges: "
              "md.holds()." % (doc["snapshot_id"], doc["cut_at"], doc.get("contract_version"),
                               doc.get("lineage"), "verified" if doc.get("lineage_verified") else "NOT verified"),
              flush=True)
        return dict(doc)

    # ------------------------------------------------------------- results ----
    def _attrs(self, df, doc, set_name, fn, params, raw):
        df.attrs["medcea"] = {
            "source": "lake", "snapshot_id": int(doc["snapshot_id"]), "cut_at": doc.get("cut_at"),
            "contract_version": doc.get("contract_version"), "lineage": doc.get("lineage"),
            "lineage_verified": bool(doc.get("lineage_verified")), "set": set_name,
            "set_digest": (doc.get("digests") or {}).get(set_name),
            "query": {"function": fn, "params": {k: v for k, v in params if v is not None}},
            "response_sha256": hashlib.sha256(raw).hexdigest(),
        }
        return df

    def _set(self, fn, set_name, columns, snapshot=None):
        import pandas as pd
        doc = self._find(snapshot) if snapshot is not None else self._current()
        params = [("p_snapshot", int(doc["snapshot_id"]))]
        rows, raw = self.rpc(fn, params)
        return self._attrs(pd.DataFrame(rows, columns=columns), doc, set_name, fn, params, raw)

    def units(self, snapshot=None):
        self._warn_once("ids", "the lake has codes, not the platform's ids or descriptions: units() and zones() "
                               "are keyed by unit_code and zone_code")
        return self._set("units", "units", ["unit_code", "recipe_type", "area", "height", "is_active",
                                            "snapshot_id"], snapshot)

    def zones(self, snapshot=None):
        self._warn_once("ids", "the lake has codes, not the platform's ids or descriptions: units() and zones() "
                               "are keyed by unit_code and zone_code")
        return self._set("zones", "zones", ["unit_code", "zone_code", "is_active", "snapshot_id"], snapshot)

    def recipes(self, snapshot=None):
        return self._set("recipes", "recipes", ["recipe_id", "recipe_type", "status", "snapshot_id"], snapshot)

    def recipe_lines(self, snapshot=None):
        return self._set("recipe_lines", "recipe_lines",
                         ["recipe_id", "seq", "cycle_number", "light_type", "light_on_minutes",
                          "light_off_minutes", "setpoints", "snapshot_id"], snapshot)

    def catalogue(self, snapshot=None):
        return self._set("catalogue", "catalogue", ["kind", "code", "doc", "snapshot_id"], snapshot)

    def holds(self):
        """The held-out ranges (unit, zone or every zone, measured_at in [from, to)): never
        in the lake. Who reserved them and why is not shown."""
        import pandas as pd
        rows, _ = self.rpc("holds")
        df = pd.DataFrame(rows, columns=["unit_code", "zone_code", "from_at", "to_at"])
        for c in ("from_at", "to_at"):
            df[c] = pd.to_datetime(df[c], utc=True)
        return df

    def measurement_params(self, unit, zone, tag="air_temperature", minutes=60, limit=MAX_LIMIT, sensor=None,
                           snapshot=None, start=None, end=None):
        """(snapshot doc, params) of one measurements() call. The window is (cut - minutes,
        cut] unless start/end are given (start exclusive, end inclusive; either may be
        left out)."""
        if not unit or not zone:
            raise ValueError("unit and zone are required")
        limit = int(limit)
        if not 1 <= limit <= MAX_LIMIT:
            raise ValueError("limit must be between 1 and %d" % MAX_LIMIT)
        doc = self._find(snapshot) if snapshot is not None else self._current()
        if start is None and end is None:
            minutes = float(minutes)
            if minutes <= 0:
                raise ValueError("minutes must be positive")
            cut = _ts(doc["cut_at"])
            p_from, p_to = cut - datetime.timedelta(minutes=minutes), cut
            self._warn_once("window", "minutes count back from the snapshot's cut (%s), not from now: the lake is "
                                      "refreshed nightly. Pass start=/end= for another window" % doc["cut_at"])
        else:
            p_from = _ts(start) if start is not None else None
            p_to = _ts(end) if end is not None else None
        params = [("p_snapshot", int(doc["snapshot_id"])), ("p_unit", unit), ("p_zone", zone), ("p_tag", tag),
                  ("p_from", _iso(p_from) if p_from is not None else None),
                  ("p_to", _iso(p_to) if p_to is not None else None),
                  ("p_sensor", sensor), ("p_limit", limit)]
        return doc, params

    def measurements(self, unit, zone, tag="air_temperature", minutes=60, limit=MAX_LIMIT, sensor=None, *,
                     snapshot=None, start=None, end=None):
        import pandas as pd
        doc, params = self.measurement_params(unit, zone, tag, minutes, limit, sensor, snapshot, start, end)
        rows, raw = self.rpc("measurements", params)
        df = pd.DataFrame([{"measure_timestamp": r.get("measured_at"), "unit_code": r.get("unit_code"),
                            "zone_code": r.get("zone_code"), "tag": r.get("tag"), "value": r.get("value"),
                            "unit_of_measurement": r.get("uom"), "sensor": r.get("sensor"),
                            "ingested_at": r.get("ingested_at"), "snapshot_id": r.get("snapshot_id")} for r in rows],
                          columns=list(LAKE_MEASUREMENT_COLUMNS))
        df["measure_timestamp"] = pd.to_datetime(df["measure_timestamp"], utc=True)
        df["ingested_at"] = pd.to_datetime(df["ingested_at"], utc=True)
        df["value"] = pd.to_numeric(df["value"])
        df = df.sort_values("measure_timestamp", kind="stable").reset_index(drop=True)
        df.attrs["truncated"] = len(rows) >= int(limit)
        if df.attrs["truncated"]:
            warnings.warn("only the latest %d readings of the window: it holds more. Shorten it or raise "
                          "limit= (at most %d) to see all of it" % (int(limit), MAX_LIMIT), stacklevel=2)
        return self._attrs(df, doc, "measurement", "measurements", params, raw)

    # ------------------------------------------------------- kept names ----
    def sign_in(self):
        print("sign_in() is not needed here: the workbench reads person-free snapshots without a sign-in "
              "(md.connect() pins the newest)", flush=True)

    def sign_out(self):
        print("sign_out() is not needed here: nothing is signed in", flush=True)

    def whoami(self):
        return {"user": self.user, "role": None,
                "snapshot": int(self._pinned["snapshot_id"]) if self._pinned else None}


def provenance(df):
    """Where a result came from (lake mode): snapshot, cut, contract version, lineage and
    whether it recomputed, the set's digest, the query, sha256 of the raw answer. None
    for a platform-mode result."""
    p = getattr(df, "attrs", {}).get("medcea")
    return dict(p) if p else None


# One session per kernel, for the module-level shortcuts.
_session = None


def session():
    """This kernel's session: a LakeSession in lake mode, a Session (sign-in) otherwise."""
    global _session
    if _session is None:
        _session = LakeSession() if mode() == "lake" else Session()
    return _session


def _lake():
    s = session()
    if not isinstance(s, LakeSession):
        raise AccessError("only in the research zone: this server reads the platform (md.mode() is 'platform')")
    return s


def connect():
    """Ready to read. Lake: pins the newest snapshot and prints its provenance. Platform:
    signs you in (sign_in())."""
    s = session()
    return s.connect() if isinstance(s, LakeSession) else s.sign_in()


def sign_in():
    return session().sign_in()


def sign_out():
    session().sign_out()


def whoami():
    s = session()
    if isinstance(s, LakeSession):
        return s.whoami()
    return {"user": s.user, "role": s.role}


def units():
    return session().units()


def zones():
    return session().zones()


def measurements(unit, zone, tag="air_temperature", minutes=60, limit=50000, sensor=None, *, snapshot=None,
                 start=None, end=None):
    s = session()
    if isinstance(s, LakeSession):
        return s.measurements(unit, zone, tag, minutes, limit, sensor, snapshot=snapshot, start=start, end=end)
    if snapshot is not None or start is not None or end is not None:
        raise ValueError("snapshot=, start= and end= are for the research zone's lake (md.mode() is 'platform')")
    return s.measurements(unit, zone, tag, minutes, limit, sensor=sensor)


def snapshots():
    return _lake().snapshots()


def snapshot(n=None):
    return _lake().snapshot(n)


def use_snapshot(n, expect=None):
    return _lake().use_snapshot(n, expect)


def holds():
    return _lake().holds()


def recipes():
    return _lake().recipes()


def recipe_lines():
    return _lake().recipe_lines()


def catalogue():
    return _lake().catalogue()
