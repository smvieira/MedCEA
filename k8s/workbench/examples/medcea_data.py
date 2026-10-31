"""medcea_data — read MedCEA platform data from a notebook, as yourself.

    import medcea_data as md          # on PYTHONPATH in every server (medcea-examples/)
    md.sign_in()                      # shows a link and a code; open it, sign in, confirm
    md.units(); md.zones()            # pandas DataFrames of what your role may see
    md.measurements("UNIT01", "ZONE01", tag="air_temperature", minutes=60)

How it works (IAM 3.2b). The notebook signs you in with a device code (RFC 8628) on the
public Keycloak client `workbench-notebook`: no secret and no password is in this pod or
in any file. Your tokens live only in this kernel's memory — never on disk, never in an
environment variable — are refreshed while you work, and are gone when the kernel stops
(restart the kernel or call sign_out() to drop them sooner). Every request goes to
config-api (PostgREST) with your own token, so the database runs it as your platform
role with its row security: you read exactly what your role may read, nothing more, and
the database refuses the rest. A notebook sign-in only reads: the database refuses any
write or approval made with it, whatever your role may do in the Config UI.

The notebook reaches only Keycloak and config-api among the platform's services, and only
while the platform verifies tokens (IAM_POSTGREST_JWT and IAM_DB_ROLES true). Telemetry is
regulated data: keep it on the platform. Cell outputs are stripped when you commit a
notebook to git (nbstripout); do not paste values into code or text cells.

The pod's environment names the endpoints (set by infra/deploy-workbench.sh):
  MEDCEA_KEYCLOAK   http://keycloak.<namespace>.svc.cluster.local/realms/<realm>
  MEDCEA_API        http://config-api.<namespace>.svc.cluster.local:3000
  MEDCEA_CLIENT_ID  workbench-notebook
Standard library only, except pandas for the DataFrames (in the workbench image).
"""
import base64
import datetime
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
MEASUREMENT_COLUMNS = ("measure_timestamp", "unit_code", "zone_code", "tag", "value", "unit_of_measurement")
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


def measurement_query(unit, zone, tag="air_temperature", minutes=60, now=None, limit=50000):
    """(path, params) for one unit, zone and tag over the last `minutes`, newest first, at
    most `limit` rows (so a window that holds more keeps its latest readings; measurements()
    sorts them oldest first and warns). Reads the view v_ap_measurements (actual points),
    which the database filters by your role's row security like the table under it."""
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

    def measurements(self, unit, zone, tag="air_temperature", minutes=60, limit=50000):
        import pandas as pd
        rows = self.get(*measurement_query(unit, zone, tag, minutes, limit=limit))
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


# One session per kernel, for the module-level shortcuts.
_session = None


def session():
    global _session
    if _session is None:
        _session = Session()
    return _session


def sign_in():
    return session().sign_in()


def sign_out():
    session().sign_out()


def whoami():
    s = session()
    return {"user": s.user, "role": s.role}


def units():
    return session().units()


def zones():
    return session().zones()


def measurements(unit, zone, tag="air_temperature", minutes=60, limit=50000):
    return session().measurements(unit, zone, tag, minutes, limit)
