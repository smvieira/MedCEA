"""apps/superset/medcea_security.py — Superset's sign-in, gate and sessions for MedCEA.

Loaded by superset_config.py (CUSTOM_SECURITY_MANAGER, FLASK_APP_MUTATOR) from
/app/pythonpath, where ConfigMap superset-config is mounted. Written against the
pinned image apache/superset:6.1.0 (Flask-AppBuilder 5.0.2, Flask 2.3.3, Flask-Login
0.6.3) and Authlib 1.9.5; re-read FAB's AuthOAuthView before moving either.

What it decides, and why it is not left to FAB's defaults:

* **The gate is here, not in FAB.** FAB logs a person in whatever their roles map to,
  zero roles included (AUTH_USER_REGISTRATION_ROLE=None refuses nobody), and shows its
  refusals as flash messages, which Superset 6.1.0's page never renders. So the OAuth
  callback refuses with a rendered 403 "No access to Superset" when none of the
  person's realm roles (the ID token's `groups`) is a key of AUTH_ROLES_MAPPING
  (compiled from the access policy: `cli.py compile superset`), before
  auth_user_oauth can create or update a Superset user.
* **Keycloak only.** /login/ goes straight to /login/keycloak (keeping ?next), so there
  is no provider page; any other provider is 404. MedceaSecurityManager turns off
  Superset's own SPA login view (it also claims /login/) and its registration view;
  the registration routes FAB still adds for AUTH_USER_REGISTRATION and the JSON
  password login (/api/v1/security/login, /refresh: provider "db" is accepted even
  under OAuth, and every OAuth user carries a hash of the empty password) answer 404
  in before_request, as does /api/v1/security/guest_token/ (no embedding here).
* **The person comes from the ID token Authlib validated** (signature against the
  realm's keys, issuer, audience, nonce): `resp["userinfo"]`, never a header.
* **The access token is not kept.** FAB's set_oauth_session would put it in the
  session cookie, which Flask only signs: readable by whoever holds the cookie. The
  callback never calls it, and clears the session (Authlib's state, FAB's oauth_state)
  before login_user, so the signed-in session starts empty (no fixation).
* **Short sessions (owner decision D6, 6 Nov 2026):** idle 5 min through a permanent
  session refreshed on every request (PERMANENT_SESSION_LIFETIME in superset_config.py;
  nobody upstream marks the session permanent), at most 1 h after sign-in through the
  sign-in time kept in the session and checked in before_request.
* **Sign-out ends the Keycloak session** in one hop: FAB's logout, then the session
  cleared (FAB's logout_user leaves the rest of it), then Keycloak's end-session with
  client_id and post_logout_redirect_uri and never id_token_hint (Keycloak then shows
  its confirmation page, as for every other MedCEA host). The return address is the
  platform's one-hop chain (MEDCEA_LOGOUT_RETURN in superset_config.py, stage C N4), so
  the portal and workbench sessions end with it.

Never logs a token, a secret or a cookie.
"""
import html
import json
import logging
import time
from urllib.parse import quote, urlencode

log = logging.getLogger(__name__)

PROVIDER = "keycloak"
LOGIN_AT = "medcea_login_at"

# The two kinds of Superset person the policy compiles (tools.py, kind superset):
# builders get Alpha plus SQL Lab, viewers Gamma plus the read-only data role that
# bootstrap.py keeps. Nothing else may appear in the mapping: never Admin.
ROLE_SETS = (("Alpha", "sql_lab"), ("Gamma", "MedCEA Viewer"))

# Routes nobody reaches here (404), whatever their permissions say.
BLOCKED_EXACT = {
    "/api/v1/security/login",
    "/api/v1/security/refresh",
    "/api/v1/security/guest_token",
}
BLOCKED_PREFIXES = ("/register", "/registeruser")


# ---------------------------------------------------------------------------
# Pure helpers (no Flask): tests/test_superset_render.py runs them directly.
# ---------------------------------------------------------------------------

def parse_roles_mapping(text):
    """AUTH_ROLES_MAPPING from the compiled JSON; ValueError unless it is a non-empty
    {realm role: one of ROLE_SETS} map."""
    try:
        mapping = json.loads(text or "")
    except ValueError:
        raise ValueError("SUPERSET_ROLES_MAPPING is not JSON") from None
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("SUPERSET_ROLES_MAPPING is empty: nobody could sign in")
    allowed = {tuple(sorted(s)) for s in ROLE_SETS}
    out = {}
    for key, roles in mapping.items():
        if not isinstance(key, str) or not key or not key.replace("_", "").replace("-", "").isalnum():
            raise ValueError("SUPERSET_ROLES_MAPPING has a key that is not a realm role name")
        if (not isinstance(roles, list) or not all(isinstance(r, str) for r in roles)
                or tuple(sorted(roles)) not in allowed):
            raise ValueError("SUPERSET_ROLES_MAPPING maps %s to %r; only %s are allowed"
                             % (key, roles, " or ".join(str(list(s)) for s in ROLE_SETS)))
        out[key] = list(roles)
    return out


def userinfo_from_claims(claims):
    """FAB's userinfo dict from the ID token's validated claims; ValueError without a
    username (nothing else names the person)."""
    claims = claims or {}
    username = claims.get("preferred_username")
    if not isinstance(username, str) or not username.strip():
        raise ValueError("the ID token carries no preferred_username")
    groups = claims.get("groups") or []
    if not isinstance(groups, list):
        groups = []
    return {
        "username": username,
        "first_name": claims.get("given_name", "") or "",
        "last_name": claims.get("family_name", "") or "",
        "email": claims.get("email", "") or "",
        "role_keys": [g for g in groups if isinstance(g, str)],
    }


def admitted(mapping, role_keys):
    """The person's realm roles that the mapping knows, sorted (empty: refuse)."""
    return sorted(k for k in set(role_keys or []) if k in mapping)


def end_session_url(keycloak_domain, realm, client_id, post_logout_uri):
    """Keycloak's RP-initiated logout without id_token_hint."""
    query = urlencode({"client_id": client_id, "post_logout_redirect_uri": post_logout_uri})
    return ("https://%s/realms/%s/protocol/openid-connect/logout?%s"
            % (keycloak_domain, quote(realm, safe=""), query))


def session_expired(login_at, now, max_seconds):
    """True when a signed-in session has no sign-in time or is older than max_seconds."""
    if not isinstance(login_at, (int, float)) or isinstance(login_at, bool):
        return True
    return now - login_at >= max_seconds or login_at > now + 60


def blocked_path(path):
    p = (path or "").rstrip("/") or "/"
    return p in BLOCKED_EXACT or any(p == b or p.startswith(b + "/") for b in BLOCKED_PREFIXES)


def page(title, paragraphs, links=()):
    """A small self-contained HTML page (no script; inline style is allowed by the CSP)."""
    body = "".join("<p>%s</p>" % html.escape(p) for p in paragraphs)
    nav = " &middot; ".join('<a href="%s">%s</a>' % (html.escape(h, quote=True), html.escape(t))
                            for t, h in links)
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>%s</title><style>body{font-family:system-ui,sans-serif;max-width:40em;"
            "margin:4em auto;padding:0 16px;line-height:1.5;color:#1f2933}h1{font-size:1.4em}"
            "a{color:#2563eb}</style></head><body><h1>%s</h1>%s<p>%s</p></body></html>"
            % (html.escape(title), html.escape(title), body, nav))


def no_access_page(username, mapping, portal_url):
    return page(
        "No access to Superset",
        ["You are signed in as %s, but your account holds none of the roles that may open "
         "Superset: %s." % (username, ", ".join(sorted(mapping))),
         "Ask an administrator for one of these roles (User Manager). Sign out first if "
         "you meant to use another account."],
        [("Platform portal", portal_url), ("Sign out", "/logout/")])


def failed_page(portal_url):
    return page(
        "Sign-in to Superset failed",
        ["The sign-in could not be completed (it took longer than five minutes, was "
         "refused, or Keycloak could not be reached). Nothing was changed."],
        [("Try again", "/login/"), ("Platform portal", portal_url)])


# ---------------------------------------------------------------------------
# Flask / FAB / Superset parts: imported only inside the Superset image.
# ---------------------------------------------------------------------------

from flask import Response, current_app, g, jsonify, redirect, request, session  # noqa: E402
from flask_appbuilder.security.utils import generate_random_string  # noqa: E402
from flask_appbuilder.security.views import AuthOAuthView  # noqa: E402
from flask_appbuilder.utils.base import get_safe_redirect  # noqa: E402
from flask_appbuilder.views import expose  # noqa: E402
from flask_login import current_user, login_user, logout_user  # noqa: E402
import jwt  # noqa: E402  (PyJWT, in the image)
from superset.security import SupersetSecurityManager  # noqa: E402


def _html(status, text):
    return Response(text, status=status, mimetype="text/html",
                    headers={"Cache-Control": "no-store"})


def _cfg(name):
    return current_app.config[name]


class MedceaOAuthView(AuthOAuthView):
    """FAB's OAuth view with the gate, the session rules and the one-hop sign-out."""

    @expose("/login/")
    @expose("/login/<provider>")
    def login(self, provider=None):
        if g.user is not None and getattr(g.user, "is_authenticated", False):
            return redirect(self.appbuilder.get_url_for_index)
        if provider is None:
            qs = request.query_string.decode("utf-8", "replace")
            return redirect("/login/%s%s" % (PROVIDER, "?" + qs if qs else ""))
        if provider != PROVIDER or provider not in self.appbuilder.sm.oauth_remotes:
            return _html(404, page("Not found", ["Superset signs in through Keycloak only."]))
        # FAB's own state: the request's arguments (next), signed with a random key kept
        # in the session; Authlib adds its state, nonce and PKCE verifier there too.
        random_state = generate_random_string()
        state = jwt.encode(request.args.to_dict(flat=False), random_state, algorithm="HS256")
        session["oauth_state"] = random_state
        try:
            # The registered callback, not url_for: the host is fixed, whatever a
            # forwarded header says.
            return self.appbuilder.sm.oauth_remotes[provider].authorize_redirect(
                redirect_uri=_cfg("MEDCEA_CALLBACK_URL"),
                state=state.decode("ascii") if isinstance(state, bytes) else state,
            )
        except Exception as e:  # noqa: BLE001 — Keycloak unreachable, metadata unreadable
            log.error("medcea: cannot start the Keycloak sign-in (%s)", type(e).__name__)
            return _html(502, failed_page(_cfg("MEDCEA_PORTAL_URL")))

    @expose("/oauth-authorized/<provider>")
    def oauth_authorized(self, provider):
        sm = self.appbuilder.sm
        portal = _cfg("MEDCEA_PORTAL_URL")
        if provider != PROVIDER or provider not in sm.oauth_remotes:
            return _html(404, page("Not found", ["Superset signs in through Keycloak only."]))
        try:
            resp = sm.oauth_remotes[provider].authorize_access_token()
        except Exception as e:  # noqa: BLE001 — ?error=, state mismatch, bad ID token
            log.warning("medcea: sign-in not completed (%s)", type(e).__name__)
            return _html(400, failed_page(portal))
        if not resp:
            return _html(400, failed_page(portal))
        try:
            userinfo = sm.oauth_user_info(provider, resp)
        except Exception as e:  # noqa: BLE001
            log.warning("medcea: no usable identity in the ID token (%s)", type(e).__name__)
            return _html(400, failed_page(portal))
        mapping = _cfg("AUTH_ROLES_MAPPING")
        if not admitted(mapping, userinfo.get("role_keys")):
            log.warning("medcea: refused %s: none of the roles Superset admits", userinfo["username"])
            return _html(403, no_access_page(userinfo["username"], mapping, portal))
        try:
            state = jwt.decode(request.args["state"], session["oauth_state"], algorithms=["HS256"])
        except (jwt.InvalidTokenError, KeyError):
            return _html(400, failed_page(portal))
        user = sm.auth_user_oauth(userinfo)
        if user is None:
            log.warning("medcea: %s is deactivated in Superset", userinfo["username"])
            return _html(403, page(
                "No access to Superset",
                ["Your Superset user is deactivated. Ask an administrator."],
                [("Platform portal", portal), ("Sign out", "/logout/")]))
        next_url = self.appbuilder.get_url_for_index
        if state.get("next"):
            next_url = get_safe_redirect(state["next"][0])
        session.clear()  # Authlib's state, FAB's oauth_state; never the access token
        login_user(user, remember=False)
        session.permanent = True  # idle limit: PERMANENT_SESSION_LIFETIME
        session[LOGIN_AT] = int(time.time())  # absolute limit: before_request
        return redirect(next_url)

    @expose("/logout/")
    def logout(self):
        logout_user()
        session.clear()
        return redirect(_cfg("MEDCEA_LOGOUT_URL"))


class MedceaSecurityManager(SupersetSecurityManager):
    authoauthview = MedceaOAuthView
    register_superset_auth_view = False  # MedceaOAuthView alone owns /login/
    register_superset_registeruser_view = False  # no self-registration

    def get_oauth_user_info(self, provider, resp):
        if provider != PROVIDER:
            raise ValueError("unknown provider")
        return userinfo_from_claims(resp.get("userinfo"))


def before_request():
    """Registered by superset_config.FLASK_APP_MUTATOR, after FAB's own (g.user is set)."""
    if blocked_path(request.path):
        return _html(404, page("Not found", ["This Superset route is not offered here."]))
    if current_user.is_authenticated and session_expired(
            session.get(LOGIN_AT), time.time(), _cfg("MEDCEA_SESSION_MAX_SECONDS")):
        logout_user()
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify(message="Your Superset session has ended: sign in again."), 401
        target = request.path + ("?" + request.query_string.decode("utf-8", "replace")
                                 if request.query_string else "")
        return redirect("/login/?" + urlencode({"next": target}))
    return None
