"""apps/superset/superset_config.py — MedCEA's configuration of Superset 6.1.0.

Mounted from ConfigMap superset-config at /app/pythonpath and named by
SUPERSET_CONFIG_PATH (k8s/superset.yaml, k8s/superset-init.yaml). Superset copies only
the UPPERCASE names of this module over its defaults (superset/config.py), so helpers
are lower case. Every secret arrives as an environment variable from a secretKeyRef
(Secret superset-secrets, and db-svc-superset for the data connection in bootstrap.py);
a missing one is a KeyError, so Superset does not start rather than start open.

Decisions (decision record "Superset for data analysis", stage B, 6 Nov 2026):
no Redis and no Celery worker (D2: every cache is NullCache or the metadata database,
no async queries, alerts, reports or thumbnails); sessions 5 min idle and 1 h at most
(D6, medcea_security.py); sign-in through Keycloak only, refused unless a realm role
maps (AUTH_ROLES_MAPPING is compiled from the access policy); no local admin, no
public role, no self-registration, no telemetry hosts in the content security policy.
"""
import hashlib
import hmac
import os
from datetime import timedelta
from urllib.parse import quote

from flask_appbuilder.security.manager import AUTH_OAUTH

import medcea_security

_env = os.environ

# --- secrets (secretKeyRef only) ------------------------------------------------
SECRET_KEY = _env["SUPERSET_SECRET_KEY"]
if len(SECRET_KEY) < 32 or SECRET_KEY.startswith("CHANGE_ME"):
    raise RuntimeError("SUPERSET_SECRET_KEY is shorter than 32 characters or a default")
# Embedding is off and the guest-token route answers 404 (medcea_security), but the
# upstream default secret is public: derive one nobody knows.
GUEST_TOKEN_JWT_SECRET = hmac.new(SECRET_KEY.encode(), b"medcea guest token", hashlib.sha256).hexdigest()

_namespace = _env["MEDCEA_NAMESPACE"]
SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://superset_meta:%s@rdbms-postgresql.%s.svc.cluster.local:5432/superset" % (
    quote(_env["SUPERSET_META_DB_PASS"], safe=""), _namespace)
SQLALCHEMY_TRACK_MODIFICATIONS = False

# --- sign-in: Keycloak only (medcea_security.MedceaOAuthView) ---------------------
_keycloak = _env["KEYCLOAK_DOMAIN"]
_realm = _env["KEYCLOAK_REALM"]
_superset = _env["SUPERSET_DOMAIN"]
_issuer = "https://%s/realms/%s" % (_keycloak, _realm)

AUTH_TYPE = AUTH_OAUTH
CUSTOM_SECURITY_MANAGER = medcea_security.MedceaSecurityManager
OAUTH_PROVIDERS = [{
    "name": medcea_security.PROVIDER,
    "icon": "fa-key",
    "token_key": "access_token",
    "remote_app": {
        "client_id": "superset",
        "client_secret": _env["SUPERSET_CLIENT_SECRET"],
        # Reached by its public name (hostAliases → the node) and verified against
        # the platform CA (REQUESTS_CA_BUNDLE): the issuer in the ID token must match.
        "server_metadata_url": _issuer + "/.well-known/openid-configuration",
        # no trailing slash after openid-connect (urljoin would double the segment)
        "api_base_url": _issuer + "/protocol/",
        "client_kwargs": {
            "scope": "openid profile email groups",
            "code_challenge_method": "S256",
            "timeout": 10,
        },
    },
}]
# {realm role: Superset roles}, `cli.py compile superset` (policy_tool superset in
# apps/superset/deploy.sh). Empty or anything but the two role sets: no start.
AUTH_ROLES_MAPPING = medcea_security.parse_roles_mapping(_env["SUPERSET_ROLES_MAPPING"])
AUTH_ROLES_SYNC_AT_LOGIN = True  # a changed realm role applies at the next sign-in
AUTH_USER_REGISTRATION = True  # FAB creates the user at first sign-in, nobody else
AUTH_USER_REGISTRATION_ROLE = None  # not the gate: MedceaOAuthView's 403 is
AUTH_ROLE_PUBLIC = "Public"
PUBLIC_ROLE_LIKE = None  # the Public role stays empty: nothing for anonymous visitors
AUTH_RATE_LIMITED = True

MEDCEA_CALLBACK_URL = "https://%s/oauth-authorized/%s" % (_superset, medcea_security.PROVIDER)
MEDCEA_PORTAL_URL = "https://%s/" % _env["PORTAL_DOMAIN"]
MEDCEA_LOGOUT_URL = medcea_security.end_session_url(_keycloak, _realm, "superset", "https://%s/" % _superset)
LOGOUT_REDIRECT_URL = MEDCEA_LOGOUT_URL

# --- sessions (D6): 5 min idle, 1 h at most ---------------------------------------
PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
SESSION_REFRESH_EACH_REQUEST = True
MEDCEA_SESSION_MAX_SECONDS = 3600
SESSION_SERVER_SIDE = False
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # Talisman never clears it, and never sets it either
SESSION_COOKIE_SAMESITE = "Lax"


def FLASK_APP_MUTATOR(app):  # noqa: N802 — Superset's name
    """Runs after FAB's before_request is registered, so ours sees g.user."""
    app.before_request(medcea_security.before_request)


# --- behind the ingress ------------------------------------------------------------
ENABLE_PROXY_FIX = True  # X-Forwarded-Proto/Host from ingress-nginx (one hop)
# ingress-nginx sets X-Forwarded-For/-Proto/-Host/-Port itself; it passes a client's
# X-Forwarded-Prefix through, so that one is not trusted
PROXY_FIX_CONFIG = {"x_for": 1, "x_proto": 1, "x_host": 1, "x_port": 1, "x_prefix": 0}
PREFERRED_URL_SCHEME = "https"

TALISMAN_ENABLED = True
_fonts = ["fonts.googleapis.com", "fonts.gstatic.com", "use.typekit.net", "use.typekit.com"]
# Superset 6.1.0's default policy without the Scarf telemetry pixel (rendered by the
# page whatever the config says: leaving its hosts out is what stops it), the map tile
# and Mapbox hosts (MedCEA draws no maps) and the documentation CDN.
TALISMAN_CONFIG = {
    "content_security_policy": {
        "base-uri": ["'self'"],
        "default-src": ["'self'"],
        "img-src": ["'self'", "blob:", "data:"],
        "worker-src": ["'self'", "blob:"],
        "connect-src": ["'self'"],
        "object-src": "'none'",
        "style-src": ["'self'", "'unsafe-inline'"] + ["https://" + d for d in _fonts],
        "font-src": ["'self'"] + ["https://" + d for d in _fonts],
        "script-src": ["'self'", "'strict-dynamic'"],
        "frame-ancestors": ["'self'"],
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,  # TLS ends at the ingress, which redirects plain HTTP
    "session_cookie_secure": True,
    "session_cookie_samesite": "Lax",
}
ENABLE_CORS = False  # on by default upstream, for map tiles

# --- no Redis, no worker (D2) --------------------------------------------------------
CACHE_CONFIG = {"CACHE_TYPE": "NullCache"}
DATA_CACHE_CONFIG = {"CACHE_TYPE": "NullCache"}
THUMBNAIL_CACHE_CONFIG = {"CACHE_TYPE": "NullCache"}
# FILTER_STATE_CACHE_CONFIG and EXPLORE_FORM_DATA_CACHE_CONFIG keep their default, the
# metadata database (dashboard filters and Explore need them).
RESULTS_BACKEND = None
CELERY_CONFIG = None
RATELIMIT_STORAGE_URI = "memory://"  # per process; one pod

# --- what people may do --------------------------------------------------------------
DEBUG = False
SHOW_STACKTRACE = False
WTF_CSRF_ENABLED = True
PREVENT_UNSAFE_DB_CONNECTIONS = True
PREVENT_UNSAFE_DEFAULT_URLS_ON_DATASET = True
SQL_MAX_ROW = 100000
SQLLAB_TIMEOUT = 30
SQLLAB_CTAS_NO_LIMIT = False
MAPBOX_API_KEY = ""
FEATURE_FLAGS = {
    "ALERT_REPORTS": False,
    "THUMBNAILS": False,
    "GLOBAL_ASYNC_QUERIES": False,
    "TAGGING_SYSTEM": False,
    "ENABLE_TEMPLATE_PROCESSING": False,  # no Jinja in SQL
    "RLS_IN_SQLLAB": False,
    "EMBEDDED_SUPERSET": False,
    "DASHBOARD_RBAC": False,
    "SSH_TUNNELING": False,
    "ALLOW_FULL_CSV_EXPORT": False,
    "ENABLE_JAVASCRIPT_CONTROLS": False,
    "DYNAMIC_PLUGINS": False,
    "ESTIMATE_QUERY_COST": False,
}

APP_NAME = "MedCEA Superset"
