#!/usr/bin/env python3
"""Who an onboarding run acts as: the edge-wizard's tokens and their holder.

A board is registered in the platform database by a person, and from IAM Phase 2
PostgREST checks who (azp edge-wizard, aud medcea-api, SET ROLE rr_<role>). So a
flash run needs a valid access token at every database call, and a run is long:
firmware download, erase, flash and wiring questions easily outlast the realm's
300 s access-token lifespan, and the SSO session's 30 min idle on top of that.

The answer is one HOLDER per run, the only process that ever has the refresh
token and the client secret:

    wizard_server.py --daemon        one serve thread per run (socketpair fd)
    wizard_server.py --token-channel stdio   for flash-device.sh --ui (coproc)
    edge_auth.py agent               the terminal: device authorization grant

flash-device.sh asks it for a token, one line per request, right before each
platform_db call, and hands that token to platform_db on fd 3. Nothing else in
the run ever sees more than a few minutes' worth of access token.

Line protocol (shell -> holder):   token<TAB><min_ttl 0..3600><TAB><why>
              (holder -> shell):   WAIT<TAB>device<TAB><uri><TAB><user_code><TAB><expires_in>
                                   WAIT<TAB>browser<TAB><message>
                                   WAIT<TAB>retry<TAB><message>
                                   OK<TAB><exp><TAB><user><TAB><name><TAB><role><TAB><access_token>
                                   ERR<TAB><code><TAB><message ending with what to do>
OK and ERR end a request; WAIT lines may come before either. Every field is
non-empty ('-') and tab-free, because bash's `IFS=$'\\t' read` merges empty
fields; every reply is one write of at most LINE_MAX bytes, because `read -t`
keeps half a line when it times out.

Stdlib only: this runs on the host, outside edge/.venv.
"""

import argparse
import base64
import http.client
import json
import os
import select
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

MIN_SERVE = 60      # never hand out a token with less left
KEEPALIVE_S = 30    # tick while a run is bound
REAUTH_WAIT = 900   # how long a token request waits for a re-sign-in / first sign-in
LINE_MAX = 4096     # one reply = one write < PIPE_BUF, so bash never reads half a line
REQ_MAX = 512
# A min_ttl above the realm's 300 s access-token lifespan forces a refresh: the
# callers use it right before an irreversible step (erase) and before register,
# so a session that ended mid-run is found while it can still be acted on.
FORCE_TTL = 330
# Network trouble with this much left on the current token is not worth a wait:
# keep serving it and let the next request try again.
GRACE_S = 30
UNREACHABLE_BACKOFF = (5, 10, 20, 40, 45)   # = 2 min
# For display only ("signed in as … (role)"). Access decisions read the token.
PLATFORM_ROLES = ("operator", "production_manager", "maintenance", "qc", "qa", "qp",
                  "engineer", "bio_scientist", "control_scientist", "admin", "auditor")
CODES = ("reauth", "denied", "expired_code", "role", "unreachable", "client",
         "timeout", "no_session", "bad_request")
# What a request to Keycloak can fail with short of an HTTP answer. HTTPException
# is not an OSError: a truncated body during a Keycloak restart raises
# IncompleteRead, which used to escape every handler and end the token channel.
NET_ERRORS = (OSError, http.client.HTTPException)


class AuthError(Exception):
    """A request that ends in ERR: a protocol code and a message for a person."""

    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


# ------------------------------------------------------------------ claims ---
def claims(tok):
    """Read a token's payload without verifying its signature.

    That is safe *here* and only here: the token did not come from the browser,
    it came back on a direct back-channel request this process made to the
    token endpoint, authenticated with the client secret. There is no untrusted
    party in that exchange to forge it. A token accepted from a browser would
    have to be signature-verified against the JWKS.
    """
    try:
        payload = (tok or "").split(".")[1]
        payload += "=" * (-len(payload) % 4)
        c = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8", "replace"))
        return c if isinstance(c, dict) else {}
    except (ValueError, IndexError, UnicodeDecodeError):
        return {}


def roles_of(need):
    """The required roles as a tuple, or None when nothing is required.

    `need` is None, '', a comma-separated str ("engineer,maintenance": the list
    the access policy compiles, `cli.py compile edge-wizard`) or an iterable.
    A single name still works as before IAM 3.4.
    """
    if not need:
        return None
    if isinstance(need, str):
        need = need.split(",")
    names = tuple(n.strip() for n in need if n and n.strip())
    return names or None


def roles_text(need):
    """"the 'engineer' role" or "one of the roles 'engineer', 'maintenance'"."""
    names = roles_of(need) or ()
    if len(names) == 1:
        return "the '%s' role" % names[0]
    return "one of the roles %s" % ", ".join("'%s'" % n for n in names)


def has_role(c, need):
    """True if the realm role, a client role or the groups claim holds any one
    of the roles in `need` (see roles_of).

    Read from the ACCESS token. Keycloak's default realm-roles mapper puts
    realm_access in the access token only, so a check on the ID token (what the
    wizard did before) refuses everyone as soon as a role is required.
    """
    names = roles_of(need) or ()
    held = set((c.get("realm_access") or {}).get("roles") or [])
    for v in (c.get("resource_access") or {}).values():
        held.update((v or {}).get("roles") or [])
    held.update(c.get("groups") or [])
    return any(n in held for n in names)


def platform_role(c):
    for g in c.get("groups") or []:
        if g in PLATFORM_ROLES:
            return g
    return "-"


def check_access_claims(c, azp="edge-wizard", aud="medcea-api"):
    """None, or what the token lacks for Phase 2's PostgREST to accept it.

    Checked on every new access token, so a client that deploy-infra has not
    configured yet (no audience mapper, no groups scope) is reported the day it
    is used rather than the day enforcement starts.
    """
    if c.get("typ") != "Bearer":
        return "typ Bearer"
    if c.get("azp") != azp:
        return "azp %s" % azp
    a = c.get("aud")
    if aud not in (a if isinstance(a, list) else [a]):
        return "the %s audience" % aud
    if not c.get("groups"):
        return "a groups claim"
    return None


# ---------------------------------------------------------------- tokens ----
class TokenSet:
    """One person's tokens. Never printed: repr shows who and until when."""

    def __init__(self):
        self.access = ""
        self.access_exp = 0.0
        self.refresh = ""
        self.refresh_exp = 0.0
        self.refresh_ttl = 0          # refresh_expires_in as issued; 0 = no idle limit
        self.sub = ""
        self.user = "-"
        self.name = "-"
        self.role = "-"
        self.state = "ok"             # ok | reauth | closed
        self.ended = None             # (code, msg) when closed for a reason a request reports
        # Re-entrant: fresh() holds it across the refresh POST, so two requests
        # at once make one refresh, not two (the second would race a rotated
        # refresh token).
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)

    def __repr__(self):
        return "<TokenSet %s %s exp=%d>" % (self.user, self.state, int(self.access_exp))

    @classmethod
    def from_response(cls, tok, now):
        ts = cls()
        ts._store(tok, now)
        c = claims(ts.access)
        ts.sub = c.get("sub") or ""
        ts.user = c.get("preferred_username") or ts.sub or "-"
        ts.name = c.get("name") or "-"
        ts.role = platform_role(c)
        return ts

    def _store(self, tok, now):
        self.access = tok.get("access_token") or ""
        self.access_exp = now + int(tok.get("expires_in") or 0)
        # Only replace the refresh token when a new one comes back: correct with
        # refresh-token rotation on (a new one every time) and off (sometimes none).
        if tok.get("refresh_token"):
            self.refresh = tok["refresh_token"]
            self.refresh_ttl = int(tok.get("refresh_expires_in") or 0)
            self.refresh_exp = now + (self.refresh_ttl or 10 ** 9)
        # A refreshed token carries the person's CURRENT role (a role change in
        # the User Manager does not end their Keycloak session).
        if self.access:
            self.role = platform_role(claims(self.access))

    def copy(self):
        """An independent set with the same tokens and identity (its own lock)."""
        other = TokenSet()
        with self.lock:
            for k in ("access", "access_exp", "refresh", "refresh_exp", "refresh_ttl",
                      "sub", "user", "name", "role", "state"):
                setattr(other, k, getattr(self, k))
        return other

    def adopt(self, other):
        """Take over another set's tokens: a re-sign-in by the same person."""
        with self.lock:
            for k in ("access", "access_exp", "refresh", "refresh_exp", "refresh_ttl",
                      "name", "role"):
                setattr(self, k, getattr(other, k))
            self.state = "ok"
            self.cond.notify_all()

    def wipe(self, ended=None):
        with self.lock:
            self.access = self.refresh = ""
            self.access_exp = self.refresh_exp = 0.0
            self.state = "closed"
            if ended is not None:
                self.ended = ended
            self.cond.notify_all()


def _post(url, data, ctx, timeout=15):
    """(status, json body) for any HTTP answer; network failure raises NET_ERRORS.

    An HTTP error is an answer, not a failure: Keycloak's 400 invalid_grant is
    how a refresh learns the session has ended.
    """
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
        e.close()
    try:
        body = json.loads(raw.decode("utf-8", "replace")) if raw.strip() else {}
    except ValueError:
        body = {}
    return status, (body if isinstance(body, dict) else {})


def fresh(ts, oidc, client_id, secret, ctx, min_ttl, now=time.time, post=None,
          required_role=None):
    """Make sure `ts` holds an access token with at least `min_ttl` s left.

    ("ok", None), ("reauth", msg) when the Keycloak session is gone, ("client",
    msg) when the client is misconfigured, ("role", msg) when a refreshed token
    no longer holds `required_role`, or ("unreachable", msg).

    The role is checked on every refreshed token, not just at sign-in: a role
    change does not end the Keycloak session, so without this a run (and its
    keepalive ticks) would go on serving tokens to someone who lost the role.
    A set refused for its role is wiped and stays refused.
    """
    post = post or _post
    with ts.lock:
        if ts.state == "closed" and ts.ended:
            return ts.ended
        if ts.state != "ok":
            return "reauth", "the sign-in has ended"
        t = now()
        if ts.access and ts.access_exp - t >= min_ttl:
            return "ok", None
        if not ts.refresh:
            ts.state = "reauth"
            return "reauth", "no refresh token"
        try:
            status, body = post(oidc["token_endpoint"], {
                "grant_type": "refresh_token", "refresh_token": ts.refresh,
                "client_id": client_id, "client_secret": secret}, ctx)
        except NET_ERRORS as e:
            if ts.access and ts.access_exp - t > GRACE_S:
                return "ok", None
            return "unreachable", "%s" % (getattr(e, "reason", None) or e.__class__.__name__)
        if status == 200 and body.get("access_token"):
            ts._store(body, t)
            c = claims(ts.access)
            why = check_access_claims(c, azp=client_id)
            if why:
                return "client", "%s tokens lack %s — run ./deploy-infra.sh" % (client_id, why)
            if required_role and not has_role(c, required_role):
                ended = ("role", "%s no longer has %s, which is required to onboard "
                         "boards — the run stops here. Ask an administrator in the User "
                         "Manager." % (ts.user, roles_text(required_role)))
                ts.wipe(ended)
                return ended
            if ts.access_exp - t < MIN_SERVE:
                return "unreachable", "token lifetime too short"
            return "ok", None
        err = body.get("error") or ""
        if status in (400, 401) and err == "invalid_grant":
            ts.state = "reauth"
            ts.access = ""
            return "reauth", body.get("error_description") or err
        if status == 401 and err in ("invalid_client", "unauthorized_client"):
            return "client", ("EDGE_WIZARD_SECRET in config.env does not match Keycloak — "
                              "run ./deploy-infra.sh")
        if status >= 500 and ts.access and ts.access_exp - t > GRACE_S:
            return "ok", None
        return "unreachable", "Keycloak answered %d %s" % (status, err)


# --------------------------------------------------------------- protocol ---
def _field(v):
    s = "" if v is None else str(v)
    s = s.replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()
    return s or "-"


def _line(*fields):
    b = ("\t".join(_field(f) for f in fields) + "\n").encode("utf-8", "replace")
    if len(b) > LINE_MAX:
        return fmt_err("client", "token too large for the channel")
    return b


def fmt_ok(ts):
    return _line("OK", int(ts.access_exp), ts.user, ts.name, ts.role, ts.access)


def fmt_wait(kind, *fields):
    return _line("WAIT", kind, *fields)


def fmt_err(code, msg):
    # Short by construction, so this can never recurse through _line's cap.
    return ("\t".join(_field(f) for f in ("ERR", code, str(msg)[:1000])) + "\n").encode(
        "utf-8", "replace")


def parse_request(line):
    """(min_ttl, why) from one request line (bytes, no newline), or None."""
    if len(line) > REQ_MAX:
        return None
    parts = line.decode("utf-8", "replace").rstrip("\r").split("\t")
    if len(parts) != 3 or parts[0] != "token" or not parts[1].isdigit():
        return None
    ttl = int(parts[1])
    if not 0 <= ttl <= 3600:
        return None
    return ttl, parts[2].strip() or "continue"


def _write(fd, b):
    while b:
        n = os.write(fd, b)
        b = b[n:]


# ----------------------------------------------------------------- holder ---
class Waiter:
    """What a holder does when it has no tokens yet, or they stopped working.

    The browser holders wait for a sign-in through wizard_server's callback; the
    terminal agent runs the device grant. The default refuses.
    """

    def wait_bind(self, holder, why, emit):
        raise AuthError("no_session", "nobody is signed in to this run")

    def wait_reauth(self, holder, why, emit):
        raise AuthError("reauth", "the sign-in has ended — re-run and sign in again")

    def on_reauth(self, holder):
        pass

    def on_close(self, holder):
        pass


class Holder:
    """The policy shared by all three holder kinds."""

    def __init__(self, oidc, ctx, client_id, secret, required_role=None, waiter=None,
                 ts=None, sleep=time.sleep, now=time.time, post=None):
        self.ts = ts
        self.oidc = oidc
        self.ctx = ctx
        self.client_id = client_id
        self.secret = secret
        self.required_role = roles_of(required_role)
        self.waiter = waiter or Waiter()
        self.sleep, self.now, self.post = sleep, now, post
        self.alive = lambda: True
        # Signalled on a bind or a re-sign-in (offer), so a waiting request wakes.
        self.cond = threading.Condition()

    def host(self):
        return urllib.parse.urlparse((self.oidc or {}).get("issuer", "")).hostname or "?"

    def _fresh(self, min_ttl):
        kind, msg = fresh(self.ts, self.oidc, self.client_id, self.secret, self.ctx,
                          min_ttl, now=self.now, post=self.post,
                          required_role=self.required_role)
        if kind in ("reauth", "role"):
            # A lost role drops the browser sessions too: the next page load signs
            # in again, and the callback's role check refuses it.
            self.waiter.on_reauth(self)
        return kind, msg

    def handle(self, min_ttl, why, emit):
        """One token request; returns the terminal reply line (OK or ERR)."""
        try:
            if self.ts is None:
                self.waiter.wait_bind(self, why, emit)
            backoff = list(UNREACHABLE_BACKOFF)
            while True:
                kind, msg = self._fresh(min_ttl)
                if kind == "ok":
                    return fmt_ok(self.ts)
                if kind in ("client", "role"):
                    return fmt_err(kind, msg)
                if kind == "reauth":
                    self.waiter.wait_reauth(self, why, emit)
                    continue
                if not backoff:
                    return fmt_err("unreachable", "Keycloak at %s is not answering (%s) — "
                                   "check the platform, then re-run" % (self.host(), msg))
                if len(backoff) == len(UNREACHABLE_BACKOFF):
                    emit(fmt_wait("retry", "Keycloak at %s is not answering — retrying for "
                                  "2 min" % self.host()))
                self.sleep(backoff.pop(0))
        except AuthError as e:
            return fmt_err(e.code, e.msg)

    def offer(self, ts, may_bind=False):
        """A browser sign-in that may (re)bind this run: (taken, reason).

        An unbound run (flash-device.sh --ui) is bound only by a sign-in that
        `may_bind`: one started from the address the terminal printed, which
        carries the run's URL token. Anyone else on the LAN who merely reaches
        the port first would otherwise become the run's identity. After that
        only the same person may resume a run whose sign-in has ended. A different
        person signing in gets their own browser session and leaves the run alone.
        """
        with self.cond:
            if self.ts is None:
                if not may_bind:
                    return False, ("signed in as %s from an address without the run's "
                                   "token — not bound to the run" % ts.user)
                self.ts = ts.copy()
                self.cond.notify_all()
                return True, None
            if self.ts.state != "reauth":
                return False, None
            if ts.sub != self.ts.sub:
                return False, ("signed in as %s, but this run belongs to %s"
                               % (ts.user, self.ts.user))
            self.ts.adopt(ts)
            self.cond.notify_all()
            return True, None

    def end_session(self, sub):
        """The run's owner signed out: stop serving the cached access token now."""
        ts = self.ts
        if ts is None or ts.sub != sub:
            return False
        with ts.lock:
            if ts.state == "ok":
                ts.state = "reauth"
                ts.access = ""
        self.waiter.on_reauth(self)
        return True

    def wait_until(self, ready, timeout):
        """Block until ready() or timeout; False on timeout or when the run ends."""
        deadline = self.now() + timeout
        with self.cond:
            while not ready():
                left = deadline - self.now()
                if left <= 0 or not self.alive():
                    return False
                self.cond.wait(min(left, 5))
        return True

    def tick(self):
        """Keep the run's sign-in alive while it is waiting on something else.

        A refresh resets the SSO session's idle timer, so a run left at a wiring
        prompt for an hour is still signed in when it reaches register. Failures
        stay silent here; the next token request reports them.
        """
        ts = self.ts
        if ts is None:
            return
        with ts.lock:
            if ts.state != "ok":
                return
            t = self.now()
            idle = ts.refresh_ttl and ts.refresh_exp - t < min(600, ts.refresh_ttl / 2)
            due = idle or ts.access_exp - t < 90
        if due:
            try:
                self._fresh(10 ** 9)
            except Exception:       # noqa: BLE001 — a tick must never end the channel
                pass

    def close(self):
        try:
            self.waiter.on_close(self)
        finally:
            if self.ts is not None:
                self.ts.wipe()


def serve(rfd, wfd, holder, alive=lambda: True):
    """Answer token requests on (rfd, wfd) until EOF, a write failure or not alive()."""
    holder.alive = alive
    buf = b""
    emit = lambda b: _write(wfd, b)     # noqa: E731
    try:
        while alive():
            r, _, _ = select.select([rfd], [], [], KEEPALIVE_S)
            if not r:
                holder.tick()
                continue
            chunk = os.read(rfd, 1024)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                req = parse_request(line)
                if req is None:
                    emit(fmt_err("bad_request", "not a token request"))
                    return
                # Anything unexpected becomes an ERR, not the end of the channel:
                # a run whose holder vanished could only report "the helper
                # stopped" for every later step.
                try:
                    reply = holder.handle(req[0], req[1], emit)
                except (BrokenPipeError, ConnectionResetError):
                    raise
                except Exception as e:     # noqa: BLE001
                    reply = fmt_err("unreachable", "the sign-in helper failed (%s) — the "
                                    "next step tries again" % e.__class__.__name__)
                emit(reply)
            if len(buf) > REQ_MAX:
                emit(fmt_err("bad_request", "request line too long"))
                return
    except (BrokenPipeError, ConnectionResetError):
        pass
    except OSError:
        pass
    finally:
        holder.close()


# ------------------------------------------------------------- device grant --
def _device_client_error(err, desc, client_id):
    if err == "invalid_client":
        return AuthError("client", "EDGE_WIZARD_SECRET in config.env does not match Keycloak — "
                                   "run ./deploy-infra.sh")
    if err == "unauthorized_client" or "device" in (desc or "").lower():
        return AuthError("client", "the %s client does not allow terminal sign-in yet — run "
                                   "./deploy-infra.sh once, or use --ui" % client_id)
    return AuthError("client", "Keycloak refused the sign-in: %s %s — run ./deploy-infra.sh"
                     % (err or "?", desc or ""))


def device_login(oidc, client_id, secret, ctx, emit, required_role=None,
                 sleep=time.sleep, now=time.time, post=None):
    """Sign a person in from a terminal (RFC 8628) and return their TokenSet.

    The terminal shows a URL and a code; the person opens the URL on any device
    with a browser and Keycloak does the rest. No offline_access: the run's
    authority ends with the person's Keycloak session, like the browser's.
    """
    post = post or _post
    ep = oidc.get("device_authorization_endpoint")
    if not ep:
        raise AuthError("client", "Keycloak does not offer the device authorization grant — "
                                  "run ./deploy-infra.sh, or use --ui")
    try:
        status, body = post(ep, {"client_id": client_id, "client_secret": secret,
                                 "scope": "openid"}, ctx)
    except NET_ERRORS as e:
        raise AuthError("unreachable", "cannot reach Keycloak (%s) — check the platform, "
                                       "then re-run" % (getattr(e, "reason", None) or e))
    if status >= 500:
        raise AuthError("unreachable", "Keycloak answered %d — check the platform, then "
                                       "re-run" % status)
    if status != 200 or not body.get("device_code"):
        raise _device_client_error(body.get("error"), body.get("error_description"), client_id)

    expires_in = int(body.get("expires_in") or 600)
    emit(fmt_wait("device", body.get("verification_uri"), body.get("user_code"), expires_in))
    interval = max(1, int(body.get("interval") or 5))
    deadline = now() + expires_in
    net_err = None
    while True:
        sleep(interval)
        if now() >= deadline:
            if net_err:
                raise AuthError("unreachable", "Keycloak stopped answering while waiting for "
                                               "the sign-in (%s) — re-run" % net_err)
            raise AuthError("expired_code", "the code expired before the sign-in was "
                            "finished — re-run for a new one (if Keycloak said your account "
                            "is disabled, your access request is pending or the account was "
                            "deactivated — ask an administrator)")
        try:
            status, tok = post(oidc["token_endpoint"], {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": body["device_code"],
                "client_id": client_id, "client_secret": secret}, ctx)
        except NET_ERRORS as e:
            net_err = "%s" % (getattr(e, "reason", None) or e.__class__.__name__)
            continue
        if status == 200 and tok.get("access_token"):
            break
        err = tok.get("error")
        # A 5xx, or any answer without an OAuth error code (ingress-nginx's HTML
        # 502 while Keycloak restarts), is the network, not a refusal: keep
        # polling until the code expires rather than blame the client config.
        if status >= 500 or not err:
            net_err = "Keycloak answered %d" % status
            continue
        net_err = None
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        if err == "access_denied":
            raise AuthError("denied", "the sign-in was denied in the browser — nothing was "
                                      "written; re-run to try again")
        if err == "expired_token":
            raise AuthError("expired_code", "the code expired before the sign-in was "
                            "finished — re-run for a new one (if Keycloak said your account "
                            "is disabled, your access request is pending or the account was "
                            "deactivated — ask an administrator)")
        raise _device_client_error(err, tok.get("error_description"), client_id)

    ts = TokenSet.from_response(tok, now())
    c = claims(ts.access)
    why = check_access_claims(c, azp=client_id)
    if why:
        raise AuthError("client", "%s tokens lack %s — run ./deploy-infra.sh" % (client_id, why))
    if required_role and not has_role(c, required_role):
        raise AuthError("role", "%s is signed in but does not have %s, which is "
                        "required to onboard boards. Ask an administrator to change it in "
                        "the User Manager, then re-run. Nothing was written."
                        % (ts.user, roles_text(required_role)))
    return ts



def discover(issuer, ctx, timeout=15):
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def insecure_ctx():
    """The ingress certificate is the platform CA's, which this host may not trust."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ------------------------------------------------------------------ agent ----
class DeviceWaiter(Waiter):
    """The terminal holder: a device code for the first sign-in and any re-sign-in."""

    def __init__(self, issuer):
        self.issuer = issuer
        self.closing = False

    def _oidc(self, holder):
        # Lazy: --help and --unregistered never reach Keycloak.
        if holder.oidc is None:
            try:
                holder.oidc = discover(self.issuer, holder.ctx)
            except (OSError, ValueError) as e:
                raise AuthError("unreachable", "cannot reach Keycloak at %s (%s) — check the "
                                "platform, then re-run" % (self.issuer, e))
        return holder.oidc

    def _login(self, holder, emit):
        return device_login(self._oidc(holder), holder.client_id, holder.secret, holder.ctx,
                            emit, required_role=holder.required_role, sleep=holder.sleep,
                            now=holder.now, post=holder.post)

    def wait_bind(self, holder, why, emit):
        holder.ts = self._login(holder, emit)

    def wait_reauth(self, holder, why, emit):
        owner = holder.ts.user
        emit(fmt_wait("retry", "your sign-in has ended (signed out, or the account was "
                               "deactivated) — sign in again as %s to %s" % (owner, why)))
        deadline = holder.now() + REAUTH_WAIT
        while holder.now() < deadline:
            ts = self._login(holder, emit)
            if ts.sub == holder.ts.sub:
                holder.ts.adopt(ts)
                return
            ts.wipe()
            emit(fmt_wait("retry", "signed in as %s, but this run belongs to %s — sign in "
                                   "as %s" % (ts.user, owner, owner)))
        raise AuthError("timeout", "%s did not sign in again within %d min — re-run"
                        % (owner, REAUTH_WAIT // 60))

    def on_close(self, holder):
        # No revocation at Keycloak: for a refresh token Keycloak's revocation
        # endpoint detaches the client from EVERY session of that person (its
        # revokeClient), ending their other edge-wizard runs and browser tabs,
        # and the logout endpoint would end their whole SSO session, portal
        # included, since a device sign-in reuses the browser's. Holder.close
        # wipes the tokens; nothing else ever had the refresh token.
        self.closing = True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ag = sub.add_parser("agent", help="hold one terminal run's tokens on stdin/stdout")
    ag.add_argument("--issuer", required=True)
    ag.add_argument("--client-id", default="edge-wizard")
    ag.add_argument("--required-role", default="",
                    help="comma-separated roles, any one admits (the access policy's onboarding list)")
    ag.add_argument("--oidc-insecure", action="store_true")
    a = ap.parse_args(argv)

    # From the environment, and popped: argv is world-readable in /proc, and
    # nothing this process starts should inherit it.
    secret = os.environ.pop("EDGE_WIZARD_SECRET", "")
    if not secret:
        print("edge_auth agent: EDGE_WIZARD_SECRET is not in the environment", file=sys.stderr)
        return 2

    waiter = DeviceWaiter(a.issuer)
    holder = Holder(None, insecure_ctx() if a.oidc_insecure else None, a.client_id, secret,
                    required_role=a.required_role, waiter=waiter)

    # The shell's trap kills the agent and EOF ends it, both through
    # holder.close; Ctrl-C at the terminal reaches the whole process group and
    # is the shell's to handle, not this process's.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    def on_term(_sig, _frm):
        if not waiter.closing:
            raise SystemExit(0)
    signal.signal(signal.SIGTERM, on_term)

    parent = os.getppid()
    try:
        serve(0, 1, holder, alive=lambda: os.getppid() == parent)
    except SystemExit:
        holder.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
