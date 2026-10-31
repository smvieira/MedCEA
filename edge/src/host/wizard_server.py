#!/usr/bin/env python3
"""Browser front-end for edge/flash-device.sh.

Runs on the provisioning HOST alongside the script — it does not reimplement any
of it. The shell stays the engine: it writes prompts and log lines into a spool
directory, this server renders them and posts answers back. One implementation,
so the terminal and browser paths cannot drift.

    shell  --write--> <spool>/prompt.json --serve--> browser
    shell  <--read--- <spool>/answer      <--POST--- browser
    shell  --append-> <spool>/log         --poll---> browser

Why it exists: the bench machine is usually reached over SSH, so the person
flashing a board has a terminal but often wants the WiFi picker and the final
credentials somewhere they can read and copy properly.

Every request requires the token from the URL. The page carries a WiFi PSK field
and displays a WebREPL password, and it binds to a LAN address by default, so
the token is the only thing between it and the rest of the network. It is
single-run: the server dies with the script.

Under --auth keycloak it is also the holder of the run's tokens (edge_auth.py):
the code exchange keeps the access and refresh tokens in the session, a run gets
its own copy when it starts, and flash-device.sh asks for a fresh access token
before each platform database call — on the --token-fd socket in daemon mode, on
stdin/stdout under --token-channel stdio. No token ever goes into a response,
the spool or a log line.
"""

import argparse
import html
import json
import os
import posixpath
import secrets
import shutil
import socket
import subprocess
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import edge_auth  # noqa: E402  (same directory; stdlib only)

STATE = {
    "dir": None, "token": None, "onboard_url": None,
    "title": "CEA edge provisioning",
    # auth: "token" (a secret in the URL) or "keycloak" (OIDC authorization code)
    "auth": "token",
    "oidc": None,             # discovery document
    "client_id": None, "client_secret": None,
    "required_role": None,
    "ssl_ctx": None,
    "hosts": {},              # Host: value -> scheme we build a redirect_uri with
    "sessions": {},           # sid -> {"user", "sub", "exp", "id_token", "tok": TokenSet}
    "daemon": False,          # long-lived: start runs on demand instead of mirroring one
    "repo_root": None,
    "flash_args": [],
    "catalog": [],            # device types this wizard can provision
    "run": None,              # subprocess.Popen of the current flash run
    "pending": {},            # oauth state -> {"exp":..., "redirect_uri":...}
    # The current run's edge_auth.Holder, or None. Its TokenSet is a COPY taken
    # from the session that pressed Start, so a closed tab or an expired cookie
    # does not stop the run.
    "run_auth": None,
    # {"sub", "user"} of the person the current run acts as: the session that
    # pressed Start, or (--token-channel stdio) the sign-in that bound the run.
    # Only they may answer its prompts, since every answer is acted on with
    # their token and recorded under their name.
    "run_owner": None,
    "lock": threading.Lock(),
}

# How long a BROWSER session lasts. It is still not re-checked against Keycloak
# mid-life (an in-memory map; oauth2-proxy re-checks every cookie_refresh, this
# does not), so a deactivation reaches the page only when the entry expires —
# keep it tight. A RUN's authority is different since IAM 1.5: it comes from the
# refresh token, is refreshed before every database call, and ends when the
# Keycloak session ends, not at SESSION_TTL.
SESSION_TTL = 60 * 60
COOKIE = "cea_wizard_sid"


def run_active():
    r = STATE["run"]
    return r is not None and r.poll() is None


def load_catalog(path, repo_root):
    """Read the device-type catalogue and keep only entries that can actually run.

    A tile is a promise that pressing it does something, so an entry whose script
    is missing or not executable is downgraded to 'unavailable' here rather than
    failing when someone presses it.
    """
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    out = []
    for e in raw.get("devices", []):
        if not e.get("id") or not e.get("name"):
            continue
        entry = {k: e.get(k) for k in
                 ("id", "name", "subtitle", "icon", "status", "connection",
                  "vendor", "roles", "description")}
        script = e.get("script")
        entry["_script"] = None
        if entry.get("status") == "available":
            if not script:
                entry["status"] = "unavailable"
            else:
                full = os.path.realpath(os.path.join(repo_root, script))
                # Refuse anything outside the checkout: the catalogue is a config
                # file, and a path escaping the repo would make it a way to run
                # arbitrary programs as this service.
                if not full.startswith(os.path.realpath(repo_root) + os.sep):
                    entry["status"] = "unavailable"
                elif not os.access(full, os.X_OK):
                    entry["status"] = "unavailable"
                else:
                    entry["_script"] = full
        out.append(entry)
    return out


def catalog_public():
    return [{k: v for k, v in e.items() if not k.startswith("_")} for e in STATE["catalog"]]


def start_run(sess, device_id):
    """Spawn one provisioning run against this spool directory: (http status, error).

    The command comes from the catalogue entry, never from the request — the
    request only names an id. The daemon owns the spool and the HTTP server; the
    script writes prompts and log lines into it exactly as it does when it starts
    its own server. Keeping one implementation is the whole point.

    Under Keycloak the run gets its own copy of the session's tokens, refreshed
    here first (the plan's "refresh before spawning": a session that has ended is
    found now, with nothing started), and a socketpair whose child end is the
    script's --token-fd. The run asks on it for a fresh access token before every
    database call; the refresh token and the secret stay in this process.
    """
    if run_active():
        return 409, "a device is already being provisioned"
    entry = next((e for e in STATE["catalog"] if e["id"] == device_id), None)
    if entry is None:
        return 409, "unknown device type %r" % device_id
    if entry["status"] != "available" or not entry["_script"]:
        return 409, "%s is not available yet" % entry["name"]
    user = (sess or {}).get("user", "operator")

    ts = None
    if STATE["auth"] == "keycloak":
        tok = (sess or {}).get("tok")
        kind, msg = "reauth", None
        if tok is not None:
            # The SESSION's own set is refreshed, and the run takes a copy of the
            # result. Refreshing only a copy left the session holding the refresh
            # token from its sign-in, which Keycloak refuses once the idle timeout
            # (30 min) has passed since it was issued, however busy the session
            # was since: a second Start after a long first run said "login required".
            kind, msg = edge_auth.fresh(tok, STATE["oidc"], STATE["client_id"],
                                        STATE["client_secret"], STATE["ssl_ctx"],
                                        edge_auth.FORCE_TTL,
                                        required_role=STATE["required_role"])
        if kind == "role":
            drop_sessions(sid=(sess or {}).get("sid"))
            return 403, msg
        if kind != "ok":
            # The page answers a 401 by reloading, which is a silent SSO sign-in
            # while Keycloak's session lives, and the login form once it has not.
            drop_sessions(sid=(sess or {}).get("sid"))
            return 401, "login required"
        ts = tok.copy()

    d = STATE["dir"]
    for name in ("log", "prompt.json", "answer", "done.json", "finished", "phase"):
        try:
            os.unlink(os.path.join(d, name))
        except OSError:
            pass
    with open(os.path.join(d, "log"), "w") as f:
        f.write("%s — started by %s\n" % (entry["name"], user))
    STATE["run_owner"] = {"sub": ts.sub, "user": ts.user} if ts is not None else None
    cmd = [entry["_script"], "--ui-spool", d]
    parent = child = None
    if ts is not None:
        parent, child = socket.socketpair()
        cmd += ["--token-fd", str(child.fileno())]
    cmd += STATE["flash_args"]
    try:
        STATE["run"] = subprocess.Popen(
            cmd, cwd=STATE["repo_root"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            # close_fds stays on: exactly the one socket end is passed.
            pass_fds=(child.fileno(),) if child is not None else (),
            start_new_session=True)
    except OSError as e:
        if parent is not None:
            parent.close()
            child.close()
            ts.wipe()
        return 409, str(e)
    if child is None:
        return 200, None
    child.close()
    holder = edge_auth.Holder(STATE["oidc"], STATE["ssl_ctx"], STATE["client_id"],
                              STATE["client_secret"], STATE["required_role"],
                              waiter=BrowserWaiter(), ts=ts)
    STATE["run_auth"] = holder

    def channel():
        try:
            edge_auth.serve(parent.fileno(), parent.fileno(), holder, alive=run_active)
        finally:
            parent.close()
    threading.Thread(target=channel, daemon=True, name="token-channel").start()
    return 200, None


class BrowserWaiter(edge_auth.Waiter):
    """A run whose sign-in comes from the browser (daemon, or --token-channel stdio).

    No page change is needed for a re-sign-in: dropping the owner's local
    sessions makes their next /api/state a 401, the page reloads into Keycloak's
    login, and the callback hands the new tokens to the run (Holder.offer).
    """

    def wait_bind(self, holder, why, emit):
        need = holder.required_role
        emit(edge_auth.fmt_wait("browser", "waiting for a sign-in%s at the address printed "
                                "above — that exact link: a sign-in from the bare address "
                                "does not act for this run"
                                % (" with %s" % edge_auth.roles_text(need) if need else "")))
        if not holder.wait_until(lambda: holder.ts is not None, edge_auth.REAUTH_WAIT):
            raise edge_auth.AuthError("timeout", "nobody signed in within %d min — re-run"
                                      % (edge_auth.REAUTH_WAIT // 60))

    def wait_reauth(self, holder, why, emit):
        ts = holder.ts
        emit(edge_auth.fmt_wait("browser", "Your sign-in has ended (signed out, or the account "
                                "was deactivated). Sign in again as %s in the browser to %s. "
                                "The run is paused; nothing is lost." % (ts.user, why)))
        if not holder.wait_until(lambda: ts.state == "ok", edge_auth.REAUTH_WAIT):
            raise edge_auth.AuthError("timeout", "%s did not sign in again within %d min — "
                                      "re-run" % (ts.user, edge_auth.REAUTH_WAIT // 60))

    def on_reauth(self, holder):
        if holder.ts is not None and holder.ts.sub:
            drop_sessions(sub=holder.ts.sub)

    def on_close(self, holder):
        with STATE["lock"]:
            if STATE["run_auth"] is holder:
                STATE["run_auth"] = None


# --------------------------------------------------------------- OIDC --------
def _http_json(url, data=None, headers=None):
    body = urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers or {})
    with urllib.request.urlopen(req, timeout=15, context=STATE["ssl_ctx"]) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def oidc_discover(issuer, ctx):
    STATE["ssl_ctx"] = ctx
    return _http_json(issuer.rstrip("/") + "/.well-known/openid-configuration")


# Back-channel tokens only: see edge_auth.claims for why no signature check.
_claims_from_id_token = edge_auth.claims


def new_session(claims, id_token="", tokset=None):
    sid = secrets.token_urlsafe(32)
    with STATE["lock"]:
        STATE["sessions"][sid] = {
            "sid": sid,
            "user": claims.get("preferred_username") or claims.get("sub") or "unknown",
            "name": claims.get("name") or "",
            "sub": claims.get("sub") or "",
            "exp": time.time() + SESSION_TTL,
            # Kept so logout can prove to Keycloak which session to end.
            "id_token": id_token,
            # The access and refresh tokens (IAM plan Section 2, "Wizard"): a run
            # started from this session takes a copy of them.
            "tok": tokset,
        }
    return sid


def offer_run(ts, may_bind):
    """Hand a fresh browser sign-in to the run's holder, if there is one."""
    ra = STATE["run_auth"]
    if ra is None or ts is None:
        return
    unbound = ra.ts is None
    taken, why = ra.offer(ts, may_bind=may_bind)
    if taken and unbound:
        STATE["run_owner"] = {"sub": ts.sub, "user": ts.user}
    if why:
        # The reason goes to stderr, never a token.
        print("wizard: run not bound or resumed: %s" % why, file=sys.stderr)


def drop_sessions(sid=None, sub=None):
    """Forget local sessions by id or by person, wiping the tokens they held."""
    with STATE["lock"]:
        for k in [k for k, v in STATE["sessions"].items()
                  if (sid is not None and k == sid) or (sub and v.get("sub") == sub)]:
            s = STATE["sessions"].pop(k)
            if s.get("tok") is not None:
                s["tok"].wipe()


def get_session(sid):
    if not sid:
        return None
    with STATE["lock"]:
        s = STATE["sessions"].get(sid)
        if not s:
            return None
        if s["exp"] < time.time():
            STATE["sessions"].pop(sid, None)
            if s.get("tok") is not None:
                s["tok"].wipe()
            return None
        return s


def spool(name):
    return os.path.join(STATE["dir"], name)


def read(name, default=""):
    try:
        with open(spool(name), encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
_UI_CACHE = {}


def ui_asset(name):
    """One editor asset, inlined into the page.

    Inlined rather than served as its own URL because every other byte this
    server sends is already behind the session check, and a separate static
    route is one more thing to get the auth wrong on. Read once and cached —
    the daemon is long-lived and these do not change under it.
    """
    if name not in _UI_CACHE:
        try:
            with open(os.path.join(UI_DIR, name), encoding="utf-8") as f:
                _UI_CACHE[name] = f.read()
        except OSError:
            # A missing asset must not take the whole page down: every other
            # prompt kind still works without the editor.
            _UI_CACHE[name] = ("/* %s not found in %s */" % (name, UI_DIR))
    return _UI_CACHE[name]


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flash an ESP32 &middot; CEA edge</title>
<style>
  :root{
    --ground:#eef2f3; --surface:#fff; --surface-2:#f6f9fa; --ink:#101a1e; --ink-2:#33474f;
    --muted:#647f89; --line:#d3dee2; --accent:#0b6f78; --accent-soft:#dceff0;
    --warn:#96581a; --warn-soft:#fbeddb; --ok:#1d6b4f; --crit:#a52c1c;
  }
  @media (prefers-color-scheme:dark){:root{
    --ground:#0c1315; --surface:#131c1f; --surface-2:#182327; --ink:#e7eef0; --ink-2:#bccbd0;
    --muted:#86a0a9; --line:#27363b; --accent:#48c2ca; --accent-soft:#143437;
    --warn:#dda45f; --warn-soft:#2e2314; --ok:#63c69f; --crit:#ec8574;
  }}
  *{box-sizing:border-box}
  body{margin:0;background:var(--ground);color:var(--ink);
    font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  header{background:var(--surface);border-bottom:1px solid var(--line);padding:1.1rem 1.3rem}
  .hin{max-width:60rem;margin:0 auto;display:flex;gap:1rem;align-items:baseline;flex-wrap:wrap}
  h1{font-size:1.12rem;margin:0;letter-spacing:-.01em}
  .sub{font-size:.8rem;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .spacer{flex:1}
  a.onboard{font-size:.84rem;color:var(--accent);text-decoration:none;border:1px solid var(--accent);
    border-radius:4px;padding:.34rem .7rem;white-space:nowrap}
  a.onboard:hover{background:var(--accent-soft)}
  a.onboard .ph{color:var(--muted);font-size:.72rem}
  .who{font-size:.8rem;color:var(--muted);font-family:ui-monospace,Menlo,monospace}
  .who a{color:var(--muted)}
  main{max-width:60rem;margin:0 auto;padding:1.3rem}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:6px;
    padding:1.1rem 1.2rem;margin-bottom:1rem}
  .card.prompt{border-color:var(--accent);box-shadow:0 6px 24px -18px rgba(0,0,0,.6)}
  .label{font-weight:600;margin:0 0 .2rem}
  .hint{font-size:.84rem;color:var(--muted);margin:0 0 .9rem}
  .opts{display:flex;flex-direction:column;gap:.4rem;margin-bottom:.9rem}
  .opt{display:flex;gap:.7rem;align-items:center;padding:.5rem .7rem;border:1px solid var(--line);
    border-radius:4px;cursor:pointer;background:var(--surface-2);font-family:ui-monospace,Menlo,monospace;
    font-size:.83rem;text-align:left;color:var(--ink);width:100%}
  .opt:hover{border-color:var(--accent)}
  .opt[aria-selected=true]{border-color:var(--accent);background:var(--accent-soft)}
  .opt .n{color:var(--accent);font-weight:600;flex:none;min-width:1.6rem}
  .opt .tag{margin-left:auto;color:var(--muted);font-size:.76rem;white-space:nowrap}
  .grouphdr{font-size:.72rem;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);
    margin:.6rem 0 .1rem;font-family:ui-monospace,Menlo,monospace}
  input[type=text],input[type=password]{width:100%;padding:.55rem .7rem;border:1px solid var(--line);
    border-radius:4px;background:var(--surface-2);color:var(--ink);font-size:.95rem;
    font-family:ui-monospace,Menlo,monospace}
  input:focus{outline:2px solid var(--accent);outline-offset:1px}
  .row{display:flex;gap:.6rem;margin-top:.8rem;flex-wrap:wrap}
  button.go{background:var(--accent);color:#fff;border:0;border-radius:4px;padding:.55rem 1.1rem;
    font-size:.92rem;font-weight:600;cursor:pointer}
  button.alt{background:transparent;color:var(--ink-2);border:1px solid var(--line);
    border-radius:4px;padding:.55rem 1.1rem;font-size:.92rem;cursor:pointer}
  button:disabled{opacity:.5;cursor:default}
  pre.log{background:var(--surface-2);border:1px solid var(--line);border-radius:6px;
    padding:.9rem 1rem;max-height:26rem;overflow:auto;font-family:ui-monospace,Menlo,monospace;
    font-size:.79rem;line-height:1.55;color:var(--ink-2);margin:0;white-space:pre-wrap;
    word-break:break-word}
  .idle{color:var(--muted);font-size:.88rem;display:flex;align-items:center;gap:.6rem}
  .dot{width:.5rem;height:.5rem;border-radius:50%;background:var(--accent);flex:none;
    animation:p 1.4s ease-in-out infinite}
  @keyframes p{0%,100%{opacity:.25}50%{opacity:1}}
  @media (prefers-reduced-motion:reduce){.dot{animation:none}}
  dl.sum{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1.1rem;margin:0;
    font-family:ui-monospace,Menlo,monospace;font-size:.84rem}
  dl.sum dt{color:var(--muted)}
  dl.sum dd{margin:0;word-break:break-all}
  dl.sum dd.big{font-weight:700;font-size:.95rem;color:var(--accent)}
  .copy{border:1px solid var(--line);background:var(--surface-2);color:var(--ink-2);border-radius:3px;
    font-size:.7rem;padding:.05rem .35rem;cursor:pointer;margin-left:.45rem}
  .banner{border-left:3px solid var(--warn);background:var(--warn-soft);padding:.7rem .9rem;
    border-radius:3px;font-size:.85rem;margin-top:.9rem;color:var(--ink-2)}
  .banner.done{border-left-color:var(--ok);background:transparent;border:1px solid var(--line)}
  .storehdr{display:flex;align-items:baseline;gap:.7rem;margin:0 0 .2rem}
  .storehdr h2{font-size:1.05rem;margin:0}
  .storehdr .count{font-size:.78rem;color:var(--muted);font-family:ui-monospace,Menlo,monospace}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(15.5rem,1fr));gap:.9rem;margin-top:1rem}
  .tile{display:flex;flex-direction:column;gap:.5rem;background:var(--surface);
    border:1px solid var(--line);border-radius:8px;padding:1rem 1.05rem;text-align:left}
  .tile.on{cursor:pointer}
  .tile.on:hover{border-color:var(--accent);box-shadow:0 6px 22px -18px rgba(0,0,0,.65)}
  .tile.off{opacity:.55}
  .tile .top{display:flex;gap:.7rem;align-items:flex-start}
  .tile .ico{font-size:1.6rem;line-height:1;flex:none}
  .tile .nm{font-weight:600;font-size:.97rem;color:var(--ink)}
  .tile .sub{font-size:.82rem;color:var(--muted)}
  .tile .desc{font-size:.83rem;color:var(--ink-2);margin:0}
  .tile .meta{display:flex;flex-wrap:wrap;gap:.35rem;margin-top:auto;padding-top:.5rem}
  .chip{font-family:ui-monospace,Menlo,monospace;font-size:.66rem;letter-spacing:.04em;
    padding:.16em .45em;border-radius:3px;border:1px solid var(--line);color:var(--muted)}
  .chip.ok{color:var(--accent);border-color:var(--accent);background:var(--accent-soft)}
  .chip.soon{color:var(--warn);border-color:var(--warn);background:var(--warn-soft)}
  .tile .cta{margin-top:.6rem;font-size:.84rem;font-weight:600;color:var(--accent)}
  .tile.off .cta{color:var(--muted);font-weight:400}
__CHANNELMAP_CSS__
</style></head><body>
<header><div class="hin">
  <h1>Flash an ESP32</h1>
  <span class="sub" id="phase">connecting&hellip;</span>
  <span class="spacer"></span>
  <span class="who" id="who">__WHO__</span>
  <a class="onboard" href="__ONBOARD__" target="_blank" rel="noopener">
    Device onboarding &rarr; <span class="ph">placeholder</span></a>
</div></header>
<main>
  <div class="card prompt" id="promptcard" hidden>
    <p class="label" id="plabel"></p>
    <p class="hint" id="phint" hidden></p>
    <div class="opts" id="popts"></div>
    <div id="pmap" hidden></div>
    <div id="pfree" hidden><input type="text" id="pinput" autocomplete="off"></div>
    <div class="row" id="prow"><button class="go" id="psend">Continue</button>
      <button class="alt" id="preset" hidden>Reset to reference wiring</button>
      <span class="hint" id="pmapwarn" hidden></span></div>
  </div>
  <div class="card" id="startcard" hidden>
    <div class="storehdr">
      <h2 id="storetitle">Onboard a device</h2>
      <span class="count" id="storecount"></span>
    </div>
    <p class="hint" id="storehint">Pick the kind of device you are adding. It must be attached to
      this machine — onboarding runs on the host the platform runs on.</p>
    <div class="grid" id="store"></div>
  </div>
  <div class="card" id="idlecard" hidden><div class="idle"><span class="dot"></span><span id="idletext">Waiting for the script&hellip;</span></div></div>
  <div class="card" id="donecard" hidden></div>
  <div class="card"><pre class="log" id="log"></pre></div>
</main>
<script>__CHANNELMAP_JS__</script>
<script>
const T = new URLSearchParams(location.search).get("t") || "";
// 401 means the session expired mid-run; a reload re-enters the login flow.
function reauth() { location.reload(); }
const $ = i => document.getElementById(i);
let curId = null, sel = null, lastLog = "", mapCtl = null;

function api(p, o) { return fetch(p + (p.includes("?") ? "&" : "?") + "t=" + encodeURIComponent(T), o); }

function renderPrompt(p) {
  if (!p) { $("promptcard").hidden = true; curId = null; return; }
  if (p.id === curId) return;
  curId = p.id; sel = null;
  $("promptcard").hidden = false;
  $("plabel").textContent = p.label || "";
  $("phint").textContent = p.hint || ""; $("phint").hidden = !p.hint;
  const box = $("popts"); box.innerHTML = "";
  const free = $("pfree"), inp = $("pinput"), map = $("pmap");
  // The editor is torn down between prompts, and rebuilt only when the id
  // changes — the poll loop calls this every second, and re-mounting on each
  // tick would throw away whatever the operator had half-typed.
  map.hidden = true; map.innerHTML = ""; mapCtl = null;
  $("preset").hidden = true; $("pmapwarn").hidden = true;

  if (p.kind === "channelmap") {
    free.hidden = true; map.hidden = false;
    mapCtl = ChannelMap.mount({
      el: map, spec: p.spec || {}, initial: (p.spec || {}).reference,
      onchange: ctl => {
        const n = ctl.errors();
        // Errors are refused by the renderer anyway; blocking here is what
        // keeps that from happening after the board has been erased.
        $("psend").disabled = n > 0;
        $("pmapwarn").hidden = n === 0;
        $("pmapwarn").textContent = n
          ? n + (n === 1 ? " error" : " errors") + " to fix before this can be sent"
          : "";
      }
    });
    $("preset").hidden = false;
    $("preset").onclick = () => mapCtl && mapCtl.reset((p.spec || {}).reference);
  } else if (p.kind === "choice") {
    free.hidden = true;
    let n = 0;
    (p.options || []).forEach(o => {
      if (typeof o === "string" && o.startsWith("## ")) {
        const h = document.createElement("div");
        h.className = "grouphdr"; h.textContent = o.slice(3); box.appendChild(h); return;
      }
      n += 1; const idx = n;
      const parts = String(o).split("|");
      const b = document.createElement("button");
      b.className = "opt"; b.type = "button"; b.setAttribute("aria-selected", String(idx) === String(p.default));
      if (String(idx) === String(p.default)) sel = String(idx);
      b.innerHTML = "";
      const sn = document.createElement("span"); sn.className = "n"; sn.textContent = idx;
      const st = document.createElement("span"); st.textContent = parts[0];
      b.appendChild(sn); b.appendChild(st);
      if (parts[1]) { const tg = document.createElement("span"); tg.className = "tag"; tg.textContent = parts[1]; b.appendChild(tg); }
      b.onclick = () => {
        sel = String(idx);
        [...box.querySelectorAll(".opt")].forEach(x => x.setAttribute("aria-selected", "false"));
        b.setAttribute("aria-selected", "true");
        if (p.submit_on_click) send();
      };
      box.appendChild(b);
    });
  } else if (p.kind === "confirm") {
    free.hidden = true;
    [["Yes", "y"], ["No", "n"]].forEach(([t, v]) => {
      const b = document.createElement("button");
      b.className = "opt"; b.type = "button"; b.textContent = t;
      b.onclick = () => { sel = v; send(); };
      box.appendChild(b);
    });
  } else {
    free.hidden = false;
    inp.type = p.kind === "secret" ? "password" : "text";
    inp.value = p.default && p.kind !== "secret" ? p.default : "";
    inp.onkeydown = e => { if (e.key === "Enter") send(); };
    setTimeout(() => inp.focus(), 30);
  }
  $("psend").hidden = (p.kind === "confirm");
  $("psend").disabled = false;
}

function send() {
  if (curId === null) return;
  let p;
  if (mapCtl) {
    if (mapCtl.errors() > 0) return;      // the button is disabled; belt and braces
    // The board it was checked against goes with it: the shell re-checks the
    // map against the chip it reads off the silicon, and cannot without this.
    p = JSON.stringify({ config: mapCtl.value(), variant: mapCtl.variant() });
  } else {
    p = $("pfree").hidden ? sel : $("pinput").value;
  }
  if (p === null || p === undefined) return;
  const id = curId; curId = null; mapCtl = null;
  $("promptcard").hidden = true;
  api("/api/answer", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, value: String(p) })
  }).then(async r => {
    // Someone else's run: the prompt comes back on the next poll, unanswered.
    if (r.status === 403) {
      const j = await r.json().catch(() => ({}));
      alert(j.error || "not your run");
    }
  });
}
$("psend").onclick = send;

let storeDrawn = "";
function renderStore(cat, finished) {
  $("storetitle").textContent = finished ? "Onboard another device" : "Onboard a device";
  const avail = cat.filter(d => d.status === "available").length;
  $("storecount").textContent = avail + " of " + cat.length + " available";
  const sig = JSON.stringify(cat) + finished;
  if (sig === storeDrawn) return;      // don't rebuild under the poll
  storeDrawn = sig;
  const g = $("store"); g.innerHTML = "";
  cat.forEach(d => {
    const on = d.status === "available";
    const el = document.createElement(on ? "button" : "div");
    el.className = "tile " + (on ? "on" : "off");
    if (on) el.type = "button";

    const top = document.createElement("div"); top.className = "top";
    const ic = document.createElement("span"); ic.className = "ico"; ic.textContent = d.icon || "\u2699";
    const nb = document.createElement("div");
    const nm = document.createElement("div"); nm.className = "nm"; nm.textContent = d.name;
    const sb = document.createElement("div"); sb.className = "sub"; sb.textContent = d.subtitle || "";
    nb.appendChild(nm); nb.appendChild(sb);
    top.appendChild(ic); top.appendChild(nb); el.appendChild(top);

    if (d.description) {
      const p = document.createElement("p"); p.className = "desc"; p.textContent = d.description;
      el.appendChild(p);
    }
    const meta = document.createElement("div"); meta.className = "meta";
    const st = document.createElement("span");
    st.className = "chip " + (on ? "ok" : "soon");
    st.textContent = on ? "available" : d.status;
    meta.appendChild(st);
    if (d.connection) { const c = document.createElement("span"); c.className = "chip"; c.textContent = d.connection; meta.appendChild(c); }
    (d.roles || []).forEach(r => { const c = document.createElement("span"); c.className = "chip"; c.textContent = r; meta.appendChild(c); });
    el.appendChild(meta);

    const cta = document.createElement("div"); cta.className = "cta";
    cta.textContent = on ? "Set up \u2192" : "Not available yet";
    el.appendChild(cta);

    if (on) el.onclick = () => startDevice(d.id, el);
    g.appendChild(el);
  });
}

async function startDevice(id, el) {
  [...$("store").querySelectorAll(".tile")].forEach(t => { t.disabled = true; });
  try {
    const r = await api("/api/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device: id })
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      alert(j.error || "could not start");
    }
  } finally {
    setTimeout(() => { [...$("store").querySelectorAll(".tile")].forEach(t => { t.disabled = false; }); }, 1500);
  }
  $("donecard").hidden = true; $("donecard").dataset.done = ""; $("donecard").innerHTML = "";
  storeDrawn = "";
  tick();
}

// navigator.clipboard exists only in a secure context (HTTPS or localhost), and
// the daemon is reached as http://<LAN or Tailscale IP>:8088 — so there it is
// undefined and the button silently did nothing. Fall back to execCommand on a
// hidden textarea, which still works over plain HTTP, and say what happened.
function copyText(v, btn) {
  const said = ok => {
    btn.textContent = ok ? "copied" : "select & Ctrl+C";
    setTimeout(() => { btn.textContent = "copy"; }, 1500);
  };
  const fallback = () => {
    const t = document.createElement("textarea");
    t.value = v; t.setAttribute("readonly", "");
    t.style.position = "fixed"; t.style.opacity = "0";
    document.body.appendChild(t); t.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(t);
    said(ok);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(v).then(() => said(true), fallback);
  } else {
    fallback();
  }
}

function renderDone(d) {
  if (!d) { $("donecard").hidden = true; return; }
  $("donecard").hidden = false;
  if ($("donecard").dataset.done === "1") return;
  $("donecard").dataset.done = "1";
  const dl = document.createElement("dl"); dl.className = "sum";
  (d.fields || []).forEach(([k, v, big]) => {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v; if (big) dd.className = "big";
    const c = document.createElement("button"); c.className = "copy"; c.textContent = "copy";
    c.onclick = () => copyText(v, c);
    dd.appendChild(c);
    dl.appendChild(dt); dl.appendChild(dd);
  });
  const h = document.createElement("p"); h.className = "label"; h.textContent = d.title || "Done";
  $("donecard").appendChild(h); $("donecard").appendChild(dl);
  if (d.note) { const n = document.createElement("div"); n.className = "banner done"; n.textContent = d.note; $("donecard").appendChild(n); }
}

async function tick() {
  try {
    const r = await api("/api/state");
    if (r.status === 401) { reauth(); return; }
    if (!r.ok) { $("phase").textContent = r.status === 403 ? "not authorised" : "error " + r.status; return; }
    const s = await r.json();
    $("phase").textContent = s.phase || "";
    if (s.log !== lastLog) {
      lastLog = s.log;
      const el = $("log");
      const stick = el.scrollTop + el.clientHeight >= el.scrollHeight - 40;
      el.textContent = s.log;
      if (stick) el.scrollTop = el.scrollHeight;
    }
    renderPrompt(s.prompt);
    renderDone(s.done);
    // Daemon mode has a third state the one-shot server never has: idle, with
    // nothing running and nothing to show yet.
    const idle = s.daemon && !s.running && !s.prompt;
    $("startcard").hidden = !idle;
    if (idle) renderStore(s.catalog || [], !!(s.done || s.finished));
    $("idlecard").hidden = !!(s.prompt || s.done || idle);
    if (s.finished && !s.done) {
      $("idletext").textContent = s.exit && s.exit !== "0"
        ? "The run stopped with exit code " + s.exit + " \u2014 see the log."
        : "The run has finished.";
    }
  } catch (e) { $("phase").textContent = "disconnected"; }
}
tick(); setInterval(tick, 700);
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "cea-edge-wizard"

    def log_message(self, *a):
        pass  # keep the script's terminal output clean

    # ---- auth ----
    def _cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def _base_url(self):
        """Where the browser thinks it is, so the redirect_uri matches.

        Taken from the Host header, but only if that host was registered at
        startup — Keycloak would reject an unregistered redirect_uri anyway,
        and this refuses it one step earlier.
        """
        host = self.headers.get("Host", "")
        scheme = STATE["hosts"].get(host)
        if scheme is None:
            return None
        return "%s://%s" % (scheme, host)

    def _auth(self):
        if STATE["auth"] == "token":
            q = parse_qs(urlparse(self.path).query)
            if (q.get("t") or [""])[0] != STATE["token"]:
                self._send(403, "text/plain", b"forbidden: bad or missing token\n")
                return False
            return True

        # keycloak. The URL token no longer admits anyone here, but it still
        # marks the sign-in that may BIND an unbound run (--token-channel stdio):
        # only the terminal printed it, so whoever merely reaches the port first
        # cannot become the run's identity.
        t = (parse_qs(urlparse(self.path).query).get("t") or [""])[0]
        bind = bool(t) and bool(STATE["token"]) and secrets.compare_digest(t, STATE["token"])
        sess = get_session(self._cookie(COOKIE))
        if sess:
            self.session = sess
            if bind:
                offer_run(sess.get("tok"), may_bind=True)
            return True

        path = posixpath.normpath(urlparse(self.path).path)
        if path.startswith("/api/"):
            # Don't bounce XHR through a login redirect; the page handles 401
            # by reloading, which then gets the interactive redirect.
            self._send(401, "application/json", b'{"error":"login required"}')
            return False

        base = self._base_url()
        if base is None:
            self._send(400, "text/plain",
                       b"this address is not a registered redirect target for the wizard\n")
            return False

        state = secrets.token_urlsafe(24)
        redirect_uri = base + "/oauth2/callback"
        with STATE["lock"]:
            STATE["pending"][state] = {"exp": time.time() + 600, "redirect_uri": redirect_uri,
                                       "bind": bind}
        url = STATE["oidc"]["authorization_endpoint"] + "?" + urlencode({
            "client_id": STATE["client_id"],
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": redirect_uri,
            "state": state,
        })
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        return False

    def _do_callback(self):
        q = parse_qs(urlparse(self.path).query)
        code = (q.get("code") or [""])[0]
        state = (q.get("state") or [""])[0]
        err = (q.get("error") or [""])[0]
        if err:
            return self._send(400, "text/plain",
                              ("keycloak refused the login: %s\n" % err).encode())
        with STATE["lock"]:
            pend = STATE["pending"].pop(state, None)
        if not pend or pend["exp"] < time.time():
            # Single-use and time-limited: a replayed or stale callback is not a login.
            return self._send(400, "text/plain", b"stale or unknown login attempt; retry\n")

        try:
            tok = _http_json(STATE["oidc"]["token_endpoint"], data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": pend["redirect_uri"],
                "client_id": STATE["client_id"],
                "client_secret": STATE["client_secret"],
            }, headers={"Content-Type": "application/x-www-form-urlencoded"})
        except (urllib.error.URLError, OSError, ValueError) as e:
            return self._send(502, "text/plain",
                              ("could not exchange the code with keycloak: %s\n" % e).encode())

        claims = _claims_from_id_token(tok.get("id_token", ""))
        if not claims:
            return self._send(502, "text/plain", b"keycloak returned no usable id_token\n")

        # Roles from the ACCESS token: Keycloak puts realm_access there only, so
        # reading it off the ID token refused everyone once a role was required.
        access = edge_auth.claims(tok.get("access_token", ""))
        lack = edge_auth.check_access_claims(access, azp=STATE["client_id"])
        if lack:
            return self._send(502, "text/plain",
                              ("%s tokens lack %s — run ./deploy-infra.sh\n"
                               % (STATE["client_id"], lack)).encode())
        need = STATE["required_role"]
        if need and not edge_auth.has_role(access, need):
            who = claims.get("preferred_username", "?")
            return self._send(403, "text/plain",
                              ("%s is signed in but does not have %s, which is "
                               "required to provision hardware. Ask an administrator to "
                               "change your role in the User Manager, then reload.\n"
                               % (who, edge_auth.roles_text(need))).encode())

        tokset = edge_auth.TokenSet.from_response(tok, time.time())
        sid = new_session(claims, tok.get("id_token", ""), tokset)
        # A run waiting for its first sign-in (--token-channel stdio, and only
        # from the terminal's link) or for its owner to sign in again takes
        # these tokens. Anyone else just gets a browser session.
        offer_run(tokset, may_bind=bool(pend.get("bind")))
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie",
                         "%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                         % (COOKIE, sid, SESSION_TTL))
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _do_logout(self):
        """End the local session AND the Keycloak one.

        Dropping only the local cookie would look like signing out while leaving
        the SSO session alive — the next visit would be signed straight back in
        without credentials, which is the opposite of what the button promises.
        """
        sid = self._cookie(COOKIE)
        with STATE["lock"]:
            sess = STATE["sessions"].pop(sid, None) or {}
        if sess.get("tok") is not None:
            sess["tok"].wipe()
        # The Keycloak logout below invalidates the run's refresh token anyway;
        # this stops the run's cached access token from being served meanwhile.
        ra = STATE["run_auth"]
        if ra is not None and sess.get("sub"):
            ra.end_session(sess["sub"])
        dest = "/"
        end = (STATE["oidc"] or {}).get("end_session_endpoint")
        if end:
            # id_token_hint is how Keycloak identifies the session to end. No
            # post_logout_redirect_uri: it must be pre-registered, and Keycloak's
            # own confirmation page is a clearer end state than a silent bounce.
            hint = sess.get("id_token")
            dest = end + ("?" + urlencode({"id_token_hint": hint})) if hint else end
        self.send_response(302)
        self.send_header("Location", dest)
        self.send_header("Set-Cookie", "%s=; Path=/; HttpOnly; Max-Age=0" % COOKIE)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # This page shows a WebREPL password; keep it out of referrers and frames.
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_GET(self):
        path = posixpath.normpath(urlparse(self.path).path)
        if STATE["auth"] == "keycloak":
            if path == "/oauth2/callback":
                return self._do_callback()
            if path == "/logout":
                return self._do_logout()
        if not self._auth():
            return
        if path == "/":
            who = ""
            if STATE["auth"] == "keycloak":
                sess = getattr(self, "session", None) or {}
                who = "%s &middot; <a href=\"/logout\">sign out</a>" % html.escape(
                    sess.get("user", "?"))
            page = (PAGE.replace("__ONBOARD__", html.escape(STATE["onboard_url"], quote=True))
                        .replace("__WHO__", who)
                        .replace("__CHANNELMAP_CSS__", ui_asset("channelmap.css"))
                        .replace("__CHANNELMAP_JS__", ui_asset("channelmap.js")))
            return self._send(200, "text/html; charset=utf-8", page.encode())
        if path == "/api/state":
            prompt = None
            raw = read("prompt.json")
            if raw.strip():
                try:
                    prompt = json.loads(raw)
                except ValueError:
                    prompt = None
            done = None
            raw = read("done.json")
            if raw.strip():
                try:
                    done = json.loads(raw)
                except ValueError:
                    done = None
            body = json.dumps({
                "phase": read("phase").strip(),
                "log": read("log"),
                "prompt": prompt,
                "done": done,
                "finished": os.path.exists(spool("finished")),
                "daemon": STATE["daemon"],
                "catalog": catalog_public() if STATE["daemon"] else [],
                "running": run_active(),
                "exit": read("finished").strip() or None,
            }).encode()
            return self._send(200, "application/json", body)
        self._send(404, "text/plain", b"not found\n")

    def do_POST(self):
        path = posixpath.normpath(urlparse(self.path).path)
        if not self._auth():
            return
        if path == "/api/start":
            if not STATE["daemon"]:
                return self._send(404, "text/plain", b"not a daemon\n")
            try:
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n).decode()) if n else {}
            except (ValueError, OSError):
                body = {}
            status, err = start_run(getattr(self, "session", None), body.get("device"))
            if status != 200:
                return self._send(status, "application/json",
                                  json.dumps({"error": err}).encode())
            return self._send(200, "application/json", b'{"ok":true}')
        if path != "/api/answer":
            return self._send(404, "text/plain", b"not found\n")
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        if n <= 0 or n > 65536:
            return self._send(400, "text/plain", b"bad length\n")
        try:
            payload = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
        except ValueError:
            return self._send(400, "text/plain", b"bad json\n")

        # Only answer the prompt currently on offer. A stale tab posting an old
        # answer must not satisfy a different question.
        cur = read("prompt.json")
        try:
            cur_id = json.loads(cur).get("id") if cur.strip() else None
        except ValueError:
            cur_id = None
        if cur_id is None or payload.get("id") != cur_id:
            return self._send(409, "text/plain", b"stale prompt\n")
        # Every answer is acted on with the run owner's token and recorded under
        # their name, so nobody else may give one. Others still see the run.
        owner = STATE["run_owner"]
        if STATE["auth"] == "keycloak" and owner and \
                (getattr(self, "session", None) or {}).get("sub") != owner["sub"]:
            return self._send(403, "application/json", json.dumps({
                "error": "this run belongs to %s — only they can answer its questions"
                         % owner["user"]}).encode())

        value = str(payload.get("value", ""))
        tmp = spool("answer.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(value)
        os.replace(tmp, spool("answer"))       # atomic: the shell polls for this
        try:
            os.unlink(spool("prompt.json"))
        except OSError:
            pass
        self._send(200, "application/json", b'{"ok":true}')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True, help="spool directory shared with the shell script")
    ap.add_argument("--token", required=True)
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--onboard-url", default="#")
    ap.add_argument("--parent-pid", type=int, default=0,
                    help="exit if this pid goes away (survives SIGKILL of the shell)")
    ap.add_argument("--auth", choices=("token", "keycloak"), default="token")
    ap.add_argument("--issuer", default="", help="e.g. http://keycloak.<domain>/realms/medcea")
    ap.add_argument("--client-id", default="edge-wizard")
    ap.add_argument("--client-secret", default="",
                    help="deprecated: visible in ps; pass EDGE_WIZARD_SECRET in the environment")
    ap.add_argument("--required-role", default="",
                    help="roles that may provision hardware, comma-separated; any one "
                         "admits (edge/wizard-daemon.sh passes the access policy's list)")
    ap.add_argument("--allowed-host", action="append", default=[],
                    help="host:port the browser may reach this on directly, or "
                         "https://host when it comes through a TLS proxy; repeatable")
    ap.add_argument("--daemon", action="store_true",
                    help="stay up and start flash runs on demand instead of mirroring one")
    ap.add_argument("--repo-root", default="",
                    help="MedCEA checkout containing edge/flash-device.sh")
    ap.add_argument("--catalog", default="",
                    help="device type catalogue (default: <repo>/edge/catalog.json)")
    ap.add_argument("--flash-arg", action="append", default=[],
                    help="extra argument passed to each flash-device.sh run; repeatable")
    ap.add_argument("--oidc-insecure", action="store_true",
                    help="skip TLS verification to Keycloak (self-signed ingress cert)")
    ap.add_argument("--token-channel", choices=("none", "stdio"), default="none",
                    help="stdio: hold one run's tokens and answer its token requests on "
                         "stdin/stdout (flash-device.sh --ui runs this as a coproc)")
    a = ap.parse_args()

    # The secret comes from the environment and is popped, so no child (the
    # flash runs) inherits it; argv is readable by every account on the host.
    secret = os.environ.pop("EDGE_WIZARD_SECRET", "")
    if a.client_secret:
        print("deprecated: --client-secret is visible in ps; pass EDGE_WIZARD_SECRET in the "
              "environment", file=sys.stderr)
        secret = secret or a.client_secret
    # stdout is the token channel under stdio: nothing else may ever write to it.
    proto_out = None
    if a.token_channel == "stdio":
        proto_out = os.dup(1)
        os.dup2(2, 1)
        sys.stdout = sys.stderr

    STATE["dir"] = a.dir
    STATE["token"] = a.token
    STATE["onboard_url"] = a.onboard_url
    STATE["auth"] = a.auth
    STATE["client_id"] = a.client_id
    STATE["client_secret"] = secret
    STATE["required_role"] = edge_auth.roles_of(a.required_role)
    # "host:port" is reached directly over http; "https://host" through the
    # TLS ingress (apps/edge-wizard), which keeps the Host header.
    STATE["hosts"] = {}
    for h in a.allowed_host:
        if h.startswith("https://"):
            STATE["hosts"][h[len("https://"):].rstrip("/")] = "https"
        else:
            STATE["hosts"][h] = "http"
    STATE["daemon"] = a.daemon
    STATE["repo_root"] = a.repo_root or os.getcwd()
    STATE["flash_args"] = a.flash_arg
    if a.daemon:
        cat = a.catalog or os.path.join(STATE["repo_root"], "edge", "catalog.json")
        try:
            STATE["catalog"] = load_catalog(cat, STATE["repo_root"])
        except (OSError, ValueError) as e:
            print("cannot read the device catalogue %s: %s" % (cat, e), file=sys.stderr)
            return 4
        avail = [e["id"] for e in STATE["catalog"] if e["status"] == "available"]
        if not avail:
            print("no device type in %s is available — nothing could be onboarded" % cat,
                  file=sys.stderr)
            return 5
        print("catalogue: %d device types, %d available (%s)"
              % (len(STATE["catalog"]), len(avail), ", ".join(avail)), file=sys.stderr)

    if a.auth == "keycloak":
        if not a.issuer or not secret:
            print("--auth keycloak needs --issuer and EDGE_WIZARD_SECRET in the environment",
                  file=sys.stderr)
            return 2
        ctx = None
        if a.oidc_insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            STATE["oidc"] = oidc_discover(a.issuer, ctx)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print("cannot reach Keycloak at %s: %s" % (a.issuer, e), file=sys.stderr)
            return 3

    try:
        srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    except OSError as e:
        print("wizard server could not bind %s:%d — %s" % (a.bind, a.port, e), file=sys.stderr)
        return 1
    srv.daemon_threads = True
    with open(os.path.join(a.dir, "server.port"), "w") as f:
        f.write(str(srv.server_address[1]))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    # One run, its own holder: the first browser sign-in binds it. EOF here
    # means the script closed its end (after register, or on exit): the tokens
    # are wiped, and the server stays up for the summary until `stop`.
    if proto_out is not None:
        if a.auth != "keycloak":
            os.close(proto_out)
        else:
            holder = edge_auth.Holder(STATE["oidc"], STATE["ssl_ctx"], STATE["client_id"],
                                      secret, STATE["required_role"], waiter=BrowserWaiter())
            STATE["run_auth"] = holder
            def channel():
                try:
                    edge_auth.serve(0, proto_out, holder)
                finally:
                    # Close both ends, so a holder that stopped while the script
                    # still runs is an EOF there, not a request nobody reads.
                    for fd in (0, proto_out):
                        try:
                            os.close(fd)
                        except OSError:
                            pass
            threading.Thread(target=channel, daemon=True, name="token-channel").start()
    # Exit when the shell says stop, removes the spool directory, or dies. The
    # parent check is what covers SIGKILL, where the shell's trap never runs and
    # nothing else would ever shut this down.
    def parent_gone():
        if not a.parent_pid:
            return False
        try:
            os.kill(a.parent_pid, 0)
            return False
        except ProcessLookupError:
            return True
        except PermissionError:
            return False

    try:
        while not os.path.exists(os.path.join(a.dir, "stop")):
            # In daemon mode the spool is ours and there is no parent shell, so
            # neither of those conditions applies.
            if not a.daemon and (not os.path.isdir(a.dir) or parent_gone()):
                break
            t.join(0.5)
    except KeyboardInterrupt:
        pass
    if run_active():
        STATE["run"].terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
