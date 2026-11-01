#!/usr/bin/env python3
"""tests/test_workbench_render.py — the AI workbench's gate as deploy-workbench.sh renders it
(IAM 3.2), offline: no cluster, no lock, no config.env.

policy_workbench (infra/lib-oauth2-proxy.sh) is run in bash, then k8s/workbench/values.yaml
is filled with lib-render.sh's `render` exactly as the deploy does, and the result parsed:
  IAM_GATES=true   allow_all false, allowed_groups and the hub role workbench-admin's
                   groups the two lists `cli.py compile jupyterhub` prints, its users [],
                   delete_pvc false, the 403 text
  IAM_GATES=false  allow_all true, workbench-admin held by ADMIN_USER alone
Either way nobody holds JupyterHub's built-in admin role (Authenticator.admin_users [],
no admin_groups, hub.loadRoles.admin.users []) and workbench-admin's scopes are exactly
the decided ones (WORKBENCH_ADMIN_ROLE_SCOPES): no tokens, access:servers, shares,
admin:users, groups or admin:auth_state. The roles are in hub.loadRoles, never in
hub.config.JupyterHub.load_roles (which would drop the chart's idle-culler role).
Either way no ${VAR} is left but the home setup script's own shell variables, which must
reach the pod.
A cli.py that fails, or prints [], makes policy_workbench return 1 (the deploy dies
before helm and the running hub stays as it is).
IAM 3.2b: policy_workbench_egress renders singleuser.networkPolicy.egress — exactly
`cli.py compile egress notebooks` (Keycloak and config-api) while IAM_POSTGREST_JWT and
IAM_DB_ROLES are both true, [] otherwise — with private addresses still closed; the pod
gets endpoints only (no secret) and the examples read-only in the home.
The home setup (1 Nov 2026) is singleuser.extraFiles medcea-home-setup, an executable in
docker-stacks' before-notebook.d, so it runs BEFORE the server starts (a postStart ran
concurrently, and a new home's server started without the collaboration extension); the
hub's http_timeout covers its bounded installs. Run under sh with stub python3/pip/git/curl
it installs jupyter-collaboration, jupyter-vscode-proxy and code-server once (a second run
calls neither pip nor curl), makes nbstripout the global git filter idempotently, fails
closed when pip and curl fail (attribute, clean command, `required` and the pre-commit
output guard still written; nb_output_guard.py is tried against a real git repository),
always exits 0, sets git's user.name to the person only while unset and shows the person in
the prompt (~/.bashrc from /etc/skel when missing, the block appended once, a person's own
lines kept). workbench_egress_close (the database and frontend deploys, on a switch to
false) removes exactly the compiled hops from the live NetworkPolicy.

  python3 tests/test_workbench_render.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(REPO, "infra", "deploy-workbench.sh")
VARS = ["WORKBENCH_ALLOW_ALL", "WORKBENCH_HUBADMIN_USERS", "WORKBENCH_ALLOWED_GROUPS",
        "WORKBENCH_ADMIN_GROUPS", "WORKBENCH_403_MESSAGE"]
# The decided abilities of the hub administrator (decision record, compliance chapter).
ADMIN_SCOPES = ["admin-ui", "delete:users", "list:users", "read:users", "servers"]
# The home setup script's own shell variables: none is on the render list, so render keeps them.
SCRIPT_VARS = {"$HOME", "$ATTRS", "$HOOKS", "$JUPYTERHUB_USER", "$inst", "$ilog", "$secs"}
SETUP_DIR = "/usr/local/bin/before-notebook.d/"
NEVER = {"tokens", "read:tokens", "access:servers", "shares", "users:shares", "admin:users",
         "groups", "admin:groups", "admin:auth_state", "admin:servers", "admin:server_state"}


def render_list():
    """The variables deploy-workbench.sh hands to render for values.yaml."""
    with open(DEPLOY) as f:
        src = f.read()
    call = re.search(r'render "\$REPO_ROOT/k8s/workbench/values.yaml"(.*?)>', src, re.S).group(1)
    return call.replace("\\", " ").split()


def logout_assignment():
    """deploy-workbench.sh's own WORKBENCH_LOGOUT_URL line, run as it is by run() below, so
    removing or renaming it there fails the render tests (review of 1 Nov 2026: an unset
    variable renders logout_redirect_url: "" and Sign out stops at the hub)."""
    with open(DEPLOY) as f:
        lines = f.read().splitlines()
    found = [i for i, l in enumerate(lines) if re.match(r'WORKBENCH_LOGOUT_URL=', l)]
    render_at = [i for i, l in enumerate(lines) if l.startswith('render "$REPO_ROOT/k8s/workbench/values.yaml"')]
    assert len(found) == 1 and len(render_at) == 1 and found[0] < render_at[0], (found, render_at)
    return lines[found[0]]


def run(gates, repo_root=REPO, jwt="false", db_roles="false"):
    """(exit code, rendered values or stderr) of policy_workbench(_egress) + render."""
    env = dict(os.environ, IAM_GATES=gates, ADMIN_USER="boss", PORTAL_DOMAIN="portal.test",
               WORKBENCH_SECRET="s3cret", WORKBENCH_DOMAIN="ai-workbench.test", KEYCLOAK_DOMAIN="kc.test",
               KEYCLOAK_REALM="medcea", NAMESPACE="medcea", WORKBENCH_IMAGE_NAME="img",
               WORKBENCH_IMAGE_TAG="1", WORKBENCH_STORAGE="10Gi", WORKBENCH_NOTEBOOK_REPO="smvieira/medcea-notebooks",
               IAM_POSTGREST_JWT=jwt, IAM_DB_ROLES=db_roles, RR=repo_root, LIBS=REPO)
    script = ('source "$LIBS/infra/lib-render.sh"; REPO_ROOT="$RR" source "$LIBS/infra/lib-oauth2-proxy.sh"; '
              'REPO_ROOT="$RR" policy_workbench || exit 1; REPO_ROOT="$RR" policy_workbench_egress || exit 1; '
              'die() { echo "$*" >&2; exit 1; }; ' + logout_assignment() + '; '
              f'render "$LIBS/k8s/workbench/values.yaml" {" ".join(render_list())}')
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    return r.returncode, r.stdout if r.returncode == 0 else r.stderr


def lib_constant(name):
    """A JSON constant of infra/lib-oauth2-proxy.sh, as bash sees it."""
    r = subprocess.run(["bash", "-c", f'REPO_ROOT="{REPO}"; source "{REPO}/infra/lib-oauth2-proxy.sh"; printf %s "${name}"'],
                       capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def compiled(setting):
    out = subprocess.run([sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"),
                          "compile", "jupyterhub", "--setting", setting], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def compiled_egress():
    out = subprocess.run([sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"),
                          "compile", "egress", "notebooks"], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


class RenderTest(unittest.TestCase):
    def check_common(self, text):
        v = yaml.safe_load(text)
        hub = v["hub"]["config"]
        # admin_access is deprecated since JupyterHub 2.0 and does nothing; if present it
        # stays false so no reader takes it for on. The roles below are what decides.
        self.assertIs(hub["JupyterHub"].get("admin_access", False), False)
        self.assertNotIn("load_roles", hub["JupyterHub"], "load_roles would replace the chart's idle-culler role")
        self.assertEqual(hub["Authenticator"]["admin_users"], [])
        self.assertNotIn("admin_groups", hub["GenericOAuthenticator"], "admin_groups gives the built-in admin role")
        roles = v["hub"]["loadRoles"]
        self.assertEqual(set(roles), {"workbench-admin", "admin"})
        self.assertEqual(roles["admin"], {"users": []}, "the built-in admin role: scopes untouched, nobody holds it")
        wa = roles["workbench-admin"]
        self.assertEqual(sorted(wa["scopes"]), ADMIN_SCOPES)
        self.assertEqual(sorted(wa["scopes"]), lib_constant("WORKBENCH_ADMIN_ROLE_SCOPES"))
        self.assertFalse({x.split("!")[0] for x in wa["scopes"]} & NEVER)
        self.assertLessEqual(set(lib_constant("WORKBENCH_ADMIN_ROLE_FORBIDDEN")), NEVER)
        self.assertEqual(set(wa) - {"description", "scopes", "groups", "users"}, set())
        # Short sessions (decision of 1 Nov 2026): the hub's sign-in and an open lab tab's
        # token last 5 minutes, then follow whoever is signed in to Keycloak now.
        self.assertEqual(hub["JupyterHub"]["oauth_token_expires_in"], 300)
        self.assertAlmostEqual(hub["JupyterHub"]["cookie_max_age_days"] * 86400, 300, delta=1)
        self.assertNotIn("shutdown_on_logout", hub["JupyterHub"])   # default false: logout never stops servers
        self.assertIs(hub["Authenticator"]["auto_login"], True)
        # One-hop sign-out: /hub/logout goes to Keycloak's end-session for client workbench
        # and back to the portal's proxy sign-out. Fixed, no token, nothing from a request.
        out = hub["GenericOAuthenticator"]["logout_redirect_url"]
        u = urllib.parse.urlsplit(out)
        self.assertEqual((u.scheme, u.netloc, u.path),
                         ("https", "kc.test", "/realms/medcea/protocol/openid-connect/logout"))
        q = urllib.parse.parse_qs(u.query, strict_parsing=True)
        self.assertEqual(q, {"client_id": ["workbench"],
                             "post_logout_redirect_uri": ["https://portal.test/oauth2/sign_out?rd=%2F"]})
        self.assertNotRegex(out.lower(), r"id_token|access_token|token=|\{")
        self.assertEqual(logout_assignment(),
                         'WORKBENCH_LOGOUT_URL="$(workbench_logout_url)" || die "could not build the workbench\'s '
                         'logout URL (python3 missing?)"')
        self.assertIs(hub["KubeSpawner"]["delete_pvc"], False)
        self.assertIs(hub["Authenticator"]["allow_existing_users"], False)
        self.assertIs(hub["Authenticator"]["enable_auth_state"], False)
        self.assertEqual(hub["GenericOAuthenticator"]["auth_state_groups_key"], "oauth_user.groups")
        # OAuthenticator 17 refuses to start (ValueError) with group keys but no
        # manage_groups: the hub crash-looped on 2026-10-31 without it.
        self.assertIs(hub["GenericOAuthenticator"]["manage_groups"], True)
        self.assertEqual(hub["GenericOAuthenticator"]["client_secret"], "s3cret")
        left = set(re.findall(r"\$\{?[A-Za-z_]+", text))
        self.assertEqual(left, SCRIPT_VARS, "an unrendered variable, or the home setup's shell variables were eaten")
        return hub

    def test_gated(self):
        rc, out = run("true")
        self.assertEqual(rc, 0, out)
        hub = self.check_common(out)
        self.assertIs(hub["Authenticator"]["allow_all"], False)
        g = hub["GenericOAuthenticator"]
        self.assertEqual(g["allowed_groups"], compiled("allowed_groups"))
        wa = yaml.safe_load(out)["hub"]["loadRoles"]["workbench-admin"]
        self.assertEqual(wa["groups"], compiled("admin_groups"))
        self.assertEqual(wa["groups"], ["admin"])
        self.assertEqual(wa["users"], [])
        msg = g["custom_403_message"]
        self.assertTrue(msg.startswith("No access to AI Workbench. It is open to: "), msg)
        self.assertIn("System Administrator", msg)
        self.assertNotIn("&amp;", msg)       # Jinja escapes it once, on the page
        self.assertIn("https://portal.test/", msg)

    def test_pre_policy(self):
        rc, out = run("false")
        self.assertEqual(rc, 0, out)
        hub = self.check_common(out)
        self.assertIs(hub["Authenticator"]["allow_all"], True)
        self.assertEqual(hub["GenericOAuthenticator"]["allowed_groups"], [])
        wa = yaml.safe_load(out)["hub"]["loadRoles"]["workbench-admin"]
        self.assertEqual(wa["groups"], [])
        self.assertEqual(wa["users"], ["boss"], "IAM_GATES=false: ADMIN_USER holds workbench-admin, not the built-in admin")

    def singleuser(self, **kw):
        rc, out = run("true", **kw)
        self.assertEqual(rc, 0, out)
        self.check_common(out)
        return yaml.safe_load(out)["singleuser"]

    def test_notebook_egress_follows_the_switches(self):
        want = compiled_egress()
        self.assertEqual([r["to"][0]["podSelector"]["matchLabels"] for r in want], [{"app": "config-api"}, {"app": "keycloak"}])
        self.assertEqual([r["ports"] for r in want], [[{"port": 3000, "protocol": "TCP"}], [{"port": 8080, "protocol": "TCP"}]])
        for jwt, dbr, expect in (("true", "true", want), ("true", "false", []), ("false", "true", []), ("false", "false", [])):
            with self.subTest(jwt=jwt, db_roles=dbr):
                np = self.singleuser(jwt=jwt, db_roles=dbr)["networkPolicy"]
                self.assertIs(np["enabled"], True)
                self.assertEqual(np["egress"], expect)
                self.assertIs(np["egressAllowRules"]["privateIPs"], False)
                self.assertIs(np["egressAllowRules"]["cloudMetadataServer"], False)

    def test_egress_fails_closed(self):
        for body in ("import sys; sys.exit(1)\n", "print('nonsense')\n"):
            with self.subTest(body):
                rc, _ = run("true", self.stub_with_jupyterhub(body), jwt="true", db_roles="true")
                self.assertEqual(rc, 1)

    def stub_with_jupyterhub(self, egress_body):
        """A cli.py that compiles jupyterhub like the real one but answers `egress` with egress_body."""
        return self.stub(
            "import subprocess, sys\n"
            f"real = {os.path.join(REPO, 'apps', 'iam', 'compiler', 'cli.py')!r}\n"
            "if sys.argv[1:3] == ['compile', 'egress']:\n"
            + "".join("    " + line + "\n" for line in egress_body.splitlines()) +
            "    sys.exit(0)\n"
            "sys.exit(subprocess.run([sys.executable, real] + sys.argv[1:]).returncode)\n")

    def test_endpoints_examples_and_hook(self):
        su = self.singleuser(jwt="true", db_roles="true")
        env = su["extraEnv"]
        self.assertEqual(env["MEDCEA_KEYCLOAK"], "http://keycloak.medcea.svc.cluster.local/realms/medcea")
        self.assertEqual(env["MEDCEA_API"], "http://config-api.medcea.svc.cluster.local:3000")
        self.assertEqual(env["MEDCEA_CLIENT_ID"], "workbench-notebook")
        self.assertEqual(env["MEDCEA_NOTEBOOK_REPO"], "smvieira/medcea-notebooks")
        self.assertEqual(env["PYTHONPATH"], "/home/jovyan/medcea-examples")
        self.assertFalse([k for k in env if re.search(r"SECRET|PASS|TOKEN", k)], "no credential in a notebook pod")
        self.assertNotIn("s3cret", json.dumps(su), "the hub's client secret must not reach the notebooks")
        st = su["storage"]
        self.assertEqual(st["extraVolumes"], [{"name": "medcea-examples", "configMap": {"name": "workbench-examples"}}])
        self.assertEqual(st["extraVolumeMounts"], [{"name": "medcea-examples", "mountPath": "/home/jovyan/medcea-examples",
                                                    "readOnly": True}])
        self.assertNotIn("lifecycleHooks", su, "a postStart runs at the same time as the server: the setup is a before-notebook script")
        cmd = self.setup_script(su)
        self.assertIn("python3 -m nbstripout --is-installed --global ||", cmd)
        self.assertIn("python3 -m nbstripout --install --global", cmd)
        self.assertIn("git config --global filter.nbstripout.required true", cmd)
        self.assertNotIn("nbstripout) &&", cmd, "a failed pip install must not skip the filter's setup")
        self.assertIn("/home/jovyan/medcea-examples/nb_output_guard.py", cmd)

    @staticmethod
    def setup_script(su=None):
        """The before-notebook script medcea-home-setup, as rendered."""
        if su is None:
            su = yaml.safe_load(run("true")[1])["singleuser"]
        return su["extraFiles"]["medcea-home-setup"]["stringData"]

    def test_setup_runs_before_the_server(self):
        """The setup is an executable in before-notebook.d (start.sh runs it, then execs the
        server), not a postStart; the hub waits long enough for its bounded installs."""
        rc, out = run("true")
        self.assertEqual(rc, 0, out)
        v = yaml.safe_load(out)
        su = v["singleuser"]
        self.assertNotIn("lifecycleHooks", su)
        self.assertEqual(set(su["extraFiles"]), {"medcea-home-setup"})
        f = su["extraFiles"]["medcea-home-setup"]
        self.assertTrue(f["mountPath"].startswith(SETUP_DIR), f["mountPath"])
        self.assertNotIn("/", f["mountPath"][len(SETUP_DIR):])
        self.assertFalse(f["mountPath"].endswith(".sh"), "a .sh hook is sourced into start.sh, whose `set -e` and `exit` it would share")
        self.assertEqual(f["mode"], 0o755)
        self.assertEqual(set(f) - {"mountPath", "mode", "stringData"}, set())
        script = f["stringData"]
        self.assertTrue(script.startswith("#!/bin/sh\n"))
        self.assertNotIn("${", script, "the script goes through render")
        self.assertEqual(subprocess.run(["sh", "-n", "-c", script]).returncode, 0)
        if shutil.which("busybox"):
            self.assertEqual(subprocess.run(["busybox", "sh", "-n", "-c", script]).returncode, 0)
        lines = [l.strip() for l in script.splitlines() if l.strip() and not l.strip().startswith("#")]
        self.assertEqual(lines[-1], "exit 0", "a failed setup must never stop the server")
        self.assertNotIn("set -e", script)
        # Every install is bounded, and the hub's wait for the server covers them all.
        code = "\n".join(l for l in script.splitlines() if not l.strip().startswith("#"))
        installs = re.findall(r"\b(pip install|curl|sh \"\$inst\")", code)
        self.assertEqual(len(installs), 4)
        self.assertEqual(len(re.findall(r"limited \d+ (?:pip install|curl|sh \"\$inst\")", code)), len(installs),
                         "an unbounded install could outrun the hub's http_timeout")
        total = sum(int(n) for n in re.findall(r"limited (\d+) ", script))
        self.assertGreaterEqual(v["hub"]["config"]["KubeSpawner"]["http_timeout"], total + 60)
        self.assertGreaterEqual(v["hub"]["config"]["KubeSpawner"]["http_timeout"], 660)
        self.assertGreaterEqual(su["startTimeout"], 600, "a first image pull of about 2 GB")

    def test_chart_pin(self):
        with open(DEPLOY) as f:
            src = f.read()
        self.assertEqual(re.findall(r'^CHART_VERSION="([^"]*)"', src, re.M), ["4.4.4"])

    def hook_home(self, pip_works=True, curl_works=True, code_server=False):
        """A scratch home with stub pip/python3/git/curl that record what the setup does."""
        home = tempfile.mkdtemp()
        bin_ = os.path.join(home, "bin")
        os.makedirs(os.path.join(home, ".local", "bin"))
        os.makedirs(bin_)
        if code_server:
            open(os.path.join(home, ".local", "bin", "code-server"), "w").close()
            os.chmod(os.path.join(home, ".local", "bin", "code-server"), 0o755)
        # A module is importable once pip "installed" it: $HOME/mod-<module>.
        # git config --global as files under $HOME/cfg/<key>: --get prints and fails when unset
        pip_body = ('for a in "$@"; do case "$a" in -*|install) ;; *) touch "$HOME/mod-$(echo "$a" | tr - _)" ;; esac; done'
                    if pip_works else "exit 1")
        # The installer curl "downloads" creates code-server under its --prefix.
        installer = ('for a; do case "$a" in --prefix=*) p="$(echo "$a" | cut -d= -f2)" ;; esac; done\n'
                     'mkdir -p "$p/bin" && printf "#!/bin/sh\\n" > "$p/bin/code-server" && chmod +x "$p/bin/code-server"\n')
        with open(os.path.join(home, "installer"), "w") as f:
            f.write(installer)
        curl_body = ('while [ "$1" != "-o" ]; do shift; done; cp "$HOME/installer" "$2"' if curl_works else "exit 22")
        stubs = {
            "pip": 'echo "pip $*" >> "$LOG"\n' + pip_body,
            "python3": ('mkdir -p "$HOME/cfg"\ncase "$*" in\n'
                        '  "-c import "*) for m in $(echo "$2" | sed "s/^import //; s/,/ /g"); do\n'
                        '        test -e "$HOME/mod-$m" || exit 1; done ;;\n'
                        '  *--is-installed*) test -e "$HOME/cfg/filter.nbstripout.clean" ;;\n'
                        '  *"--install --global"*) test -e "$HOME/mod-nbstripout" || exit 1\n'
                        '      echo "install $*" >> "$LOG"; echo "py -m nbstripout" > "$HOME/cfg/filter.nbstripout.clean" ;;\n'
                        '  *) exit 1 ;;\n'
                        'esac'),
            "git": ('mkdir -p "$HOME/cfg"\n'
                    '[ "$1 $2" = "config --global" ] || exit 0\n'
                    'shift 2; [ "$1" = "--path" ] && shift\n'
                    'if [ "$1" = "--get" ]; then test -e "$HOME/cfg/$2" && cat "$HOME/cfg/$2"; exit; fi\n'
                    'echo "set $1 $2" >> "$LOG"; printf %s "$2" > "$HOME/cfg/$1"'),
            "curl": 'echo "curl $*" >> "$LOG"\n' + curl_body,
        }
        for name, body in stubs.items():
            p = os.path.join(bin_, name)
            with open(p, "w") as f:
                f.write("#!/bin/sh\n" + body + "\n")
            os.chmod(p, 0o755)
        return home, {"HOME": home, "PATH": bin_ + ":/usr/bin:/bin", "LOG": os.path.join(home, "calls"),
                      "JUPYTERHUB_USER": "ana"}

    def run_setup(self, env):
        """The rendered script, run as start.sh runs it: an executable file of its own."""
        script = os.path.join(env["HOME"], "50-medcea-home-setup")
        with open(script, "w") as f:
            f.write(self.setup_script())
        os.chmod(script, 0o755)
        r = subprocess.run([script], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout

    def calls(self, env):
        if not os.path.exists(env["LOG"]):
            return []
        with open(env["LOG"]) as f:
            return f.read().splitlines()

    def test_setup_is_idempotent(self):
        """Run twice on an empty home: the extensions, code-server and nbstripout are installed
        once, the filter, attribute, hook, credential helper and author name set once,
        `required` kept true; the second run calls neither pip nor curl."""
        home, env = self.hook_home()
        out = self.run_setup(env)
        first = self.calls(env)
        self.assertIn("medcea-home-setup: installed jupyter-collaboration and jupyter-vscode-proxy", out)
        self.assertIn("medcea-home-setup: installed code-server into ~/.local", out)
        self.assertTrue(os.access(os.path.join(home, ".local", "bin", "code-server"), os.X_OK))
        self.assertTrue(all(l.startswith("medcea-home-setup: ") for l in out.splitlines()), out)
        out2 = self.run_setup(env)
        second = self.calls(env)[len(first):]
        attrs = os.path.join(home, ".config", "git", "attributes")
        hooks = os.path.join(home, ".config", "git", "hooks")
        self.assertEqual(first[0], "pip install --quiet --user jupyter-collaboration jupyter-vscode-proxy")
        self.assertTrue(first[1].startswith("curl -fsSL https://code-server.dev/install.sh -o "), first[1])
        self.assertEqual(first[2:], ["pip install --quiet --user nbstripout",
                                     "install -m nbstripout --install --global",
                                     "set filter.nbstripout.required true",
                                     "set core.attributesFile " + attrs,
                                     "set core.hooksPath " + hooks,
                                     "set credential.helper store",
                                     "set user.name ana"])
        self.assertEqual(second, ["set filter.nbstripout.required true"], "a second start installs nothing")
        self.assertNotIn("installed", out2)
        with open(attrs) as f:
            self.assertEqual(f.read(), "*.ipynb filter=nbstripout\n")
        with open(os.path.join(hooks, "pre-commit")) as f:
            self.assertIn("nb_output_guard.py", f.read())
        self.assertTrue(os.access(os.path.join(hooks, "pre-commit"), os.X_OK))

    def test_setup_skips_a_code_server_it_has(self):
        home, env = self.hook_home(code_server=True)
        self.run_setup(env)
        self.assertFalse([c for c in self.calls(env) if c.startswith("curl")])

    def test_setup_fails_closed(self):
        """pip and curl fail: the start still succeeds (exit 0), the filter is still required,
        with a clean command that then fails, the attribute and the pre-commit guard are
        written, and the failures are in the pod log."""
        home, env = self.hook_home(pip_works=False, curl_works=False)
        out = self.run_setup(env)
        cfg = lambda k: open(os.path.join(home, "cfg", k)).read()
        self.assertEqual(cfg("filter.nbstripout.required"), "true")
        self.assertEqual(cfg("filter.nbstripout.clean"), "python3 -m nbstripout")
        with open(os.path.join(home, ".config", "git", "attributes")) as f:
            self.assertEqual(f.read(), "*.ipynb filter=nbstripout\n")
        self.assertTrue(os.path.exists(os.path.join(home, ".config", "git", "hooks", "pre-commit")))
        self.assertFalse(os.path.exists(os.path.join(home, ".local", "bin", "code-server")))
        self.assertEqual(len([l for l in out.splitlines() if "WARNING" in l]), 3, out)
        self.assertIn("medcea-home-setup: done", out)

    def test_hook_keeps_a_chosen_hooks_path(self):
        home, env = self.hook_home(code_server=True)
        os.makedirs(os.path.join(home, "cfg"))
        with open(os.path.join(home, "cfg", "core.hooksPath"), "w") as f:
            f.write(os.path.join(home, "mine"))
        self.run_setup(env)
        self.assertFalse(os.path.exists(os.path.join(home, "mine")), "a person's own hooks folder is left alone")

    def test_setup_shows_the_person(self):
        """git's author name is the person's workbench name only while unset; the e-mail is
        left to the person (a hint in the log)."""
        home, env = self.hook_home(code_server=True)
        out = self.run_setup(env)
        with open(os.path.join(home, "cfg", "user.name")) as f:
            self.assertEqual(f.read(), "ana")
        self.assertFalse(os.path.exists(os.path.join(home, "cfg", "user.email")))
        self.assertIn("git has no user.email", out)
        home, env = self.hook_home(code_server=True)
        os.makedirs(os.path.join(home, "cfg"))
        for k, v in (("user.name", "Ana Silva"), ("user.email", "ana@example.org")):
            with open(os.path.join(home, "cfg", k), "w") as f:
                f.write(v)
        out = self.run_setup(env)
        self.assertNotIn("set user.name", "\n".join(self.calls(env)), "a name the person set is kept")
        self.assertNotIn("user.email", out)
        home, env = self.hook_home(code_server=True)
        env["JUPYTERHUB_USER"] = ""
        self.run_setup(env)
        self.assertNotIn("set user.name", "\n".join(self.calls(env)))

    @unittest.skipUnless(os.path.isfile("/etc/skel/.bashrc") and os.path.isfile("/etc/skel/.profile")
                         and shutil.which("bash"), "no /etc/skel start files or bash here")
    def test_setup_prompt(self):
        """A new home gets ~/.bashrc and ~/.profile from /etc/skel and the prompt block once;
        an existing ~/.bashrc keeps its own lines; bash then shows the person, not jovyan."""
        home, env = self.hook_home(code_server=True)
        self.run_setup(env)
        self.run_setup(env)
        with open("/etc/skel/.bashrc") as f:
            skel = f.read()
        with open(os.path.join(home, ".bashrc")) as f:
            rc = f.read()
        self.assertTrue(rc.startswith(skel))
        self.assertEqual(rc.count("# >>> medcea workbench prompt >>>"), 1)
        self.assertEqual(rc.count("# <<< medcea workbench prompt <<<"), 1)
        self.assertTrue(os.path.isfile(os.path.join(home, ".profile")))
        # An interactive bash reads ~/.bashrc itself (skel's returns at once otherwise).
        r = subprocess.run(["bash", "-i", "-c", 'printf %s "${PS1@P}"'], stdin=subprocess.DEVNULL, cwd=home,
                           env=dict(env, PATH="/usr/bin:/bin", TERM="xterm-256color", PS1="x"),
                           capture_output=True, text=True)
        self.assertTrue(r.stdout.endswith("ana@workbench:~$ "), r.stdout)
        self.assertIn("\x1b]0;ana@workbench: ~\x07", r.stdout, "the terminal title")
        self.assertNotIn("jovyan", r.stdout)
        # A person's own .bashrc (and login file) is kept; the block is appended after it.
        home, env = self.hook_home(code_server=True)
        with open(os.path.join(home, ".bashrc"), "w") as f:
            f.write("alias ll='ls -l'\nPS1='mine$ '\n")
        with open(os.path.join(home, ".bash_profile"), "w") as f:
            f.write(". ~/.bashrc\n")
        self.run_setup(env)
        with open(os.path.join(home, ".bashrc")) as f:
            rc = f.read()
        self.assertTrue(rc.startswith("alias ll='ls -l'\nPS1='mine$ '\n"))
        self.assertEqual(rc.count("# >>> medcea workbench prompt >>>"), 1)
        self.assertFalse(os.path.exists(os.path.join(home, ".profile")), "a home with its own login file gets no .profile")

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_output_guard(self):
        """nb_output_guard.py in a real repository: a staged notebook with an output is refused
        (whatever .gitattributes says), a stripped one passes, other files are not read."""
        guard = os.path.join(REPO, "k8s", "workbench", "examples", "nb_output_guard.py")
        d = tempfile.mkdtemp()
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        git = lambda *a: subprocess.run(["git", "-C", d] + list(a), env=env, capture_output=True, check=True)
        git("init", "-q")
        cell = {"cell_type": "code", "metadata": {}, "source": ["print(21.5)"], "outputs": [], "execution_count": None}
        nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": [cell]}
        with open(os.path.join(d, ".gitattributes"), "w") as f:
            f.write("*.ipynb -filter\n")
        with open(os.path.join(d, "clean.ipynb"), "w") as f:
            json.dump(nb, f)
        with open(os.path.join(d, "notes.txt"), "w") as f:
            f.write("not a notebook {")
        git("add", "-A")
        r = subprocess.run([sys.executable, guard], cwd=d, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        cell.update(outputs=[{"output_type": "stream", "name": "stdout", "text": ["21.5\n"]}], execution_count=1)
        with open(os.path.join(d, "run.ipynb"), "w") as f:
            json.dump(nb, f)
        git("add", "run.ipynb")
        r = subprocess.run([sys.executable, guard], cwd=d, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("Commit refused", r.stderr)
        self.assertIn("run.ipynb", r.stderr)
        self.assertNotIn("clean.ipynb", r.stderr)
        self.assertNotIn("21.5", r.stderr, "the guard never prints a value")

    def run_close(self, netpol):
        """workbench_egress_close against a fake kubectl: (exit code, stdout, the patch sent)."""
        d = tempfile.mkdtemp()
        k = os.path.join(d, "kubectl")
        with open(os.path.join(d, "netpol.json"), "w") as f:
            f.write(netpol)
        with open(k, "w") as f:
            f.write('#!/bin/sh\ncase "$1" in\n'
                    '  get) cat "$(dirname "$0")/netpol.json" ;;\n'
                    '  patch) shift; while [ "$1" != "-p" ]; do shift; done; printf %s "$2" > "$(dirname "$0")/patch" ;;\n'
                    '  *) exit 1 ;;\nesac\n')
        os.chmod(k, 0o755)
        r = subprocess.run(["bash", "-c", f'REPO_ROOT="{REPO}"; source "{REPO}/infra/lib-oauth2-proxy.sh"; '
                                          'n="$(workbench_egress_close medcea)" || exit 1; echo "n=$n"'],
                           env=dict(os.environ, KUBECTL=k), capture_output=True, text=True)
        patch = os.path.join(d, "patch")
        return r.returncode, r.stdout.strip(), (json.load(open(patch)) if os.path.exists(patch) else None)

    def test_close_removes_only_the_hops(self):
        """A rollback's database or frontend deploy closes the notebooks' hops on the running
        workbench: exactly the compiled hops' rules go, the chart's own rules stay."""
        hub = {"to": [{"podSelector": {"matchLabels": {"app": "jupyterhub", "component": "hub"}}}],
               "ports": [{"port": 8081, "protocol": "TCP"}]}
        dns = {"to": [{"namespaceSelector": {}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
               "ports": [{"port": 53, "protocol": "UDP"}]}
        rules = [hub] + compiled_egress() + [dns]
        rc, out, patch = self.run_close(json.dumps({"spec": {"egress": rules}}))
        self.assertEqual((rc, out), (0, "n=2"))
        removed = [op["path"] for op in patch if op["op"] == "remove"]
        self.assertEqual(removed, ["/spec/egress/2", "/spec/egress/1"])   # highest first: indices stay valid
        tests = [op for op in patch if op["op"] == "test"]
        self.assertEqual([t["value"] for t in tests], [rules[2], rules[1]])
        rc, out, patch = self.run_close(json.dumps({"spec": {"egress": [hub, dns]}}))
        self.assertEqual((rc, out, patch), (0, "n=0", None))
        rc, out, patch = self.run_close("")                                 # no workbench
        self.assertEqual((rc, out, patch), (0, "n=0", None))

    def test_close_is_called_before_the_switch(self):
        with open(os.path.join(REPO, "apps", "database", "deploy.sh")) as f:
            db = f.read()
        self.assertLess(db.index('workbench_egress_close "$NAMESPACE"'), db.index('db_apply "$NAMESPACE"'))
        with open(os.path.join(REPO, "apps", "frontend", "deploy.sh")) as f:
            fe = f.read()
        self.assertLess(fe.index('workbench_egress_close "$NAMESPACE"'), fe.index('pgrst_deploy "$IAM_POSTGREST_JWT"'))
        with open(DEPLOY) as f:
            src = f.read()
        self.assertLess(src.index("pgrst_db_enforcing"), src.index("render \"$REPO_ROOT/k8s/workbench/values.yaml\""))

    def test_image_split(self):
        """deploy-workbench.sh's split of WORKBENCH_IMAGE into the chart's name and tag."""
        with open(DEPLOY) as f:
            src = f.read()
        block = src[src.index('_img="${WORKBENCH_IMAGE%%@*}"'):]
        block = block[:block.index("\nfi\n") + 4]
        for image, name, tag in (
                ("quay.io/jupyter/scipy-notebook:lab-4.6.4", "quay.io/jupyter/scipy-notebook", "lab-4.6.4"),
                ("quay.io/jupyter/scipy-notebook:2026-10-27@sha256:ab12", "quay.io/jupyter/scipy-notebook",
                 "2026-10-27@sha256:ab12"),
                ("registry.local:5000/scipy:1", "registry.local:5000/scipy", "1"),
                ("registry.local:5000/scipy", "registry.local:5000/scipy", "latest")):
            with self.subTest(image):
                out = subprocess.run(["bash", "-c", block + '\necho "$WORKBENCH_IMAGE_NAME|$WORKBENCH_IMAGE_TAG"'],
                                     env=dict(os.environ, WORKBENCH_IMAGE=image), capture_output=True, text=True)
                self.assertEqual(out.stdout.strip(), f"{name}|{tag}", out.stderr)
        self.assertIn('WORKBENCH_IMAGE="${WORKBENCH_IMAGE:-quay.io/jupyter/scipy-notebook:latest@sha256:d416eea5c12a44981c2fcb56520649dbd92f7ae5983f4e68e14d1d0ebdf0c2ce}"', src)

    def stub(self, body):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "apps", "iam", "compiler"))
        with open(os.path.join(d, "apps", "iam", "compiler", "cli.py"), "w") as f:
            f.write(body)
        return d

    def test_fails_closed(self):
        for body in ("import sys; sys.exit(1)\n", "print('[]')\n", "print('')\n"):
            with self.subTest(body):
                rc, _ = run("true", self.stub(body))
                self.assertEqual(rc, 1)

    def test_deploy_dies_before_helm(self):
        with open(DEPLOY) as f:
            src = f.read()
        self.assertLess(src.index("policy_workbench || die"), src.index("$HELM upgrade --install workbench"))
        self.assertLess(src.index("policy_workbench_egress || die"), src.index("$HELM upgrade --install workbench"))
        self.assertLess(src.index("create configmap workbench-examples"), src.index("$HELM upgrade --install workbench"))
        self.assertEqual(set(VARS) - set(render_list()), set())


if __name__ == "__main__":
    unittest.main()
