#!/usr/bin/env python3
"""tests/test_workbench_render.py — the AI workbench's gate as deploy-workbench.sh renders it
(IAM 3.2), offline: no cluster, no lock, no config.env.

policy_workbench (infra/lib-oauth2-proxy.sh) is run in bash, then k8s/workbench/values.yaml
is filled with lib-render.sh's `render` exactly as the deploy does, and the result parsed:
  IAM_GATES=true   allow_all false, admin_users [], the two lists `cli.py compile
                   jupyterhub` prints, admin_access false, delete_pvc false, the 403 text
  IAM_GATES=false  allow_all true, admin_users [ADMIN_USER], still admin_access false
Either way no ${VAR} is left but the postStart command's $HOME, $ATTRS and $HOOKS, which
must reach the pod.
A cli.py that fails, or prints [], makes policy_workbench return 1 (the deploy dies
before helm and the running hub stays as it is).
IAM 3.2b: policy_workbench_egress renders singleuser.networkPolicy.egress — exactly
`cli.py compile egress notebooks` (Keycloak and config-api) while IAM_POSTGREST_JWT and
IAM_DB_ROLES are both true, [] otherwise — with private addresses still closed; the pod
gets endpoints only (no secret), the examples read-only in the home, and a postStart that
makes nbstripout the global git filter idempotently, fails closed when nbstripout cannot be
installed (attribute, clean command and `required` still written), installs the
pre-commit output guard (nb_output_guard.py, tried against a real git repository) and
never fails the start. workbench_egress_close (the database and frontend deploys, on a
switch to false) removes exactly the compiled hops from the live NetworkPolicy.

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

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(REPO, "infra", "deploy-workbench.sh")
VARS = ["WORKBENCH_ALLOW_ALL", "WORKBENCH_ADMIN_USERS", "WORKBENCH_ALLOWED_GROUPS",
        "WORKBENCH_ADMIN_GROUPS", "WORKBENCH_403_MESSAGE"]


def render_list():
    """The variables deploy-workbench.sh hands to render for values.yaml."""
    with open(DEPLOY) as f:
        src = f.read()
    call = re.search(r'render "\$REPO_ROOT/k8s/workbench/values.yaml"(.*?)>', src, re.S).group(1)
    return call.replace("\\", " ").split()


def run(gates, repo_root=REPO, jwt="false", db_roles="false"):
    """(exit code, rendered values or stderr) of policy_workbench(_egress) + render."""
    env = dict(os.environ, IAM_GATES=gates, ADMIN_USER="boss", PORTAL_DOMAIN="portal.test",
               WORKBENCH_SECRET="s3cret", WORKBENCH_DOMAIN="ai-workbench.test", KEYCLOAK_DOMAIN="kc.test",
               KEYCLOAK_REALM="medcea", NAMESPACE="medcea", WORKBENCH_IMAGE_NAME="img",
               WORKBENCH_IMAGE_TAG="1", WORKBENCH_STORAGE="10Gi", WORKBENCH_NOTEBOOK_REPO="smvieira/medcea-notebooks",
               IAM_POSTGREST_JWT=jwt, IAM_DB_ROLES=db_roles, RR=repo_root, LIBS=REPO)
    script = ('source "$LIBS/infra/lib-render.sh"; REPO_ROOT="$RR" source "$LIBS/infra/lib-oauth2-proxy.sh"; '
              'REPO_ROOT="$RR" policy_workbench || exit 1; REPO_ROOT="$RR" policy_workbench_egress || exit 1; '
              f'render "$LIBS/k8s/workbench/values.yaml" {" ".join(render_list())}')
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    return r.returncode, r.stdout if r.returncode == 0 else r.stderr


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
        self.assertIs(hub["JupyterHub"]["admin_access"], False)
        self.assertEqual(hub["JupyterHub"]["oauth_token_expires_in"], 3600)
        self.assertIs(hub["KubeSpawner"]["delete_pvc"], False)
        self.assertIs(hub["Authenticator"]["allow_existing_users"], False)
        self.assertIs(hub["Authenticator"]["enable_auth_state"], False)
        self.assertEqual(hub["GenericOAuthenticator"]["auth_state_groups_key"], "oauth_user.groups")
        # OAuthenticator 17 refuses to start (ValueError) with group keys but no
        # manage_groups: the hub crash-looped on 2026-10-31 without it.
        self.assertIs(hub["GenericOAuthenticator"]["manage_groups"], True)
        self.assertEqual(hub["GenericOAuthenticator"]["client_secret"], "s3cret")
        left = set(re.findall(r"\$\{?[A-Za-z_]+", text))
        self.assertEqual(left, {"$HOME", "$ATTRS", "$HOOKS"}, "an unrendered variable, or the postStart's shell variables were eaten")
        return hub

    def test_gated(self):
        rc, out = run("true")
        self.assertEqual(rc, 0, out)
        hub = self.check_common(out)
        self.assertIs(hub["Authenticator"]["allow_all"], False)
        self.assertEqual(hub["Authenticator"]["admin_users"], [])
        g = hub["GenericOAuthenticator"]
        self.assertEqual(g["allowed_groups"], compiled("allowed_groups"))
        self.assertEqual(g["admin_groups"], compiled("admin_groups"))
        self.assertEqual(g["admin_groups"], ["admin"])
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
        self.assertEqual(hub["Authenticator"]["admin_users"], ["boss"])
        self.assertEqual(hub["GenericOAuthenticator"]["allowed_groups"], [])
        self.assertEqual(hub["GenericOAuthenticator"]["admin_groups"], [])

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
        hook = su["lifecycleHooks"]["postStart"]["exec"]["command"]
        self.assertEqual(hook[:2], ["sh", "-c"])
        cmd = hook[2]
        self.assertIn("python3 -m nbstripout --is-installed --global ||", cmd)
        self.assertIn("python3 -m nbstripout --install --global", cmd)
        self.assertIn("git config --global filter.nbstripout.required true", cmd)
        self.assertNotIn("nbstripout) &&", cmd, "a failed pip install must not skip the filter's setup")
        self.assertIn("/home/jovyan/medcea-examples/nb_output_guard.py", cmd)
        self.assertTrue(cmd.rstrip().endswith("true"), "a failed setup must never stop the server")
        self.assertEqual(subprocess.run(["sh", "-n", "-c", cmd]).returncode, 0)

    def hook_home(self, pip_works=True):
        """A scratch home with stub pip/python3/git/curl that record what the postStart does."""
        home = tempfile.mkdtemp()
        bin_ = os.path.join(home, "bin")
        os.makedirs(os.path.join(home, ".local", "bin"))
        os.makedirs(bin_)
        open(os.path.join(home, ".local", "bin", "code-server"), "w").close()
        os.chmod(os.path.join(home, ".local", "bin", "code-server"), 0o755)
        # git config --global as files under $HOME/cfg/<key>: --get prints and fails when unset
        stubs = {
            "pip": ('echo "pip $*" >> "$LOG"; ' + ('touch "$HOME/nbstripout-installed"' if pip_works else "exit 1")),
            "python3": ('mkdir -p "$HOME/cfg"\ncase "$*" in\n'
                        '  "-c import nbstripout") test -e "$HOME/nbstripout-installed" ;;\n'
                        '  *--is-installed*) test -e "$HOME/cfg/filter.nbstripout.clean" ;;\n'
                        '  *"--install --global"*) test -e "$HOME/nbstripout-installed" || exit 1\n'
                        '      echo "install $*" >> "$LOG"; echo "py -m nbstripout" > "$HOME/cfg/filter.nbstripout.clean" ;;\n'
                        'esac'),
            "git": ('mkdir -p "$HOME/cfg"\n'
                    '[ "$1 $2" = "config --global" ] || exit 0\n'
                    'shift 2; [ "$1" = "--path" ] && shift\n'
                    'if [ "$1" = "--get" ]; then test -e "$HOME/cfg/$2" && cat "$HOME/cfg/$2"; exit; fi\n'
                    'echo "set $1 $2" >> "$LOG"; printf %s "$2" > "$HOME/cfg/$1"'),
            "curl": "exit 1",
        }
        for name, body in stubs.items():
            p = os.path.join(bin_, name)
            with open(p, "w") as f:
                f.write("#!/bin/sh\n" + body + "\n")
            os.chmod(p, 0o755)
        return home, {"HOME": home, "PATH": bin_ + ":/usr/bin:/bin", "LOG": os.path.join(home, "calls")}

    def hook_cmd(self):
        return yaml.safe_load(run("true")[1])["singleuser"]["lifecycleHooks"]["postStart"]["exec"]["command"][2]

    def test_hook_is_idempotent(self):
        """The postStart command run twice: nbstripout installed once, the filter, attribute,
        hook and credential helper set once, `required` kept true."""
        home, env = self.hook_home()
        for _ in range(2):
            self.assertEqual(subprocess.run(["sh", "-c", self.hook_cmd()], env=env).returncode, 0)
        with open(env["LOG"]) as f:
            calls = f.read().splitlines()
        attrs = os.path.join(home, ".config", "git", "attributes")
        hooks = os.path.join(home, ".config", "git", "hooks")
        self.assertEqual(calls, ["pip install --quiet --user nbstripout",
                                 "install -m nbstripout --install --global",
                                 "set filter.nbstripout.required true",
                                 "set core.attributesFile " + attrs,
                                 "set core.hooksPath " + hooks,
                                 "set credential.helper store",
                                 "set filter.nbstripout.required true"])
        with open(attrs) as f:
            self.assertEqual(f.read(), "*.ipynb filter=nbstripout\n")
        with open(os.path.join(hooks, "pre-commit")) as f:
            self.assertIn("nb_output_guard.py", f.read())
        self.assertTrue(os.access(os.path.join(hooks, "pre-commit"), os.X_OK))

    def test_hook_fails_closed_without_nbstripout(self):
        """pip fails: the filter is still required, with a clean command that then fails, the
        attribute and the pre-commit guard are written, and the start still succeeds."""
        home, env = self.hook_home(pip_works=False)
        self.assertEqual(subprocess.run(["sh", "-c", self.hook_cmd()], env=env).returncode, 0)
        cfg = lambda k: open(os.path.join(home, "cfg", k)).read()
        self.assertEqual(cfg("filter.nbstripout.required"), "true")
        self.assertEqual(cfg("filter.nbstripout.clean"), "python3 -m nbstripout")
        self.assertTrue(os.path.exists(os.path.join(home, ".config", "git", "hooks", "pre-commit")))

    def test_hook_keeps_a_chosen_hooks_path(self):
        home, env = self.hook_home()
        os.makedirs(os.path.join(home, "cfg"))
        with open(os.path.join(home, "cfg", "core.hooksPath"), "w") as f:
            f.write(os.path.join(home, "mine"))
        self.assertEqual(subprocess.run(["sh", "-c", self.hook_cmd()], env=env).returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(home, "mine")), "a person's own hooks folder is left alone")

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
