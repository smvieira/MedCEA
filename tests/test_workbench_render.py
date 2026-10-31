#!/usr/bin/env python3
"""tests/test_workbench_render.py — the AI workbench's gate as deploy-workbench.sh renders it
(IAM 3.2), offline: no cluster, no lock, no config.env.

policy_workbench (infra/lib-oauth2-proxy.sh) is run in bash, then k8s/workbench/values.yaml
is filled with lib-render.sh's `render` exactly as the deploy does, and the result parsed:
  IAM_GATES=true   allow_all false, admin_users [], the two lists `cli.py compile
                   jupyterhub` prints, admin_access false, delete_pvc false, the 403 text
  IAM_GATES=false  allow_all true, admin_users [ADMIN_USER], still admin_access false
Either way no ${VAR} is left but the postStart command's $HOME, which must reach the pod.
A cli.py that fails, or prints [], makes policy_workbench return 1 (the deploy dies
before helm and the running hub stays as it is).

  python3 tests/test_workbench_render.py
"""
import json
import os
import re
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


def run(gates, repo_root=REPO):
    """(exit code, rendered values or stderr) of policy_workbench + render."""
    env = dict(os.environ, IAM_GATES=gates, ADMIN_USER="boss", PORTAL_DOMAIN="portal.test",
               WORKBENCH_SECRET="s3cret", WORKBENCH_DOMAIN="ai-workbench.test", KEYCLOAK_DOMAIN="kc.test",
               KEYCLOAK_REALM="medcea", NAMESPACE="medcea", WORKBENCH_IMAGE_NAME="img",
               WORKBENCH_IMAGE_TAG="1", WORKBENCH_STORAGE="10Gi", RR=repo_root, LIBS=REPO)
    script = ('source "$LIBS/infra/lib-render.sh"; REPO_ROOT="$RR" source "$LIBS/infra/lib-oauth2-proxy.sh"; '
              'REPO_ROOT="$RR" policy_workbench || exit 1; '
              f'render "$LIBS/k8s/workbench/values.yaml" {" ".join(render_list())}')
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    return r.returncode, r.stdout if r.returncode == 0 else r.stderr


def compiled(setting):
    out = subprocess.run([sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"),
                          "compile", "jupyterhub", "--setting", setting], capture_output=True, text=True, check=True)
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
        self.assertEqual(hub["GenericOAuthenticator"]["client_secret"], "s3cret")
        left = set(re.findall(r"\$\{?[A-Za-z_]+", text))
        self.assertEqual(left, {"$HOME"}, "an unrendered variable, or the postStart $HOME was eaten")
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
        self.assertEqual(set(VARS) - set(render_list()), set())


if __name__ == "__main__":
    unittest.main()
