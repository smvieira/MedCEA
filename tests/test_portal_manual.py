#!/usr/bin/env python3
"""tests/test_portal_manual.py — the platform manual in the portal (3 Nov 2026).

Offline. The manual is served at https://<PORTAL_DOMAIN>/manual/ by the portal's nginx,
behind the portal's oauth2-proxy (no policy change), from ConfigMap portal-manual, which
infra/lib-manual.sh builds from docs/manual/chapters at deploy time and stores gzipped.

  Render     k8s/portal/portal.yaml rendered with deploy-infra.sh's own render list: it
             parses, / still serves portal-html with its readiness probe, the landing page
             has the "Platform manual" card, the nginx config and the manual are mounted;
             the MedCEA Dashboard card opens the dashboard chooser (Grafana, and Superset
             greyed out until installed), which lib-portal's portal_card enables and
             deploy-infra keeps enabled for an installed Superset
  Nginx      k8s/portal/nginx.conf routes /, /images/ and /manual/ (gzip_static always,
             gunzip, charset, no-cache) onto the mount's path; deploy-infra writes it and
             publishes the manual before the portal's manifest; apps/frontend no longer does
  Build      build.py --out writes the page there and leaves docs/manual/index.html alone;
             a chapter build.py refuses stops the publish before any kubectl call
  ConfigMap  manual_cm_json: gzipped, deterministic, the annotation is the page's sha256;
             over MANUAL_MAX_BYTES it refuses (exit 3) with a message, not a kubectl error
  Publish    manual_publish against a fake kubectl: a server-side apply, then the portal's
             restart and wait (not with --no-roll); no restart and no "served" claim when the
             portal Deployment does not mount portal-manual yet; no kubectl call when the
             build fails
  Health     health-check.sh's check_manual against a fake kubectl that refuses every
             writing verb: OK, lagging (WARN with the fix), not published (WARN), not
             mounted (WARN), corrupt (FAIL), build refused (FAIL), no portal (SKIP)

Nothing here touches a cluster or writes in the repository (scratch trees under mktemp).
"""
import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


FAKE_KUBECTL = r'''#!/usr/bin/env python3
# A fake kubectl for tests/test_portal_manual.py: answers from FAKE_DIR, logs every call.
import json, os, sys
FD = os.environ["FAKE_DIR"]
a = sys.argv[1:]
data = sys.stdin.read() if "-f" in a and a[a.index("-f") + 1] == "-" else ""
with open(os.path.join(FD, "calls.log"), "a") as f:
    f.write(json.dumps(a) + "\n")
words = [x for i, x in enumerate(a) if x != "-n" and (i == 0 or a[i - 1] != "-n")]
verb = words[0] if words else ""
if os.environ.get("FAKE_READ_ONLY") and verb != "get":
    print(f"fake kubectl: refusing to {verb}", file=sys.stderr)
    sys.exit(99)
if verb == "get":
    kind, name = words[1], words[2]
    path = os.path.join(FD, f"{kind}-{name}.json")
    if not os.path.exists(path):
        print(f'Error from server (NotFound): {kind}s "{name}" not found', file=sys.stderr)
        sys.exit(1)
    if "-o" in a:
        print(open(path).read())
    else:
        print(f"{kind}/{name}")
    sys.exit(0)
if verb == "apply":
    src = a[a.index("-f") + 1]
    body = data or open(src).read()
    with open(os.path.join(FD, "applied.json"), "w") as f:
        f.write(body)
    print("configmap/portal-manual serverside-applied")
    sys.exit(0)
if verb == "rollout":
    sys.exit(0)
print(f"fake kubectl: unexpected {a}", file=sys.stderr)
sys.exit(98)
'''


def portal_render_vars():
    """The variable list deploy-infra.sh renders k8s/portal/portal.yaml with."""
    src = read("deploy-infra.sh")
    m = re.search(r'render "\$SCRIPT_DIR/k8s/portal/portal\.yaml" ([A-Z_ ]+?)\s*\\?\n', src)
    return m.group(1).split()


def render_portal():
    names = portal_render_vars()
    env = dict(os.environ, **{n: f"{n.lower()}.example" for n in names})
    env["NAMESPACE"] = "medcea"
    env["PORTAL_DOMAIN"] = "portal.example"
    out = subprocess.run(["bash", "-c", 'source infra/lib-render.sh; render k8s/portal/portal.yaml "$@"', "render"] + names,
                         cwd=REPO, env=env, capture_output=True, text=True, check=True).stdout
    return out.replace("__PORTAL_BG_STYLE__", "", 1)


class Render(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = render_portal()
        cls.docs = {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(cls.text) if d}

    def test_render_list_names_portal_domain(self):
        self.assertIn("PORTAL_DOMAIN", portal_render_vars())
        # envsubst leaves an unlisted ${VAR} as literal text
        used = set(re.findall(r"\$\{([A-Z_]+)\}", read("k8s/portal/portal.yaml")))
        self.assertLessEqual(used, set(portal_render_vars()))

    def test_parses_and_keeps_the_portal(self):
        self.assertEqual(set(self.docs), {("ConfigMap", "portal-html"), ("Deployment", "portal"), ("Service", "portal")})
        html = self.docs[("ConfigMap", "portal-html")]["data"]["index.html"]
        self.assertIn("<title>MedCEA Platform</title>", html)
        self.assertIn("/_account/user-menu.js", html)
        c = self.docs[("Deployment", "portal")]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["readinessProbe"]["httpGet"], {"path": "/", "port": 80})
        mounts = {m["mountPath"]: m for m in c["volumeMounts"]}
        self.assertEqual(mounts["/usr/share/nginx/html/index.html"], {"name": "html", "mountPath": "/usr/share/nginx/html/index.html", "subPath": "index.html"})

    def test_the_card(self):
        html = self.docs[("ConfigMap", "portal-html")]["data"]["index.html"]
        main = html[html.index('id="v-portal"'):html.index('id="v-management"')]
        m = re.search(r'<a class="card" href="/manual/" target="_blank" rel="noopener">(.*?)</a>', main, re.S)
        self.assertIsNotNone(m, "no Platform manual card on the landing page")
        card = m.group(1)
        self.assertIn('<div class="ct">Platform manual</div>', card)
        for cls in ("ci", "cl", "cd", "ck", "ck-a"):
            self.assertIn(f'class="{cls}"', card)
        self.assertIn("https://portal.example/manual/", card)
        # not on the management sub-page, and the user menu is not touched
        self.assertNotIn("/manual/", html[html.index('id="v-management"'):])
        self.assertNotIn("manual", read("apps/access/html/user-menu.js").lower())
        # lib-portal's card switch never matches it (its URLs are https://<host>)
        self.assertEqual(html.count('href="/manual/"'), 1)

    def test_dashboard_chooser(self):
        html = self.docs[("ConfigMap", "portal-html")]["data"]["index.html"]
        main = html[html.index('id="v-portal"'):html.index('id="v-dashboards"')]
        # the landing card opens the chooser instead of linking Grafana
        self.assertIn("""<div class="card" onclick="show('dashboards')">""", main)
        self.assertIn('<div class="ct">MedCEA Dashboard</div>', main)
        self.assertNotIn("grafana_domain.example", main)
        view = html[html.index('id="v-dashboards"'):html.index('id="v-management"')]
        self.assertIn("onclick=\"show('portal')\"", view)
        self.assertIn('<a class="card" href="https://grafana_domain.example" target="_blank" rel="noopener">', view)
        # Superset: exactly the disabled form lib-portal's portal_card enable matches
        self.assertRegex(view, r'(?s)<div class="card card-dis" data-href="https://superset_domain\.example">.*?</div><!--/card-->')
        self.assertIn(".card-dis .cd::after", html)
        self.assertNotIn("${", html)

    def test_portal_card_enables_superset(self):
        html = self.docs[("ConfigMap", "portal-html")]["data"]["index.html"]
        with tempfile.TemporaryDirectory() as d:
            src, out = os.path.join(d, "in.html"), os.path.join(d, "out.html")
            open(src, "w").write(html)
            fake = os.path.join(d, "kubectl")
            open(fake, "w").write(f"""#!/bin/sh
case "$*" in
  "get cm portal-html"*) cat {src} ;;
  "create configmap portal-html"*) cat > {out}.yaml ;;
  "apply -f -") cat > /dev/null ;;
  "rollout restart"*) : ;;
  *) echo "fake kubectl: $*" >&2; exit 98 ;;
esac
""")
            os.chmod(fake, 0o755)
            subprocess.run(["bash", "-c", 'source infra/lib-portal.sh; portal_card enable "https://superset_domain.example"'],
                           cwd=REPO, env=dict(os.environ, KUBECTL=fake, NAMESPACE="medcea"), check=True)
            # the fake records what create configmap read from stdin (--from-file=index.html=/dev/stdin)
            enabled = open(out + ".yaml").read()
        self.assertIn('<a class="card" href="https://superset_domain.example" target="_blank" rel="noopener">', enabled)
        self.assertNotIn('data-href="https://superset_domain.example"', enabled)

    def test_deploy_infra_keeps_an_installed_superset_enabled(self):
        src = read("deploy-infra.sh")
        sec = src[src.index('render "$SCRIPT_DIR/k8s/portal/portal.yaml"'):src.index("rollout restart deployment/portal")]
        self.assertIn('kubectl get deployment superset -n "$NAMESPACE"', sec)
        self.assertIn('portal_card enable "https://${SUPERSET_DOMAIN}"', sec)
        self.assertIn('SUPERSET_DOMAIN="${SUPERSET_DOMAIN:-superset.$DOMAIN}"', src)
        self.assertIn('SUPERSET_DOMAIN="superset.$DOMAIN"', read("config.env.example"))

    def test_mounts(self):
        spec = self.docs[("Deployment", "portal")]["spec"]["template"]["spec"]
        vols = {v["name"]: v for v in spec["volumes"]}
        mounts = {m["name"]: m for m in spec["containers"][0]["volumeMounts"]}
        self.assertEqual(vols["portal-nginx"]["configMap"], {"name": "portal-nginx"})
        self.assertEqual(mounts["portal-nginx"]["mountPath"], "/etc/nginx/conf.d/default.conf")
        self.assertEqual(mounts["portal-nginx"]["subPath"], "default.conf")
        self.assertEqual(vols["manual"]["configMap"], {"name": "portal-manual", "optional": True})
        self.assertEqual(mounts["manual"]["mountPath"], "/usr/share/nginx/manual")
        self.assertNotIn("subPath", mounts["manual"])   # a directory mount refreshes itself
        self.assertNotIn("images", vols)                 # apps/frontend/deploy.sh adds it


class Nginx(unittest.TestCase):
    conf = read("k8s/portal/nginx.conf")

    def block(self, loc):
        # No location nests, so a body is a balanced {...} without braces inside: a block
        # never runs on into the next one.
        m = re.search(r"location " + re.escape(loc) + r" \{([^{}]*)\}", self.conf)
        self.assertIsNotNone(m, loc)
        return m.group(1)

    def test_blocks_stay_their_own(self):
        for loc in ("/", "/images/", "= /manual", "= /manual/", "/manual/"):
            self.assertNotIn("gzip_static", self.block(loc), loc)
            self.assertNotIn("location", self.block(loc), loc)

    def test_braces_balance(self):
        body = "\n".join(l.split("#")[0] for l in self.conf.splitlines())
        self.assertEqual(body.count("{"), body.count("}"))
        self.assertEqual(len(re.findall(r"^server \{", body, re.M)), 1)

    def test_portal_root_unchanged(self):
        b = self.block("/")
        self.assertIn("root /usr/share/nginx/html;", b)
        self.assertIn("index index.html;", b)
        self.assertIn('Cache-Control "no-cache" always', b)
        self.assertIn("alias /usr/share/nginx/html/images/;", self.block("/images/"))

    def test_manual_routes(self):
        self.assertIn("absolute_redirect off;", self.conf)
        self.assertIn("return 301 /manual/;", self.block("= /manual"))
        self.assertIn("rewrite ^ /manual/index.html last;", self.block("= /manual/"))
        b = self.block("= /manual/index.html")
        for d in ("gzip_static always;", "gunzip on;", "charset utf-8;", 'Cache-Control "no-cache" always'):
            self.assertIn(d, b)
        root = re.search(r"root (\S+);", b).group(1)
        # root + URI is the ConfigMap mount's file; gzip_static adds .gz, the ConfigMap's key
        self.assertEqual(root + "/manual/index.html", "/usr/share/nginx/manual/index.html")
        self.assertIn('"index.html.gz"', read("infra/lib-manual.sh"))
        self.assertIn("return 404;", self.block("/manual/"))

    def test_who_writes_it(self):
        infra = read("deploy-infra.sh")
        sec = infra[infra.index("# 9. SERVICE PORTAL"):]
        i_cm = sec.index('--from-file=default.conf="$SCRIPT_DIR/k8s/portal/nginx.conf"')
        i_pub = sec.index('manual_publish "$NAMESPACE" --no-roll')
        i_apply = sec.index('render "$SCRIPT_DIR/k8s/portal/portal.yaml"')
        i_roll = sec.index("rollout restart deployment/portal")
        self.assertLess(i_cm, i_apply)
        self.assertLess(i_pub, i_apply)
        self.assertLess(i_apply, i_roll)
        self.assertIn('source "$SCRIPT_DIR/infra/lib-manual.sh"', sec)
        front = read("apps/frontend/deploy.sh")
        self.assertNotIn("create configmap portal-nginx", front)
        self.assertNotIn('"name":"portal-nginx"', front)
        self.assertFalse(os.path.exists(os.path.join(REPO, "apps/frontend/k8s/portal-nginx.conf")))


class Tree:
    """A scratch tree with docs/manual and infra/lib-manual.sh, and a fake kubectl."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="medcea-manual-")
        shutil.copytree(os.path.join(REPO, "docs/manual"), self.path("docs/manual"),
                        ignore=shutil.ignore_patterns("__pycache__", "index.html"))
        os.makedirs(self.path("infra"))
        shutil.copy(os.path.join(REPO, "infra/lib-manual.sh"), self.path("infra/lib-manual.sh"))
        self.fd = self.path(".fake")
        os.makedirs(self.fd)
        self.kubectl = os.path.join(self.fd, "kubectl")
        with open(self.kubectl, "w") as fh:
            fh.write(FAKE_KUBECTL)
        os.chmod(self.kubectl, 0o755)

    def path(self, rel):
        return os.path.join(self.root, rel)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def bash(self, script, **env):
        e = {k: v for k, v in os.environ.items() if k != "MANUAL_MAX_BYTES"}
        e.update(FAKE_DIR=self.fd, KUBECTL=self.kubectl, **env)
        return subprocess.run(["bash", "-c", f'source {self.path("infra/lib-manual.sh")}\n' + script],
                              capture_output=True, text=True, env=e, cwd=self.root)

    def calls(self):
        p = os.path.join(self.fd, "calls.log")
        if not os.path.exists(p):
            return []
        with open(p) as fh:
            return [json.loads(l) for l in fh]

    def break_chapter(self):
        with open(self.path("docs/manual/chapters/apps.html"), "a") as fh:
            fh.write('\n<p><a href="#no-such-section-anywhere">dead</a></p>\n')

    def build(self):
        out = self.path("built.html")
        subprocess.run(["python3", self.path("docs/manual/build.py"), "--out", out, "--standalone"],
                       check=True, capture_output=True)
        return out


class Build(unittest.TestCase):
    def test_out_leaves_index_html_alone(self):
        idx = os.path.join(REPO, "docs/manual/index.html")
        before = (sha(idx), os.stat(idx).st_mtime_ns)
        d = tempfile.mkdtemp()
        try:
            out = os.path.join(d, "page.html")
            p = subprocess.run(["python3", os.path.join(REPO, "docs/manual/build.py"), "--out", out],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(f"build: wrote {out}", p.stdout)
            with open(out, encoding="utf-8") as fh:
                page = fh.read()
            self.assertNotIn("{{", page)
            self.assertIn('id="training"', page)
            self.assertFalse(page.startswith("<!DOCTYPE"))   # the artifact's page, as index.html
            out2 = os.path.join(d, "standalone.html")
            p = subprocess.run(["python3", os.path.join(REPO, "docs/manual/build.py"), "--out", out2, "--standalone"],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(out2, encoding="utf-8") as fh:
                alone = fh.read()
            # what the portal serves: a complete document (no quirks mode), the same page inside
            self.assertTrue(alone.startswith('<!DOCTYPE html>\n<html lang="en">\n<meta charset="utf-8">'))
            self.assertTrue(alone.rstrip().endswith("</html>"))
            self.assertIn(page.rstrip("\n"), alone)
            for bad in (["--out"], ["--out", "--standalone"]):
                p = subprocess.run(["python3", os.path.join(REPO, "docs/manual/build.py")] + bad, capture_output=True, text=True)
                self.assertEqual(p.returncode, 2, bad)
        finally:
            shutil.rmtree(d)
        self.assertEqual((sha(idx), os.stat(idx).st_mtime_ns), before)

    def test_a_refused_build_publishes_nothing(self):
        t = Tree()
        try:
            t.break_chapter()
            p = t.bash('manual_publish medcea; echo "rc=$?"')
            self.assertIn("rc=1", p.stdout)
            self.assertIn("refuses to build the manual", p.stderr)
            self.assertIn("no-such-section-anywhere", p.stderr)
            self.assertEqual(t.calls(), [])
        finally:
            t.close()


class ConfigMap(unittest.TestCase):
    def setUp(self):
        self.t = Tree()
        self.page = self.t.build()

    def tearDown(self):
        self.t.close()

    def test_gzipped_annotated_deterministic(self):
        a = self.t.bash(f'manual_cm_json medcea {self.page}')
        b = self.t.bash(f'manual_cm_json medcea {self.page}')
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)
        cm = json.loads(a.stdout)
        self.assertEqual(cm["metadata"]["name"], "portal-manual")
        self.assertEqual(cm["metadata"]["namespace"], "medcea")
        with open(self.page, "rb") as fh:
            raw = fh.read()
        self.assertEqual(gzip.decompress(base64.b64decode(cm["binaryData"]["index.html.gz"])), raw)
        self.assertEqual(cm["metadata"]["annotations"]["medcea/manual-sha256"], hashlib.sha256(raw).hexdigest())
        self.assertNotIn("data", cm)
        # headroom: well under the 1 MiB a ConfigMap holds
        self.assertLess(len(base64.b64decode(cm["binaryData"]["index.html.gz"])), 1_000_000 // 2)

    def test_too_large_is_refused(self):
        p = self.t.bash(f'manual_cm_json medcea {self.page}; echo "rc=$?"', MANUAL_MAX_BYTES="1000")
        self.assertIn("rc=3", p.stdout)
        self.assertNotIn("binaryData", p.stdout)
        self.assertIn("over the 1000 bytes a ConfigMap may hold", p.stderr)
        self.assertIn("It is not published", p.stderr)
        p = self.t.bash('manual_publish medcea; echo "rc=$?"', MANUAL_MAX_BYTES="1000")
        self.assertIn("rc=3", p.stdout)
        self.assertEqual(self.t.calls(), [])


class Publish(unittest.TestCase):
    def setUp(self):
        self.t = Tree()
        self.deployment(mounted=True)

    def deployment(self, mounted):
        vols = [{"name": "portal-html", "configMap": {"name": "portal-html"}}]
        if mounted:
            vols.append({"name": "manual", "configMap": {"name": "portal-manual", "optional": True}})
        with open(os.path.join(self.t.fd, "deployment-portal.json"), "w") as fh:
            json.dump({"kind": "Deployment", "spec": {"template": {"spec": {"volumes": vols}}}}, fh)

    def tearDown(self):
        self.t.close()

    def test_apply_then_restart_and_wait(self):
        p = self.t.bash('manual_publish medcea; echo "rc=$?"')
        self.assertIn("rc=0", p.stdout, p.stderr)
        calls = self.t.calls()
        self.assertEqual(calls[0][:4], ["apply", "--server-side", "--force-conflicts", "--field-manager=medcea-manual"])
        self.assertIn(["rollout", "restart", "deployment/portal", "-n", "medcea"], calls)
        self.assertIn(["rollout", "status", "deployment/portal", "-n", "medcea", "--timeout=3m"], calls)
        with open(os.path.join(self.t.fd, "applied.json")) as fh:
            applied = json.load(fh)
        self.assertEqual(applied["kind"], "ConfigMap")
        self.assertEqual(applied["metadata"]["annotations"]["medcea/manual-sha256"], sha(self.t.build()))
        # the temporary files are gone, and nothing was written next to the chapters
        self.assertFalse(os.path.exists(self.t.path("docs/manual/index.html")))

    def test_restart_says_served(self):
        p = self.t.bash('manual_publish medcea; echo "rc=$?"; echo "served=$MANUAL_SERVED"')
        self.assertIn("served=yes", p.stdout)
        self.assertIn("the portal serves it at /manual/", p.stdout)

    def test_portal_older_than_the_manual(self):
        # an install whose portal Deployment predates the manual: stored, no restart, no claim
        self.deployment(mounted=False)
        p = self.t.bash('manual_publish medcea; echo "rc=$?"; echo "served=$MANUAL_SERVED"')
        self.assertIn("rc=0", p.stdout, p.stderr)
        self.assertIn("served=no", p.stdout)
        self.assertNotIn("serves it at /manual/", p.stdout)
        self.assertIn("not set up to serve it yet", p.stdout)
        self.assertIn("./deploy-infra.sh", p.stdout)
        verbs = [c[0] for c in self.t.calls()]
        self.assertEqual(verbs, ["apply", "get"])
        self.assertNotIn("rollout", verbs)

    def test_no_portal_yet(self):
        os.remove(os.path.join(self.t.fd, "deployment-portal.json"))
        p = self.t.bash('manual_publish medcea; echo "rc=$?"; echo "served=$MANUAL_SERVED"')
        self.assertIn("rc=0", p.stdout, p.stderr)
        self.assertIn("served=no", p.stdout)
        self.assertNotIn("rollout", [c[0] for c in self.t.calls()])

    def test_no_roll(self):
        p = self.t.bash('manual_publish medcea --no-roll; echo "rc=$?"')
        self.assertIn("rc=0", p.stdout, p.stderr)
        self.assertEqual([c[0] for c in self.t.calls()], ["apply"])

    def test_entry_script_logs_locks_and_publishes_only(self):
        src = read("infra/publish-manual.sh")
        self.assertLess(src.index("medcea_log publish-manual"), src.index("medcea_lock"))
        self.assertIn('manual_publish "$NAMESPACE"', src)
        self.assertNotIn("--no-roll", src.split("set -euo pipefail")[1])
        self.assertTrue(os.access(os.path.join(REPO, "infra/publish-manual.sh"), os.X_OK))
        self.assertIn('"a_manual_publish|Publish the manual to the portal|', read("guide.sh"))
        # the served URL is claimed only after the restart happened
        tail = src.split('manual_publish "$NAMESPACE"')[1]
        self.assertLess(tail.index('"$MANUAL_SERVED" == yes'), tail.index("/manual/"))


def check_manual_body():
    src = read("health-check.sh")
    return re.search(r"(?ms)^check_manual\(\) \{.*?^\}", src).group(0)


class Health(unittest.TestCase):
    def setUp(self):
        self.t = Tree()
        self.page = self.t.build()
        self.dep = {"spec": {"template": {"spec": {"volumes": [
            {"name": "html", "configMap": {"name": "portal-html"}},
            {"name": "manual", "configMap": {"name": "portal-manual", "optional": True}}]}}}}

    def tearDown(self):
        self.t.close()

    def raw(self):
        with open(self.page, "rb") as fh:
            return fh.read()

    def put(self, kind, name, doc):
        p = os.path.join(self.t.fd, f"{kind}-{name}.json")
        if doc is None:
            if os.path.exists(p):
                os.remove(p)
            return
        with open(p, "w") as fh:
            json.dump(doc, fh)

    def cm(self, page_bytes, annotation=None):
        return {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "portal-manual", "annotations": {
                    "medcea/manual-sha256": annotation or hashlib.sha256(page_bytes).hexdigest(),
                    "medcea/manual-commit": "abc1234"}},
                "binaryData": {"index.html.gz": base64.b64encode(gzip.compress(page_bytes, 9, mtime=0)).decode()}}

    def run_check(self):
        script = ('_record() { echo "RESULT|$1|$2|$3"; }\n'
                  '_ps_kubectl_usable() { return 0; }\n'
                  f'SCRIPT_DIR={self.t.root}; TIMEOUT=30\n'
                  + check_manual_body() + '\ncheck_manual "Platform manual" medcea\n')
        e = dict(os.environ, FAKE_DIR=self.t.fd, KUBECTL=self.t.kubectl, FAKE_READ_ONLY="1")
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e)
        lines = [l for l in p.stdout.splitlines() if l.startswith("RESULT|")]
        self.assertEqual(len(lines), 1, p.stdout + p.stderr)
        _, status, name, msg = lines[0].split("|", 3)
        self.assertEqual(name, "Platform manual")
        self.assertTrue(all(c[0] == "get" for c in self.t.calls()), self.t.calls())
        self.assertEqual(sorted(os.listdir(self.t.path("docs/manual"))), ["build.py", "chapters", "shell.html"])
        return status, msg

    def test_ok(self):
        self.put("deployment", "portal", self.dep)
        self.put("configmap", "portal-manual", self.cm(self.raw()))
        status, msg = self.run_check()
        self.assertEqual(status, "OK", msg)
        self.assertIn("the portal serves the manual the repository builds", msg)

    def test_lagging_is_a_warn_with_the_fix(self):
        self.put("deployment", "portal", self.dep)
        self.put("configmap", "portal-manual", self.cm(b"<!DOCTYPE html><p>an older manual</p>"))
        status, msg = self.run_check()
        self.assertEqual(status, "WARN", msg)
        self.assertIn("the portal serves the manual of abc1234", msg)
        self.assertIn("./guide.sh → Infrastructure → Publish the manual to the portal", msg)

    def test_not_published(self):
        self.put("deployment", "portal", self.dep)
        status, msg = self.run_check()
        self.assertEqual(status, "WARN", msg)
        self.assertIn("not published", msg)

    def test_not_mounted(self):
        dep = {"spec": {"template": {"spec": {"volumes": [{"name": "html", "configMap": {"name": "portal-html"}}]}}}}
        self.put("deployment", "portal", dep)
        self.put("configmap", "portal-manual", self.cm(self.raw()))
        status, msg = self.run_check()
        self.assertEqual(status, "WARN", msg)
        self.assertIn("does not mount it", msg)

    def test_content_not_its_annotation_fails(self):
        self.put("deployment", "portal", self.dep)
        raw = self.raw()
        self.put("configmap", "portal-manual", self.cm(b"something else", annotation=hashlib.sha256(raw).hexdigest()))
        status, msg = self.run_check()
        self.assertEqual(status, "FAIL", msg)
        self.assertIn("its annotation says", msg)

    def test_a_manual_that_does_not_build_fails(self):
        self.put("deployment", "portal", self.dep)
        self.put("configmap", "portal-manual", self.cm(self.raw()))
        self.t.break_chapter()
        status, msg = self.run_check()
        self.assertEqual(status, "FAIL", msg)
        self.assertIn("build.py refuses", msg)

    def test_no_portal_skips(self):
        status, msg = self.run_check()
        self.assertEqual(status, "SKIP", msg)

    def test_wiring(self):
        conf = read("health-checks.conf")
        lines = [l for l in conf.splitlines() if l.strip() and not l.startswith("#")]
        self.assertEqual(len(lines), 56)
        row = [l for l in lines if l.split("|")[0].strip() == "Platform manual"]
        self.assertEqual(len(row), 1)
        self.assertEqual([x.strip() for x in row[0].split("|")[1:3]], ["manual", "$NAMESPACE"])
        src = read("health-check.sh")
        self.assertIn('manual)       check_manual "$name" "$target" ;;', src)
        self.assertIn("${CYAN}manual${NC}", src)


if __name__ == "__main__":
    unittest.main()
