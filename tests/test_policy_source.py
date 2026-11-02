#!/usr/bin/env python3
"""tests/test_policy_source.py — where every compile reads the access policy (IAM Phase 4,
slice 4.0: compiler/source.py, cli.py's source rule, infra/lib-policy-source.sh).

  SourceIdentity   with no host file and no override, every cli.py output (each compile
                   target, hosts, db-roles x3, describe-gate per host) is byte for byte what
                   the pre-4.0 path printed: (a) against defaults.yaml read directly, label
                   "defaults.yaml"; (b) against the pre-4.0 cli.py itself (git archive of
                   PRE_40:apps/iam; skipped without git or that commit), check included but
                   for its new source line; and compose(skeleton, entries_and_waivers) of the
                   factory policy compiles to the same bytes for every target
                   (slice 4.1 moves routes, grants, netpol, check and the new client's
                   egress on purpose: those are compared in Phase41Delta instead)
  Phase41Delta     against PRE_41 (slice 4.0, bdc7d48): every other output byte-identical;
                   routes.json differs only by the declared iam routes, the policy_page
                   widening pairs, dual_control and the two exportable tables; only the
                   NetworkPolicies iam-iam, iam-config-api and iam-access change
  SourceRule       --file/--defaults/MEDCEA_POLICY_FILE/host file in order; the refusals
                   (exit 2) and labels; db-roles and describe-gate need no source
  Cells            cells_to_yaml's three spellings read back as model.cell() reads the YAML
  LibSource        policy_source_init's guards (bash, no kubectl)
  LibTools         policy_tool refuses an inherited MEDCEA_POLICY_FILE without the init
                   (edge/ compiles through it and never runs the init)
  Wiring           every entry script that compiles sources lib-policy-source.sh and calls
                   policy_source_init; no deploy passes --file; --defaults only for the fixture
                   namespace and the offline tests; the function libraries and edge/ do not
                   call it (design §3.4, review finding 5); the offline tests and
                   iam-routes-diff.py read the factory file

Run from the repository root:  python3 tests/test_policy_source.py
Offline: a scratch copy of apps/iam for anything that needs a host file. No cluster, no lock.
"""
import copy
import html
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
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from compiler import explain, grants, invariants, model, mqtt, netpol, proxies, routes, source, tools  # noqa: E402

CLI = os.path.join(REPO, "apps", "iam", "compiler", "cli.py")
DEFAULTS = os.path.join(REPO, "apps", "iam", "policy", "defaults.yaml")
# The last commit before slice 4.0: SourceIdentity runs its cli.py as the reference.
PRE_40 = "6b73e72"
# The last commit before slice 4.1 (slice 4.0 built): Phase41Delta's reference.
PRE_41 = "bdc7d48"
# What slice 4.1 moves on purpose (design §14.2.7): the route table (new iam routes,
# policy_page, dual_control, exports), the grants (pre_request's only_rpc block, the 008c
# members), three NetworkPolicies, check's counts, and the new client's egress. Phase41Delta
# pins how; every other output stays byte-identical to PRE_40 and PRE_41.
MOVED_IN_41 = ("routes", "netpol", "check", "egress-iam-approvals")


def moved_in_41(key):
    return key in MOVED_IN_41 or key.startswith("grants-")


def archive_cli(commit, prefix):
    """cli.py of `commit` (git archive of apps/iam), or None without git or that commit."""
    old = tempfile.mkdtemp(prefix=prefix)
    r = subprocess.run(f'git -C "{REPO}" archive {commit} apps/iam/compiler apps/iam/policy | tar -x -C "{old}"',
                       shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        shutil.rmtree(old, ignore_errors=True)
        return None, r.stderr.strip()
    return old, os.path.join(old, "apps", "iam", "compiler", "cli.py")


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("MEDCEA_POLICY")}
    env.update(extra)
    return env


def run_cli(args, cli=CLI, **env):
    r = subprocess.run([sys.executable, cli] + list(args), capture_output=True, text=True, env=clean_env(**env))
    return r.returncode, r.stdout, r.stderr


def scratch_tree():
    """A temp root with apps/iam/{compiler,policy}: its own state/ (the host file's place)."""
    root = tempfile.mkdtemp(prefix="medcea-source-")
    for d in ("compiler", "policy"):
        shutil.copytree(os.path.join(REPO, "apps", "iam", d), os.path.join(root, "apps", "iam", d),
                        ignore=shutil.ignore_patterns("__pycache__"))
    return root


def host_file_text(data, version=3, kind="change", skeleton_digest=None):
    head = (f"# medcea-applied: version={version} kind={kind} entries_digest={'e' * 64} "
            f"skeleton_digest={skeleton_digest or source.skeleton_digest(data)} git_commit=abc1234 "
            f"written_at=2026-11-02T00:00:00Z\n")
    return head + yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def artefacts(p, label="defaults.yaml"):
    """Every compiled artefact of a Policy, as cli.py prints it (stdout text)."""
    out = {
        "routes": routes.dumps(routes.compile(p, label)) + "\n",
        "mqtt": mqtt.dumps(mqtt.compile(p)) + "\n",
        "grafana": tools.grafana_role_path(p) + "\n",
        "node-red": json.dumps(tools.node_red_permissions(p), sort_keys=True) + "\n",
        "edge-wizard": ",".join(tools.edge_wizard_roles(p)) + "\n",
        "pgadmin": tools.pgadmin_claims(p) + "\n",
        "netpol": json.dumps(netpol.compile(p, "medcea", ["10.0.0.5"]), indent=1) + "\n",
        "grants-json": json.dumps(grants.document(p, False, False), indent=1, sort_keys=True) + "\n",
        "grants-json-smoke-without-iam": json.dumps(grants.document(p, True, True), indent=1, sort_keys=True) + "\n",
    }
    for s in ("allowed_groups", "admin_groups"):
        out["jupyterhub-" + s] = proxies.toml_list(tools.jupyterhub_groups(p, s)) + "\n"
    for c in sorted((p.data["network"].get("clients") or {})):
        out["egress-" + c] = json.dumps(netpol.egress(p, c), sort_keys=True, separators=(",", ":")) + "\n"
    for h in p.hosts:
        out["proxy-" + h] = proxies.toml_list(proxies.admitted(p, h)) + "\n"
    for mode in ("additive", "enforce", "verify"):
        for part in ("body", "assert", "all", "functions"):
            out[f"grants-{mode}-{part}"] = grants.sql(p, mode, False, part, [], False, label)
        out[f"grants-{mode}-smoke-without-iam"] = grants.sql(p, mode, True, "all", [], True, label)
    out["grants-additive-logins"] = grants.sql(p, "additive", False, "all", ["svc_scheduler", "svc_monitor"],
                                               False, label)
    # the commands that do not compile: hosts reads the source, db-roles and describe-gate
    # only the skeleton (cli.py SKELETON_ONLY)
    out["hosts"] = "".join(f"{h:18} [{proxies.ENFORCEMENT.get(h, 'unknown')}] {' '.join(proxies.admitted(p, h))}\n"
                           for h in p.hosts)
    out["db-roles-names"] = "\n".join(grants.managed(p) + ["mqtt_auth"]) + "\n"
    out["db-roles-logins"] = "\n".join(grants.login_roles(p)) + "\n"
    out["db-roles-passwords"] = "\n".join(f"{r} {v}" for r, v in grants.passwords(p)) + "\n"
    for h in p.hosts:
        lab, roles = proxies.describe(p, h, ["admin"])
        out["describe-gate-" + h] = html.escape(lab) + "\t" + html.escape(", ".join(roles)) + "\n"
    return out


def cli_argv(key):
    """The cli.py arguments that print artefacts()[key]."""
    if key in ("routes", "mqtt", "grafana", "node-red", "edge-wizard", "pgadmin"):
        return ["compile", key]
    if key in ("hosts", "check"):
        return [key]
    if key.startswith("db-roles-"):
        return ["db-roles", "--" + key[len("db-roles-"):]]
    if key.startswith("describe-gate-"):
        return ["describe-gate", key[len("describe-gate-"):], '["admin"]']
    if key == "netpol":
        return ["compile", "netpol", "--namespace", "medcea", "--node-ip", "10.0.0.5"]
    if key == "grants-json":
        return ["compile", "grants", "--format", "json"]
    if key == "grants-json-smoke-without-iam":
        return ["compile", "grants", "--format", "json", "--smoke", "--without-iam"]
    if key.startswith("jupyterhub-"):
        return ["compile", "jupyterhub", "--setting", key[len("jupyterhub-"):]]
    if key.startswith("egress-"):
        return ["compile", "egress", key[len("egress-"):]]
    if key.startswith("proxy-"):
        return ["compile", "proxy", key[len("proxy-"):]]
    if key == "grants-additive-logins":
        return ["compile", "grants", "--mode", "additive", "--service-logins", "svc_scheduler,svc_monitor"]
    _, mode, part = key.split("-", 2)
    if part == "smoke-without-iam":
        return ["compile", "grants", "--mode", mode, "--smoke", "--without-iam"]
    return ["compile", "grants", "--mode", mode, "--part", part]


class SourceIdentity(unittest.TestCase):
    """Slice 4.0's proof: nothing compiled changes."""

    @classmethod
    def setUpClass(cls):
        cls.root = scratch_tree()   # no state/: no host file, whatever this host has
        cls.cli = os.path.join(cls.root, "apps", "iam", "compiler", "cli.py")
        with open(DEFAULTS) as f:
            cls.direct = model.Policy(yaml.safe_load(f))   # the pre-4.0 model.load()
        cls.want = artefacts(cls.direct)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_every_target_byte_identical(self):
        self.assertGreater(len(self.want), 55)
        for key, want in self.want.items():
            rc, out, err = run_cli(cli_argv(key), cli=self.cli)
            self.assertEqual(rc, 0, f"{key}: {err}")
            self.assertEqual(out, want, key)
            self.assertNotIn("label from file name", err, key)

    def test_pre_40_cli_byte_identical(self):
        """The reference is the pre-4.0 cli.py and compiler, not a reimplementation."""
        old = tempfile.mkdtemp(prefix="medcea-pre40-")
        try:
            r = subprocess.run(f'git -C "{REPO}" archive {PRE_40} apps/iam/compiler apps/iam/policy | tar -x -C "{old}"',
                               shell=True, capture_output=True, text=True)
            if r.returncode != 0:
                self.skipTest(f"no git archive of {PRE_40}: {r.stderr.strip()}")
            old_cli = os.path.join(old, "apps", "iam", "compiler", "cli.py")
            for key in list(self.want) + ["check"]:
                if moved_in_41(key):
                    continue   # Phase41Delta
                argv = cli_argv(key)
                rc_old, want, err_old = run_cli(argv, cli=old_cli)
                rc, got, err = run_cli(argv, cli=self.cli)
                self.assertEqual(rc_old, 0, f"{key} (pre-4.0): {err_old}")
                self.assertEqual(rc, 0, f"{key}: {err}")
                if key == "check":
                    first, got = got.split("\n", 1)
                    self.assertEqual(first, "source: defaults.yaml (no applied version on this host)")
                self.assertEqual(got, want, key)
                self.assertEqual(err, err_old, key)
        finally:
            shutil.rmtree(old, ignore_errors=True)

    def test_load_is_the_factory_file(self):
        self.assertEqual(model.load_defaults().data, self.direct.data)
        src = source.resolve(env={}, host_file=os.path.join(self.root, "state", "policy-applied.yaml"))
        self.assertEqual((src.kind, source.label(src)), ("defaults", "defaults.yaml"))
        self.assertEqual(src.data, self.direct.data)

    def test_compose_round_trip_every_target(self):
        d = self.direct.data
        ew = source.entries_and_waivers(d)
        self.assertTrue(any(w.get("objects") for w in ew["waivers"]), "a waiver with objects (F-3)")
        composed = source.compose(source.skeleton(d), ew)
        self.assertEqual(composed["matrix"], d["matrix"])
        self.assertEqual(composed["waivers"], d["waivers"])
        self.assertEqual(composed["policy_version"], d["policy_version"])
        self.assertEqual(source.skeleton_digest(composed), source.skeleton_digest(d))
        got = artefacts(model.Policy(composed))
        for key in self.want:
            self.assertEqual(got[key], self.want[key], key)

    def test_compose_keeps_the_factory_policy_version(self):
        d = copy.deepcopy(self.direct.data)
        d["policy_version"] = 99
        composed = source.compose(source.skeleton(d), source.entries_and_waivers(d))
        self.assertEqual(composed["policy_version"], self.direct.data["policy_version"])
        self.assertEqual(source.compose(source.skeleton(d), source.entries_and_waivers(d), 7)["policy_version"], 7)

    def test_skeleton_excludes_matrix_waivers_version(self):
        sk = source.skeleton(self.direct.data)
        self.assertFalse({"matrix", "waivers", "policy_version"} & set(sk))
        d = copy.deepcopy(self.direct.data)
        d["matrix"]["portal"]["qa"] = ["R", "X"]
        d["waivers"] = []
        self.assertEqual(source.skeleton_digest(d), source.skeleton_digest(self.direct.data))
        d["roles"]["qa"]["label"] += " (changed)"
        self.assertNotEqual(source.skeleton_digest(d), source.skeleton_digest(self.direct.data))

    def test_entries_one_row_per_level(self):
        rows = [e for e in source.entries_and_waivers(self.direct.data)["entries"]
                if e["group_code"] == "master_data" and e["role"] == "qa"]
        self.assertEqual(sorted((e["level"], e["constraint_name"]) for e in rows),
                         [("A", "not_own_author"), ("R", None)])

    def test_compose_refuses_unknown_keys(self):
        d = self.direct.data
        ew = source.entries_and_waivers(d)
        ew["entries"].append({"role": "nobody", "group_code": "portal", "level": "R", "constraint_name": None})
        with self.assertRaises(source.SourceError):
            source.compose(source.skeleton(d), ew)


class Cells(unittest.TestCase):
    ORDER = ["R", "X", "C", "U", "A", "O", "K", "D"]

    def read(self, cell):
        p = model.Policy({**model.load_defaults().data, "matrix": {"portal": {"qa": cell}}})
        return p.cell("portal", "qa")

    def test_spellings(self):
        cases = [
            ([("U", None), ("R", None), ("C", None)], ["R", "C", "U"]),
            ([("R", None), ("A", "not_own_author")], {"levels": ["R", "A"], "constraint": "not_own_author",
                                                       "applies_to": ["A"]}),
            ([("R", "own_unit")], {"levels": ["R"], "constraint": "own_unit"}),
            ([("O", "assigned_run"), ("R", "own_unit")], {"levels": ["R", "O"],
                                                          "constraint": {"R": "own_unit", "O": "assigned_run"}}),
        ]
        for rows, want in cases:
            got = source.cells_to_yaml(rows, self.ORDER)
            self.assertEqual(got, want)
            self.assertEqual(self.read(got), self.read(want))
            self.assertEqual(source._cell_levels(got) and sorted(source._cell_levels(got)), sorted(rows))


class SourceRule(unittest.TestCase):

    def setUp(self):
        self.root = scratch_tree()
        self.cli = os.path.join(self.root, "apps", "iam", "compiler", "cli.py")
        self.state = os.path.join(self.root, "state")
        self.host = os.path.join(self.state, "policy-applied.yaml")
        self.factory = model.load_defaults().data

    def tearDown(self):
        if os.path.isdir(self.state):
            os.chmod(self.state, 0o700)
        shutil.rmtree(self.root, ignore_errors=True)

    def write_host(self, text):
        os.makedirs(self.state, mode=0o700, exist_ok=True)
        with open(self.host, "w") as f:
            f.write(text)

    def narrowed(self):
        d = copy.deepcopy(self.factory)
        del d["matrix"]["portal"]["engineer"]
        return d

    def routes_doc(self, *args, **env):
        rc, out, err = run_cli(list(args) + ["compile", "routes"], cli=self.cli, **env)
        return rc, (json.loads(out) if rc == 0 else None), err

    def test_defaults_without_anything(self):
        rc, doc, err = self.routes_doc()
        self.assertEqual((rc, doc["source"]), (0, "defaults.yaml"))
        rc, out, _ = run_cli(["check"], cli=self.cli)
        self.assertIn("source: defaults.yaml (no applied version on this host)", out)

    def test_break_glass_needs_a_reason(self):
        other = os.path.join(self.root, "other.yaml")
        with open(other, "w") as f:
            yaml.safe_dump(self.narrowed(), f)
        rc, _, err = self.routes_doc(MEDCEA_POLICY_FILE=other)
        self.assertEqual(rc, 2)
        self.assertIn("MEDCEA_POLICY_FILE is a break-glass override", err)
        rc, _, err = self.routes_doc(MEDCEA_POLICY_FILE=other, MEDCEA_POLICY_BREAK_GLASS="   ")
        self.assertEqual(rc, 2)
        rc, doc, _ = self.routes_doc(MEDCEA_POLICY_FILE=other, MEDCEA_POLICY_BREAK_GLASS="keycloak down")
        self.assertEqual((rc, doc["source"]), (0, "break-glass:keycloak down"))
        rc, out, _ = run_cli(["compile", "proxy", "PORTAL_DOMAIN"], cli=self.cli, MEDCEA_POLICY_FILE=other,
                             MEDCEA_POLICY_BREAK_GLASS="keycloak down")
        self.assertEqual(rc, 0)
        self.assertNotIn('"engineer"', out)

    def test_host_file_is_the_source(self):
        self.write_host(host_file_text(self.narrowed(), version=5))
        rc, doc, err = self.routes_doc()
        self.assertEqual((rc, doc["source"]), (0, "version-5"), err)
        rc, out, _ = run_cli(["compile", "proxy", "PORTAL_DOMAIN"], cli=self.cli)
        self.assertNotIn('"engineer"', out)
        rc, out, _ = run_cli(["--defaults", "compile", "proxy", "PORTAL_DOMAIN"], cli=self.cli)
        self.assertIn('"engineer"', out)
        rc, out, _ = run_cli(["check"], cli=self.cli)
        self.assertIn("source: version 5 (change)", out)
        rc, doc, _ = self.routes_doc("--label", "draft-7")
        self.assertEqual(doc["source"], "draft-7")

    def test_bad_host_files_exit_2(self):
        good = host_file_text(self.narrowed())
        bad = {
            "no header": good.split("\n", 1)[1],
            "digest mismatch": host_file_text(self.narrowed(), skeleton_digest="0" * 64),
            "bad version": good.replace("version=3", "version=x", 1),
            "bad kind": good.replace("kind=change", "kind=bogus", 1),
            "missing field": good.replace(" git_commit=abc1234", "", 1),
            "not a mapping": good.split("\n", 1)[0] + "\n- a\n- b\n",
        }
        for name, text in bad.items():
            self.write_host(text)
            rc, _, err = self.routes_doc()
            self.assertEqual(rc, 2, name)
            self.assertIn("ERROR:", err, name)
            # a skeleton-only command needs no source
            rc, out, _ = run_cli(["db-roles", "--names"], cli=self.cli)
            self.assertEqual(rc, 0, name)
            self.assertIn("rr_qa", out)

    def test_skeleton_only_commands_need_no_source(self):
        env = {"MEDCEA_POLICY_FILE": "/nonexistent"}
        rc, out, _ = run_cli(["db-roles", "--passwords"], cli=self.cli, **env)
        self.assertEqual(rc, 0)
        rc, out, _ = run_cli(["describe-gate", "PORTAL_DOMAIN", '["qa"]'], cli=self.cli, **env)
        self.assertEqual(rc, 0)
        rc, _, _ = run_cli(["compile", "routes"], cli=self.cli, **env)
        self.assertEqual(rc, 2)

    @unittest.skipIf(os.geteuid() == 0, "root reads a mode-000 directory")
    def test_unreadable_state_is_refused(self):
        self.write_host(host_file_text(self.narrowed()))
        os.chmod(self.state, 0)
        rc, _, err = self.routes_doc()
        self.assertEqual(rc, 2)
        self.assertIn("permission denied", err)

    def test_file_label_warns_and_file_beats_everything(self):
        self.write_host("garbage")
        f = os.path.join(self.root, "draft.yaml")
        with open(f, "w") as fh:
            yaml.safe_dump(self.factory, fh)
        rc, doc, err = self.routes_doc("--file", f, MEDCEA_POLICY_FILE="/nonexistent")
        self.assertEqual((rc, doc["source"]), (0, "draft.yaml"), err)
        self.assertIn("label from file name: not for deploys", err)
        rc, doc, err = self.routes_doc("--file", f, "--label", "x")
        self.assertNotIn("label from file name", err)
        rc, _, err = run_cli(["--file", f, "--defaults", "check"], cli=self.cli)
        self.assertEqual(rc, 2)

    def test_header_roundtrip(self):
        text = host_file_text(self.factory, version=12, kind="rollback")
        h = source.parse_header(text)
        self.assertEqual((h["version"], h["kind"]), ("12", "rollback"))
        with self.assertRaises(source.SourceError):
            source.parse_header(text.replace("version=12", "version=12 version=13", 1))


class Invariants(unittest.TestCase):

    def test_missing_approval_group_is_an_error(self):
        # S-B2: I12 no longer skips a missing iam_policy / iam_users group
        for g in ("iam_policy", "iam_users"):
            d = copy.deepcopy(model.load_defaults().data)
            del d["resource_groups"][g]
            d["matrix"].pop(g, None)
            mirrors = d["resource_groups"]["db_export"]["mirrors"]
            if g in mirrors:
                mirrors.remove(g) if isinstance(mirrors, list) else mirrors.pop(g)
            errors, _ = invariants.check(model.Policy(d))
            self.assertTrue(any(e.startswith(f"I12 group {g} is missing") for e in errors), g)


class Reach(unittest.TestCase):
    """explain.reach / model.widening_between (design §7): what a change adds."""

    @classmethod
    def setUpClass(cls):
        cls.p = model.load_defaults()

    def changed(self, fn):
        d = copy.deepcopy(self.p.data)
        fn(d)
        return model.Policy(d)

    def test_identity_and_unknown_role(self):
        for r in self.p.roles:
            self.assertEqual(model.widening_between(self.p, self.p, r), frozenset(), r)
            self.assertTrue(explain.reach(self.p, r), r)
        self.assertEqual(explain.reach(self.p, "nobody"), frozenset())

    def test_narrowing_adds_nothing(self):
        q = self.changed(lambda d: d["matrix"]["portal"].pop("engineer"))
        self.assertEqual(model.widening_between(self.p, q, "engineer"), frozenset())
        self.assertIn(("host", "PORTAL_DOMAIN", None), model.widening_between(q, self.p, "engineer"))

    def test_lost_constraint_widens(self):
        cell = self.p.matrix["master_data"]["qa"]
        self.assertIsInstance(cell, dict)
        q = self.changed(lambda d: d["matrix"]["master_data"].__setitem__("qa", list(cell["levels"])))
        added = model.widening_between(self.p, q, "qa")
        self.assertEqual({t for t in added if t[0] == "level"}, {("level", "master_data", "A", None)})

    def test_includes_expanded(self):
        # qa includes auditor (Keycloak composite): a cell given to auditor widens qa too
        self.assertIn("auditor", self.p.effective_roles("qa"))
        g = next(g for g in self.p.groups if not self.p.direct(g, "qa")[0] and "R" in self.p.levels
                 and any(m["type"] == "ui" for m in self.p.groups[g]["members"]))
        q = self.changed(lambda d: d["matrix"].setdefault(g, {}).__setitem__("auditor", ["R"]))
        added = model.widening_between(self.p, q, "auditor")
        self.assertIn(("level", g, "R", None), added)
        self.assertTrue(added <= model.widening_between(self.p, q, "qa"), g)

    def test_tool_and_mqtt(self):
        q = self.changed(lambda d: d["matrix"]["dashboards"].__setitem__("operator", ["R"]))
        self.assertIn(("tool", "dashboards", "Viewer", None), model.widening_between(self.p, q, "operator"))
        self.assertTrue(any(t[0] == "mqtt" for t in explain.reach(self.p, "engineer")))


LIB = os.path.join(REPO, "infra", "lib-policy-source.sh")


def bash(script, root=None, **env):
    """Run script after sourcing a copy of the library placed in root/infra."""
    root = root or tempfile.mkdtemp(prefix="medcea-libsrc-")
    os.makedirs(os.path.join(root, "infra"), exist_ok=True)
    shutil.copy(LIB, os.path.join(root, "infra"))
    e = clean_env(**env)
    e.pop("MEDCEA_LOCK_HELD", None)
    e.update({k: v for k, v in env.items()})
    r = subprocess.run(["bash", "-c", f'source "{root}/infra/lib-policy-source.sh"\n{script}'],
                       capture_output=True, text=True, env=e)
    return r.returncode, r.stdout, r.stderr, root


class LibSource(unittest.TestCase):

    def test_stub_passes_and_marks_once(self):
        rc, out, err, root = bash('policy_source_init medcea && echo "done=$MEDCEA_POLICY_SOURCE_DONE"',
                                  MEDCEA_LOCK_HELD="4242")
        self.assertEqual(rc, 0, err)
        self.assertIn("done=4242", out)
        self.assertEqual(err, "")
        shutil.rmtree(root)

    def test_usage(self):
        rc, _, _, root = bash("policy_source_init")
        self.assertEqual(rc, 2)
        rc, _, _, _ = bash("policy_source_init medcea --bogus", root=root)
        self.assertEqual(rc, 2)
        shutil.rmtree(root)

    def test_deploy_refuses_break_glass_until_recorded(self):
        rc, _, err, root = bash("policy_source_init medcea", MEDCEA_POLICY_FILE="/x", MEDCEA_POLICY_BREAK_GLASS="r")
        self.assertEqual(rc, 1)
        self.assertIn("MEDCEA_POLICY_FILE is set", err)
        shutil.rmtree(root)

    def test_deploy_refuses_an_unverified_host_file(self):
        root = tempfile.mkdtemp(prefix="medcea-libsrc-")
        os.makedirs(os.path.join(root, "state"))
        open(os.path.join(root, "state", "policy-applied.yaml"), "w").close()
        rc, _, err, _ = bash("policy_source_init medcea", root=root)
        self.assertEqual(rc, 1)
        self.assertIn("policy-applied.yaml exists", err)
        rc, _, err, _ = bash("policy_source_init medcea --read-only", root=root)
        self.assertEqual(rc, 0)
        self.assertIn("WARNING", err)
        shutil.rmtree(root)

    def test_read_only_drops_inherited_sources(self):
        rc, out, err, root = bash(
            'policy_source_init medcea --read-only && echo "[${MEDCEA_POLICY_FILE:-}|${MEDCEA_POLICY_BREAK_GLASS:-}|'
            '${MEDCEA_POLICY_SOURCE_DONE:-}]"',
            MEDCEA_POLICY_FILE="/x", MEDCEA_POLICY_BREAK_GLASS="r", MEDCEA_POLICY_SOURCE_DONE="1")
        self.assertEqual((rc, out.strip()), (0, "[||]"), err)
        shutil.rmtree(root)

    def test_marker_only_counts_under_the_same_lock(self):
        # a stale exported marker from another lock does not skip the guards
        rc, _, err, root = bash("policy_source_init medcea", MEDCEA_POLICY_SOURCE_DONE="111", MEDCEA_LOCK_HELD="222",
                                MEDCEA_POLICY_FILE="/x")
        self.assertEqual(rc, 1)
        rc, _, _, _ = bash("policy_source_init medcea", root=root, MEDCEA_POLICY_SOURCE_DONE="222",
                           MEDCEA_LOCK_HELD="222", MEDCEA_POLICY_FILE="/x")
        self.assertEqual(rc, 0)
        shutil.rmtree(root)


TOOLS = os.path.join(REPO, "infra", "lib-policy-tools.sh")


def tools_bash(script, **env):
    e = clean_env(REPO_ROOT=REPO, **env)
    for k in ("MEDCEA_LOCK_HELD", "IAM_GATES", "EDGE_WIZARD_ROLE"):
        if k not in env:
            e.pop(k, None)
    r = subprocess.run(["bash", "-c", f'source "{TOOLS}"\n{script}'], capture_output=True, text=True, env=e)
    return r.returncode, r.stdout, r.stderr


class LibTools(unittest.TestCase):
    """policy_tool is how edge/ compiles; it never inherits a break-glass file silently."""

    def test_no_override_compiles(self):
        rc, out, err = tools_bash("policy_tool edge-wizard")
        self.assertEqual((rc, out), (0, artefacts(model.load_defaults())["edge-wizard"]), err)

    def test_inherited_override_is_refused(self):
        for tool in ("edge-wizard", "pgadmin"):
            rc, out, err = tools_bash(f"policy_tool {tool}", MEDCEA_POLICY_FILE=DEFAULTS,
                                      MEDCEA_POLICY_BREAK_GLASS="trial")
            self.assertEqual((rc, out), (1, ""), tool)
            self.assertIn("MEDCEA_POLICY_FILE is set", err)

    def test_after_the_init_it_is_cli_pys_rule(self):
        # an entry script that ran the init (same shell) is past the guard; cli.py decides
        rc, out, err = tools_bash('MEDCEA_POLICY_SOURCE_DONE=1; policy_tool edge-wizard',
                                  MEDCEA_POLICY_FILE=DEFAULTS, MEDCEA_POLICY_BREAK_GLASS="trial")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, artefacts(model.load_defaults())["edge-wizard"])

    def test_gates_off_needs_no_compile(self):
        rc, out, _ = tools_bash("policy_tool pgadmin", IAM_GATES="false", MEDCEA_POLICY_FILE="/nonexistent")
        self.assertEqual((rc, out), (0, "{'groups': ['admin']}\n"))


def read(rel):
    with open(os.path.join(REPO, rel)) as f:
        return f.read()


# Entry scripts that compile the policy (directly or through lib-oauth2-proxy.sh,
# lib-policy-tools.sh or lib-db-apply.sh's db_apply), and how they call the init.
WRITERS = ["deploy-infra.sh", "infra/deploy-workbench.sh"] + [
    f"apps/{c}/deploy.sh" for c in ("access", "database", "edge-wizard", "frontend", "iam", "monitor",
                                    "mqtt-explorer", "scheduler")]
READERS = ["health-check.sh", "tests/iam-hosts.sh", "tests/iam-schema.sh", "tests/iam-signin.sh",
           "tests/iam-mqtt.sh", "tests/iam-access.sh"]
# Fixture-only: they compile the factory policy (--defaults / db_apply on medcea-iamtest).
FIXTURE = ["tests/iam-runner.sh", "tests/iam-db-fixture.sh", "tests/iam-postgrest.sh"]
# --defaults on the fixture namespace, the read-only init on any other.
EITHER = ["tests/iam-db.sh"]
COMPILES = re.compile(r"cli\.py\"? (compile|check|hosts)|\$CLI\"? (\"\$\{SRC\[@\]\}\" )?compile|"
                      r"\bpolicy_(groups|grafana|workbench|workbench_egress|tool)\b [A-Za-z\"$]|^\s*db_apply |"
                      r"\bdb_apply \"")


def code(text):
    """The script without comments (whole-line, and trailing `  # …`)."""
    return "\n".join(re.sub(r"\s+#\s.*$", "", l) for l in text.splitlines() if not l.lstrip().startswith("#"))


class Wiring(unittest.TestCase):

    def entry_scripts(self):
        out = []
        for d, _, files in os.walk(REPO):
            rel = os.path.relpath(d, REPO)
            if rel.startswith((".git", "docs", "codeplan", "logs", "edge", "schd")) or "__pycache__" in rel:
                continue
            for f in files:
                if f.endswith(".sh"):
                    p = os.path.normpath(os.path.join(rel, f))
                    if "medcea_log" in read(p) or p in ("deploy-infra.sh",):
                        out.append(p)
        return out

    def test_every_compiling_entry_script_is_wired(self):
        listed = set(WRITERS + READERS + FIXTURE + EITHER + ["guide.sh"])
        for p in self.entry_scripts():
            if COMPILES.search(code(read(p))):
                self.assertIn(p, listed, f"{p} compiles the policy: wire it (tests/test_policy_source.py)")

    def test_writers_call_the_init(self):
        for p in WRITERS:
            t = code(read(p))
            self.assertRegex(t, r'source "\$[A-Z_]+(/infra)?/lib-policy-source\.sh"', p)
            self.assertRegex(t, r'policy_source_init "\$\{?NAMESPACE(:-medcea\})?"? \|\| exit 1', p)
            self.assertNotIn("--read-only", re.findall(r"policy_source_init[^\n]*", t)[0], p)
            first_init = t.index("policy_source_init \"")
            m = COMPILES.search(t)
            self.assertTrue(m is None or m.start() > first_init, f"{p}: a compile before policy_source_init")

    def test_either_by_namespace(self):
        t = code(read("tests/iam-db.sh"))
        self.assertIn('if [[ "$NS" == "medcea-iamtest" ]]; then\n    SRC=(--defaults)\nelse\n'
                      '    source infra/lib-policy-source.sh; policy_source_init "$NS" --read-only\nfi', t)
        self.assertEqual(len(re.findall(r'python3 "\$CLI" compile', t)), 0)

    def test_readers_call_the_read_only_init(self):
        for p in READERS:
            t = code(read(p))
            self.assertRegex(t, r"policy_source_init \"\$\{NAMESPACE:-medcea\}\" --read-only", p)

    def test_no_deploy_passes_file_or_defaults(self):
        for p in WRITERS + READERS + ["infra/lib-oauth2-proxy.sh", "infra/lib-policy-tools.sh",
                                      "infra/lib-db-roles.sh", "apps/database/lib-db-apply.sh"]:
            t = code(read(p))
            self.assertNotRegex(t, r"cli\.py\"?[^\n|]*--file\b", p)
            if p != "apps/database/lib-db-apply.sh":
                self.assertNotIn("--defaults", t, p)
        lib = code(read("apps/database/lib-db-apply.sh"))
        self.assertIn('[[ "$ns" == medcea-iamtest ]] && src=(--defaults)', lib)
        self.assertEqual(lib.count("--defaults"), 1)

    def test_function_libraries_and_edge_do_not_init(self):
        # review finding 5: edge/ sources lib-policy-tools.sh at boot and without the
        # microk8s group; a library defines functions only
        for p in ("infra/lib-policy-tools.sh", "infra/lib-oauth2-proxy.sh", "infra/lib-db-roles.sh",
                  "apps/database/lib-db-apply.sh", "edge/wizard-daemon.sh", "edge/flash-device.sh"):
            self.assertNotIn("policy_source_init", code(read(p)), p)
            self.assertNotIn("lib-policy-source.sh", code(read(p)), p)

    def test_offline_tests_read_the_factory_policy(self):
        # iam-routes-diff.py too: offline, run by guide.sh (which does not init), and its
        # routes are skeleton, compared with the code on disk
        offline = [f for f in os.listdir(os.path.join(REPO, "tests"))
                   if f.startswith("test_") and f.endswith(".py") and f != "test_policy_source.py"]
        for f in offline + ["iam-routes-diff.py"]:
            t = read(os.path.join("tests", f))
            self.assertNotRegex(t, r"model\.load\((None)?\)", f)
            self.assertNotRegex(t, r"POLICY_MODEL\.load\(\)", f)
        self.assertIn("model.load_defaults()", read("tests/iam-routes-diff.py"))


class Phase41Delta(unittest.TestCase):
    """Slice 4.1 moves exactly what design §14.2.7 lists, against PRE_41 (slice 4.0)."""

    @classmethod
    def setUpClass(cls):
        cls.old, cls.old_cli = archive_cli(PRE_41, "medcea-pre41-")
        with open(DEFAULTS) as f:
            cls.p = model.Policy(yaml.safe_load(f))
        cls.want = artefacts(cls.p)

    @classmethod
    def tearDownClass(cls):
        if cls.old:
            shutil.rmtree(cls.old, ignore_errors=True)

    def setUp(self):
        if not self.old:
            self.skipTest(f"no git archive of {PRE_41}: {self.old_cli}")

    def old_out(self, key):
        rc, out, err = run_cli(cli_argv(key), cli=self.old_cli)
        self.assertEqual(rc, 0, f"{key} ({PRE_41}): {err}")
        return out

    def test_unmoved_outputs_byte_identical(self):
        for key, want in self.want.items():
            if moved_in_41(key):
                continue
            self.assertEqual(self.old_out(key), want, key)

    def test_routes_delta(self):
        old, new = json.loads(self.old_out("routes")), json.loads(self.want["routes"])
        self.assertNotIn("dual_control", old)
        self.assertEqual(new["dual_control"], {"iam_policy": {"approver_roles": ["qa"], "maker_roles": ["admin"]},
                                               "iam_users": {"approver_roles": ["qa"], "maker_roles": ["admin"]}})
        # services: only iam's routes, by exactly the declared ones; its clients unchanged
        self.assertEqual(set(old["services"]), set(new["services"]))
        for svc in new["services"]:
            if svc != "iam":
                self.assertEqual(old["services"][svc], new["services"][svc], svc)
        self.assertEqual(old["services"]["iam"]["clients"], new["services"]["iam"]["clients"])
        o, n = old["services"]["iam"]["routes"], new["services"]["iam"]["routes"]
        self.assertEqual(set(o) - set(n), {"GET /api/zones", "PUT /api/zones"})
        declared = {r for g in ("policy_page", "iam_policy", "audit_histories")
                    for m in self.p.groups[g]["members"] if m["type"] == "api" and m["service"] == "iam"
                    for r in m["routes"]}
        self.assertEqual(set(n), declared)
        for r in set(o) & set(n):
            self.assertEqual(o[r], n[r], r)
        # widening: only (policy_page, R) added, nothing removed
        for old_role in set(old["widening"]) | set(new["widening"]):
            ow, nw = old["widening"].get(old_role, {}), new["widening"].get(old_role, {})
            for new_role in set(ow) | set(nw):
                a = {tuple(x) for x in nw.get(new_role, [])}
                b = {tuple(x) for x in ow.get(new_role, [])}
                self.assertLessEqual(a - b, {("policy_page", "R")}, (old_role, new_role))
                self.assertEqual(b - a, set(), (old_role, new_role))
        self.assertTrue(any(["policy_page", "R"] in v for row in new["widening"].values() for v in row.values()))
        # exports: iam_policy gains skeleton and version_diff (approval_evidence is owner-only)
        og, ng = old["exports"]["groups"], new["exports"]["groups"]
        self.assertEqual(set(ng["iam_policy"]) - set(og["iam_policy"]), {"iam_policy.skeleton", "iam_policy.version_diff"})
        self.assertEqual(set(og["iam_policy"]) - set(ng["iam_policy"]), set())
        self.assertEqual({g: v for g, v in og.items() if g != "iam_policy"}, {g: v for g, v in ng.items() if g != "iam_policy"})
        self.assertEqual(old["exports"]["roles"], new["exports"]["roles"])
        # the rest of the body is unchanged
        for k in set(old) | set(new):
            if k not in ("services", "widening", "dual_control", "exports", "digest"):
                self.assertEqual(old.get(k), new.get(k), k)
        self.assertNotEqual(old["digest"], new["digest"])

    def test_netpol_delta(self):
        old = {i["metadata"]["name"]: i for i in json.loads(self.old_out("netpol"))["items"]}
        new = {i["metadata"]["name"]: i for i in json.loads(self.want["netpol"])["items"]}
        self.assertEqual(set(old), set(new))
        changed = {k for k in new if old[k] != new[k]}
        self.assertEqual(changed, {"iam-iam", "iam-config-api", "iam-access"})
        ports = [r["ports"][0]["port"] for r in new["iam-iam"]["spec"]["ingress"]]
        self.assertEqual(ports, [8085, 8083])

    def test_no_route_moves_mqtt_or_a_gate(self):
        """mqtt.json, the tool settings and every proxy gate: no restart, no credential retired."""
        for key in ["mqtt", "grafana", "node-red", "edge-wizard", "pgadmin", "hosts"] + \
                   [k for k in self.want if k.startswith(("proxy-", "describe-gate-", "jupyterhub-", "egress-notebooks"))]:
            self.assertEqual(self.old_out(key), self.want[key], key)


if __name__ == "__main__":
    unittest.main()
