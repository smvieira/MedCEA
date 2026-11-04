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
  Phase42aDelta    against PRE_42A (slice 4.1, 08fab15): every output byte-identical but
                   routes.json (its digest, which no longer hashes the source label, and the
                   new unhashed applied_version: null) and the grants SQL (role_widening()'s
                   COMMENT and the verify assert's digest literal, pre_request's only_rpc
                   block before the mode check, the fns assert array gaining
                   iam_policy._system_as(text[])); the grants document is unchanged
  SourceRule       --file/--defaults/MEDCEA_POLICY_FILE/host file in order; the refusals
                   (exit 2) and labels; db-roles and describe-gate need no source
  Cells            cells_to_yaml's three spellings read back as model.cell() reads the YAML
  HostFile         (4.2a) the host applied file: its two header lines, mode 600 in a 700
                   state/, written only under a verified lock (no lock, a fake or a non-ancestor
                   MEDCEA_LOCK_HELD, a 755 state/ refused), written_at alone no rewrite, edits
                   and a consistent forgery refused, an unreadable state/ an error, dropped rows,
                   the git key order, waiver rows, export-applied
  Gate             (4.2a) the skeleton gate: equal, narrowing, person and system widening, the
                   sections, the prose keys, cli.py's exit codes, --check, --against-git
  LibSource        (4.2a) policy_source_init and friends against a fake kubectl/psql in a
                   scratch tree: every state, the gate (narrowing accepted as system:deploy,
                   widening 2 with nothing written), --precheck, --read-only, the lock,
                   break-glass (refusals, OA-a, the record, the snapshot), the marker path,
                   policy_source_finish, policy_state_retire, the seed queue, policy_db_state's
                   kubectl rules
  LibTools         policy_tool refuses MEDCEA_POLICY_FILE unless this run recorded it (event
                   and sha256; edge/ compiles through it and never runs the init)
  V1HostFile       (4.2a) a host file of version 1 compiles every output as --defaults does
  Wiring           every entry script that compiles sources lib-policy-source.sh and calls
                   policy_source_init; no deploy passes --file; --defaults only for the fixture
                   namespace and the offline tests; the function libraries and edge/ do not
                   call it (design §3.4, review finding 5); the offline tests and
                   iam-routes-diff.py read the factory file

Run from the repository root:  python3 tests/test_policy_source.py
Offline: a scratch copy (tests/_scratch.py) for anything that needs a host file, a lock or
the shell libraries. No cluster; the only lock taken is a scratch tree's own.
"""
import base64
import copy
import hashlib
import html
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from compiler import explain, grants, invariants, model, mqtt, netpol, proxies, routes, source, tools  # noqa: E402
from compiler import cli as cli_mod  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scratch import clean_env, scratch_repo  # noqa: E402

CLI = os.path.join(REPO, "apps", "iam", "compiler", "cli.py")
DEFAULTS = os.path.join(REPO, "apps", "iam", "policy", "defaults.yaml")
# The last commit before slice 4.0: SourceIdentity runs its cli.py as the reference.
PRE_40 = "6b73e72"
# The last commit before slice 4.1 (slice 4.0 built): Phase41Delta's reference.
PRE_41 = "bdc7d48"
# The last commit before slice 4.2a (slice 4.1 built and deployed): Phase42aDelta's reference.
PRE_42A = "08fab15"
PRE_43 = "e18b4ee"   # slice 4.2b deployed: 4.3 changes no compiled artefact and no skeleton
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


def as_of_43(key, out):
    """An older commit's output with IAM 4.3's one listing change applied: `cli.py hosts`
    marks POLICY_DOMAIN [compiled] since its proxy exists (proxies.ENFORCEMENT is code, not
    skeleton; Phase43Delta pins that it is the only line that moved)."""
    return out.replace("[not deployed (Phase 4)]", "[compiled]") if key == "hosts" else out


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


def pg_order(obj):
    """obj with every dict's keys in jsonb's order (length, then bytes): what psql returns."""
    if isinstance(obj, dict):
        return {k: pg_order(obj[k]) for k in sorted(obj, key=lambda k: (len(k.encode()), k.encode()))}
    if isinstance(obj, list):
        return [pg_order(x) for x in obj]
    return obj


def make_state(data, version=3, kind="change", accepted=None, **extra):
    """A policy_db_state document for an applied version whose rows are data's matrix and
    waivers (round-tripped through JSON as psql returns them) and whose accepted skeleton is
    accepted's (default data's), in jsonb key order."""
    skel = source.skeleton(accepted if accepted is not None else data)
    ew = source.entries_and_waivers(data)
    st = {"state": f"version-{version}", "version": version, "kind": kind, "status": "applied",
          "entries_digest": source.policy_entries_digest(data, kind),
          "groups": sorted(data["resource_groups"]), "roles": sorted(data["roles"]),
          "based_on": None, "confirmed_at": None, "disputed_at": None, "claimed_by_person": None,
          "accepted": {"digest": source.skeleton_digest(skel), "body": pg_order(json.loads(json.dumps(skel))),
                       "git_commit": "abc1234"},
          "entries": json.loads(json.dumps(ew["entries"])),
          "waivers": pg_order(json.loads(json.dumps([source.waiver_row(w) for w in ew["waivers"]]))),
          "last_apply_event": {"event": "bootstrap_applied", "event_id": 9, "at": "2026-11-02T10:00:00+00:00"},
          "break_glass_open": [], "system_functions": {"system_as": True, "record": True}}
    st.update(extra)
    return st


def host_file_text(data, version=3, kind="change", skeleton_digest=None):
    """A well-formed host applied file of data (both header lines, as source writes them)."""
    text = source.host_file_text(make_state(data, version, kind), "abc1234", "2026-11-02T00:00:00Z", data=data)
    if skeleton_digest:
        text = text.replace(f"skeleton_digest={source.skeleton_digest(data)}", f"skeleton_digest={skeleton_digest}", 1)
    return text


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
                self.assertEqual(got, as_of_43(key, want), key)
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


class HostFile(unittest.TestCase):
    """The host applied file (design §14.4.3): text, checks, modes, the lock, export."""

    def setUp(self):
        self.root = scratch_repo()
        self.cli = os.path.join(self.root, "apps", "iam", "compiler", "cli.py")
        self.state_dir = os.path.join(self.root, "state")
        self.host = os.path.join(self.state_dir, "policy-applied.yaml")
        self.factory = model.load_defaults().data
        self.st = make_state(self.factory, version=1, kind="bootstrap")
        self.sf = os.path.join(self.root, "st.json")
        with open(self.sf, "w") as f:
            json.dump(self.st, f)

    def tearDown(self):
        for d in (self.state_dir,):
            if os.path.isdir(d):
                os.chmod(d, 0o700)
        shutil.rmtree(self.root, ignore_errors=True)

    def locked(self, cmd, **env):
        """cmd (a cli.py argument list) under a real medcea_lock of the scratch tree"""
        args = " ".join(shlex.quote(a) for a in cmd)
        r = subprocess.run(["bash", "-c", f'source "{self.root}/infra/lib-lock.sh"; medcea_lock; '
                                          f'python3 "{self.cli}" {args}'],
                           capture_output=True, text=True, env=clean_env(**env))
        return r.returncode, r.stdout, r.stderr

    def test_text_and_two_header_lines(self):
        text = source.host_file_text(self.st, "a" * 40, "2026-11-02T15:04:05Z", data=self.factory)
        l1, l2, l3, l4 = text.split("\n")[:4]
        self.assertRegex(l1, r"^# medcea-applied: version=1 kind=bootstrap entries_digest=[0-9a-f]{64} "
                             r"skeleton_digest=[0-9a-f]{64} git_commit=a{40} written_at=2026-11-02T15:04:05Z$")
        self.assertRegex(l2, r"^# medcea-applied-body: body_digest=[0-9a-f]{64} groups=\d+ roles=11 dropped=0 "
                             r"keys=[0-9a-f]{64}$")
        self.assertTrue(l3.startswith("# Written by infra/lib-policy-source.sh") and l4.startswith("# database's"))
        self.assertIn(f"entries_digest={source.policy_entries_digest(self.factory, 'bootstrap')}", l1)
        body = yaml.safe_load(text)
        self.assertEqual(body["matrix"], self.factory["matrix"])
        self.assertEqual(body["waivers"], self.factory["waivers"])
        skel_keys = lambda d: [k for k in d if k not in source.NOT_SKELETON]
        self.assertEqual(skel_keys(body), skel_keys(self.factory))   # the git key order, never jsonb's
        self.assertEqual(list(body["roles"]), list(self.factory["roles"]))

    def test_write_modes_lock_and_no_rewrite(self):
        rc, out, err = self.locked(["write-applied", "--state", self.sf])
        self.assertEqual(rc, 0, err)
        self.assertIn("version 1 (bootstrap) written", out)
        self.assertEqual(stat.S_IMODE(os.stat(self.state_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.host).st_mode), 0o600)
        with open(self.host) as f:
            first = f.read()
        self.assertNotIn("matrix", out + err)   # never prints the body
        # written_at/git_commit alone: no rewrite
        rc, out, err = self.locked(["write-applied", "--state", self.sf, "--if-different"])
        self.assertEqual((rc, out.strip()), (0, "[policy] state/policy-applied.yaml: version 1 (bootstrap) unchanged"), err)
        with open(self.host) as f:
            self.assertEqual(f.read(), first)
        # a different version rewrites
        with open(self.sf, "w") as f:
            json.dump(make_state(self.factory, version=2, kind="bootstrap"), f)
        rc, out, err = self.locked(["write-applied", "--state", self.sf, "--if-different"])
        self.assertIn("rewritten: it differed from the database", out, err)
        # it compiles: the routes record version-2, digest as defaults
        rc, out, err = run_cli(["compile", "routes"], cli=self.cli)
        self.assertEqual(rc, 0, err)
        self.assertEqual(err, "")
        doc = json.loads(out)
        self.assertEqual((doc["source"], doc["applied_version"]), ("version-2", 2))
        self.assertEqual(doc["digest"], routes.compile(model.load_defaults())["digest"])

    def test_writer_refusals(self):
        # no lock, a fake MEDCEA_LOCK_HELD, a live process that is not an ancestor
        rc, _, err = run_cli(["write-applied", "--state", self.sf], cli=self.cli)
        self.assertEqual(rc, 2)
        self.assertIn("deploy lock is not held", err)
        rc, _, err = run_cli(["write-applied", "--state", self.sf], cli=self.cli, MEDCEA_LOCK_HELD="1")
        self.assertEqual(rc, 2)
        other = subprocess.Popen(["sleep", "30"])
        try:
            rc, _, err = run_cli(["write-applied", "--state", self.sf], cli=self.cli, MEDCEA_LOCK_HELD=str(other.pid))
            self.assertEqual(rc, 2)
            self.assertIn("not an ancestor", err)
        finally:
            other.kill(); other.wait()
        self.assertFalse(os.path.exists(self.state_dir))
        # a state/ of mode 755
        os.mkdir(self.state_dir, 0o755)
        os.chmod(self.state_dir, 0o755)
        rc, _, err = self.locked(["write-applied", "--state", self.sf])
        self.assertEqual(rc, 2)
        self.assertIn("has mode 755", err)
        self.assertFalse(os.path.exists(self.host))
        self.assertEqual(stat.S_IMODE(os.stat(self.state_dir).st_mode), 0o755)   # never chmods it

    @unittest.skipIf(os.geteuid() != 0, "a foreign owner needs root to set up")
    def test_foreign_owner_refused(self):
        os.mkdir(self.state_dir, 0o700)
        os.chown(self.state_dir, 65534, 65534)
        rc, _, err = self.locked(["write-applied", "--state", self.sf])
        self.assertEqual(rc, 2)

    def write(self, text):
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        with open(self.host, "w") as f:
            f.write(text)

    def compile_rc(self):
        return run_cli(["compile", "routes"], cli=self.cli)[0]

    def test_edits_are_refused(self):
        good = source.host_file_text(self.st, "abc1234", "2026-11-02T00:00:00Z", data=self.factory)
        self.write(good)
        self.assertEqual(self.compile_rc(), 0)
        edits = {
            "matrix": good.replace("    qa:\n    - R\n", "    qa:\n    - R\n    - X\n", 1),
            "waiver": good.replace("review_by: '2027-10-27'", "review_by: '2029-10-27'", 1),
            "skeleton": good.replace("title: MedCEA default access policy", "title: X", 1),
            "line 2 gone": "\n".join(l for i, l in enumerate(good.split("\n")) if i != 1),
            "truncated": good[:len(good) // 2],
        }
        for name, text in edits.items():
            self.assertNotEqual(text, good, name)
            self.write(text)
            self.assertEqual(self.compile_rc(), 2, name)

    def test_consistent_forgery(self):
        # the matrix edited and body_digest recomputed, line 1 kept: the entries digest catches it
        good = source.host_file_text(self.st, "abc1234", "2026-11-02T00:00:00Z", data=self.factory)
        forged = copy.deepcopy(self.factory)
        forged["matrix"]["portal"]["qc"] = ["R", "X"]
        lines = good.split("\n")
        body = yaml.safe_load(good)
        body["matrix"] = forged["matrix"]
        old_bd = source.parse_body_header(good)["body_digest"]
        lines[1] = lines[1].replace(old_bd, source.body_digest(body))
        text = "\n".join(lines[:4]) + "\n" + yaml.safe_dump(body, sort_keys=False, allow_unicode=True, width=1000)
        self.write(text)
        rc, _, err = run_cli(["compile", "routes"], cli=self.cli)
        self.assertEqual(rc, 2)
        self.assertIn("entries_digest", err)
        # with dropped>0 (or other keys) the self-check cannot recompute; expected_body FAILs it
        text2 = text.replace(" dropped=0 ", " dropped=1 ", 1)
        self.write(text2)
        self.assertEqual(self.compile_rc(), 0)
        probs = source.host_file_problems(self.st, self.host)
        self.assertIn(("FAIL", "state/policy-applied.yaml differs from the applied version: the next deploy "
                               "rewrites it; until then edge compiles read it"), probs)
        self.assertEqual(source.host_file_differs(self.st, self.host), "different")

    @unittest.skipIf(os.geteuid() == 0, "root reads a mode-000 directory")
    def test_unreadable_state_is_an_error_never_absent(self):
        self.write(source.host_file_text(self.st, "abc1234", "2026-11-02T00:00:00Z", data=self.factory))
        os.chmod(self.state_dir, 0)
        with self.assertRaises(source.SourceError):
            source._host_file_present(self.host)
        self.assertEqual(source.host_file_problems(self.st, self.host)[0][0], "FAIL")

    def test_dropped_and_jsonb_order(self):
        # the accepted (= git) skeleton lost a group that has cells in the version
        d = copy.deepcopy(self.factory)
        gone = "portal"
        n = sum(len(source._cell_levels(c)) for c in d["matrix"][gone].values())
        st = make_state(d)
        skel = copy.deepcopy(d)
        del skel["resource_groups"][gone]
        st["accepted"] = {"digest": source.skeleton_digest(skel), "body": pg_order(json.loads(json.dumps(source.skeleton(skel)))),
                          "git_commit": "x"}
        composed, dropped = source.compose_applied(st, data=skel)
        self.assertEqual(dropped, n)
        self.assertNotIn(gone, composed["matrix"])
        self.assertEqual(list(composed["resource_groups"]), list(skel["resource_groups"]))   # git order
        text = source.host_file_text(st, "abc1234", "2026-11-02T00:00:00Z", data=skel)
        self.assertIn(f" dropped={n} ", text.split("\n")[1])
        self.assertEqual(source.expected_body(st)[1], n)
        # compose before the gate is an internal error
        with self.assertRaises(source.SourceError):
            source.compose_applied(st, data=d)

    def test_waiver_rows_round_trip(self):
        rows = make_state(self.factory)["waivers"]
        self.assertEqual([source.waiver_from_row(r) for r in rows], self.factory["waivers"])
        self.assertEqual([w["id"] for w in self.factory["waivers"]],
                         sorted((w["id"] for w in self.factory["waivers"]), key=lambda x: x.encode()))

    def test_export_applied(self):
        rc, _, err = run_cli(["export-applied"], cli=self.cli)
        self.assertEqual(rc, 2)
        self.assertIn("no applied version on this host", err)
        d = copy.deepcopy(self.factory)
        del d["matrix"]["portal"]["engineer"]
        st = make_state(d)
        self.write(source.host_file_text(st, "abc1234", "2026-11-02T00:00:00Z", data=d))
        rc, out, err = run_cli(["export-applied"], cli=self.cli)
        self.assertEqual(rc, 0, err)
        parsed = yaml.safe_load(out)
        self.assertEqual(parsed["matrix"], d["matrix"])
        self.assertEqual(parsed["waivers"], d["waivers"])
        self.assertEqual(source.skeleton(parsed), source.skeleton(d))
        with open(DEFAULTS) as f:
            orig = f.read()

        def outside(text):
            lines = text.splitlines(keepends=True)
            blocks = cli_mod._top_blocks(lines)
            keep = [l for i, l in enumerate(lines)
                    if not any(a <= i < b for k, (a, b) in blocks.items() if k in ("matrix", "waivers"))]
            return "".join(keep)
        self.assertEqual(outside(out), outside(orig))
        self.assertIn("# ── Invariants", out)


def broken_narrowing(data):
    """A skeleton that only narrows but fails the checker: master_data loses the function
    member its approval rule names."""
    git = copy.deepcopy(data)
    ms = git["resource_groups"]["master_data"]["members"]
    ms.remove(next(m for m in ms if m.get("function", "").startswith("medcea.approve_change(")))
    return git


class Gate(unittest.TestCase):
    """The skeleton gate (design §14.4.5): what counts as widening."""

    @classmethod
    def setUpClass(cls):
        cls.f = model.load_defaults().data
        cls.ew = source.entries_and_waivers(cls.f)

    def gate(self, change):
        d = copy.deepcopy(self.f)
        change(d)
        return explain.gate(self.f, d, self.ew)

    def api_member(self, d, group="audit_histories"):
        return next(m for m in d["resource_groups"][group]["members"] if m["type"] == "api")

    def test_equal_narrowing(self):
        self.assertEqual(explain.gate(self.f, copy.deepcopy(self.f), self.ew)["verdict"], "equal")
        g = self.gate(lambda d: d["resource_groups"]["portal"].__setitem__("description", "other words"))
        self.assertEqual((g["verdict"], g["added"]), ("narrowing", {}))
        g = self.gate(lambda d: d["hosts"]["PORTAL_DOMAIN"].__setitem__("label", "Portal"))
        self.assertEqual(g["verdict"], "narrowing")
        # a route removed narrows the roles that had it
        g = self.gate(lambda d: self.api_member(d, "portal")["routes"].pop("GET /_account/api/me"))
        self.assertEqual(g["verdict"], "narrowing")
        self.assertIn("qa", g["narrowed"])

    def widening(self, change, key=None):
        g = self.gate(change)
        self.assertEqual(g["verdict"], "widening", g)
        if key:
            self.assertIn(key, g["added"], g["added"])
        return g

    def test_person_widening(self):
        self.widening(lambda d: d["hosts"]["MONITOR_DOMAIN"]["serves"].append("scheduler"))
        g = self.widening(lambda d: self.api_member(d)["routes"].__setitem__("GET /api/e13-probe", "R"), "auditor")
        self.assertTrue(any(t[0] == "route" and t[2] == "GET /api/e13-probe" for t in g["added"]["auditor"]))
        self.widening(lambda d: d["roles"]["qc"].__setitem__("includes", ["engineer"]), "qc")
        self.widening(lambda d: d["resource_groups"]["dashboards"]["tool"]["settings"].insert(
            0, {"setting": "Admin", "levels": ["R"]}) if "settings" in d["resource_groups"]["dashboards"].get("tool", {})
            else d["resource_groups"]["dashboards"]["tool"].__setitem__("x", 1))

    def test_system_widening(self):
        g = self.widening(lambda d: d["public_routes"].append({"service": "monitor", "route": "GET /api/e13-public",
                                                               "why": "E13"}), "_system")
        self.assertIn(["public", "monitor", "GET /api/e13-public"], g["added"]["_system"])
        self.assertIn("anonymous and services: public monitor GET /api/e13-public", explain.gate_message(g))
        g = self.widening(lambda d: d["network"]["pods"]["iam"]["ingress"][0]["from"].append("ingress"), "_system")
        self.assertIn(["ingress", "iam", 8085, "ingress"], g["added"]["_system"])
        self.widening(lambda d: d["network"]["unproxied"].__setitem__("MONITOR_DOMAIN", "node"), "_system")
        self.widening(lambda d: d["network"]["clients"]["iam-approvals"]["only_rpc"].append("approve_change"), "_system")
        self.widening(lambda d: d["network"]["clients"]["notebooks"].__setitem__("read_only", False), "_system")
        self.widening(lambda d: d["service_identities"]["svc_ingest"]["ceiling"]["devices"].append("C"))

    def test_sections(self):
        g = self.widening(lambda d: d["invariants"].pop(0), "_sections")
        self.assertIn(["section", "invariants"], g["added"]["_sections"])
        self.widening(lambda d: d["invariants"][1].__setitem__("kind", "workflow"), "_sections")
        g = self.gate(lambda d: d["invariants"].append({"code": "I99", "kind": "matrix", "rule": "x", "rationale": "y"}))
        self.assertEqual(g["verdict"], "narrowing")
        self.widening(lambda d: d["waivable"].append("I12"), "_sections")
        g = self.widening(lambda d: d["constraints"]["own_unit"].__setitem__("effect", "other"), "_sections")
        self.assertIn(["section", "constraints"], g["added"]["_sections"])
        self.assertEqual(self.gate(lambda d: d["constraints"]["own_unit"].__setitem__("summary", "x"))["verdict"],
                         "narrowing")
        self.assertEqual(self.gate(lambda d: d["db_roles"]["anon"].__setitem__("why", "x"))["verdict"], "narrowing")

    def test_network_and_service_residue_widens(self):
        # review 4.2a: what a symbolic ingress source cannot show is compared whole
        cases = {
            "network.ingress_namespace": lambda d: d["network"].__setitem__("ingress_namespace", "medcea"),
            "network.no_shared_upstreams": lambda d: d["network"].__setitem__("no_shared_upstreams", []),
            "network.proxies.PORTAL_DOMAIN": lambda d: d["network"]["proxies"].__setitem__("PORTAL_DOMAIN", "x"),
            "network.pods.scheduler.selector.app": lambda d: d["network"]["pods"]["scheduler"].__setitem__(
                "selector", {"app": "nomatch"}),
            "network.pods.scheduler.carries.scheduler": lambda d: d["network"]["pods"]["scheduler"].__setitem__(
                "carries", {}),
            "network.clients.notebooks.selector.component": lambda d: d["network"]["clients"]["notebooks"][
                "selector"].pop("component"),
            "network.clients.iam-approvals.only_rpc": lambda d: d["network"]["clients"]["iam-approvals"][
                "only_rpc"].pop(),
            "service_identities.svc_monitor.mqtt_user": lambda d: d["service_identities"]["svc_monitor"].__setitem__(
                "mqtt_user", "mon"),
            "service_identities.svc_ingest.db_role": lambda d: d["service_identities"]["svc_ingest"].__setitem__(
                "db_role", "svc_other"),
            "roles.qc.db_role": lambda d: d["roles"]["qc"].__setitem__("db_role", "rr_other"),
        }
        for path, change in cases.items():
            with self.subTest(path):
                g = self.widening(change, "_sections")
                self.assertIn(["section", path], g["added"]["_sections"])
                self.assertIn(f"section {path} changed", explain.gate_message(g))
        # removing a source, a rule, a hop or an unproxied host still only narrows; prose too
        for change in (lambda d: d["network"]["pods"]["iam"]["ingress"][0]["from"].remove("node"),
                       lambda d: d["network"]["pods"]["iam"]["ingress"].pop(1),
                       lambda d: d["network"]["unproxied"].pop("ONBOARD_DOMAIN"),
                       lambda d: d["network"]["clients"]["notebooks"]["egress"].pop(0),
                       lambda d: d["network"]["pods"]["iam"]["ingress"][0].__setitem__("why", "other words"),
                       lambda d: d["roles"]["qc"].__setitem__("responsibilities", "other words")):
            self.assertEqual(self.gate(change)["verdict"], "narrowing")

    def test_every_skeleton_key_is_classified(self):
        # the pin: a key added to defaults.yaml needs a decision in explain.py (REACH_PATHS,
        # PROSE_PATHS, RESIDUE_PATHS or a section); until then it counts as residue (fails closed)
        found = {pat for pat, _, _ in explain.leaves(source.skeleton(self.f))}
        unclassified = sorted(p for p in found if explain.path_class(p) == "residue" and p not in explain.RESIDUE_PATHS)
        self.assertEqual(unclassified, [], "classify these skeleton keys in apps/iam/compiler/explain.py")
        for reg in (explain.REACH_PATHS, explain.PROSE_PATHS, explain.RESIDUE_PATHS):
            self.assertEqual(sorted(reg - found), [], "a registered path the policy no longer has")
        self.assertFalse(explain.REACH_PATHS & explain.RESIDUE_PATHS or explain.REACH_PATHS & explain.PROSE_PATHS
                         or explain.PROSE_PATHS & explain.RESIDUE_PATHS)
        # an unknown key anywhere is a widening
        g = self.widening(lambda d: d["network"]["pods"]["iam"].__setitem__("hostNetwork", True), "_sections")
        self.assertIn(["section", "network.pods.iam.hostNetwork"], g["added"]["_sections"])
        self.widening(lambda d: d.__setitem__("new_top_level", {"x": 1}), "_sections")

    def test_a_narrowing_that_fails_the_checker_is_refused(self):
        # review 4.2a: a narrowing is accepted without review, so it must pass the checker
        # composed with the applied rows first (cli.py skeleton-gate exit 2, verdict refused)
        root = scratch_repo()
        try:
            cli = os.path.join(root, "apps", "iam", "compiler", "cli.py")
            pol = os.path.join(root, "apps", "iam", "policy", "defaults.yaml")
            git = broken_narrowing(self.f)
            self.assertEqual(explain.gate(self.f, git, self.ew)["verdict"], "narrowing")
            self.assertTrue(explain.checker_errors(git, self.ew))
            with open(pol, "w") as fh:
                yaml.safe_dump(git, fh, sort_keys=False)
            sf = os.path.join(root, "st.json")
            with open(sf, "w") as fh:
                json.dump(make_state(self.f, accepted=self.f), fh)
            rc, out, err = run_cli(["skeleton-gate", "--state", sf], cli=cli)
            self.assertEqual(rc, 2, err)
            g = json.loads(out)
            self.assertEqual(g["verdict"], "refused")
            self.assertNotIn("body", g)
            self.assertIn("fails the checker", err)
            self.assertIn("it is not accepted and nothing was changed", err)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_text_keys_constant(self):
        self.assertEqual(source.TEXT_KEYS, ("help", "why", "summary", "label", "description", "title", "about"))
        found = set()

        def walk(x):
            if isinstance(x, dict):
                found.update(k for k in x if k in source.TEXT_KEYS)
                for v in x.values():
                    walk(v)
            elif isinstance(x, list):
                for v in x:
                    walk(v)
        walk(self.f)
        self.assertEqual(found, set(source.TEXT_KEYS) - {"help"} | ({"help"} & found))

    def test_cli_exit_codes_and_body(self):
        root = scratch_repo()
        try:
            cli = os.path.join(root, "apps", "iam", "compiler", "cli.py")
            sf = os.path.join(root, "st.json")
            older = copy.deepcopy(self.f)
            older["resource_groups"]["portal"]["description"] = "older words"
            for accepted, rc_want, verdict in ((self.f, 0, "equal"), (older, 0, "narrowing")):
                with open(sf, "w") as fh:
                    json.dump(make_state(self.f, accepted=accepted), fh)
                rc, out, err = run_cli(["skeleton-gate", "--state", sf], cli=cli)
                g = json.loads(out)
                self.assertEqual((rc, g["verdict"]), (rc_want, verdict), err)
                self.assertEqual("body" in g, verdict == "narrowing")
                if verdict == "narrowing":
                    self.assertEqual(hashlib.sha256(source.canonical(g["body"])).hexdigest(), g["git_digest"])
                    rc, out, _ = run_cli(["skeleton-gate", "--state", sf, "--check"], cli=cli)
                    self.assertNotIn("body", json.loads(out))
            wider = copy.deepcopy(self.f)
            wider["public_routes"] = [r for r in wider["public_routes"] if r["route"] != "GET /register"]
            with open(sf, "w") as fh:
                json.dump(make_state(self.f, accepted=wider), fh)
            rc, out, err = run_cli(["skeleton-gate", "--state", sf], cli=cli)
            self.assertEqual(rc, 3)
            self.assertEqual(json.loads(out)["verdict"], "widening")
            self.assertNotIn("body", json.loads(out))
            self.assertIn("Break-glass (MEDCEA_POLICY_FILE) does not bypass this check", err)
            self.assertIn("Nothing was changed.", err)
            with open(sf, "w") as fh:
                fh.write('{"state": "empty"}')
            self.assertEqual(run_cli(["skeleton-gate", "--state", sf], cli=cli)[0], 2)
            self.assertEqual(run_cli(["--defaults", "skeleton-gate", "--state", sf], cli=cli)[0], 2)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    @unittest.skipIf(shutil.which("git") is None, "no git")
    def test_against_git(self):
        root = scratch_repo()
        try:
            cli = os.path.join(root, "apps", "iam", "compiler", "cli.py")
            g = lambda *a: subprocess.run(["git", "-C", root] + list(a), capture_output=True, text=True, check=True)
            g("init", "-q")
            g("-c", "user.email=t@t", "-c", "user.name=t", "add", "apps/iam/policy")
            g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
            rc, out, err = run_cli(["skeleton-gate", "--against-git", "HEAD"], cli=cli)
            self.assertEqual((rc, json.loads(out)["verdict"]), (0, "equal"), err)
            pol = os.path.join(root, "apps", "iam", "policy", "defaults.yaml")
            with open(pol) as fh:
                text = fh.read()
            text = text.replace("public_routes:\n", "public_routes:\n  - {service: monitor, route: \"GET /api/e13-public\", why: E13}\n", 1)
            with open(pol, "w") as fh:
                fh.write(text)
            rc, out, err = run_cli(["skeleton-gate", "--against-git", "HEAD"], cli=cli)
            self.assertEqual(rc, 3, err)
            self.assertNotIn("body", json.loads(out))
            self.assertEqual(source.git_commit(root)[-6:], "-dirty")
        finally:
            shutil.rmtree(root, ignore_errors=True)


FAKE_KUBECTL = r"""#!/usr/bin/env python3
'''A fake kubectl for tests/test_policy_source.py LibSource: the cluster lives in $FAKE_DIR.
  sts        found | notfound | error            (get statefulset)
  pod        the PostgreSQL pod's name            (get pod -l …); empty: none
  ready      True | False                         (get pod NAME -o jsonpath; wait)
  sleep      seconds every call sleeps first
  db         1 | (empty)                          (the pg_database probe)
  state.json the state query's answer; an accept rewrites its accepted skeleton
  fail_write any non-read-only psql input fails (exit 1)
Every call is appended to log (argv), and an exec's stdin to log.sql (with a ---- line).'''
import base64, json, os, re, sys, time

D = os.environ["FAKE_DIR"]


def get(name, default=""):
    try:
        return open(os.path.join(D, name)).read().strip()
    except OSError:
        return default


args = sys.argv[1:]
with open(os.path.join(D, "log"), "a") as f:
    f.write(" ".join(args) + "\n")
if get("sleep"):
    time.sleep(float(get("sleep")))
if args[:2] == ["get", "statefulset"]:
    s = get("sts", "found")
    if s == "notfound":
        print(f'Error from server (NotFound): statefulsets.apps "{args[2]}" not found', file=sys.stderr)
        sys.exit(1)
    if s == "error":
        print("The connection to the server 127.0.0.1:16443 was refused", file=sys.stderr)
        sys.exit(1)
    print("statefulset.apps/" + args[2])
    sys.exit(0)
if args[:2] == ["get", "pod"] and "-l" in args:
    print(get("pod", "rdbms-postgresql-0"), end="")
    sys.exit(0)
if args[:2] == ["get", "pod"]:
    print(get("ready", "True"), end="")
    sys.exit(0)
if args[:1] == ["wait"]:
    sys.exit(0 if get("ready", "True") == "True" else 1)
if args[:1] == ["exec"]:
    sql = sys.stdin.read()
    with open(os.path.join(D, "log.sql"), "a") as f:
        f.write(sql + "\n----\n")
    if "FROM pg_catalog.pg_database" in sql:
        print(get("db", "1"))
        sys.exit(0)
    if "BEGIN TRANSACTION READ ONLY" in sql:
        print(get("state.json", '{"state": "none"}').replace("\n", " "))
        sys.exit(0)
    if os.path.exists(os.path.join(D, "fail_write")):
        print("ERROR:  fake failure", file=sys.stderr)
        sys.exit(1)
    if "_accept_skeleton" in sql:
        sets = dict(re.findall(r"^\\set (\w+) '([^']*)'$", sql, re.M))
        st = json.loads(get("state.json"))
        st["accepted"] = {"digest": sets["digest"], "body": json.loads(base64.b64decode(sets["body"])),
                          "git_commit": base64.b64decode(sets["commit"]).decode()}
        open(os.path.join(D, "state.json"), "w").write(json.dumps(st))
        sys.exit(0)
    if "_record('break_glass_seen'" in sql:
        print("41")
        sys.exit(0)
    sys.exit(0)
print("fake kubectl: unhandled " + " ".join(args), file=sys.stderr)
sys.exit(1)
"""


def lib_tree():
    """A scratch tree plus a bin/ with the fake kubectl and a fake microk8s, and a FAKE_DIR"""
    root = scratch_repo("medcea-libsrc-")
    for d in ("bin", "fake"):
        os.mkdir(os.path.join(root, d))
    for name in ("kubectl", "microk8s"):
        p = os.path.join(root, "bin", name)
        with open(p, "w") as f:
            f.write(FAKE_KUBECTL if name == "kubectl" else '#!/bin/sh\n[ "$1" = kubectl ] && shift\nexec kubectl "$@"\n')
        os.chmod(p, 0o755)
    return root


def bash(script, root=None, lock=True, **env):
    """Run script in a scratch tree (fake cluster on PATH, no terminal) after sourcing the
    library, under a real medcea_lock of that tree unless lock=False."""
    root = root or lib_tree()
    tmp = os.path.join(root, "tmp")   # the read-only init's state documents stay in the tree
    os.makedirs(tmp, mode=0o700, exist_ok=True)
    e = clean_env(PATH=os.path.join(root, "bin") + ":" + os.environ["PATH"], FAKE_DIR=os.path.join(root, "fake"),
                  KUBECTL="kubectl", POSTGRES_DB="medcea_db", TIMEOUT="5", TMPDIR=tmp)
    e.update(env)
    pre = f'source "{root}/infra/lib-lock.sh"; medcea_lock\n' if lock else ""
    r = subprocess.run(["bash", "-c", f'{pre}source "{root}/infra/lib-policy-source.sh"\n{script}'],
                       capture_output=True, text=True, env=e, cwd=root, start_new_session=True)
    return r.returncode, r.stdout, r.stderr, root


class LibSource(unittest.TestCase):
    """infra/lib-policy-source.sh against a fake cluster (design §14.4.4)."""

    def setUp(self):
        self.root = lib_tree()
        self.fake = os.path.join(self.root, "fake")
        self.factory = model.load_defaults().data
        self.host = os.path.join(self.root, "state", "policy-applied.yaml")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def put(self, name, value):
        with open(os.path.join(self.fake, name), "w") as f:
            f.write(value if isinstance(value, str) else json.dumps(value))

    def log(self, name="log"):
        try:
            with open(os.path.join(self.fake, name)) as f:
                return f.read()
        except OSError:
            return ""

    def run_(self, script, **kw):
        return bash(script, root=self.root, **kw)

    def init(self, *args, **kw):
        rc, out, err, _ = self.run_('policy_source_init medcea ' + " ".join(args) +
                                    '; rc=$?; echo "rc=$rc done=${MEDCEA_POLICY_SOURCE_DONE:-} state=${MEDCEA_POLICY_STATE:-}"'
                                    '; exit $rc', **kw)
        return rc, out, err

    def write_state(self, accepted=None, data=None, **extra):
        self.put("state.json", make_state(data or self.factory, version=1, kind="bootstrap", accepted=accepted, **extra))

    def write_host(self):
        os.makedirs(os.path.dirname(self.host), mode=0o700, exist_ok=True)
        with open(self.host, "w") as f:
            f.write(source.host_file_text(make_state(self.factory, 1, "bootstrap"), "abc1234", "2026-11-02T00:00:00Z"))

    def writes(self):
        return [b for b in self.log("log.sql").split("\n----\n")
                if b.strip() and "BEGIN TRANSACTION READ ONLY" not in b and "pg_catalog.pg_database" not in b]

    def test_usage(self):
        self.assertEqual(self.run_("policy_source_init")[0], 2)
        self.assertEqual(self.run_("policy_source_init medcea --bogus")[0], 2)

    def test_lock_is_verified(self):
        for env in ({}, {"MEDCEA_LOCK_HELD": "1"}, {"MEDCEA_LOCK_HELD": "1", "MEDCEA_POLICY_SOURCE_DONE": "1"},
                    {"MEDCEA_LOCK_HELD": "1", "MEDCEA_POLICY_SOURCE_DONE": "1", "MEDCEA_POLICY_FILE": DEFAULTS,
                     "MEDCEA_POLICY_BREAK_GLASS_EVENT": "5"}):
            rc, _, err = self.init(lock=False, **env)
            self.assertEqual(rc, 1, env)
            self.assertIn("runs under the deploy lock", err)
        holder = subprocess.Popen(["bash", "-c", f'source "{self.root}/infra/lib-lock.sh"; medcea_lock; sleep 30'],
                                  env=clean_env(), start_new_session=True)
        try:
            lock = os.path.join(self.root, ".medcea.lock")
            for _ in range(50):
                if os.path.exists(lock) and os.path.getsize(lock):
                    break
                time.sleep(0.1)
            rc, _, err = self.init(lock=False, MEDCEA_LOCK_HELD=str(holder.pid))
            self.assertEqual(rc, 1)
        finally:
            holder.kill(); holder.wait()
        self.assertFalse(self.writes())

    def test_none(self):
        rc, out, err = self.init(KUBECTL="")
        self.assertEqual(rc, 0, err)
        self.assertRegex(out, r"rc=0 done=\d+ state=none")
        self.put("sts", "notfound")
        rc, out, err = self.init()
        self.assertIn("state=none", out)
        self.put("sts", "found"); self.put("db", "")
        self.assertIn("state=none", self.init()[1])
        self.write_host()
        rc, _, err = self.init()
        self.assertEqual(rc, 1)
        self.assertIn("database has no policy versions", err)

    def test_empty_partial_unreachable(self):
        self.put("state.json", {"state": "empty", "break_glass_open": [], "system_functions": {"system_as": True}})
        rc, out, err = self.init()
        self.assertEqual((rc, "state=empty" in out), (0, True), err)
        self.assertFalse(os.path.exists(os.path.join(self.root, "state")))
        self.write_host()
        rc, _, err = self.init()
        self.assertEqual(rc, 1)
        self.assertIn("no applied version", err)
        self.put("state.json", {"state": "partial"})
        rc, _, err = self.init()
        self.assertEqual(rc, 1)
        self.assertIn("apply.sh --status", err)
        self.put("ready", "False")
        for present in (True, False):
            if not present:
                os.unlink(self.host)
            rc, _, err = self.init()
            self.assertEqual(rc, 1)
            self.assertIn("PostgreSQL is not Ready", err)
        self.put("sts", "error")
        self.assertEqual(self.init()[0], 1)

    def test_version_equal_writes_the_host_file_once(self):
        self.write_state()
        rc, out, err = self.init()
        self.assertEqual(rc, 0, err)
        self.assertIn("state/policy-applied.yaml: version 1 (bootstrap) written", out)
        self.assertIn("state=version-1", out)
        self.assertEqual(stat.S_IMODE(os.stat(self.host).st_mode), 0o600)
        with open(self.host) as f:
            first = f.read()
        self.assertFalse(self.writes())
        rc, out, err = self.init()
        self.assertNotIn("written", out)
        with open(self.host) as f:
            self.assertEqual(f.read(), first)
        # a different body on disk is rewritten
        with open(self.host, "w") as f:
            f.write(first.replace("dropped=0", "dropped=1"))
        rc, out, err = self.init()
        self.assertIn("rewritten: it differed from the database", out, err)
        # the marker path: a child under the same lock
        rc, out, err, _ = self.run_('policy_source_init medcea && bash -c "source infra/lib-policy-source.sh; '
                                    'policy_source_init medcea; echo child=\\$?"')
        self.assertIn("child=0", out, err)

    def test_narrowing_is_accepted_as_a_deploy(self):
        older = copy.deepcopy(self.factory)
        older["resource_groups"]["portal"]["description"] = "older words"
        self.write_state(accepted=older)
        rc, out, err = self.init()
        self.assertEqual(rc, 0, err)
        self.assertIn("accepted skeleton " + source.skeleton_digest(self.factory)[:12], out)
        w = self.writes()
        self.assertEqual(len(w), 1, w)
        self.assertIn("_set_internal_actor('system:deploy')", w[0])
        self.assertLess(w[0].index("_accept_skeleton"), w[0].index("_sync_skeleton"))
        self.assertTrue(os.path.exists(self.host))

    def widen(self):
        wider = copy.deepcopy(self.factory)
        wider["public_routes"] = [r for r in wider["public_routes"] if r["route"] != "GET /register"]
        self.write_state(accepted=wider)

    def test_a_narrowing_failing_the_checker_writes_nothing(self):
        # review 4.2a: the accept never happens before the checker has passed
        older = copy.deepcopy(self.factory)
        older["resource_groups"]["portal"]["description"] = "older words"
        pol = os.path.join(self.root, "apps", "iam", "policy", "defaults.yaml")
        git = broken_narrowing(self.factory)
        with open(pol, "w") as fh:
            yaml.safe_dump(git, fh, sort_keys=False)
        self.write_state(accepted=older)
        rc, out, err = self.init()
        self.assertEqual(rc, 1, out + err)
        self.assertIn("fails the checker", err)
        self.assertFalse(self.writes())
        self.assertFalse(os.path.exists(self.host))

    def test_versioned_mark(self):
        # review 4.2a: once a version was applied here, an absent host file is an error for
        # every compile outside a deploy, never a silent defaults.yaml
        mark = os.path.join(self.root, "state", ".policy-versioned")
        self.write_state()
        rc, out, err = self.init()
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.exists(mark), "written with the first host file")
        self.assertEqual(stat.S_IMODE(os.stat(mark).st_mode), 0o600)
        cli = os.path.join(self.root, "apps", "iam", "compiler", "cli.py")
        self.assertEqual(run_cli(["compile", "edge-wizard"], cli=cli)[0], 0)
        # a restore's step 2a moves the host file and keeps the mark: compiles refuse
        rc, _, err, _ = self.run_("policy_state_retire restore")
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.exists(mark))
        rc, _, err = run_cli(["compile", "edge-wizard"], cli=cli)
        self.assertEqual(rc, 2)
        self.assertIn("a policy version was applied on this host", err)
        # PostgreSQL cannot be asked: the init refuses too
        rc, _, err = self.init(KUBECTL="")
        self.assertEqual(rc, 1)
        self.assertIn("state/.policy-versioned", err)
        # the restored database answers "no applied version": the init retires the mark
        self.put("state.json", {"state": "empty", "break_glass_open": [], "system_functions": {"system_as": True}})
        rc, out, err = self.init()
        self.assertEqual(rc, 0, err)
        self.assertFalse(os.path.exists(mark))
        self.assertIn("-no-version", out)
        self.assertEqual(run_cli(["compile", "edge-wizard"], cli=cli)[0], 0)
        # purge-data (and reset, uninstall, rollback) move the mark with the rest
        self.write_state()
        self.assertEqual(self.init()[0], 0)
        self.assertTrue(os.path.exists(mark))
        rc, _, err, _ = self.run_("policy_state_retire purge-data")
        self.assertEqual(rc, 0, err)
        self.assertFalse(os.path.exists(mark))
        self.assertFalse(os.path.exists(self.host))

    def test_widening_returns_2_and_writes_nothing(self):
        self.widen()
        rc, out, err = self.init()
        self.assertEqual(rc, 2, err)
        self.assertIn("this git change gives access that has not been approved", err)
        self.assertFalse(self.writes())
        self.assertFalse(os.path.exists(self.host))
        self.assertIn("done= state=", out)

    def test_precheck(self):
        self.widen()
        rc, out, err = self.init("--precheck")
        self.assertEqual(rc, 2, err)
        self.assertNotIn("wait ", self.log())
        self.assertFalse(self.writes())
        self.write_state()
        rc, out, err = self.init("--precheck")
        self.assertEqual(rc, 0, err)
        self.assertIn("precheck: version-1", out)
        self.assertFalse(os.path.exists(self.host))
        self.put("ready", "False")
        self.assertEqual(self.init("--precheck")[0], 0)
        self.assertEqual(self.init("--precheck", lock=False)[0], 0)   # read-only: no lock needed

    def test_read_only(self):
        self.write_state()
        script = ('policy_source_init medcea --read-only; echo "rc=$? v=$POLICY_SOURCE_VERDICT s=$POLICY_SOURCE_STATE '
                  'd=$POLICY_SOURCE_DETAIL f=${MEDCEA_POLICY_FILE:-}"')
        rc, out, err, _ = self.run_(script, lock=False, MEDCEA_POLICY_FILE="/x", MEDCEA_POLICY_BREAK_GLASS="r",
                                    MEDCEA_POLICY_SOURCE_DONE="1")
        self.assertEqual(rc, 0)
        self.assertIn("rc=0 v=fail s=version-1", out)
        self.assertIn("is absent", out)
        self.assertIn("f=\n", out)
        self.assertFalse(self.writes())
        self.assertFalse(os.path.exists(os.path.join(self.root, "state")))
        self.assertNotIn("wait ", self.log())
        self.write_host()
        rc, out, _, _ = self.run_(script, lock=False)
        self.assertIn("v=ok", out)
        self.widen()
        rc, out, _, _ = self.run_(script, lock=False)
        self.assertIn("v=fail", out)
        self.assertIn("widens", out)
        self.put("state.json", {"state": "empty"})
        os.unlink(self.host)
        rc, out, _, _ = self.run_(script, lock=False)
        self.assertIn("v=fail", out)
        self.assertIn("no applied version: a widening git change is not gated", out)
        rc, out, _, _ = self.run_(script, lock=False, KUBECTL="")
        self.assertIn("v=skip", out)

    def test_db_state_kubectl_rules(self):
        st = os.path.join(self.root, "st.json")
        # a function as the first word counts (mk8s), with microk8s on PATH
        rc, out, err, _ = self.run_(f'mk8s() {{ microk8s "$@"; }}; KUBECTL="mk8s kubectl"; policy_db_state medcea {st}',
                                    lock=False)
        self.assertEqual(out.strip(), "none", err)   # no state.json in the fake: none
        self.assertIn("get statefulset rdbms-postgresql", self.log())
        rc, out, err, _ = self.run_(f'policy_db_state medcea {st}', lock=False, PG_RELEASE="other")
        self.assertIn("get statefulset other-postgresql", self.log())
        self.assertEqual(stat.S_IMODE(os.stat(st).st_mode), 0o600)
        # --no-wait: no kubectl wait, and a bound
        open(os.path.join(self.fake, "log"), "w").close()
        self.put("sleep", "20")
        t = time.time()
        rc, out, err, _ = self.run_(f'policy_db_state medcea {st} --no-wait', lock=False, TIMEOUT="1")
        self.assertLess(time.time() - t, 15)
        self.assertEqual(out.strip(), "unreachable")
        os.unlink(os.path.join(self.fake, "sleep"))
        self.assertNotIn("wait ", self.log())
        # sudo: read-only callers run sudo -n
        sudo = os.path.join(self.root, "bin", "sudo")
        with open(sudo, "w") as f:
            f.write(f'#!/bin/sh\necho "sudo $*" >> "{self.fake}/sudo.log"\n[ "$1" = -n ] && shift\nexec "$@"\n')
        os.chmod(sudo, 0o755)
        self.run_(f'policy_db_state medcea {st} --no-wait', lock=False, KUBECTL="sudo kubectl")
        self.assertTrue(all(l.startswith("sudo -n kubectl") for l in self.log("sudo.log").splitlines()), self.log("sudo.log"))
        # no kubectl at all
        rc, out, _, _ = self.run_(f'policy_db_state medcea {st}', lock=False, KUBECTL="no-such-kubectl")
        self.assertEqual(out.strip(), "none")

    def test_sourced_from_elsewhere(self):
        other = tempfile.mkdtemp()
        try:
            r = subprocess.run(["bash", "-c", f'unset REPO_ROOT; cd "{other}"; source "{self.root}/infra/lib-policy-source.sh" '
                                              '&& declare -F _dba_psql _dbr_pg_pod medcea_lock_verify dba_record_event >/dev/null '
                                              '&& echo "$POLICY_HOST_FILE"'],
                               capture_output=True, text=True, env=clean_env())
            self.assertEqual(r.stdout.strip(), os.path.join(self.root, "state", "policy-applied.yaml"), r.stderr)
        finally:
            shutil.rmtree(other)

    def test_retire(self):
        self.write_host()
        sd = os.path.join(self.root, "state")
        os.mkdir(os.path.join(sd, "break-glass"), 0o700)
        open(os.path.join(sd, "seed-facts.jsonl"), "w").close()
        self.assertEqual(self.run_("policy_state_retire purge-data", lock=False)[0], 1)
        rc, out, err, _ = self.run_("policy_state_retire purge-data")
        self.assertEqual(rc, 0, err)
        left = os.listdir(sd)
        self.assertEqual(len(left), 1)
        self.assertTrue(left[0].startswith("retired-") and left[0].endswith("-purge-data"))
        self.assertEqual(sorted(os.listdir(os.path.join(sd, left[0]))),
                         ["break-glass", "policy-applied.yaml", "seed-facts.jsonl"])
        # purge, then deploy: none and absent
        self.put("db", "")
        self.assertEqual(self.init()[0], 0)
        self.assertEqual(self.run_("policy_state_retire 'bad why'")[0], 2)

    def seed(self, n=2, bad=False):
        sd = os.path.join(self.root, "state")
        os.makedirs(sd, mode=0o700, exist_ok=True)
        with open(os.path.join(sd, "seed-facts.jsonl"), "w") as f:
            for i in range(n):
                fact = {"fact": "observed", "username": f"u{i}", "sub": f"0000000{i}-0000-0000-0000-000000000000",
                        "role": "qa", "person_id": None, "by": "deploy-infra.sh"}
                fact["fact_id"] = source.fact_id(fact)
                f.write(json.dumps(fact) + "\n")
            if bad:
                f.write("{not json\n")
        return os.path.join(sd, "seed-facts.jsonl")

    def test_seed_flush(self):
        q = self.seed()
        self.put("state.json", {"state": "empty", "system_functions": {"system_as": True}})
        rc, out, err = self.init()
        self.assertEqual(rc, 0, err)
        self.assertIn("2 queued account fact(s) recorded", out)
        self.assertFalse(os.path.exists(q))
        w = self.writes()
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0].count("_record('account_seeded'"), 2)
        # a failing flush, in empty and in version-N: a WARNING, the queue stays, rc 0
        self.seed()
        self.put("fail_write", "")
        for st in ({"state": "empty", "system_functions": {"system_as": True}}, None):
            if st:
                self.put("state.json", st)
            else:
                self.write_state()
            rc, out, err = self.init()
            self.assertEqual(rc, 0, err)
            self.assertIn("WARNING", err)
            self.assertTrue(os.path.exists(q))
        os.unlink(os.path.join(self.fake, "fail_write"))
        q = self.seed(bad=True)
        rc, out, err = self.init()
        self.assertEqual(rc, 0)
        self.assertIn("line 3 of state/seed-facts.jsonl is not a seed fact", err)
        # without _system_as the queue waits silently
        self.seed()
        self.put("state.json", {"state": "empty", "system_functions": {"system_as": False}})
        rc, out, err = self.init()
        self.assertTrue(os.path.exists(q))
        self.assertNotIn("recorded", out)

    def break_glass_file(self, change=None):
        d = copy.deepcopy(self.factory)
        del d["matrix"]["portal"]["engineer"]
        if change:
            change(d)
        fd, p = tempfile.mkstemp(prefix="draft-", suffix=".yaml", dir=self.root)
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(d, f, sort_keys=False)
        return p

    def bg(self, **env):
        e = {"MEDCEA_POLICY_FILE": self.break_glass_file(), "MEDCEA_POLICY_BREAK_GLASS": "keycloak down",
             "MEDCEA_POLICY_COMPONENTS": "monitor,scheduler"}
        e.update(env)
        script = ('policy_source_init medcea; rc=$?; echo "rc=$rc ev=${MEDCEA_POLICY_BREAK_GLASS_EVENT:-} '
                  'sha=${MEDCEA_POLICY_BREAK_GLASS_SHA256:-} acc=${MEDCEA_POLICY_ACCEPTED_SKELETON:-} '
                  'file=${MEDCEA_POLICY_FILE:-}"; [ $rc = 0 ] && python3 apps/iam/compiler/cli.py compile routes '
                  '| python3 -c "import json,sys; print(\'src=\' + json.load(sys.stdin)[\'source\'])"; exit $rc')
        rc, out, err, _ = self.run_(script, **{k: v for k, v in e.items() if v is not None})
        return rc, out, err

    def test_break_glass_refusals(self):
        self.write_state()
        rc, _, err = self.bg(MEDCEA_POLICY_BREAK_GLASS=" ")
        self.assertEqual(rc, 1)
        self.assertIn("set MEDCEA_POLICY_BREAK_GLASS=<reason>", err)
        rc, _, err = self.bg()   # no terminal, not asked by deploy-apps
        self.assertEqual(rc, 1)
        self.assertIn("needs a person at the terminal", err)
        # deploy-apps/install asked already (MEDCEA_POLICY_BREAK_GLASS_ASKED = the lock holder)
        self.put("state.json", {"state": "empty", "system_functions": {"system_as": True}})
        rc, _, err = self.bg_asked()
        self.assertEqual(rc, 1)
        self.assertIn("break-glass needs an applied policy version: there is none", err)
        self.widen()
        rc, _, err = self.bg_asked()
        self.assertEqual(rc, 2)   # OA-a: a widening git skeleton is refused under break-glass too
        self.assertIn("does not bypass this check", err)
        self.write_state()
        rc, _, err = self.bg_asked(MEDCEA_POLICY_FILE=self.break_glass_file(
            lambda d: d["resource_groups"]["portal"].__setitem__("description", "x")))
        self.assertEqual(rc, 1)
        self.assertIn("a skeleton change goes through git", err)
        rc, _, err = self.bg_asked(MEDCEA_POLICY_FILE=self.break_glass_file(
            lambda d: d["matrix"]["iam_users"].__setitem__("operator", ["R"])))
        self.assertEqual(rc, 1)
        self.assertIn("cannot change who approves", err)
        self.assertFalse([w for w in self.writes() if "break_glass_seen" in w])
        self.assertFalse(os.path.exists(self.host))

    def bg_asked(self, **env):
        e = {"MEDCEA_POLICY_FILE": self.break_glass_file(), "MEDCEA_POLICY_BREAK_GLASS": "keycloak down",
             "MEDCEA_POLICY_COMPONENTS": "monitor,scheduler"}
        e.update(env)
        script = ('export MEDCEA_POLICY_BREAK_GLASS_ASKED="$MEDCEA_LOCK_HELD"; policy_source_init medcea; rc=$?; '
                  'echo "rc=$rc ev=${MEDCEA_POLICY_BREAK_GLASS_EVENT:-} sha=${MEDCEA_POLICY_BREAK_GLASS_SHA256:-} '
                  'acc=${MEDCEA_POLICY_ACCEPTED_SKELETON:-} file=${MEDCEA_POLICY_FILE:-}"; '
                  '[ $rc = 0 ] || exit $rc; '
                  'python3 apps/iam/compiler/cli.py compile routes | python3 -c "import json,sys; '
                  'print(\'src=\' + json.load(sys.stdin)[\'source\'])"; '
                  'echo tampered >> "$MEDCEA_POLICY_FILE"; python3 apps/iam/compiler/cli.py compile routes >/dev/null; '
                  'echo "after-edit=$?"; policy_source_init medcea; echo "marker=$?"')
        rc, out, err, _ = self.run_(script, **e)
        return rc, out, err

    def test_break_glass_recorded(self):
        self.write_state()
        orig = self.break_glass_file()
        rc, out, err = self.bg_asked(MEDCEA_POLICY_FILE=orig)
        self.assertEqual(rc, 0, err)
        m = re.search(r"rc=0 ev=(\S+) sha=(\S+) acc=(\S+) file=(\S+)", out)
        self.assertTrue(m, out)
        ev, sha, acc, snap = m.groups()
        self.assertEqual(ev, "41")
        self.assertEqual(acc, source.skeleton_digest(self.factory))
        self.assertTrue(snap.startswith(os.path.join(self.root, "state", "break-glass") + "/"), snap)
        self.assertEqual(sha, source.file_sha256(orig))
        self.assertIn("src=break-glass:keycloak down", out)
        self.assertIn("BREAK-GLASS: compiling", err)
        # the snapshot edited after the record: every compile and the marker path refuse it
        self.assertIn("after-edit=2", out)
        self.assertIn("marker=1", out)
        rec = [w for w in self.writes() if "_record('break_glass_seen'" in w]
        self.assertEqual(len(rec), 1)
        payload = json.loads(base64.b64decode(re.search(r"\\set payload '([^']+)'", rec[0]).group(1)))
        self.assertEqual((payload["source"], payload["version"], payload["reason"], payload["components"]),
                         ("file", 1, "keycloak down", ["monitor", "scheduler"]))
        self.assertEqual(payload["file_sha256"], sha)
        self.assertTrue(payload["snapshot"].startswith("state/break-glass/"))
        # the host file still names the applied version
        with open(self.host) as f:
            self.assertIn("version=1 kind=bootstrap", f.readline())

    def test_marker_path_break_glass_checks(self):
        f = self.break_glass_file()
        base = 'export MEDCEA_POLICY_SOURCE_DONE="$MEDCEA_LOCK_HELD"; '
        for extra, want in (("", 1), ("export MEDCEA_POLICY_BREAK_GLASS_EVENT=5; ", 1),
                            ("export MEDCEA_POLICY_BREAK_GLASS_EVENT=5 MEDCEA_POLICY_BREAK_GLASS_SHA256=" + "0" * 64 + "; ", 1),
                            ("export MEDCEA_POLICY_BREAK_GLASS_EVENT=5 MEDCEA_POLICY_BREAK_GLASS_SHA256="
                             + source.file_sha256(f) + "; ", 0)):
            rc, _, err, _ = self.run_(base + extra + "policy_source_init medcea", MEDCEA_POLICY_FILE=f,
                                      MEDCEA_POLICY_BREAK_GLASS="r")
            self.assertEqual(rc, want, extra + err)

    def test_finish(self):
        bg_open = json.dumps([{"event_id": 41, "open": ["monitor", "scheduler"]}, {"event_id": 50, "open": ["iam"]}])
        rc, out, err, _ = self.run_("policy_source_finish medcea monitor", MEDCEA_POLICY_BG_OPEN=bg_open)
        self.assertEqual(rc, 0, err)
        recs = [l for l in self.log("log").splitlines() if l.startswith("exec")]
        self.assertEqual(len(recs), 1, self.log())
        self.assertIn("ended for monitor", out)
        self.assertIn("ev=break_glass_ended", recs[0])
        self.assertIn('"since_event": 41', recs[0])
        self.assertIn('"component": "monitor"', recs[0])
        open(os.path.join(self.fake, "log"), "w").close()
        for script, env in (("policy_source_finish medcea monitor", {"MEDCEA_POLICY_FILE": "/x"}),
                            ("policy_source_finish medcea frontend", {})):
            rc, _, _, _ = self.run_(script, MEDCEA_POLICY_BG_OPEN=bg_open, **env)
            self.assertEqual(rc, 0)
        self.assertNotIn("exec", self.log())
        self.put("fail_write", "")
        rc, _, err, _ = self.run_("policy_source_finish medcea iam", MEDCEA_POLICY_BG_OPEN=bg_open)
        self.assertEqual(rc, 0)
        self.assertIn("the break-glass end of iam is not recorded", err)


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

    def test_done_without_a_recorded_event_is_refused(self):
        rc, out, err = tools_bash("MEDCEA_POLICY_SOURCE_DONE=1; policy_tool edge-wizard",
                                  MEDCEA_POLICY_FILE=DEFAULTS, MEDCEA_POLICY_BREAK_GLASS="trial")
        self.assertEqual((rc, out), (1, ""))
        rc, out, err = tools_bash("MEDCEA_POLICY_SOURCE_DONE=1; policy_tool edge-wizard",
                                  MEDCEA_POLICY_FILE=DEFAULTS, MEDCEA_POLICY_BREAK_GLASS="trial",
                                  MEDCEA_POLICY_BREAK_GLASS_EVENT="41", MEDCEA_POLICY_BREAK_GLASS_SHA256="0" * 64)
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("is not the break-glass file this run recorded", err)

    def test_a_recorded_override_is_cli_pys_rule(self):
        rc, out, err = tools_bash("MEDCEA_POLICY_SOURCE_DONE=1; policy_tool edge-wizard",
                                  MEDCEA_POLICY_FILE=DEFAULTS, MEDCEA_POLICY_BREAK_GLASS="trial",
                                  MEDCEA_POLICY_BREAK_GLASS_EVENT="41",
                                  MEDCEA_POLICY_BREAK_GLASS_SHA256=source.file_sha256(DEFAULTS))
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
WRITERS = ["deploy-infra.sh", "infra/deploy-workbench.sh", "infra/deploy-policy.sh"] + [
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
            # `|| exit $?` passes a widening's 2 on (IAM 4.2a); never `|| exit 1`
            self.assertRegex(t, r'policy_source_init "\$\{?NAMESPACE(:-medcea\})?"? \|\| exit \$\?', p)
            self.assertNotRegex(t, r"policy_source_init[^\n]*\|\| exit 1", p)
            self.assertNotIn("--read-only", "".join(re.findall(r"policy_source_init[^\n]*", t)), p)
            full_init = re.search(r'policy_source_init "\$\{?NAMESPACE(:-medcea\})?"? \|\|', t).start()
            m = COMPILES.search(t)
            self.assertTrue(m is None or m.start() > full_init, f"{p}: a compile before policy_source_init")

    def test_every_writer_ends_with_finish(self):
        # review 4.2a: break_glass_ended needs policy_source_finish at the end of each success path
        comps = {"deploy-infra.sh": "infra", "infra/deploy-workbench.sh": "workbench", "infra/deploy-policy.sh": "infra"}
        for p in WRITERS:
            comp = comps.get(p) or p.split("/")[1]
            t = code(read(p))
            self.assertIn(f'policy_source_finish "$NAMESPACE" {comp}', t, p)
            if p == "deploy-infra.sh":
                self.assertLess(t.index("policy_source_finish"), t.index("SUCCESS: $NAMESPACE is live!"))
            elif p != "apps/iam/deploy.sh":
                self.assertTrue(t.rstrip().endswith(f'policy_source_finish "$NAMESPACE" {comp}'), p)

    def test_deploy_infra_reads_the_policy_after_postgres(self):
        # review 4.2a: the precheck after the API wait; the full init after the rdbms helm
        # --wait, before anything compiled reaches the cluster; nothing compiles before it
        t = code(read("deploy-infra.sh"))
        api = t.index('echo -e "${GREEN}API ready.${NC}"')
        pre = t.index('policy_source_init "$NAMESPACE" --precheck || exit $?')
        self.assertLess(api, pre)
        self.assertLess(t.index('KUBECTL="$MK8S kubectl"\npolicy_source_init'), pre + 1)
        self.assertLess(pre, t.index("DOCKER_CERTS_DIR="))
        rdbms = t.index("helm3 upgrade --install rdbms")
        full = t.index('policy_source_init "$NAMESPACE" || exit $?')
        self.assertLess(rdbms, full)
        self.assertIn("--wait", t[rdbms:full])
        # IAM 4.2b: the blocks are infra/lib-policy-artefacts.sh's, called at the same place
        self.assertLess(full, t.index("pa_iam_lib full"))
        self.assertLess(full, t.index("pa_netpol full"))
        lib = code(read("infra/lib-policy-artefacts.sh"))
        self.assertIn("create configmap medcea-iam-lib", lib)
        self.assertIn("compile netpol", lib)
        self.assertNotRegex(lib, r"policy_source_init ")
        for pat in (r"cli\.py\"? (compile|check|hosts)", r"\bpolicy_(groups|grafana|workbench|workbench_egress|tool)\b "):
            m = re.search(pat, t)
            self.assertTrue(m is None or m.start() > full, pat)
        self.assertEqual(len(re.findall(r"policy_source_init ", t)), 2)

    def test_purge_reset_uninstall_retire_the_host_files(self):
        # review 4.2a: design §14.4.4 (ops-1); the manual says they do this themselves
        t = code(read("apps/database/uninstall.sh"))
        self.assertLess(t.index("DROP DATABASE IF EXISTS"), t.index("policy_state_retire purge-data"))
        self.assertLess(t.index("medcea_lock"), t.index("policy_state_retire purge-data"))
        t = code(read("deploy-infra.sh"))
        reset = t[t.index('if [[ "${1:-}" == "--reset" ]]'):t.index('infra/configure.sh"')]
        self.assertLess(reset.index("delete namespace"), reset.index("policy_state_retire reset"))
        self.assertLess(reset.index('read -p "Type \'reset\' to confirm'), reset.index("policy_state_retire reset"))
        unin = t[t.index('if [[ "${1:-}" == "--uninstall" ]]'):t.index('if [[ "${1:-}" == "--reset" ]]')]
        self.assertLess(unin.index("remove_microk8s"), unin.index("policy_state_retire uninstall"))
        self.assertLess(t.index("medcea_lock\n"), t.index("policy_state_retire uninstall"))

    def test_deploy_apps_and_install_break_glass(self):
        # review 4.2a: --break-glass "<reason>" (design §14.4.6); without it the override is dropped
        da, ins = code(read("deploy-apps.sh")), code(read("install.sh"))
        self.assertIn("unset MEDCEA_POLICY_FILE MEDCEA_POLICY_BREAK_GLASS", da)
        self.assertIn("unset MEDCEA_POLICY_FILE MEDCEA_POLICY_BREAK_GLASS MEDCEA_POLICY_BREAK_GLASS_ASKED", ins)
        self.assertIn('MEDCEA_POLICY_BREAK_GLASS_ASKED="$MEDCEA_LOCK_HELD"', ins)
        self.assertLess(ins.index("medcea_lock"), ins.index('MEDCEA_POLICY_BREAK_GLASS_ASKED="$MEDCEA_LOCK_HELD"'))
        self.assertIn('./deploy-apps.sh --all "${APPS_BG[@]}"', ins)
        self.assertIn('policy_source_init "$NAMESPACE" || exit $?', da)
        self.assertIn('policy_db_state "$NAMESPACE"', da)
        self.assertLess(da.index("medcea_lock"), da.index('policy_source_init "$NAMESPACE"'))
        self.assertLess(da.index('policy_source_init "$NAMESPACE"'), da.index('bash "$deploy_script"'))
        self.assertEqual(set(re.search(r"POLICY_COMPILING=\(([^)]*)\)", da).group(1).split()),
                         {p.split("/")[1] for p in WRITERS if p.startswith("apps/")})
        # the refusals come before any lock (run from a scratch copy: no lock of this tree)
        d = tempfile.mkdtemp(prefix="medcea-bg-")
        try:
            for f in ("deploy-apps.sh", "install.sh"):
                shutil.copy(os.path.join(REPO, f), d)
            env = clean_env()
            env.pop("MEDCEA_POLICY_FILE", None)
            for argv, want in ((["deploy-apps.sh", "--all", "--break-glass", "r"], "--break-glass needs MEDCEA_POLICY_FILE"),
                               (["deploy-apps.sh", "--break-glass"], "--break-glass needs a reason"),
                               (["install.sh", "--break-glass", "r"], "--break-glass needs MEDCEA_POLICY_FILE"),
                               (["install.sh", "--uninstall-apps", "--break-glass", "r"], "--break-glass goes with an install")):
                r = subprocess.run(["bash", os.path.join(d, argv[0])] + argv[1:], capture_output=True, text=True,
                                   env=env, cwd=d, stdin=subprocess.DEVNULL, timeout=60)
                self.assertEqual(r.returncode, 1, argv)
                self.assertIn(want, r.stderr, argv)
                self.assertFalse(os.path.exists(os.path.join(d, ".medcea.lock")), argv)
        finally:
            shutil.rmtree(d, ignore_errors=True)

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

    # The repository's own cli.py, however a test spells its path.
    REPO_CLI = re.compile(r'os\.path\.join\((REPO|ROOT), ["\']apps["\'], ["\']iam["\'], ["\']compiler["\'], ["\']cli\.py["\']\)'
                          r'|os\.path\.join\((REPO|ROOT), ["\']apps/iam/compiler/cli\.py["\']\)'
                          r'|\{(REPO|ROOT)\}/apps/iam/compiler/cli\.py')
    # A shell library that compiles, pointed at the repository itself.
    REPO_LIB = re.compile(r'(REPO_ROOT|SCRIPT_DIR)=("?\{(REPO|ROOT)\}|(REPO|ROOT)\b)')
    LIB_COMPILES = re.compile(r'\b(policy_(tool|groups|workbench|workbench_egress|grafana)|workbench_egress_close'
                              r'|check_(onboardroles|pgadminroles|iamworkbench|grafanarole))\b')

    @staticmethod
    def repo_cli_statements(text):
        """(line, reason) of every simple statement of a test module that runs the
        repository's cli.py without --defaults or --file (design v4 §14.4.15): an alias of
        the path (`CLI = os.path.join(REPO, …)`) is followed to its uses, and run_cli()
        without cli= runs CLI. A cli.py inside a scratch_repo() tree never matches."""
        import ast
        tree = ast.parse(text)
        compound = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For, ast.While,
                    ast.With, ast.Try, ast.AsyncFor, ast.AsyncWith)
        simple = [n for n in ast.walk(tree) if isinstance(n, ast.stmt) and not isinstance(n, compound)]
        consts = lambda n: {c.value for c in ast.walk(n) if isinstance(c, ast.Constant)}  # noqa: E731
        ok = lambda n: bool({"--defaults", "--file"} & consts(n))  # noqa: E731
        aliases, bad = set(), []
        for n in simple:
            seg = ast.get_source_segment(text, n) or ""
            if not Wiring.REPO_CLI.search(seg):
                continue
            if (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                    and Wiring.REPO_CLI.fullmatch((ast.get_source_segment(text, n.value) or "").strip())):
                aliases.add(n.targets[0].id)
            elif not ok(n):
                bad.append((n.lineno, "the repository's cli.py"))
        for n in simple:
            seg = ast.get_source_segment(text, n) or ""
            if Wiring.REPO_LIB.search(seg) and Wiring.LIB_COMPILES.search(seg):
                bad.append((n.lineno, "a compiling shell function with REPO_ROOT at the repository"))
        for n in simple:
            names = {x.id for x in ast.walk(n) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)}
            default_cli = any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "run_cli"
                              and not any(k.arg == "cli" for k in c.keywords) and len(c.args) < 2
                              for c in ast.walk(n))
            if ((names & aliases) or default_cli) and not ok(n):
                bad.append((n.lineno, "an alias of the repository's cli.py"))
        return bad

    def test_no_offline_test_runs_the_repository_cli_unpinned(self):
        """§14.4.15's guard: on the live host state/policy-applied.yaml exists, so an offline
        test that ran the repository's cli.py without --defaults or --file would compile the
        host's applied version (or exit 2 with the mark and no file). Such a test runs in a
        scratch_repo() tree or passes --defaults/--file. The live flows (iam_*_flow.py) read
        the host's source on purpose and are not offline tests."""
        offline = sorted(f for f in os.listdir(os.path.join(REPO, "tests"))
                         if f.startswith("test_") and f.endswith(".py"))
        for f in offline:
            self.assertEqual(self.repo_cli_statements(read(os.path.join("tests", f))), [], f)
        # the guard itself catches each spelling
        for snippet in ('subprocess.run([sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"),\n'
                        '                "compile", "routes"])\n',
                        'subprocess.run([sys.executable, os.path.join(REPO, "apps/iam/compiler/cli.py"), "check"])\n',
                        'subprocess.run(["bash", "-c", f\'python3 {REPO}/apps/iam/compiler/cli.py compile mqtt\'])\n',
                        'CLI = os.path.join(REPO, "apps", "iam", "compiler", "cli.py")\n'
                        'subprocess.run([sys.executable, CLI, "compile", "routes"])\n',
                        'CLI = os.path.join(REPO, "apps", "iam", "compiler", "cli.py")\nrun_cli(["check"])\n',
                        'real = f"{os.path.join(REPO, \'apps\', \'iam\', \'compiler\', \'cli.py\')!r}"\n',
                        'subprocess.run(["bash", "-c", f\'REPO_ROOT="{REPO}"; source x; policy_tool pgadmin\'])\n'):
            with self.subTest(snippet):
                self.assertNotEqual(self.repo_cli_statements(snippet), [])
        for snippet in ('subprocess.run([sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"),\n'
                        '                "--defaults", "compile", "routes"])\n',
                        'cli = os.path.join(root, "apps", "iam", "compiler", "cli.py")\n'
                        'subprocess.run([sys.executable, cli, "compile", "routes"])\n',
                        'CLI = os.path.join(REPO, "apps", "iam", "compiler", "cli.py")\n'
                        'run_cli(["--defaults", "check"])\nrun_cli(["check"], cli=scratch_cli)\n'):
            with self.subTest(snippet):
                self.assertEqual(self.repo_cli_statements(snippet), [])


class V1HostFile(unittest.TestCase):
    """Version 1 on the host (design §14.4.17, the scratch-tree half of Phase42aDelta): a host
    file composed from a state built from defaults.yaml compiles every output to exactly what
    --defaults compiles, but routes.json's unhashed source/applied_version, and no compile
    writes to stderr for a host source (§14.4.15)."""

    def test_every_output_equals_defaults(self):
        root = scratch_repo()
        try:
            cli = os.path.join(root, "apps", "iam", "compiler", "cli.py")
            f = model.load_defaults().data
            os.mkdir(os.path.join(root, "state"), 0o700)
            with open(os.path.join(root, "state", "policy-applied.yaml"), "w") as fh:
                fh.write(source.host_file_text(make_state(f, 1, "bootstrap"), "abc1234", "2026-11-02T00:00:00Z"))
            keys = list(artefacts(model.load_defaults()))
            for key in keys:
                if key == "check":
                    continue
                argv = cli_argv(key)
                rc, host_out, err = run_cli(argv, cli=cli)
                self.assertEqual((rc, err), (0, ""), key)
                rc, def_out, _ = run_cli(["--defaults"] + argv, cli=cli)
                if key == "routes":
                    h, d = json.loads(host_out), json.loads(def_out)
                    self.assertEqual((h.pop("source"), h.pop("applied_version")), ("version-1", 1))
                    self.assertEqual((d.pop("source"), d.pop("applied_version")), ("defaults.yaml", None))
                    self.assertEqual(h, d)
                else:
                    self.assertEqual(host_out, def_out, key)
            rc, out, _ = run_cli(["check"], cli=cli)
            self.assertIn("source: version 1 (bootstrap)", out)
        finally:
            shutil.rmtree(root, ignore_errors=True)


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
            self.assertEqual(as_of_43(key, self.old_out(key)), want, key)

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
            self.assertEqual(as_of_43(key, self.old_out(key)), self.want[key], key)


class Phase43Delta(unittest.TestCase):
    """Slice 4.3 (the Policy UI) compiles every artefact byte for byte as PRE_43 and leaves
    the skeleton as it was (design §14.6.0: no slice before 4.5 may widen it). Only the
    hosts listing moves: POLICY_DOMAIN's status (proxies.ENFORCEMENT, code, not skeleton)."""

    @classmethod
    def setUpClass(cls):
        cls.old, cls.old_cli = archive_cli(PRE_43, "medcea-pre43-")
        with open(DEFAULTS) as f:
            cls.p = model.Policy(yaml.safe_load(f))
        cls.want = artefacts(cls.p)

    @classmethod
    def tearDownClass(cls):
        if cls.old:
            shutil.rmtree(cls.old, ignore_errors=True)

    def setUp(self):
        if not self.old:
            self.skipTest(f"no git archive of {PRE_43}: {self.old_cli}")

    def test_every_artefact_byte_identical(self):
        for key, want in self.want.items():
            if key == "hosts":
                continue          # its POLICY_DOMAIN line: test_only_the_policy_hosts_status_moves
            rc, out, err = run_cli(cli_argv(key), cli=self.old_cli)
            self.assertEqual(rc, 0, f"{key} ({PRE_43}): {err}")
            self.assertEqual(out, want, key)

    def test_skeleton_and_matrix_unchanged(self):
        with open(os.path.join(self.old, "apps", "iam", "policy", "defaults.yaml")) as f:
            old_data = yaml.safe_load(f)
        self.assertEqual(source.skeleton_digest(old_data), source.skeleton_digest(self.p.data))
        self.assertEqual(old_data["matrix"], self.p.data["matrix"])
        self.assertEqual(old_data["waivers"], self.p.data["waivers"])

    def test_only_the_policy_hosts_status_moves(self):
        rc, old, err = run_cli(["--defaults", "hosts"], cli=self.old_cli)
        self.assertEqual(rc, 0, err)
        rc, new, err = run_cli(["--defaults", "hosts"])
        self.assertEqual(rc, 0, err)
        changed = [(a, b) for a, b in zip(old.splitlines(), new.splitlines()) if a != b]
        self.assertEqual(len(changed), 1, changed)
        self.assertIn("POLICY_DOMAIN", changed[0][1])
        self.assertIn("[compiled]", changed[0][1])


class Phase42aDelta(unittest.TestCase):
    """Slice 4.2a moves exactly what design §14.4.7 lists, against PRE_42A (slice 4.1)."""

    @classmethod
    def setUpClass(cls):
        cls.old, cls.old_cli = archive_cli(PRE_42A, "medcea-pre42a-")
        with open(DEFAULTS) as f:
            cls.p = model.Policy(yaml.safe_load(f))
        cls.want = artefacts(cls.p)
        cls.outs = {}

    @classmethod
    def tearDownClass(cls):
        if cls.old:
            shutil.rmtree(cls.old, ignore_errors=True)

    def setUp(self):
        if not self.old:
            self.skipTest(f"no git archive of {PRE_42A}: {self.old_cli}")

    def old_out(self, key):
        if key not in self.outs:
            rc, out, err = run_cli(cli_argv(key), cli=self.old_cli)
            self.assertEqual(rc, 0, f"{key} ({PRE_42A}): {err}")
            self.outs[key] = out
        return self.outs[key]

    def test_unmoved_outputs_byte_identical(self):
        # the grants document (privileges, memberships, RLS: the golden) included
        for key, want in self.want.items():
            if key == "routes" or (key.startswith("grants-") and not key.startswith("grants-json")):
                continue
            self.assertEqual(as_of_43(key, self.old_out(key)), want, key)
        # check: the same text; the skeleton digest moves (defaults.yaml's one 4.2a edit,
        # iam_policy._system_as(text[]) in infrastructure_functions), which check does not print
        rc, out, err = run_cli(["--defaults", "check"])
        self.assertEqual(rc, 0, err)
        rc, old, err = run_cli(["--defaults", "check"], cli=self.old_cli)
        self.assertEqual(rc, 0, err)
        self.assertEqual(old, out)
        with open(os.path.join(self.old, "apps", "iam", "policy", "defaults.yaml")) as f:
            old_data = yaml.safe_load(f)
        self.assertNotEqual(source.skeleton_digest(old_data), source.skeleton_digest(self.p.data))
        old_fns = {x["function"] for x in old_data["infrastructure_functions"]}
        new_fns = {x["function"] for x in self.p.data["infrastructure_functions"]}
        self.assertEqual(new_fns - old_fns, {"iam_policy._system_as(text[])"})
        self.assertEqual(old_fns - new_fns, set())
        self.assertEqual(old_data["matrix"], self.p.data["matrix"])
        self.assertEqual(old_data["waivers"], self.p.data["waivers"])

    def test_routes_only_the_digest(self):
        old, new = json.loads(self.old_out("routes")), json.loads(self.want["routes"])
        self.assertNotIn("applied_version", old)
        self.assertIsNone(new.pop("applied_version"))
        self.assertNotEqual(old.pop("digest"), new.pop("digest"))
        self.assertEqual(old, new)
        # the new digest hashes everything but the labels: the same for any source label
        self.assertEqual(json.loads(self.want["routes"])["digest"],
                         routes.compile(self.p, "version-1", 1)["digest"])

    def test_grants_only_the_declared_hunks(self):
        old_digest = json.loads(self.old_out("routes"))["digest"]
        new_digest = json.loads(self.want["routes"])["digest"]
        import difflib
        changed = set()
        for key, want in self.want.items():
            if not key.startswith("grants-") or key.startswith("grants-json"):
                continue
            old = self.old_out(key).replace(old_digest, new_digest)
            if old == want:
                continue
            changed.add(key)
            # the changed lines must lie in pre_request's text (its header comment and body)
            # or be the fns array of the asserts
            new_lines = want.splitlines()
            pre_spans = []
            for m in re.finditer(r"-- pre_request\(\): PostgREST's db-pre-request.*?\$pre\$;", want, flags=re.S):
                a = want.count("\n", 0, m.start())
                pre_spans.append((a, a + m.group(0).count("\n") + 1))
            sm = difflib.SequenceMatcher(a=old.splitlines(), b=new_lines, autojunk=False)
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == "equal":
                    continue
                for j in range(j1, j2) if j2 > j1 else [j1]:
                    inside = any(a <= j < b for a, b in pre_spans)
                    fns = j < len(new_lines) and "'iam_policy._system_as(text[])'" in new_lines[j]
                    self.assertTrue(inside or fns, f"{key}: line {j + 1} changed outside the declared hunks: "
                                                   f"{new_lines[j] if j < len(new_lines) else '(end)'}")
            # the pre_request text: the same statements, the only_rpc block moved before the mode check
            if "FUNCTION medcea_auth.pre_request()" in want:
                n = want[want.index("FUNCTION medcea_auth.pre_request()"):want.index("$pre$;")]
                self.assertLess(n.index("may only call"), n.index("medcea.iam_db_roles"))
        # every mode's functions part moves (pre_request) and every assert part (fns)
        for mode in ("additive", "enforce", "verify"):
            self.assertIn(f"grants-{mode}-functions", changed)
            self.assertIn(f"grants-{mode}-assert", changed)
        # role_widening()'s COMMENT carries the new digest
        self.assertIn(f"IS 'policy {new_digest}';", self.want["grants-additive-functions"])
        self.assertIn(f"IS 'policy {old_digest}';", self.old_out("grants-additive-functions"))


if __name__ == "__main__":
    unittest.main()
