#!/usr/bin/env python3
"""What the Configuration UI offers to the signed-in role, offline
(apps/frontend/html/index.html; decision of 12 November 2026: no policy change).

- The rights-logic block (between /* rights-logic:begin */ and /* rights-logic:end */)
  runs under node (skipped without node): classifyProbe (2xx true; 401/403 with 42501
  false; anything else null = unknown), can() (unknown counts as allowed), probeRequest
  for every PROBES table (PATCH, pk=eq.-1, a non-empty body of one null column,
  return=minimal, never tx=), panelOutcome (a refused primary read refuses the panel, a
  refused secondary read only takes something away), refusalText, friendlyWriteError
  (every draft_only, assign_only and existing_slot source message is checked against its
  RAISE in apps/database/medcea_db_migrations.sql), libraryRefusal and schedReadText.
- Static: every PROBES pk and column exists in the table's definition in
  apps/database/*.sql (PostgREST refuses an unknown column, and the filter must parse as
  an integer); loadRights uses a raw fetch, never api(), cfgReauth or /oauth2/start; no
  tx=rollback anywhere; the tables the page writes through api() (plus control_algorithm,
  written through the scheduler) are exactly the PROBES keys; every New, Edit, Import,
  Grant and library-save control is gated (data-needs or can()); the panels read with
  Promise.allSettled and escape error text; the block names no role.
- Grants (tests/iam-grants.golden.json): on every PROBES table the person roles holding
  UPDATE also hold INSERT, so the one UPDATE probe also gates New and Import (and the
  matrix's merge-duplicates upsert); only table-level privileges exist.
- Migrations: no statement-level trigger on INSERT, UPDATE or DELETE in apps/database
  (only BEFORE TRUNCATE ones), so a zero-row probe fires nothing and writes nothing.
- Docs: the manual section, the decision row and exercise E33.

Run: python3 tests/test_config_ui_rights.py
"""
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "apps", "frontend", "html", "index.html")
MIG = os.path.join(ROOT, "apps", "database", "medcea_db_migrations.sql")
SQL = sorted(glob.glob(os.path.join(ROOT, "apps", "database", "*.sql")))
GOLDEN = os.path.join(ROOT, "tests", "iam-grants.golden.json")
CHAPTERS = os.path.join(ROOT, "docs", "manual", "chapters")
NODE = shutil.which("node")

ROLES = ("admin", "auditor", "bio_scientist", "control_scientist", "engineer", "maintenance",
         "operator", "production_manager", "qa", "qc", "qp")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def block(html, name):
    m = re.search(rf"/\* {name}:begin \*/(.*?)/\* {name}:end \*/", html, re.S)
    assert m, f"{name} block missing"
    return m.group(1)


def function(html, head):
    """The source of the function starting with head, up to its closing brace."""
    i = html.index(head)
    return html[i:html.index("\n    }\n", i)]


def probes(html):
    got = dict((t, (pk, col)) for t, pk, col in re.findall(
        r"^\s*(\w+):\s*\{ pk: '(\w+)',\s*col: '(\w+)' \}", block(html, "rights-logic"), re.M))
    assert got, "PROBES not found"
    return got


def table_columns(table):
    """name -> type of medcea.<table>'s columns, from its CREATE TABLE in apps/database."""
    for path in SQL:
        if "export" in os.path.basename(path):
            continue
        s = read(path)
        m = re.search(r"CREATE TABLE (?:IF NOT EXISTS )?medcea\.%s \((.*?)\n\);" % re.escape(table), s, re.S)
        if m:
            cols = {}
            for line in m.group(1).splitlines():
                c = re.match(r"\s*\"?(\w+)\"?\s+(\w+)", line)
                if c and c.group(1).upper() not in ("CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "CHECK"):
                    cols[c.group(1)] = c.group(2).lower()
            return cols
    return None


# A refusal as the database words it (the RAISE with % filled in), its RAISE format
# (verbatim in the migration) and a fragment of what the page shows.
REFUSALS = [
    ("draft_only: the recipe of this line is not a draft; a change starts a new draft",
     "'draft_only: the recipe of this line is not a draft; a change starts a new draft'",
     "This recipe is no longer a draft"),
    ("draft_only: medcea.recipe is approved, not a draft; a change starts a new draft",
     "'draft_only: %.% is %, not a draft; a change starts a new draft'",
     "Only a draft can be changed, and this one is approved now"),
    ("assign_only: recipe 5 is not approved, or changed since",
     "'assign_only: recipe %s is not approved, or changed since'",
     "Only an approved recipe can be allowed on a unit: recipe #5"),
    ("assign_only: parameter set 3 is not approved, or changed since",
     "'assign_only: parameter set %s is not approved, or changed since'",
     "Only an approved parameter set can be assigned: set #3"),
    ("existing_slot: zone 7 has no Sensor slot to re-onboard into; a new slot is an engineer's change",
     "'existing_slot: zone %s has no %s slot to re-onboard into; a new slot is an engineer''s change'",
     "zone 7 has no inactive Sensor device to replace"),
    # format('%s', NULL) is '': a device without a zone (an import, '— Unassigned —') or a type
    ("existing_slot: zone  has no sensor slot to re-onboard into; a new slot is an engineer's change",
     "'existing_slot: zone %s has no %s slot to re-onboard into; a new slot is an engineer''s change'",
     "existing slot of a zone; choose its zone. Registering an unassigned device is an engineer's change."),
    ("existing_slot: zone 4 has no  slot to re-onboard into; a new slot is an engineer's change",
     "'existing_slot: zone %s has no %s slot to re-onboard into; a new slot is an engineer''s change'",
     "zone 4 has no inactive device of that type to replace"),
    ("permission denied for table cea_unit", None, "Your role cannot change units."),
    ("permission denied for table recipe_unit_permission", None, "Your role cannot change recipe unit permissions."),
]

HARNESS = r"""
const fs = require('fs');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const out = {};
out.tables = Object.keys(PROBES);
out.requests = {};
for (const t of out.tables) out.requests[t] = probeRequest(t);
out.classify = input.answers.map(a => classifyProbe(a[0], a[1]));
out.can = [can({ cea_unit: null }, 'cea_unit'), can({ cea_unit: false }, 'cea_unit'), can({ cea_unit: true }, 'cea_unit'),
           can({}, 'recipe'), can(null, 'recipe'),
           canAll({ recipe: true, recipe_line: false }, 'recipe recipe_line'), canAll({ recipe: true, recipe_line: null }, 'recipe recipe_line')];
const refused = { status: 'rejected', reason: { code: '42501', message: 'permission denied for table recipe' } };
const broken = { status: 'rejected', reason: { code: 'PGRST301', message: 'JWT expired' } };
const ok = { status: 'fulfilled', value: [] };
const spec = [{ table: 'recipe', primary: true }, { table: 'cea_unit', primary: true },
              { table: 'recipe_unit_permission', primary: true }, { table: 'control_algorithm', primary: false }];
out.panel = {
  all_ok: panelOutcome([ok, ok, ok, ok], spec),
  primary_refused: panelOutcome([refused, ok, refused, refused], spec, 'Your role does not read recipes or their unit permissions.'),
  primary_refused_default: panelOutcome([refused, ok, ok, ok], spec),
  aux_refused: panelOutcome([ok, ok, ok, refused], spec),
  aux_broken: panelOutcome([ok, ok, ok, broken], spec),
  primary_broken: panelOutcome([broken, ok, refused, ok], spec),
};
out.refusalText = [refusalText('device'), refusalText(['recipe', 'recipe_unit_permission']), refusalText(null),
                   refusalText('controllers_state'), refusalText('control_algorithm')];
out.write = input.refusals.map(friendlyWriteError);
out.writeOther = friendlyWriteError('duplicate key value violates unique constraint "x"');
out.library = [libraryRefusal(403, '{"error": "roles [\'admin\'] do not hold U on master_data"}', 'save'),
               libraryRefusal(403, 'not json', 'read'), libraryRefusal(500, '{"error": "disk full"}', 'save'),
               libraryRefusal(401, '', 'save')];
out.libraryRead = libraryRefusal(403, '{"error": "roles [\'qc\'] do not hold R on devices"}', 'read');
out.sched = [schedReadText(403, { error: 'no' }, 'control_algorithm'), schedReadText(403, null, null),
             schedReadText(500, { error: 'boom' }, 'control_algorithm'), schedReadText(401, null, 'x')];
console.log(JSON.stringify(out));
"""

ANSWERS = [
    [204, None], [200, None],
    [403, {"code": "42501", "message": "permission denied for table cea_unit"}],
    [401, {"code": "42501", "message": "permission denied for table cea_unit"}],
    [401, {"code": "PGRST301", "message": "JWT expired"}],
    [403, {"code": "28000", "message": "may only read"}],
    [403, None],
    [404, {"code": "PGRST205"}],
    [400, {"code": "PGRST204", "message": "Could not find the 'x' column"}],
    [0, None],
    [500, {"code": "42501"}],
]


@unittest.skipUnless(NODE, "node is not installed")
class RightsLogicUnderNode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        html = read(INDEX)
        cls.mig = read(MIG)
        tmp = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, tmp)
        js = os.path.join(tmp, "harness.js")
        with open(js, "w", encoding="utf-8") as f:
            f.write(block(html, "rights-logic") + "\n" + HARNESS)
        data = os.path.join(tmp, "input.json")
        with open(data, "w", encoding="utf-8") as f:
            json.dump({"answers": ANSWERS, "refusals": [r[0] for r in REFUSALS]}, f)
        subprocess.run([NODE, "--check", js], check=True, capture_output=True)
        r = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise AssertionError(r.stderr)
        cls.out = json.loads(r.stdout)

    def test_classify(self):
        self.assertEqual(self.out["classify"],
                         [True, True, False, False, None, None, None, None, None, None, None])

    def test_unknown_counts_as_allowed(self):
        self.assertEqual(self.out["can"], [True, False, True, True, True, False, True])

    def test_probe_requests(self):
        self.assertEqual(set(self.out["tables"]), set(probes(read(INDEX))))
        for t, q in self.out["requests"].items():
            pk, col = probes(read(INDEX))[t]
            self.assertEqual(q["method"], "PATCH", t)
            self.assertEqual(q["path"], "/%s?%s=eq.-1" % (t, pk), t)
            self.assertEqual(q["body"], {col: None}, t)       # never empty: an empty body reports a false right
            prefer = q["headers"]["Prefer"]
            self.assertIn("return=minimal", prefer, t)
            self.assertNotIn("tx=", prefer, t)

    def test_panel_outcome(self):
        p = self.out["panel"]
        self.assertEqual(p["all_ok"]["state"], "ok")
        self.assertEqual(p["primary_refused"]["state"], "refused")
        self.assertEqual(p["primary_refused"]["message"], "Your role does not read recipes or their unit permissions.")
        self.assertEqual(p["primary_refused"]["refused"], ["recipe", "recipe_unit_permission"])
        self.assertEqual(p["primary_refused_default"]["message"], "Your role does not read recipes.")
        self.assertEqual(p["aux_refused"]["state"], "ok")
        self.assertEqual(p["aux_refused"]["refusedAux"], ["control_algorithm"])
        self.assertEqual(p["aux_broken"]["state"], "ok")
        self.assertEqual(p["aux_broken"]["failedAux"], ["control_algorithm"])
        self.assertEqual(p["aux_broken"]["refusedAux"], [])
        self.assertEqual(p["primary_broken"]["state"], "error")
        self.assertEqual(p["primary_broken"]["message"], "JWT expired")

    def test_refusal_text(self):
        self.assertEqual(self.out["refusalText"], [
            "Your role does not read devices.", "Your role does not read recipes or recipe unit permissions.",
            "Your role does not read this.", "Your role does not read learned state.",
            "Your role does not read control algorithms."])
        for t in self.out["refusalText"]:
            for role in ROLES:
                self.assertNotRegex(t, r"\b%s\b" % role)

    def test_write_refusals_map_and_exist_in_migration(self):
        for (msg, fmt, want), got in zip(REFUSALS, self.out["write"]):
            self.assertIn(want, got, msg)
            self.assertNotIn("permission denied", got, msg)
            if fmt:
                self.assertIn(fmt, self.mig, f"the migration no longer raises {fmt}")
        self.assertIn("duplicate key", self.out["writeOther"])

    def test_library_refusal(self):
        save, read_, other, expired = self.out["library"]
        self.assertTrue(save["refused"])
        self.assertEqual(save["text"], "The access policy does not let your role save to the platform library.")
        self.assertIn("do not hold U on master_data", save["title"])
        self.assertFalse(read_["refused"])          # a 403 without the gate's JSON: the sign-in proxy
        self.assertIn("reload the page", read_["text"])
        self.assertEqual(self.out["libraryRead"]["text"], "The access policy does not let your role read the platform library.")
        self.assertFalse(other["refused"])
        self.assertEqual(other["text"], "Server error 500: disk full")
        self.assertIn("reload the page", expired["text"])

    def test_scheduler_reads(self):
        self.assertEqual(self.out["sched"][0], "Your role does not read control algorithms.")
        self.assertEqual(self.out["sched"][1], "Your role does not read this.")
        self.assertEqual(self.out["sched"][2], "Failed to load (500): boom")
        self.assertNotIn("No algorithms found", " ".join(self.out["sched"]))


class RightsStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = read(INDEX)
        cls.block = block(cls.html, "rights-logic")
        cls.probes = probes(cls.html)

    def test_probe_columns_exist(self):
        # PostgREST answers an unknown column with PGRST204 (unknown, so the control
        # would show for everyone); the filter's -1 must parse as the pk's type.
        for t, (pk, col) in self.probes.items():
            cols = table_columns(t)
            self.assertIsNotNone(cols, f"no CREATE TABLE medcea.{t} in apps/database")
            self.assertIn(pk, cols, f"{t}: no column {pk}")
            self.assertIn(col, cols, f"{t}: no column {col}")
            self.assertEqual(cols[pk], "integer", f"{t}.{pk} is not an integer")

    def test_probe_is_a_raw_fetch(self):
        f = function(self.html, "async function loadRights()")
        self.assertIn("fetch(API + q.path", f)
        for bad in ("api(", "cfgReauth", "oauth2/start"):
            self.assertNotIn(bad, f)
        self.assertNotIn("fetch(", self.block)       # the block stays pure
        self.assertNotIn("document.", self.block)

    def test_never_rollback(self):
        self.assertTrue("tx=rollback" not in self.html, "the page sends Prefer: tx=rollback")
        self.assertIsNone(re.search(r"Prefer[^\n]*tx=", self.html), "the page sends a Prefer tx header")

    def test_written_tables_are_probed(self):
        written = set(re.findall(r"api\('(?:POST|PATCH)',\s*'/(?!rpc/)(\w+)", self.html))
        if re.search(r"\$\{SCHED_API\}/algorithms/\$\{aid\}`,\s*\{\s*method:'PUT'", self.html):
            written.add("control_algorithm")
        self.assertEqual(written, set(self.probes),
                         "every table the page writes needs a PROBES entry (and a gated control)")

    def test_rights_ready_after_the_block(self):
        i = self.html.index("const rightsReady = loadRights()")
        self.assertGreater(i, self.html.index("/* rights-logic:end */"))
        self.assertLess(i, self.html.index("// ── Init"))
        for head in ("async function loadLocations()", "async function loadUnits()", "async function loadAllDevices()",
                     "async function loadRecipes()", "async function loadPermissionMatrix()", "async function loadAlgorithms()",
                     "async function loadParamSets()", "async function refreshZonesPanel(", "async function refreshComponentsPanel("):
            self.assertIn("await rightsReady;", function(self.html, head), head)

    def test_static_controls_gated(self):
        tags = re.findall(r"<(?:button|a)\b[^>]*>", self.html)
        def needs(pattern):
            hits = [t for t in tags if re.search(pattern, t)]
            self.assertTrue(hits, pattern)
            return [re.search(r'data-needs="([^"]+)"', t) for t in hits]
        expect = {
            r"openLocForm\(null\)": "cea_location", r"openLocImportChoice\(\)": "cea_location",
            r"openLocModal\(\)": "cea_location",
            r"openUnitForm\(null\)": "cea_unit", r"openUnitImportChoice\(\)": "cea_unit cea_zone",
            r"openDeviceModal\(null\)": "device", r"openDeviceImportChoice\(\)": "device", r"EDGE_WIZARD_URL": "device",
            r"openParamSetModal\(null\)": "unit_algorithm_params",
            r"openRecipeForm\(null\)": "recipe", r"openImportChoice\(\)": "recipe recipe_line",
        }
        for pat, want in expect.items():
            for m in needs(pat):
                self.assertIsNotNone(m, pat)
                self.assertEqual(m.group(1), want, pat)
        # every "Save to Platform Library" choice is gated by its group's table
        saves = re.findall(r'<button[^>]*?(?:data-needs="([^"]+)")?[^>]*\n\s*onclick="[^"]*\(([^)]*)\'platform\'\)">', self.html)
        self.assertEqual(len(saves), 8)
        for m in re.finditer(r"<button([^>]*)\n\s*onclick=\"close\w+\(\);(\w+)\([^\"]*'platform'\)\">", self.html):
            n = re.search(r'data-needs="([^"]+)"', m.group(1))
            self.assertIsNotNone(n, m.group(2))
            want = {"exportLoc": "cea_location", "exportAllLocs": "cea_location", "exportUnit": "cea_unit",
                    "exportAllUnits": "cea_unit", "exportDevice": "device", "exportAllDevices": "device",
                    "exportRecipe": "recipe", "exportAllRecipes": "recipe"}[m.group(2)]
            self.assertEqual(n.group(1), want, m.group(2))
        self.assertIn("document.querySelectorAll('[data-needs]')", function(self.html, "function applyRights()"))

    def test_row_controls_gated(self):
        gates = {
            "function renderLocTable()": ("cea_location", "openLocForm("),
            "function renderUnitTable()": ("cea_unit", "openUnitForm("),
            "function renderZonesPanel(": ("cea_zone", "openZoneModal("),
            "async function refreshZoneDevices(": ("device", "openDeviceModal("),
            "function renderDevContent(": ("device", "openDeviceModal("),
            "function renderComponentsPanel(": ("component", "openComponentModal("),
            "function renderPermMatrix()": ("recipe_unit_permission", "grantPermission("),
            "function renderRecipeTable()": ("recipe", "copyRecipeById("),
            "function renderRecipeFreeze(": ("recipe", "recipe-save-btn"),
            "async function loadAlgorithms()": ("control_algorithm", "saveAlgorithm("),
            "function renderParamSets()": ("unit_algorithm_params", "openParamSetModal("),
            "function openParamSetModal(": ("unit_algorithm_params", "ps-retire-btn"),
        }
        for head, (table, control) in gates.items():
            f = function(self.html, head)
            self.assertIn(control, f, head)
            self.assertRegex(f, r"can(All)?\(rights, '[^']*\b%s\b" % table, head)
        f = function(self.html, "function renderPermMatrix()")
        self.assertIn("openPermAlgoModal(", f)
        self.assertIn("(write", f)
        # View, not Edit, for a role without the right
        self.assertIn("(!write ? 'View' : (isFrozen(r.status) ? 'View' : 'Edit'))", self.html)
        self.assertIn("isFrozen(p.status) || !can(rights, 'unit_algorithm_params') ? 'View' : 'Edit'", self.html)
        # an import with components is refused before anything is written
        f = function(self.html, "async function importDevicePayload(")
        self.assertLess(f.index("can(rights, 'component')"), f.index("api('POST', '/device'"))

    def test_panels_read_with_allsettled(self):
        f = function(self.html, "async function loadPermissionMatrix()")
        self.assertIn("Promise.allSettled", f)
        self.assertIn("panelOutcome(", f)
        self.assertIn("esc(", f)
        self.assertNotIn("+ e.message", f)
        self.assertIn("{ table: 'control_algorithm', primary: false }", f)
        f = function(self.html, "async function refreshZonesPanel(")
        self.assertIn("Promise.allSettled", f)
        self.assertIn("{ table: 'device', primary: false }", f)
        f = function(self.html, "async function loadAllDevices()")
        self.assertIn("Promise.allSettled", f)
        self.assertIn("{ table: 'device', primary: true }", f)

    def test_recipes_refusal_without_toast(self):
        f = function(self.html, "async function loadRecipes()")
        i = f.index("if (isRefusal(e))")
        self.assertIn("setRecipesRefused(true)", f[i:])
        self.assertLess(f.index("return;", i), f.index("toast(", i))
        self.assertIn("if (recipesRefused) { w.innerHTML = '<div class=\"empty\">' + esc(refusalText('recipe'))",
                      function(self.html, "function renderRecipeTable()"))

    def test_probes_time_out_and_controls_wait(self):
        f = function(self.html, "async function loadRights()")
        self.assertIn("new AbortController()", f)
        self.assertIn("signal: ac.signal", f)
        self.assertIn("setTimeout(() => ac.abort(), PROBE_TIMEOUT_MS)", f)
        self.assertIn('<body class="rights-pending">', self.html)
        self.assertIn("body.rights-pending [data-needs] { visibility: hidden; }", self.html)
        self.assertIn("document.body.classList.remove('rights-pending')", function(self.html, "function applyRights()"))

    def test_scheduler_reads_check_the_status(self):
        for head in ("async function loadAlgorithms()", "async function loadUnitMemory()", "async function openAlgoStateModal("):
            f = function(self.html, head)
            self.assertIn("res.ok", f, head)
            self.assertIn("schedReadText(", f, head)
        self.assertIn("schedReadText(res.status, d, 'controllers_state')", self.html)

    def test_library_refusals(self):
        self.assertNotIn("'Server error ' + r.status", self.html.replace(self.block, ""))
        for fn in ("exportLoc", "exportAllLocs", "exportUnit", "exportAllUnits", "exportDevice", "exportAllDevices",
                   "exportRecipe", "exportAllRecipes"):
            f = function(self.html, "async function %s(" % fn)
            self.assertIn("throw await libraryError(r", f, fn)
            self.assertIn("e.title", f, fn)
        for fn in ("refreshPlatformLibrary", "loadLocPlatformLibrary", "loadUnitPlatformLibrary", "refreshDevicePlatformLibrary"):
            f = function(self.html, "async function %s(" % fn)
            self.assertIn("libraryError(r, null, 'read')", f, fn)
            self.assertIn("e.refusal ? e.message", f, fn)

    def test_write_errors_in_plain_words(self):
        self.assertIn("method && method !== 'GET' ? friendlyWriteError(msg) : friendlyDbError(msg)", self.html)
        self.assertIn("refusalText(t[1])", function(self.html, "function friendlyDbError(msg)"))

    def test_no_role_in_the_block(self):
        self.assertNotIn("rr_", self.block)
        for role in ROLES:
            self.assertNotRegex(self.block, r"['\"`]%s['\"`]" % role, role)
            self.assertNotRegex(self.block, r"\b%s\s*:" % role, role)


class GrantsInvariants(unittest.TestCase):
    """The probe is one zero-row UPDATE per table; it gates New and Import too only while
    every UPDATE holder also holds INSERT. Should the policy ever give a role UPDATE
    without INSERT (or INSERT alone, as engineer on recipe_unit_permission, which the
    upsert needs both for), this keeps the UPDATE probe the right gate; a role with UPDATE
    and no INSERT would need an INSERT probe of its own."""

    @classmethod
    def setUpClass(cls):
        cls.golden = json.loads(read(GOLDEN))
        cls.probes = probes(read(INDEX))

    def holders(self, table, priv):
        return {p[0] for p in self.golden["privileges"]
                if p[1] == "table" and p[2] == "medcea." + table and p[3] == priv and p[0].startswith("rr_")}

    def test_update_implies_insert(self):
        for t in self.probes:
            up, ins = self.holders(t, "UPDATE"), self.holders(t, "INSERT")
            self.assertLessEqual(up, ins, f"{t}: {sorted(up - ins)} hold UPDATE without INSERT: add an INSERT probe")

    def test_matrix_upsert_holders(self):
        # merge-duplicates needs INSERT and UPDATE: exactly the UPDATE probe's holders
        up = self.holders("recipe_unit_permission", "UPDATE")
        self.assertEqual(up & self.holders("recipe_unit_permission", "INSERT"), up)
        self.assertNotIn("rr_engineer", up)     # engineer holds INSERT alone: no grant buttons

    def test_only_table_level_privileges(self):
        kinds = {p[1] for p in self.golden["privileges"]}
        self.assertNotIn("column", kinds, "column privileges: the probe column must then be one the role may update")


class NoStatementTriggers(unittest.TestCase):
    def test_zero_row_probe_fires_nothing(self):
        found = 0
        for path in SQL:
            s = re.sub(r"--[^\n]*", "", read(path))
            for m in re.finditer(r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\b(.*?)EXECUTE\s+(?:FUNCTION|PROCEDURE)",
                                 s, re.S | re.I):
                found += 1
                t = re.sub(r"\s+", " ", m.group(1)).upper()
                if "FOR EACH ROW" in t:
                    continue
                # a statement-level trigger (FOR EACH STATEMENT, or no FOR EACH at all)
                events = t.split(" ON ")[0]
                self.assertNotRegex(events, r"\b(INSERT|UPDATE|DELETE)\b",
                                    f"{os.path.basename(path)}: statement trigger {t[:80]}: a zero-row probe would fire it")
        self.assertGreater(found, 10)


# The page's whole script under node against a stub DOM and a stub fetch: the gates must
# decide what renders, not only be present (a `can(...) || true` passed the static checks).
# Scenarios: none = every probe refused, all = every probe 2xx, noread = probes refused and
# the recipe and device reads refused, hang = probes never answer (aborted after the timeout).
RENDER_HARNESS = r"""
// The page's whole script against a stub DOM and a stub fetch (argv: html, scenario).
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
const scenario = process.argv[3];
const script = /<script>([\s\S]*?)<\/script>/.exec(html)[1];
const els = {};
function mk(id) {
  if (els[id]) return els[id];
  const cl = new Set();
  return els[id] = { id, innerHTML: '', textContent: '', value: '', title: '', dataset: {}, style: {}, checked: false,
    classList: { add: c => cl.add(c), remove: c => cl.delete(c), contains: c => cl.has(c),
                 toggle: (c, on) => { if (on === undefined ? !cl.has(c) : on) cl.add(c); else cl.delete(c); } },
    elements: new Proxy({}, { get: (t, k) => typeof k === 'symbol' ? (k === Symbol.iterator ? function* () {} : undefined)
                                       : (t[k] = t[k] || { value: '', disabled: false }) }), reset() {}, focus() {}, scrollIntoView() {} };
}
const needs = [];
for (const m of html.slice(0, html.indexOf("<script>")).matchAll(/data-needs="([^"]+)"/g)) { const e = mk('needs' + needs.length); e.dataset.needs = m[1]; needs.push(e); }
const body = mk('__body'); body.classList.add('rights-pending');
global.document = { body, getElementById: mk, querySelectorAll: s => s === '[data-needs]' ? needs : [], createElement: () => ({ click() {} }) };
global.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
global.location = { hash: '', pathname: '/', search: '' };
global.confirm = () => true; global.prompt = () => null;
const S = {
  none:    { probe: 'refuse', deny: [] },
  all:     { probe: 'allow',  deny: [] },
  hang:    { probe: 'hang',   deny: [] },
  noread:  { probe: 'refuse', deny: ['recipe', 'device'] },
}[scenario];
const rows = {
  cea_unit: [{ unit_id: 1, unit_code: 'U1', unit_type: 'Greens', location_id: 1, is_active: 'Y' }],
  cea_location: [{ location_id: 1, name: 'L', is_active: 'Y' }],
  cea_zone: [{ zone_id: 5, unit_id: 1, zone_code: 'Z1', is_active: 'Y' }],
  recipe: [{ recipe_id: 3, recipe_name: 'Lettuce', status: 'draft', is_active: 'Y' },
           { recipe_id: 4, recipe_name: 'Basil', status: 'approved', is_active: 'Y' }],
  recipe_unit_permission: [{ recipe_id: 3, unit_id: 1, allowed: true }],
  control_algorithm: [{ algorithm_id: 1, algorithm_code: 'PID', algorithm_name: 'PID', status: 'draft' }],
  unit_algorithm_params: [{ params_id: 1, name: 'p', algorithm_id: 1, status: 'draft' }],
  device: [{ device_id: 9, zone_id: 5, dns_name: 'u1-s-z1', device_type: 'S', serial_number: 'SN', is_active: 'Y' }],
};
const resp = (status, b) => ({ ok: status < 300, status, json: async () => b, text: async () => JSON.stringify(b), clone() { return this; } });
global.fetch = (url, opts = {}) => {
  const m = /^\/api\/(rpc\/)?(\w+)/.exec(url);
  if (url.startsWith('/scheduler-api/algorithms')) return Promise.resolve(resp(200, rows.control_algorithm));
  if (url.startsWith('/scheduler-api/')) return Promise.resolve(resp(200, []));
  if (!m) return Promise.resolve(resp(404, {}));
  const t = m[2];
  if (opts.method === 'PATCH' && /=eq\.-1$/.test(url)) {
    if (S.probe === 'hang') return new Promise((_, rej) => opts.signal.addEventListener('abort', () => rej(new Error('aborted'))));
    return Promise.resolve(S.probe === 'allow' ? resp(204, null) : resp(403, { code: '42501', message: 'permission denied for table ' + t }));
  }
  if (m[1]) return Promise.resolve(resp(404, { code: 'PGRST202' }));
  if (S.deny.includes(t)) return Promise.resolve(resp(403, { code: '42501', message: 'permission denied for table ' + t }));
  return Promise.resolve(resp(200, rows[t] || []));
};
const main = async () => {
  const out = { pendingBefore: document.body.classList.contains('rights-pending') };
  await rightsReady;
  out.rights = rights;
  out.pendingAfter = document.body.classList.contains('rights-pending');
  out.staticHidden = needs.map(n => n.classList.contains('hidden'));
  await loadLocations(); await loadUnits(); await loadPermissionMatrix();
  await loadRecipes(); await loadAllDevices(); await loadParamSets();
  const h = id => document.getElementById(id).innerHTML;
  out.loc = h('loc-table-wrap'); out.unit = h('unit-table-wrap'); out.matrix = h('security-table-wrap');
  out.recipes = h('recipe-table-wrap'); out.ps = h('ps-wrap'); out.dev = h('dev-content');
  document.getElementById('recipe-show-retired').checked = true; renderRecipeTable();
  out.recipesRetired = h('recipe-table-wrap');
  const hid = id => document.getElementById(id).classList.contains('hidden');
  out.recipeExportAllHidden = hid('recipe-export-all-btn'); out.devExportAllHidden = hid('dev-export-all-btn');
  renderRecipeFreeze({ recipe_id: 3, status: 'draft' });
  out.draftSaveHidden = hid('recipe-save-btn'); out.draftAddStepHidden = hid('recipe-addstep-btn');
  renderRecipeFreeze({ recipe_id: 3, status: 'approved' });
  out.approvedBanner = document.getElementById('recipe-frozen-banner').textContent;
  out.approvedCopyHidden = hid('recipe-copy-btn');
  console.log(JSON.stringify(out));
};
eval(script.replace(/loadLocations\(\);\s*probeApprovals\(\);\s*$/, '') + '\n;(' + main.toString() + ')().catch(e => { console.error(e && e.stack || e); process.exit(1); });');
"""


@unittest.skipUnless(NODE, "node is not installed")
class RenderUnderNode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, tmp)
        js = os.path.join(tmp, "render.js")
        with open(js, "w", encoding="utf-8") as f:
            f.write(RENDER_HARNESS)
        cls.out = {}
        for scenario in ("none", "all", "noread", "hang"):
            r = subprocess.run([NODE, js, INDEX, scenario], capture_output=True, text=True, timeout=60)
            if r.returncode:
                raise AssertionError(scenario + ": " + r.stderr)
            cls.out[scenario] = json.loads(r.stdout.strip().splitlines()[-1])

    ROW_CONTROLS = (("loc", "openLocForm("), ("unit", "openUnitForm("), ("matrix", "grantPermission("),
                    ("matrix", "openPermAlgoModal("), ("dev", "openDeviceModal("), ("recipes", "copyRecipeById("))

    def test_refused_probes_hide_every_write_control(self):
        o = self.out["none"]
        self.assertTrue(o["pendingBefore"])
        self.assertFalse(o["pendingAfter"])
        self.assertTrue(o["staticHidden"] and all(o["staticHidden"]))
        for panel, control in self.ROW_CONTROLS:
            self.assertNotIn(control, o[panel], panel)
        self.assertIn(">View</button>", o["recipes"])
        self.assertNotIn(">Edit</button>", o["recipes"] + o["ps"] + o["unit"] + o["loc"])
        self.assertTrue(o["draftSaveHidden"])
        self.assertTrue(o["draftAddStepHidden"])
        self.assertTrue(o["approvedCopyHidden"])
        self.assertEqual(o["approvedBanner"], "Approved: this recipe is frozen.")

    def test_allowed_probes_show_them(self):
        o = self.out["all"]
        self.assertFalse(o["pendingAfter"])
        self.assertFalse(any(o["staticHidden"]))
        for panel, control in self.ROW_CONTROLS:
            self.assertIn(control, o[panel], panel)
        self.assertFalse(o["draftSaveHidden"])
        self.assertFalse(o["draftAddStepHidden"])
        self.assertIn("⎘ Copy", o["approvedBanner"])
        self.assertFalse(o["recipeExportAllHidden"])
        self.assertFalse(o["devExportAllHidden"])

    def test_unanswered_probes_count_as_unknown(self):
        o = self.out["hang"]
        self.assertTrue(all(v is None for v in o["rights"].values()), o["rights"])
        self.assertFalse(o["pendingAfter"])
        self.assertFalse(any(o["staticHidden"]))
        self.assertIn("openUnitForm(", o["unit"])

    def test_refused_reads_keep_their_message(self):
        o = self.out["noread"]
        self.assertEqual(o["recipes"], '<div class="empty">Your role does not read recipes.</div>')
        self.assertEqual(o["recipesRetired"], o["recipes"])        # Show retired keeps it
        self.assertIn("Your role does not read devices.", o["dev"])
        self.assertTrue(o["recipeExportAllHidden"])
        self.assertTrue(o["devExportAllHidden"])


class Docs(unittest.TestCase):
    def test_manual(self):
        want = {"apps.html": ['id="apps-config-rights"'], "access.html": ['href="#apps-config-rights"'],
                "compliance.html": ["Configuration UI follows the database"],
                "training.html": ['id="training-e33"', 'href="#training-e33"']}
        for name, keys in want.items():
            text = read(os.path.join(CHAPTERS, name))
            for k in keys:
                self.assertTrue(k in text, f"{name} lacks {k}")


if __name__ == "__main__":
    unittest.main()
